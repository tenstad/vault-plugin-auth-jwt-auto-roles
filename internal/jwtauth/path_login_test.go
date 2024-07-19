package jwtauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestLogin_Write(t *testing.T) {
	t.Parallel()
	backend, storage := createTestBackend(t)

	configData := map[string]any{
		"roles": map[string]any{
			"foo": map[string]any{
				"project_path": []any{"foo"},
			},
			"foobar": map[string]any{
				"namespace_path": []any{"ns"},
				"project_path":   []any{"foo", "bar"},
			},
			"baz": map[string]any{
				"project_path": []any{"baz"},
			},
		},
		"jwt_auth_host": "http://localhost:8200",
		"jwt_auth_path": "jwt",
	}
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      configData,
	}

	resp, err := backend.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	backend.vaultClient = fakeVaultFetcher{
		policiesFn: func(_ context.Context, request schema.JwtLoginRequest) ([]string, error) {
			return []string{request.Role + "-policy"}, nil
		},
		rolesFn: func(_ context.Context) (map[string]any, error) {
			roles := testConfig()["roles"].(map[string]any)
			return roles, nil
		},
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unable to create private key: %s", err.Error())
	}

	for i, tt := range []struct {
		claims   jwt.MapClaims
		policies []string
	}{
		{
			claims: jwt.MapClaims{
				"project_path": "foo",
			},
			policies: []string{"foo-policy"},
		},
		{
			claims: jwt.MapClaims{
				"project_path":   "foo",
				"namespace_path": "ns",
			},
			policies: []string{"foo-policy", "foobar-policy"},
		},
		{
			claims: jwt.MapClaims{
				"project_path": "baz",
			},
			policies: []string{"baz-policy"},
		},
	} {
		token, err := jwt.NewWithClaims(jwt.SigningMethodPS512, tt.claims).SignedString(privateKey)
		if err != nil {
			t.Fatalf("unable to sign jwt: %s", err.Error())
		}

		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data: map[string]any{
				"jwt": token,
			},
		}

		resp, err = backend.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		opt := cmpopts.SortSlices(func(a, b string) bool { return a < b })
		if diff := cmp.Diff(resp.Auth.Policies, tt.policies, opt); diff != "" {
			t.Fatalf("Test case %v failed with diff:\n%s", i, diff)
		}
	}
}

type fakeVaultFetcher struct {
	policiesFn func(context.Context, schema.JwtLoginRequest) ([]string, error)
	rolesFn    func(context.Context) (map[string]any, error)
}

func (f fakeVaultFetcher) policies(ctx context.Context, request schema.JwtLoginRequest) ([]string, error) {
	return f.policiesFn(ctx, request)
}

func (f fakeVaultFetcher) roles(ctx context.Context) (map[string]any, error) {
	return f.rolesFn(ctx)
}
