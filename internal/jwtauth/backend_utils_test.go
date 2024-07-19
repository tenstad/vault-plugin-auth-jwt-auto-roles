package jwtauth

import (
	"context"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
)

func createTestBackend(t *testing.T) (*jwtAutoRolesAuthBackend, logical.Storage) {
	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.Trace),

		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: time.Hour * 12,
			MaxLeaseTTLVal:     time.Hour * 24,
		},
		StorageView: &logical.InmemStorage{},
	}

	logicalBackend, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	backend, ok := logicalBackend.(*jwtAutoRolesAuthBackend)
	if !ok {
		t.Fatal("backend is not a jwtAutoRolesAuthBackend")
	}

	return backend, config.StorageView
}

func testConfig() map[string]any {
	return map[string]any{
		"roles": map[string]any{
			"foo": map[string]any{
				"project_path": []any{"foo", "bar"},
			},
			"bar": map[string]any{
				"namespace_path": []any{"c"},
				"ref":            []any{"master", "main"},
			},
			"baz": map[string]any{
				"project_path": []any{"baz"},
			},
		},
		"jwt_auth_host": "http://localhost:8200",
		"jwt_auth_path": "foo/jwt",
		"user_claim":    "user_email",
		"vault_token":   "secret",
	}
}
