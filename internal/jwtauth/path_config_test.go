package jwtauth_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/go-test/deep"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/statnett/vault-plugin-auth-jwt-auto-roles/internal/jwtauth"
)

const configPath = "config"

func TestConfig_Write(t *testing.T) {
	t.Parallel()
	backend, storage := createTestBackend(t)

	configData := testConfig()
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      configData,
	}

	resp, err := backend.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	conf, err := jwtauth.ConfigMultiroleJWTAuthBackend(backend, context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}

	expected := &jwtauth.MultiroleJWTConfig{
		Roles:       configData["roles"].(map[string]any),
		JWTAuthHost: "http://localhost:8200",
		JWTAuthPath: "foo/jwt",
	}

	if !reflect.DeepEqual(expected, conf) {
		t.Fatalf("expected did not match actual: expected %#v\n got %#v\n", expected, conf)
	}
}

func TestConfig_Read(t *testing.T) {
	t.Parallel()
	backend, storage := createTestBackend(t)

	configData := testConfig()
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      configData,
	}

	resp, err := backend.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      nil,
	}

	resp, err = backend.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if diff := deep.Equal(resp.Data, configData); diff != nil {
		t.Fatalf("Expected did not equal actual: %v", diff)
	}
}

func TestConfig_Delete(t *testing.T) {
	t.Parallel()
	backend, storage := createTestBackend(t)

	configData := testConfig()
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      configData,
	}

	resp, err := backend.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	conf, err := jwtauth.ConfigMultiroleJWTAuthBackend(backend, context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}
	if conf == nil {
		t.Fatal("expected config to exist after write")
	}

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      nil,
	}

	resp, err = backend.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	conf, err = jwtauth.ConfigMultiroleJWTAuthBackend(backend, context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}
	if conf != nil {
		t.Fatal("expected config to not exist after delete")
	}
}
