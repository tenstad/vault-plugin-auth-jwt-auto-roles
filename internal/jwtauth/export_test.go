package jwtauth

import (
	"context"

	"github.com/hashicorp/vault-client-go/schema"
)

type (
	MultiroleJWTAuthBackend = multiroleJWTAuthBackend
	MultiroleJWTConfig      = multiroleJWTConfig
)

var ConfigMultiroleJWTAuthBackend = (*MultiroleJWTAuthBackend).config

func (b *multiroleJWTAuthBackend) SetPolicyFetcher(v policyFetcher) {
	b.policyClient = v
}

type PolicyFetchFn func(context.Context, schema.JwtLoginRequest) ([]string, error)

func (c PolicyFetchFn) policies(ctx context.Context, request schema.JwtLoginRequest) ([]string, error) {
	return c(ctx, request)
}
