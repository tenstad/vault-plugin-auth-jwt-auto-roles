package jwtauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	pathFetchRolesHelpSyn = `
Triggers plugin to fetch latest roles.
`
	pathFetchRolesHelpDesc = `
Triggers plugin to use configured vault_token to fetch all the configured
jwt auth backend's roles. To be used whenever adding/removing roles in the
configured auth backend.
`
)

func pathFetchRoles(backend *jwtAutoRolesAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: `fetchroles`,
		Fields:  map[string]*framework.FieldSchema{},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: backend.pathFetchRolesWrite,
				Summary:  "Triggers plugin to fetch latest roles.",
			},
		},

		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}
}

func (b *jwtAutoRolesAuthBackend) pathFetchRolesWrite(
	ctx context.Context, req *logical.Request, d *framework.FieldData,
) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errors.New("plugin is not configured")
	}

	if config.VaultToken == "" {
		return nil, errors.New("vault_token is not configured")
	}

	if err := b.fetchRolesInto(ctx, config); err != nil {
		return nil, err
	}

	if _, err := parseRoles(config); err != nil {
		return nil, fmt.Errorf("failed to parse roles: %w", err)
	}
	if err := writeConfig(ctx, req.Storage, config); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}
