package jwtauth

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configPath string = "config"

	pathConfigHelpSyn = `
Configures the JWT auto roles authentication backend.
`
	pathConfigHelpDesc = `
The JWT auto roles authentication backend uses configured bound claims of another
jwt auth backends's roles to quickly deduce which roles an incoming jwt unlocks.
`
)

type jwtAutoRolesConfig struct {
	// Roles map role names to bound claims. Bound claims must be of type
	// map[string][]string.
	Roles       map[string]any `json:"roles"`
	JWTAuthHost string         `json:"jwt_auth_host"`
	JWTAuthPath string         `json:"jwt_auth_path"`
	UserClaim   string         `json:"user_claim"`
}

func pathConfig(backend *jwtAutoRolesAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: `config`,
		Fields: map[string]*framework.FieldSchema{
			"roles": {
				Type: framework.TypeMap,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "List of role names",
				},
			},
			"jwt_auth_host": {
				Type: framework.TypeString,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Hostname of the vault instance",
				},
			},
			"jwt_auth_path": {
				Type: framework.TypeString,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Path of the default jwt auth plugin (without 'auth' or 'login')",
				},
			},
			"user_claim": {
				Type: framework.TypeString,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Claim in JWT claims to use for entity alias name",
				},
			},
			"vault_token": {
				Type: framework.TypeString,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Token to use to fetch roles instead of including them in 'roles'",
				},
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: backend.pathConfigRead,
				Summary:  "Read the current JWT auto roles authentication backend configuration.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: backend.pathConfigWrite,
				Summary:  "Configure the JWT auto roles authentication backend.",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: backend.pathConfigDelete,
				Summary:  "Delete the JWT auto roles authentication backend config.",
			},
		},

		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}
}

func (b *jwtAutoRolesAuthBackend) config(ctx context.Context, storage logical.Storage) (*jwtAutoRolesConfig, error) {
	if b.cachedConfig != nil {
		return b.cachedConfig, nil
	}

	b.l.Lock()
	defer b.l.Unlock()

	entry, err := storage.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	config := &jwtAutoRolesConfig{}
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}

	b.cachedConfig = config
	return config, nil
}

func (b *jwtAutoRolesAuthBackend) pathConfigWrite(
	ctx context.Context, req *logical.Request, d *framework.FieldData,
) (*logical.Response, error) {
	config := jwtAutoRolesConfig{
		Roles:       d.Get("roles").(map[string]any),
		JWTAuthHost: d.Get("jwt_auth_host").(string),
		JWTAuthPath: d.Get("jwt_auth_path").(string),
		UserClaim:   d.Get("user_claim").(string),
	}

	vaultToken := d.Get("vault_token").(string)
	if vaultToken != "" {
		if err := b.fetchRolesInto(ctx, &config, vaultToken); err != nil {
			return nil, err
		}
	}

	if _, err := parseRoles(&config); err != nil {
		return nil, fmt.Errorf("failed to parse roles: %w", err)
	}

	if err := writeConfig(ctx, req.Storage, &config); err != nil {
		return nil, err
	}

	b.reset()
	return nil, nil
}

func writeConfig(ctx context.Context, storage logical.Storage, config *jwtAutoRolesConfig) error {
	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return fmt.Errorf("failed to create storage: %w", err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to write storage: %w", err)
	}
	return nil
}

func (b *jwtAutoRolesAuthBackend) pathConfigRead(
	ctx context.Context, req *logical.Request, d *framework.FieldData,
) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]any{
			"roles":         config.Roles,
			"jwt_auth_host": config.JWTAuthHost,
			"jwt_auth_path": config.JWTAuthPath,
			"user_claim":    config.UserClaim,
		},
	}, nil
}

func (b *jwtAutoRolesAuthBackend) pathConfigDelete(
	ctx context.Context, req *logical.Request, d *framework.FieldData,
) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configPath)
	if err == nil {
		b.reset()
	}

	return nil, err
}
