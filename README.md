# vault-plugin-auth-jwt-auto-roles

A Vault plugin to automatically authenticate with all roles matching a JWT (or
OIDC) token, and grant access to the union of matching roles' policies.

**Problem**: The [builtin _jwt_ auth
plugin](https://github.com/hashicorp/vault-plugin-auth-jwt) requires a role-name
to be specified during authentication. When authenticated, access is only
granted based on the policies of that single role. Even though the JWT satisfies
multiple roles' bound claims. Repeated logins with different role names are thus
sometimes required, resulting in access being split over multiple tokens.

**Solution**: The _jwt-auto-roles_ plugin automatically determines which roles'
bound claims a JWT matches. It grants access to the union of all the matching
roles' policies. Thus a single login is sufficient to get a token with combined
access, with the JWT as the sole login parameter.

## Working Details

The plugin currently relies on the builtin _jwt_ plugin for JWT verification and
policy configuration. It simply determine the roles matching an incoming JWT's
claims, tries to login to a mount of the builtin _jwt_ plugin for each role, and
grants access to the union of policies returned by the builtin _jwt_ plugin
mount.

## Configuration

For the plugin to be able to determine matching roles, it must be configured
with all the roles of a builtin _jwt_ plugin mount, and their bound claims.

## Future work

The plugin could be configured with policies directly, instead of role names,
and not rely on the builtin _jwt_ plugin for token verification. Although
simpler to configure, security guarantees will no longer be delegated to
HashiCorp.
