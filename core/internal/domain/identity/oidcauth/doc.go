// Package oidcauth owns provider-neutral OIDC login transaction invariants.
//
// It deliberately excludes provider HTTP, PostgreSQL, HTTP cookie attributes, and Core RBAC.
// Opaque pre-authentication handles and encrypted browser proof are domain evidence,
// never an Account Session or browser admission by themselves.
// Adapters may transport the values produced here, but they cannot weaken the
// exact issuer, client, redirect, PKCE, or transaction binding.
package oidcauth
