// Package oidcauth owns provider-neutral OIDC login transaction invariants.
//
// It deliberately excludes provider HTTP, PostgreSQL, cookies, and Core RBAC.
// Adapters may transport the values produced here, but they cannot weaken the
// exact issuer, client, redirect, PKCE, or transaction binding.
package oidcauth
