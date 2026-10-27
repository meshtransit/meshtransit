package k8sstate

import (
	"strings"
	"testing"
)

// The replica reads its cluster's issuer and keys with its own token, as
// any ServiceAccount may (system:service-account-issuer-discovery).
func TestReadSigningKeys(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	issuer, jwks, err := ReadSigningKeys(t.Context(), api.config(t))
	if err != nil || issuer != testIssuer || string(jwks) != testJWKS {
		t.Fatalf("ReadSigningKeys() = %q, %q, %v", issuer, jwks, err)
	}
}

// A cluster that took the discovery binding away says so plainly.
func TestReadSigningKeysForbidden(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	api.mu.Lock()
	api.signingForbidden = true
	api.mu.Unlock()
	_, _, err := ReadSigningKeys(t.Context(), api.config(t))
	if err == nil || !strings.Contains(err.Error(), "service-account-issuer-discovery") {
		t.Fatalf("ReadSigningKeys() error = %v", err)
	}
}
