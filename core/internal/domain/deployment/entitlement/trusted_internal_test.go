package entitlement

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/deployment"
)

const scopedDeploymentText = "01890f00-0000-7000-8000-000000000001"

func encodedKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(public)
}

func TestVerifierFromKeepsEachScope(t *testing.T) {
	t.Parallel()
	offline, renewal := encodedKey(t), encodedKey(t)
	verifier, err := verifierFrom(map[string]trustedKey{
		"offline": {public: offline},
		"renewal": {public: renewal, deployment: scopedDeploymentText, profile: deployment.ProfileCloud},
	})
	if err != nil {
		t.Fatal(err)
	}
	if verifier.IsScoped("offline") || !verifier.IsScoped("renewal") {
		t.Fatal("the scope of an embedded key was lost")
	}
}

func TestVerifierFromRefusesAHalfScopeAndAReusedKey(t *testing.T) {
	t.Parallel()
	key := encodedKey(t)
	for name, entries := range map[string]map[string]trustedKey{
		"profile without Deployment": {"renewal": {public: key, profile: deployment.ProfileCloud}},
		"Deployment without profile": {"renewal": {public: key, deployment: scopedDeploymentText}},
		"one key, scoped and not": {
			"offline": {public: key},
			"renewal": {public: key, deployment: scopedDeploymentText, profile: deployment.ProfileCloud},
		},
	} {
		if _, err := verifierFrom(entries); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: verifierFrom() = %v", name, err)
		}
	}
}

func TestEmbeddedAllowlistLoads(t *testing.T) {
	t.Parallel()
	verifier, err := TrustedVerifier()
	if err != nil {
		t.Fatal(err)
	}
	// The offline key verifies any Deployment; the POC renewal key only the POC's.
	if verifier.IsScoped("meshtransit-poc-2026-10") || !verifier.IsScoped("meshtransit-cloud-renew-2026") {
		t.Fatal("embedded key scopes changed")
	}
	public, err := base64.StdEncoding.DecodeString(trustedKeys["meshtransit-cloud-renew-2026"].public)
	if err != nil {
		t.Fatal(err)
	}
	poc, err := deployment.ParseID("01995d00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.CheckRenewalKey("meshtransit-cloud-renew-2026", public, poc, deployment.ProfileCloud); err != nil {
		t.Fatalf("POC renewal key: %v", err)
	}
}
