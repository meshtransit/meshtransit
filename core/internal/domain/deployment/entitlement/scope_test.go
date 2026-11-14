package entitlement_test

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/deployment/entitlement"
	"meshtransit.net/core/internal/domain/deployment/entitlement/issuer"
)

const otherDeploymentText = "01890f00-0000-7000-8000-000000000002"

// scopedFixture trusts the fixture's key only for its own Deployment and the
// cloud profile, as a self-renewal key is.
func scopedFixture(t *testing.T) (fixture, *entitlement.Verifier) {
	t.Helper()
	f := newFixture(t)
	public, _ := f.signing.Public().(ed25519.PublicKey)
	verifier, err := entitlement.NewScopedVerifier(map[string]entitlement.TrustedKey{
		keyID: {Public: public, Deployment: f.deploymentID, Profile: deployment.ProfileCloud},
	})
	if err != nil {
		t.Fatal(err)
	}
	return f, verifier
}

func TestScopedKeyVerifiesOnlyItsDeploymentAndProfile(t *testing.T) {
	t.Parallel()
	f, verifier := scopedFixture(t)
	envelope, err := issuer.Sign(f.claims(), keyID, f.signing)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(envelope, f.deploymentID, f.installation, now); err != nil {
		t.Fatalf("in scope: %v", err)
	}

	tests := map[string]func(*issuer.Claims){
		"another Deployment": func(claims *issuer.Claims) { claims.DeploymentID = otherDeploymentText },
		"another profile": func(claims *issuer.Claims) {
			claims.Profile = string(deployment.ProfileSelfHosted)
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			claims := f.claims()
			change(&claims)
			envelope, err := issuer.Sign(claims, keyID, f.signing)
			if err != nil {
				t.Fatal(err)
			}
			// Parse alone already refuses it: the scope belongs to the key.
			if _, err := verifier.Parse(envelope, now); !errors.Is(err, entitlement.ErrUntrusted) {
				t.Fatalf("Parse() out of scope = %v, want ErrUntrusted", err)
			}
		})
	}
}

func TestRenewalKeyNeedsAScope(t *testing.T) {
	t.Parallel()
	f, scoped := scopedFixture(t)
	public, _ := f.signing.Public().(ed25519.PublicKey)
	if err := scoped.CheckRenewalKey(keyID, public, f.deploymentID, deployment.ProfileCloud); err != nil {
		t.Fatalf("scoped key: %v", err)
	}
	other, err := deployment.ParseID(otherDeploymentText)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	unscoped, err := entitlement.NewVerifier(map[string]ed25519.PublicKey{keyID: public})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]error{
		"unknown key ID":            scoped.CheckRenewalKey("other-key", public, f.deploymentID, deployment.ProfileCloud),
		"another private key":       scoped.CheckRenewalKey(keyID, otherPublic, f.deploymentID, deployment.ProfileCloud),
		"another Deployment":        scoped.CheckRenewalKey(keyID, public, other, deployment.ProfileCloud),
		"another profile":           scoped.CheckRenewalKey(keyID, public, f.deploymentID, deployment.ProfileSelfHosted),
		"an unscoped (offline) key": unscoped.CheckRenewalKey(keyID, public, f.deploymentID, deployment.ProfileCloud),
	}
	for name, err := range cases {
		if !errors.Is(err, entitlement.ErrRenewalKey) {
			t.Errorf("%s: CheckRenewalKey() = %v, want ErrRenewalKey", name, err)
		}
	}
}

func TestScopedVerifierRejectsAHalfScope(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	public, _ := f.signing.Public().(ed25519.PublicKey)
	for name, key := range map[string]entitlement.TrustedKey{
		"Deployment without profile": {Public: public, Deployment: f.deploymentID},
		"profile without Deployment": {Public: public, Profile: deployment.ProfileCloud},
	} {
		if _, err := entitlement.NewScopedVerifier(map[string]entitlement.TrustedKey{keyID: key}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestScopedKeySignsOnlyARenewalsWindow(t *testing.T) {
	t.Parallel()
	f, verifier := scopedFixture(t)
	for name, change := range map[string]func(*issuer.Claims){
		"two years":         func(claims *issuer.Claims) { claims.ExpiresAt = claims.NotBefore.AddDate(2, 0, 0) },
		"90 days of grace":  func(claims *issuer.Claims) { claims.Grace = 90 * 24 * time.Hour },
		"a huge generation": func(claims *issuer.Claims) { claims.Generation = 1 << 41 },
	} {
		claims := f.claims()
		change(&claims)
		envelope, err := issuer.Sign(claims, keyID, f.signing)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifier.Parse(envelope, now); !errors.Is(err, entitlement.ErrUntrusted) {
			t.Errorf("%s: Parse() = %v, want ErrUntrusted", name, err)
		}
	}
}
