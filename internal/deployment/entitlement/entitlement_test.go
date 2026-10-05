package entitlement_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/deployment/entitlement"
	"github.com/meshtransit/meshtransit/internal/deployment/entitlement/issuer"
)

const (
	deploymentText  = "01890f00-0000-7000-8000-000000000001"
	entitlementText = "01890f00-0000-7000-8000-0000000000e1"
	keyID           = "poc-2026-10"
)

var now = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

type fixture struct {
	signing      ed25519.PrivateKey
	verifier     *entitlement.Verifier
	installation *entitlement.Installation
	installPub   ed25519.PublicKey
	deploymentID deployment.ID
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	signingPub, signing, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := entitlement.NewVerifier(map[string]ed25519.PublicKey{keyID: signingPub})
	if err != nil {
		t.Fatal(err)
	}
	var seed [ed25519.SeedSize]byte
	seed[0], seed[31] = 7, 9
	installation, err := entitlement.NewInstallation(seed)
	if err != nil {
		t.Fatal(err)
	}
	installPub, _ := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	deploymentID, err := deployment.ParseID(deploymentText)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{signing, verifier, installation, installPub, deploymentID}
}

func (f fixture) claims() issuer.Claims {
	return issuer.Claims{
		EntitlementID: entitlementText, DeploymentID: deploymentText, InstallationPublicKey: f.installPub,
		Profile: "cloud", MaxActiveWorkspaces: 50, MaxOwnedWorkspacesPerAccount: 5,
		Capabilities: []entitlement.Capability{}, Generation: 1,
		IssuedAt: now.Add(-time.Hour), NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(30 * 24 * time.Hour),
		Grace: 14 * 24 * time.Hour,
	}
}

func (f fixture) sign(t *testing.T, claims issuer.Claims) []byte {
	t.Helper()
	raw, err := issuer.Sign(claims, keyID, f.signing)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifyAcceptsBoundEntitlement(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result, err := f.verifier.Verify(f.sign(t, f.claims()), f.deploymentID, f.installation, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile != deployment.ProfileCloud || result.Limits.MaxActiveWorkspaces != 50 ||
		result.Limits.MaxOwnedWorkspacesPerAccount != 5 || result.Generation != 1 || result.KeyID != keyID ||
		result.StateAt(now) != entitlement.StateActive || result.Has(entitlement.CapabilityCloudBilling) {
		t.Fatalf("unexpected entitlement %+v", result)
	}
}

func TestVerifyStates(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result, err := f.verifier.Verify(f.sign(t, f.claims()), f.deploymentID, f.installation, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.StateAt(result.ExpiresAt) != entitlement.StateGrace ||
		result.StateAt(result.ExpiresAt.Add(result.Grace)) != entitlement.StateExpired {
		t.Fatal("grace window boundaries are wrong")
	}
	expired := f.claims()
	expired.NotBefore, expired.IssuedAt = now.Add(-90*24*time.Hour), now.Add(-90*24*time.Hour)
	expired.ExpiresAt = now.Add(-60 * 24 * time.Hour)
	past, err := f.verifier.Verify(f.sign(t, expired), f.deploymentID, f.installation, now)
	if err != nil || past.StateAt(now) != entitlement.StateExpired {
		t.Fatalf("expired entitlement must still verify with expired state: %v", err)
	}
	future := f.claims()
	future.NotBefore, future.IssuedAt = now.Add(time.Hour), now.Add(time.Hour)
	if _, err := f.verifier.Verify(f.sign(t, future), f.deploymentID, f.installation, now); !errors.Is(err, entitlement.ErrNotYetValid) {
		t.Fatalf("future entitlement: %v", err)
	}
}

func TestVerifyRejectsForeignAndUntrusted(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	raw := f.sign(t, f.claims())
	other, err := deployment.ParseID("01890f00-0000-7000-8000-000000000002")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.verifier.Verify(raw, other, f.installation, now); !errors.Is(err, entitlement.ErrForeign) {
		t.Fatalf("foreign Deployment: %v", err)
	}
	var seed [ed25519.SeedSize]byte
	seed[0] = 1
	copied, err := entitlement.NewInstallation(seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.verifier.Verify(raw, f.deploymentID, copied, now); !errors.Is(err, entitlement.ErrForeign) {
		t.Fatalf("copied entitlement on another installation: %v", err)
	}
	stranger := newFixture(t)
	if _, err := stranger.verifier.Verify(raw, f.deploymentID, f.installation, now); !errors.Is(err, entitlement.ErrUntrusted) {
		t.Fatalf("unknown signer: %v", err)
	}
	var outer map[string]string
	if err := json.Unmarshal(raw, &outer); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(outer["payload"])
	outer["payload"] = base64.RawURLEncoding.EncodeToString(
		[]byte(strings.Replace(string(payload), `"max_active_workspaces":50`, `"max_active_workspaces":500`, 1)))
	tampered, _ := json.Marshal(outer)
	if _, err := f.verifier.Verify(tampered, f.deploymentID, f.installation, now); !errors.Is(err, entitlement.ErrUntrusted) {
		t.Fatalf("tampered limits: %v", err)
	}
}

func TestVerifyRejectsInvalidClaims(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for name, mutate := range map[string]func(*issuer.Claims){
		"zero generation":         func(c *issuer.Claims) { c.Generation = 0 },
		"unknown profile":         func(c *issuer.Claims) { c.Profile = "enterprise" },
		"zero workspaces":         func(c *issuer.Claims) { c.MaxActiveWorkspaces = 0 },
		"owned above deployment":  func(c *issuer.Claims) { c.MaxActiveWorkspaces, c.MaxOwnedWorkspacesPerAccount = 3, 5 },
		"unknown capability":      func(c *issuer.Claims) { c.Capabilities = []entitlement.Capability{"vip"} },
		"duplicate capability":    func(c *issuer.Claims) { c.Capabilities = []entitlement.Capability{"cloud_billing", "cloud_billing"} },
		"expires before start":    func(c *issuer.Claims) { c.ExpiresAt = c.NotBefore },
		"lifetime too long":       func(c *issuer.Claims) { c.ExpiresAt = c.NotBefore.Add(4 * 366 * 24 * time.Hour) },
		"grace too long":          func(c *issuer.Claims) { c.Grace = 91 * 24 * time.Hour },
		"issued after not_before": func(c *issuer.Claims) { c.IssuedAt = c.NotBefore.Add(time.Hour) },
		"bad entitlement id":      func(c *issuer.Claims) { c.EntitlementID = "not-a-uuid" },
	} {
		claims := f.claims()
		mutate(&claims)
		if _, err := f.verifier.Verify(f.sign(t, claims), f.deploymentID, f.installation, now); !errors.Is(err, entitlement.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, raw := range map[string]string{
		"empty":         "",
		"not json":      "{",
		"unknown field": `{"format":"meshtransit-deployment-entitlement/v1","key_id":"poc-2026-10","payload":"e30","signature":"AA","extra":1}`,
		"trailing data": string(f.sign(t, f.claims())) + "{}",
		"oversized":     strings.Repeat(" ", entitlement.MaxEnvelopeBytes+1),
	} {
		if _, err := f.verifier.Verify([]byte(raw), f.deploymentID, f.installation, now); !errors.Is(err, entitlement.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestConstructorsRejectBadKeys(t *testing.T) {
	t.Parallel()
	if _, err := entitlement.NewVerifier(nil); err == nil {
		t.Fatal("empty allowlist accepted")
	}
	if _, err := entitlement.NewVerifier(map[string]ed25519.PublicKey{"Bad ID": make(ed25519.PublicKey, 32)}); err == nil {
		t.Fatal("invalid key ID accepted")
	}
	if _, err := entitlement.NewInstallation([ed25519.SeedSize]byte{}); err == nil {
		t.Fatal("all-zero installation seed accepted")
	}
}

func TestTrustedVerifierLoadsEmbeddedKeys(t *testing.T) {
	t.Parallel()
	if _, err := entitlement.TrustedVerifier(); err != nil {
		t.Fatal(err)
	}
}
