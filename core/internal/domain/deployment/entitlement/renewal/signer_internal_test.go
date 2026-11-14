package renewal

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/deployment/entitlement"
)

func internalSigner(t *testing.T) *Signer {
	t.Helper()
	var seed, installSeed [ed25519.SeedSize]byte
	seed[0], installSeed[0] = 4, 6
	installation, err := entitlement.NewInstallation(installSeed)
	if err != nil {
		t.Fatal(err)
	}
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	public, _ := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	verifier, err := entitlement.NewScopedVerifier(map[string]entitlement.TrustedKey{
		"renew": {Public: public, Deployment: deploymentID, Profile: deployment.ProfileCloud},
	})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner("renew", seed, installation, deploymentID, verifier)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestSignerNeverFormatsItsKey(t *testing.T) {
	t.Parallel()
	signer := internalSigner(t)
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("signer", "signer", signer)
	formatted := fmt.Sprintf("%v %+v %#v %s", signer, signer, signer, signer) + logged.String()
	for _, secret := range []string{fmt.Sprintf("%d", []byte(signer.private)), fmt.Sprintf("%x", signer.private[:8])} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("the private key was formatted: %s", formatted)
		}
	}
	var nilSigner *Signer
	if nilSigner.String() != "renewal.Signer(nil)" {
		t.Fatal("a nil signer does not format")
	}
}

func TestForgottenSignerSignsNothing(t *testing.T) {
	t.Parallel()
	signer := internalSigner(t)
	signer.forget()
	current := Current{Generation: 1, Profile: deployment.ProfileCloud,
		Limits:    entitlement.Limits{MaxActiveWorkspaces: 1, MaxOwnedWorkspacesPerAccount: 1},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
	if _, err := signer.Next(current, time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ErrInvalidSigner) {
		t.Fatalf("Next() after forget = %v", err)
	}
}
