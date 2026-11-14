package main

import (
	"crypto/ed25519"
	"io"
	"log/slog"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/deployment/entitlement"
	"meshtransit.net/core/internal/domain/deployment/entitlement/renewal"
)

func TestRecordDeploymentEntitlementIsOptional(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	code, err := recordDeploymentEntitlement(t.Context(), nil, nil, logger, time.Now())
	if err != nil || code != "" {
		t.Fatalf("absent entitlement settings failed startup: %s %v", code, err)
	}
}

func TestEntitlementRenewerIsOptional(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	renewer, metrics, code, err := composeEntitlementRenewer(t.Context(), nil, nil, logger)
	if err != nil || code != "" || renewer != nil || metrics != nil {
		t.Fatalf("absent renewal key composed a renewer: %v %s %v", renewer, code, err)
	}
}

func TestMountSupersededOnlyByARenewal(t *testing.T) {
	t.Parallel()
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	offline, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := entitlement.NewScopedVerifier(map[string]entitlement.TrustedKey{
		"cloud-renew": {Public: public, Deployment: deploymentID, Profile: deployment.ProfileCloud},
		"offline":     {Public: offline},
	})
	if err != nil {
		t.Fatal(err)
	}
	mounted := entitlement.Entitlement{Generation: 3}
	for name, test := range map[string]struct {
		current    renewal.Current
		found      bool
		superseded bool
	}{
		"a renewal took the number":      {renewal.Current{Generation: 3, SignerKeyID: "cloud-renew"}, true, true},
		"a newer generation is recorded": {renewal.Current{Generation: 4, SignerKeyID: "offline"}, true, true},
		"an offline issuance reused it":  {renewal.Current{Generation: 3, SignerKeyID: "offline"}, true, false},
		"an unknown signer":              {renewal.Current{Generation: 3, SignerKeyID: "gone"}, true, false},
		"nothing recorded (cannot be)":   {renewal.Current{}, false, false},
	} {
		if got := mountSuperseded(mounted, test.current, test.found, verifier); got != test.superseded {
			t.Errorf("%s: mountSuperseded() = %v", name, got)
		}
	}
}
