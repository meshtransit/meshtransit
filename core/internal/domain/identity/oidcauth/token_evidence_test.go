package oidcauth

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTokenEvidencePreservesOpaqueIdentityAndCopiesAssurance(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	params := TokenEvidenceParams{Issuer: routeFixture(t).Issuer(), Subject: "Case-Sensitive-Subject", SessionID: "private-sid", Nonce: secretFixture(t).Nonce(), IssuedAt: now, ExpiresAt: now.Add(time.Minute), AuthTime: now.Add(-time.Hour), ACR: "assurance", AMR: []string{"pwd", "otp"}}
	evidence, err := NewTokenEvidence(params)
	if err != nil {
		t.Fatal(err)
	}
	params.AMR[0] = "changed"
	identity := evidence.identity
	methods := identity.AMR()
	methods[0] = "changed-again"
	if identity.Subject() != params.Subject || identity.SessionID() != params.SessionID || identity.AMR()[0] != "pwd" || identity.AuthTime() != params.AuthTime {
		t.Fatal("identity/defensive-copy invariant failed")
	}
	for _, value := range []any{params, evidence, identity} {
		if fmt.Sprint(value) != "[REDACTED]" || strings.Contains(fmt.Sprintf("%#v", value), "Subject") || strings.Contains(fmt.Sprintf("%+v", value), "private-sid") {
			t.Fatal("identity formatting leaked")
		}
	}
	params.AMR, params.AuthTime, params.ACR, params.SessionID = nil, time.Time{}, "", ""
	plain, err := NewTokenEvidence(params)
	if err != nil || !plain.identity.AuthTime().IsZero() || len(plain.identity.AMR()) != 0 || plain.identity.ACR() != "" {
		t.Fatal("absent assurance invented")
	}
}
