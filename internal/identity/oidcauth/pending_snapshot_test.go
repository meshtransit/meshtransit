package oidcauth

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestPendingSnapshotPreservesCreationHashWithoutResealing(t *testing.T) {
	t.Parallel()
	params := snapshotParamsFixture(t)
	snapshot, err := NewPendingSnapshot(params)
	if err != nil || !snapshot.IsValid() {
		t.Fatalf("NewPendingSnapshot() error = %v", err)
	}
	if snapshot.SemanticHash() != params.SemanticHash ||
		!bytes.Equal(snapshot.VerifierCiphertext().Bytes(), params.VerifierCiphertext.Bytes()) {
		t.Fatal("loading changed creation hash or ciphertext")
	}
	mutated := snapshot.VerifierCiphertext().Bytes()
	mutated[0] ^= 1
	if !snapshot.IsValid() {
		t.Fatal("ciphertext getter aliases loaded evidence")
	}
	for _, formatted := range []string{fmt.Sprint(snapshot), fmt.Sprintf("%#v", snapshot), snapshot.LogValue().String()} {
		if !bytes.Contains([]byte(formatted), []byte("REDACTED")) {
			t.Fatal("snapshot formatting disclosed evidence")
		}
	}
}

func TestPendingSnapshotRejectsUnboundOrNonPendingEvidence(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*PendingSnapshotParams)
	}{
		{"consuming", func(p *PendingSnapshotParams) { p.State = "consuming" }},
		{"terminal", func(p *PendingSnapshotParams) { p.State = "succeeded" }},
		{"other flow", func(p *PendingSnapshotParams) { p.FlowKind = "cli_loopback_authorization_code" }},
		{"other operation", func(p *PendingSnapshotParams) { p.OperationKind = "step_up" }},
		{"version", func(p *PendingSnapshotParams) { p.Version = 2 }},
		{"missing hash", func(p *PendingSnapshotParams) { p.SemanticHash = [32]byte{} }},
		{"changed hash", func(p *PendingSnapshotParams) { p.SemanticHash[0] ^= 1 }},
		{"changed state", func(p *PendingSnapshotParams) { p.StateDigest = p.NonceDigest }},
		{"timestamp precision", func(p *PendingSnapshotParams) { p.CreatedAt = p.CreatedAt.Add(time.Nanosecond) }},
		{"expiry binding", func(p *PendingSnapshotParams) { p.ExpiresAt = p.ExpiresAt.Add(time.Microsecond) }},
		{"zero route", func(p *PendingSnapshotParams) { p.Route = Route{} }},
		{"ciphertext substitution", func(p *PendingSnapshotParams) {
			value := p.VerifierCiphertext.Bytes()
			value[0] ^= 1
			p.VerifierCiphertext, _ = NewCiphertext(p.VerifierCiphertext.KeyID(), value)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			params := snapshotParamsFixture(t)
			test.mutate(&params)
			if _, err := NewPendingSnapshot(params); !errors.Is(err, ErrInvalidPendingSnapshot) {
				t.Fatalf("NewPendingSnapshot() error = %v", err)
			}
		})
	}
}

func snapshotParamsFixture(t *testing.T) PendingSnapshotParams {
	t.Helper()
	pending, _ := pendingFixture(t)
	return PendingSnapshotParams{
		TransactionID: pending.TransactionID(), Route: pending.Route(), Version: 1,
		State: "pending", FlowKind: "browser_authorization_code", OperationKind: "login",
		StateDigest: pending.StateDigest(), NonceDigest: pending.NonceDigest(),
		VerifierCiphertext: pending.VerifierCiphertext(), SemanticHash: pending.SemanticHash(),
		CreatedAt: pending.CreatedAt(), ExpiresAt: pending.ExpiresAt(),
	}
}

func TestPendingSnapshotRejectsEveryConfiguredRouteSubstitution(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*RouteParams)
	}{
		{"deployment", func(p *RouteParams) { p.DeploymentID = mustDeploymentID(t, "01890f00-0000-7000-8000-000000000101") }},
		{"workspace", func(p *RouteParams) { p.WorkspaceID = mustWorkspaceID(t, "01890f00-0000-7000-8000-000000000102") }},
		{"provider", func(p *RouteParams) { p.ProviderID = mustProviderID(t, "01890f00-0000-7000-8000-000000000103") }},
		{"client", func(p *RouteParams) { p.ClientID = mustClientID(t, "01890f00-0000-7000-8000-000000000104") }},
		{"generation", func(p *RouteParams) { p.ProviderGeneration++ }},
		{"epoch", func(p *RouteParams) { p.RecoveryEpoch++ }},
		{"issuer", func(p *RouteParams) { p.Issuer = "https://other.example.test/issuer" }},
		{"discovery", func(p *RouteParams) { p.DiscoveryURI = "https://other.example.test/discovery" }},
		{"authorization", func(p *RouteParams) { p.AuthorizationEndpoint = "https://other.example.test/auth" }},
		{"token", func(p *RouteParams) { p.TokenEndpoint = "https://other.example.test/token" }},
		{"jwks", func(p *RouteParams) { p.JWKSURI = "https://other.example.test/jwks" }},
		{"client id", func(p *RouteParams) { p.OIDCClientID = "other-client" }},
		{"auth method", func(p *RouteParams) { p.ClientAuthMethod = "private_key_jwt" }},
		{"scope ordering", func(p *RouteParams) { p.Scopes = []string{"profile", "openid", "email"} }},
		{"algorithm ordering", func(p *RouteParams) { p.AllowedAlgorithms = []string{"PS256", "RS256"} }},
		{"callback", func(p *RouteParams) { p.RedirectURI = "https://console.example.test/callback" }},
		{"redirect label", func(p *RouteParams) { p.RedirectID = "other-callback" }},
		{"return label", func(p *RouteParams) { p.ReturnRouteID = "other-return" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			params := snapshotParamsFixture(t)
			snapshot, err := NewPendingSnapshot(params)
			if err != nil {
				t.Fatal(err)
			}
			routeParams := routeParamsFixture(t)
			test.mutate(&routeParams)
			params.Route, err = NewRoute(routeParams)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.MatchesRoute(params.Route) {
				t.Fatal("changed route matched creation evidence")
			}
			if _, err := NewPendingSnapshot(params); !errors.Is(err, ErrInvalidPendingSnapshot) {
				t.Fatal("changed route accepted loaded hash")
			}
		})
	}
}
