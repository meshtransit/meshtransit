package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/publicid"
)

func TestTransitionStateMatchesExactAuthority(t *testing.T) {
	t.Parallel()
	spec, err := parseTransitionSpec(validArgs("apply"), lookupFromMap(validEnvironment(true)))
	if err != nil {
		t.Fatalf("parseTransitionSpec() error = %v", err)
	}
	valid := validTransitionState()
	if !valid.matches(spec) {
		t.Fatal("valid state was rejected")
	}
	tests := []struct {
		name   string
		mutate func(*transitionState)
	}{
		{name: "direct provider", mutate: func(state *transitionState) { state.providerAuthorityKind = "external_oidc" }},
		{name: "unproven generation", mutate: func(state *transitionState) { state.generationRecoveryMode = "unproven" }},
		{name: "scope already widened", mutate: func(state *transitionState) {
			state.clientAllowedScopes = append(state.clientAllowedScopes, "federated:id")
		}},
		{name: "missing code flow", mutate: func(state *transitionState) { state.clientAllowedFlows = []string{"device_authorization"} }},
		{name: "stale provider", mutate: func(state *transitionState) { state.providerVersion++ }},
		{name: "no active route", mutate: func(state *transitionState) { state.activeRouteCount = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			state := validTransitionState()
			test.mutate(&state)
			if state.matches(spec) {
				t.Fatal("unsafe state was accepted")
			}
		})
	}
}

func TestNewTransitionIDsRejectsGeneratorFailureAndAliasing(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("entropy unavailable")
	if _, err := newTransitionIDs(func() (publicid.ID, error) {
		return publicid.ID{}, wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("newTransitionIDs() error = %v, want entropy failure", err)
	}
	id := mustPublicID(t, "01890f00-0000-7000-8000-000000000101")
	if _, err := newTransitionIDs(func() (publicid.ID, error) { return id, nil }); !errors.Is(err, errInvalidInput) {
		t.Fatalf("newTransitionIDs() alias error = %v, want errInvalidInput", err)
	}
}

func TestNewTransitionIDsPreservesStableRoles(t *testing.T) {
	t.Parallel()
	values := []publicid.ID{
		mustPublicID(t, "01890f00-0000-7000-8000-000000000101"),
		mustPublicID(t, "01890f00-0000-7000-8000-000000000102"),
		mustPublicID(t, "01890f00-0000-7000-8000-000000000103"),
		mustPublicID(t, "01890f00-0000-7000-8000-000000000104"),
	}
	index := 0
	ids, err := newTransitionIDs(func() (publicid.ID, error) {
		id := values[index]
		index++
		return id, nil
	})
	if err != nil {
		t.Fatalf("newTransitionIDs() error = %v", err)
	}
	if ids.change != values[0] || ids.generation != values[1] ||
		ids.auditEvent != values[2] || ids.outboxEvent != values[3] {
		t.Fatalf("newTransitionIDs() = %+v", ids)
	}
}

func TestTransitionSemanticHashBindsGenerationVersionAndScopes(t *testing.T) {
	t.Parallel()
	base := transitionSemanticSnapshot{
		ProviderID: testProviderID, ClientID: testClientID,
		ProviderGeneration: 1, ProviderVersion: 1,
		GenerationVersion: 1, ClientVersion: 1,
		AllowedScopes: []string{"openid"},
	}
	baseHash, err := hashTransitionSnapshot(base)
	if err != nil {
		t.Fatalf("hashTransitionSnapshot() error = %v", err)
	}
	changed := base
	changed.ProviderGeneration = 2
	changed.ProviderVersion = 2
	changed.ClientVersion = 2
	changed.AllowedScopes = []string{"openid", "federated:id"}
	changedHash, err := hashTransitionSnapshot(changed)
	if err != nil {
		t.Fatalf("hashTransitionSnapshot() changed error = %v", err)
	}
	if bytes.Equal(baseHash[:], changedHash[:]) {
		t.Fatal("semantic hash did not bind authority transition")
	}
}

func TestTransitionSQLKeepsScopeChangeClosedAndFenced(t *testing.T) {
	t.Parallel()
	for _, fragment := range []string{
		"allowed_scopes = ARRAY['openid', 'federated:id']::TEXT[]",
		"allowed_scopes = ARRAY['openid']::TEXT[]",
		"version = $3::BIGINT",
		"state = 'active'",
		"deleted_at IS NULL",
	} {
		if !strings.Contains(updateProviderClientScopesSQL, fragment) {
			t.Fatalf("scope transition SQL missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"state = 'superseded'",
		"valid_until = pg_catalog.transaction_timestamp()",
		"version = $4::BIGINT",
	} {
		if !strings.Contains(supersedeProviderGenerationSQL, fragment) {
			t.Fatalf("generation transition SQL missing %q", fragment)
		}
	}
}

func validTransitionState() transitionState {
	return transitionState{
		deploymentInternalID: 1, deploymentProfile: "self_hosted",
		deploymentRecoveryState: "verified", deploymentState: "active",
		providerInternalID: 2, providerGeneration: 1,
		providerRecoveryState: "verified", providerState: "active",
		providerProtocol: "oidc", providerAuthorityKind: "managed_oidc", providerVersion: 1,
		generationInternalID: 3,
		generationPublicID:   "01890f00-0000-7000-8000-000000000005",
		generation:           1, trustConfigurationHash: bytes.Repeat([]byte{1}, 32),
		generationRecoveryMode: "initial", generationState: "current", generationVersion: 1,
		clientInternalID: 4, clientKind: "confidential",
		clientAllowedFlows:  []string{"authorization_code"},
		clientAllowedScopes: []string{"openid"}, clientState: "active", clientVersion: 1,
		actorInternalID: 5, actorKind: "account", actorState: "active", activeRouteCount: 1,
	}
}

func mustPublicID(t *testing.T, value string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse(value)
	if err != nil {
		t.Fatalf("publicid.Parse() error = %v", err)
	}
	return id
}
