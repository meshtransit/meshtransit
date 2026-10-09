package accessgraph_test

import (
	"errors"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/sharing"
)

func TestServiceExplainsWhyConnectionIsDenied(t *testing.T) {
	t.Parallel()

	inactive := accessgraph.ParticipantStateInactive
	missing := accessgraph.ParticipantStateMissing
	for _, test := range []struct {
		name   string
		shared bool
		change func(*testing.T, *accessgraph.SnapshotParams)
		want   accessgraph.DenyReason
	}{
		{name: "no published policy", change: withoutActiveRelease, want: accessgraph.DenyReasonNoActiveRelease},
		{name: "inactive source", change: func(t *testing.T, params *accessgraph.SnapshotParams) {
			params.Source = accessGraphParticipant(t, inactive, "poc-02")
		}, want: accessgraph.DenyReasonSourceInactive},
		{name: "missing source", change: func(t *testing.T, params *accessgraph.SnapshotParams) {
			params.Source = accessGraphParticipant(t, missing, "")
		}, want: accessgraph.DenyReasonSourceInactive},
		{name: "inactive Device target", change: func(t *testing.T, params *accessgraph.SnapshotParams) {
			params.Target = accessGraphParticipant(t, inactive, "poc-03")
		}, want: accessgraph.DenyReasonTargetInactive},
		{name: "missing shared target", shared: true, change: func(t *testing.T, params *accessgraph.SnapshotParams) {
			params.Target, params.Share = accessGraphParticipant(t, missing, ""), nil
		}, want: accessgraph.DenyReasonTargetInactive},
		{name: "share not turned on", shared: true, change: withShareState(sharing.ContractStateActivating),
			want: accessgraph.DenyReasonShareActivating},
		{name: "revoked share", shared: true, change: withShareState(sharing.ContractStateRevoked),
			want: accessgraph.DenyReasonShareEnded},
		{name: "invalidated share", shared: true, change: withShareState(sharing.ContractStateInvalidated),
			want: accessgraph.DenyReasonShareEnded},
		{name: "expired share", shared: true, change: withShareState(sharing.ContractStateExpired),
			want: accessgraph.DenyReasonShareExpired},
		{name: "everything usable but no rule", change: func(*testing.T, *accessgraph.SnapshotParams) {},
			want: accessgraph.DenyReasonNoMatchingActiveRule},
		{name: "usable share but no rule", shared: true, change: func(*testing.T, *accessgraph.SnapshotParams) {},
			want: accessgraph.DenyReasonNoMatchingActiveRule},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			query := accessGraphQueryFixture(t, false, policy.ProtocolICMP, 0)
			if test.shared {
				query = accessGraphImportedResourceQueryFixture(t)
			}
			params := accessGraphSnapshotParams(t, query, nil)
			test.change(t, &params)
			result := explainSnapshot(t, query, params)
			reason, denied := result.DenyReason()
			if !result.IsValid() || result.Decision() != accessgraph.DecisionDeny || !denied || reason != test.want ||
				result.Reason() != accessgraph.ReasonNoMatchingActiveRule {
				t.Fatalf("decision = %s, deny reason = %s (%t), want %s", result.Decision(), reason, denied, test.want)
			}
		})
	}
}

func TestServiceExplainsAllowedSharedDevice(t *testing.T) {
	t.Parallel()

	query := accessGraphImportedResourceQueryFixture(t)
	path := accessGraphSharedPathFixture(t, accessGraphContractPublicID)
	result := explainSnapshot(t, query, accessGraphSnapshotParams(t, query, []accessgraph.Path{path}))
	paths := result.Paths()
	share, hasShare := result.Snapshot().Share()
	_, denied := result.DenyReason()
	if !result.IsValid() || result.Decision() != accessgraph.DecisionAllow || denied || len(paths) != 1 ||
		paths[0].SelectorKind() != accessgraph.SelectorKindImportedResource ||
		paths[0].DestinationNodeID().IsValid() ||
		paths[0].DestinationImportedResourceID() != query.DestinationImportedResourceID() ||
		!hasShare || paths[0].TrustContractID() != share.ContractID() {
		t.Fatalf("result = %+v, paths = %+v", result, paths)
	}
	if _, expires := share.ExpiresAt(); expires {
		t.Fatal("share without expiry reported an expiry")
	}
}

func TestSnapshotRejectsInconsistentExplanationContext(t *testing.T) {
	t.Parallel()

	inactive := accessgraph.ParticipantStateInactive
	for _, test := range []struct {
		name   string
		shared bool
		paths  func(*testing.T) []accessgraph.Path
		change func(*testing.T, *accessgraph.SnapshotParams)
	}{
		{name: "path from inactive source", paths: devicePaths, change: func(t *testing.T, params *accessgraph.SnapshotParams) {
			params.Source = accessGraphParticipant(t, inactive, "poc-02")
		}},
		{name: "path to inactive target", paths: devicePaths, change: func(t *testing.T, params *accessgraph.SnapshotParams) {
			params.Target = accessGraphParticipant(t, inactive, "poc-03")
		}},
		{name: "shared path through a share not turned on", shared: true, paths: sharedPaths,
			change: withShareState(sharing.ContractStateActivating)},
		{name: "shared path through another contract", shared: true, paths: func(t *testing.T) []accessgraph.Path {
			return []accessgraph.Path{accessGraphSharedPathFixture(t, "01890f00-0000-7000-8000-000000000852")}
		}, change: func(*testing.T, *accessgraph.SnapshotParams) {}},
		{name: "shared path for a Device target", paths: sharedPaths, change: func(*testing.T, *accessgraph.SnapshotParams) {}},
		{name: "share context for a Device target", change: func(t *testing.T, params *accessgraph.SnapshotParams) {
			share := accessGraphShareFixture(t, sharing.ContractStateActive)
			params.Share = &share
		}},
		{name: "existing shared target without share", shared: true, change: func(_ *testing.T, params *accessgraph.SnapshotParams) {
			params.Share = nil
		}},
		{name: "shared target with resolved Device", shared: true, change: func(t *testing.T, params *accessgraph.SnapshotParams) {
			params.TargetNodeID = accessGraphNodeID(t, 302)
		}},
		{name: "unknown target kind", change: func(_ *testing.T, params *accessgraph.SnapshotParams) {
			params.TargetKind = accessgraph.TargetKindUnknown
		}},
		{name: "missing participants", change: func(_ *testing.T, params *accessgraph.SnapshotParams) {
			params.Source = accessgraph.Participant{}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			query := accessGraphQueryFixture(t, false, policy.ProtocolTCP, 443)
			if test.shared {
				query = accessGraphImportedResourceQueryFixture(t)
			}
			var paths []accessgraph.Path
			if test.paths != nil {
				paths = test.paths(t)
			}
			params := accessGraphSnapshotParams(t, query, paths)
			test.change(t, &params)
			if _, err := accessgraph.NewSnapshot(params); !errors.Is(err, accessgraph.ErrInvalidSnapshot) {
				t.Fatalf("NewSnapshot() error = %v, want invalid snapshot", err)
			}
		})
	}
}

func TestServiceRejectsSnapshotForAnotherTargetKind(t *testing.T) {
	t.Parallel()

	deviceQuery := accessGraphQueryFixture(t, false, policy.ProtocolTCP, 443)
	resourceQuery := accessGraphQueryFixture(t, true, policy.ProtocolTCP, 443)
	snapshot, err := accessgraph.NewSnapshot(accessGraphSnapshotParams(t, deviceQuery, nil))
	if err != nil {
		t.Fatal(err)
	}
	service, err := accessgraph.NewService(accessgraph.Dependencies{
		Reader: &accessGraphReaderFixture{snapshot: snapshot},
		Clock:  fixedAccessGraphClock{value: accessGraphTime()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Explain(t.Context(), accessGraphSessionFixture(t), resourceQuery); !errors.Is(err, accessgraph.ErrInvalidSnapshot) {
		t.Fatalf("Explain() error = %v, want invalid snapshot", err)
	}
}

func TestParticipantAndShareContextAreBounded(t *testing.T) {
	t.Parallel()

	active := accessgraph.ParticipantStateActive
	for _, test := range []struct {
		name  string
		state accessgraph.ParticipantState
		value string
	}{
		{name: "unknown state", state: accessgraph.ParticipantStateUnknown, value: "poc-01"},
		{name: "named missing participant", state: accessgraph.ParticipantStateMissing, value: "poc-01"},
		{name: "control character", state: active, value: "poc\n01"},
		{name: "invalid UTF-8", state: active, value: string([]byte{0xff})},
		{name: "oversized name", state: active, value: strings.Repeat("a", accessgraph.MaximumParticipantNameBytes+1)},
	} {
		if _, err := accessgraph.NewParticipant(test.state, test.value); !errors.Is(err, accessgraph.ErrInvalidSnapshot) {
			t.Errorf("%s: NewParticipant() error = %v", test.name, err)
		}
	}
	valid := accessGraphShareFixture(t, sharing.ContractStateActive)
	for _, name := range []string{"Upper.shared.mesh", "a..b", "-a.shared.mesh", "a_b.shared.mesh",
		strings.Repeat("a", 64) + ".mesh", strings.Repeat("a.", 127) + "a"} {
		if _, err := accessgraph.NewShareContext(accessgraph.ShareContextParams{
			ContractID: valid.ContractID(), State: sharing.ContractStateActive,
			ProviderWorkspaceCode: valid.ProviderWorkspaceCode(), ProviderNetworkCode: valid.ProviderNetworkCode(),
			AccessName: name,
		}); !errors.Is(err, accessgraph.ErrInvalidSnapshot) {
			t.Errorf("NewShareContext(%q) error = %v", name, err)
		}
	}
	if _, err := accessgraph.NewShareContext(accessgraph.ShareContextParams{
		State: sharing.ContractStateActive, ProviderWorkspaceCode: valid.ProviderWorkspaceCode(),
		ProviderNetworkCode: valid.ProviderNetworkCode(),
	}); !errors.Is(err, accessgraph.ErrInvalidSnapshot) {
		t.Errorf("share without contract error = %v", err)
	}
}

func explainSnapshot(t *testing.T, query accessgraph.Query, params accessgraph.SnapshotParams) accessgraph.Result {
	t.Helper()
	snapshot, err := accessgraph.NewSnapshot(params)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	service, err := accessgraph.NewService(accessgraph.Dependencies{
		Reader: &accessGraphReaderFixture{snapshot: snapshot},
		Clock:  fixedAccessGraphClock{value: accessGraphTime()},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Explain(t.Context(), accessGraphSessionFixture(t), query)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	return result
}

func withoutActiveRelease(_ *testing.T, params *accessgraph.SnapshotParams) {
	params.PolicyRevision, params.HasActiveRelease = 1, false
	params.ReleaseID, params.CompilerFormatVersion = publication.ReleaseID{}, 0
	params.SemanticHash, params.TargetNodeID = publication.SemanticHash{}, node.ID{}
}

func withShareState(state sharing.ContractState) func(*testing.T, *accessgraph.SnapshotParams) {
	return func(t *testing.T, params *accessgraph.SnapshotParams) {
		share := accessGraphShareFixture(t, state)
		params.Share = &share
	}
}

func devicePaths(t *testing.T) []accessgraph.Path {
	return []accessgraph.Path{accessGraphDevicePathFixture(t)}
}

func sharedPaths(t *testing.T) []accessgraph.Path {
	return []accessgraph.Path{accessGraphSharedPathFixture(t, accessGraphContractPublicID)}
}

func accessGraphDevicePathFixture(t *testing.T) accessgraph.Path {
	t.Helper()
	projectionID, ruleID := accessGraphPathIdentity(t, 7)
	portRange, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatal(err)
	}
	path, err := accessgraph.NewPath(accessgraph.PathParams{
		ProjectionID: projectionID, RuleID: ruleID,
		SourceNodeID: accessGraphNodeID(t, 301), DestinationNodeID: accessGraphNodeID(t, 302),
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{portRange},
		SelectorKind: accessgraph.SelectorKindDevice,
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func accessGraphSharedPathFixture(t *testing.T, contractPublicID string) accessgraph.Path {
	t.Helper()
	projectionID, ruleID := accessGraphPathIdentity(t, 8)
	contractID, err := sharing.ParseContractID(contractPublicID)
	if err != nil {
		t.Fatal(err)
	}
	portRange, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatal(err)
	}
	path, err := accessgraph.NewPath(accessgraph.PathParams{
		ProjectionID: projectionID, RuleID: ruleID, SourceNodeID: accessGraphNodeID(t, 301),
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{portRange},
		SelectorKind:                  accessgraph.SelectorKindImportedResource,
		DestinationImportedResourceID: accessGraphImportedResourceQueryFixture(t).DestinationImportedResourceID(),
		TrustContractID:               contractID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func accessGraphPathIdentity(t *testing.T, sequence int) (publication.ProjectionID, policy.RuleID) {
	t.Helper()
	path := accessGraphPathFixture(t, sequence, policy.ProtocolICMP, 0, 0)
	return path.ProjectionID(), path.RuleID()
}
