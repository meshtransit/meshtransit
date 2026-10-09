package simulation_test

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/accessgraph/simulation"
	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
)

func TestServiceResolvesIdentityGroupAndTagRulesFromBaselineMembers(t *testing.T) {
	t.Parallel()

	scope := simulationScope(t)
	people, _ := identitygroup.ParseID("01890f00-0000-7000-8000-000000000d01")
	servers, _ := devicetag.ParseID("01890f00-0000-7000-8000-000000000e01")
	unused, _ := devicetag.ParseID("01890f00-0000-7000-8000-000000000e02")
	peopleSide, _ := publication.NewRuleSide(publication.SideIdentityGroup, publicid.ID(people))
	serversSide, _ := publication.NewRuleSide(publication.SideDeviceTag, publicid.ID(servers))
	baseline, err := simulation.NewBaseline(simulation.BaselineParams{
		Scope: scope, RevisionVector: simulationVector(t, 5, 2, 2, 1),
		Candidate: simulationCandidate(t, scope, 1, []policy.Rule{}),
		SelectorMembers: map[publication.RuleSide][]node.ID{
			peopleSide:  {simulationNodeID(t, 301), simulationNodeID(t, 303)},
			serversSide: {simulationNodeID(t, 302), simulationNodeID(t, 303)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	intent := func(sequence int, params compilation.RuleIntentParams) compilation.RuleIntent {
		params.ID, params.Scope, params.Protocol = simulationRuleID(t, sequence), scope, policy.ProtocolICMP
		params.DestinationPortRanges = []policy.PortRange{}
		built, err := compilation.NewRuleIntent(params)
		if err != nil {
			t.Fatal(err)
		}
		return built
	}
	request := simulationRequest(t, scope, 2, []compilation.RuleIntent{
		// 301→302, 301→303, 303→302; 303→303 is not a relationship.
		intent(1, compilation.RuleIntentParams{SourceIdentityGroupID: people, DestinationTagID: servers}),
		// A tag with no live Device selects nothing.
		intent(2, compilation.RuleIntentParams{SourceTagID: unused, DestinationNodeID: simulationNodeID(t, 302)}),
	})
	reader := &simulationBaselineReader{values: []simulation.Baseline{baseline, baseline}}
	result, err := simulationService(
		t, reader, simulationCompiler(t, &simulationDestinationResolver{}),
	).Simulate(t.Context(), simulationSession(t), request)
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}
	if result.AddedRelationshipCount() != 3 || result.RemovedRelationshipCount() != 0 {
		t.Fatalf("added %d, removed %d relationships, want 3 and 0",
			result.AddedRelationshipCount(), result.RemovedRelationshipCount())
	}
}

func TestBaselineRejectsDeviceSelectorMembers(t *testing.T) {
	t.Parallel()

	scope := simulationScope(t)
	device := simulationNodeID(t, 301)
	side, _ := publication.NewRuleSide(publication.SideDevice, publicid.ID(device))
	_, err := simulation.NewBaseline(simulation.BaselineParams{
		Scope: scope, RevisionVector: simulationVector(t, 5, 2, 2, 1),
		Candidate:       simulationCandidate(t, scope, 1, []policy.Rule{}),
		SelectorMembers: map[publication.RuleSide][]node.ID{side: {device}},
	})
	if !errors.Is(err, simulation.ErrInvalidBaseline) {
		t.Fatalf("NewBaseline() error = %v, want ErrInvalidBaseline", err)
	}
}
