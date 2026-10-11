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
	// 301 sees 302 and 303; 302 sees 301 and 303; 303 sees 301 and 302.
	if peers := result.Peers(); peers.MaxPeers() != 2 || peers.DevicesOver(1) != 3 || peers.DevicesOver(2) != 0 ||
		peers.Exact() {
		t.Fatalf("peer estimate = max %d, over 1: %d, exact %t", peers.MaxPeers(), peers.DevicesOver(1), peers.Exact())
	}
}

func TestTooLargeSimulationStillEstimatesPeers(t *testing.T) {
	t.Parallel()

	scope := simulationScope(t)
	clients, _ := devicetag.ParseID("01890f00-0000-7000-8000-000000000e11")
	servers, _ := devicetag.ParseID("01890f00-0000-7000-8000-000000000e12")
	clientsSide, _ := publication.NewRuleSide(publication.SideDeviceTag, publicid.ID(clients))
	serversSide, _ := publication.NewRuleSide(publication.SideDeviceTag, publicid.ID(servers))
	const size = 450 // 450 x 450 pairs exceed what a simulation expands
	members := map[publication.RuleSide][]node.ID{}
	for index := range size {
		members[clientsSide] = append(members[clientsSide], simulationNodeID(t, 1000+index))
		members[serversSide] = append(members[serversSide], simulationNodeID(t, 2000+index))
	}
	baseline, err := simulation.NewBaseline(simulation.BaselineParams{
		Scope: scope, RevisionVector: simulationVector(t, 5, 2, 2, 1),
		Candidate:       simulationCandidate(t, scope, 1, []policy.Rule{}),
		SelectorMembers: members,
	})
	if err != nil {
		t.Fatal(err)
	}
	ruleIntent, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
		ID: simulationRuleID(t, 1), Scope: scope, Protocol: policy.ProtocolICMP,
		DestinationPortRanges: []policy.PortRange{}, SourceTagID: clients, DestinationTagID: servers,
	})
	if err != nil {
		t.Fatal(err)
	}
	reader := &simulationBaselineReader{values: []simulation.Baseline{baseline, baseline}}
	_, err = simulationService(t, reader, simulationCompiler(t, &simulationDestinationResolver{})).
		Simulate(t.Context(), simulationSession(t), simulationRequest(t, scope, 2, []compilation.RuleIntent{ruleIntent}))
	if !errors.Is(err, simulation.ErrTooLarge) {
		t.Fatalf("Simulate() error = %v, want ErrTooLarge", err)
	}
	peers, found := simulation.PeerEstimateOf(err)
	if !found || peers.MaxPeers() != size || peers.DevicesOver(size-1) != 2*size {
		t.Fatalf("estimate = %t, max %d, over %d", found, peers.MaxPeers(), peers.DevicesOver(size-1))
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
