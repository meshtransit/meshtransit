package simulation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy/compilation"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy/publication"
	"github.com/meshtransit/meshtransit/core/internal/domain/resource"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

func TestServiceReportsImportedIntentWithoutManufacturingPacketAuthority(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name              string
		current, proposed []compilation.RuleIntent
		added, removed    int
	}{
		{name: "add", proposed: []compilation.RuleIntent{simulationImportedIntent(t, 1, 443, 443)}, added: 1},
		{name: "remove", current: []compilation.RuleIntent{simulationImportedIntent(t, 1, 443, 443)}, removed: 1},
		{name: "narrow", current: []compilation.RuleIntent{simulationImportedIntent(t, 1, 80, 500)},
			proposed: []compilation.RuleIntent{simulationImportedIntent(t, 1, 443, 443)}, added: 1, removed: 1},
		{name: "preserve", current: []compilation.RuleIntent{simulationImportedIntent(t, 1, 443, 443)},
			proposed: []compilation.RuleIntent{simulationImportedIntent(t, 1, 443, 443)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			resolver := &simulationImportedResolver{value: simulationImportedResolution(t, 6, 2, simulationTime())}
			compiler := simulationImportedCompiler(t, resolver)
			current, err := compiler.Compile(t.Context(), simulationSession(t),
				simulationRequest(t, simulationScope(t), 6, append([]compilation.RuleIntent{}, test.current...)))
			if err != nil {
				t.Fatal(err)
			}
			baseline := simulationBaseline(t, current, simulationVectorWithSharing(t, 12, 8, 9, 6, 6))
			reader := &simulationBaselineReader{values: []simulation.Baseline{baseline, baseline}}
			result, err := simulationService(t, reader, compiler).Simulate(t.Context(), simulationSession(t),
				simulationRequest(t, simulationScope(t), 7, append([]compilation.RuleIntent{}, test.proposed...)))
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsValid() || result.AddedImportedIntentCount() != test.added ||
				result.RemovedImportedIntentCount() != test.removed || result.AddedRelationshipCount() != 0 ||
				result.RemovedRelationshipCount() != 0 || result.AddedExplanationCount() != 0 ||
				result.RemovedExplanationCount() != 0 || len(result.UnsupportedCapabilities()) != 6 {
				t.Fatalf("incorrect intent or synthetic packet impact: %+v", result)
			}
			wantDevices := 0
			if test.added+test.removed > 0 {
				wantDevices = 1
			}
			if result.AffectedDeviceCount() != wantDevices || result.AffectedResourceCount() != 0 {
				t.Fatal("imported impact was lost or provider inventory leaked into local affected Resources")
			}
			if test.added > 0 {
				items := result.AddedImportedIntents()
				item := items[0]
				if item.SourceNodeID() != simulationNodeID(t, 301) ||
					item.Resolution().ImportedResourceID() != resolver.value.ImportedResourceID() ||
					item.Resolution().Contract().ID() != resolver.value.Contract().ID() ||
					item.Resolution().ConsumerScope() != baseline.Scope() {
					t.Fatal("preview lost exact Consumer-local selector or bilateral provenance")
				}
				ports := item.DestinationPortRanges()
				ports[0], _ = policy.NewPortRange(1, 2)
				items[0] = publication.ImportedResourceDestination{}
				if result.AddedImportedIntents()[0].DestinationPortRanges()[0].First() == 1 || !result.IsValid() {
					t.Fatal("caller mutation changed simulation authority evidence")
				}
			}
		})
	}
}

func TestServiceImportedProvenanceChangesAndStaleConsumerRevision(t *testing.T) {
	t.Parallel()
	intent := simulationImportedIntent(t, 1, 443, 443)
	resolver := &simulationImportedResolver{value: simulationImportedResolution(t, 6, 2, simulationTime())}
	compiler := simulationImportedCompiler(t, resolver)
	current, err := compiler.Compile(t.Context(), simulationSession(t),
		simulationRequest(t, simulationScope(t), 6, []compilation.RuleIntent{intent}))
	if err != nil {
		t.Fatal(err)
	}
	baseline := simulationBaseline(t, current, simulationVectorWithSharing(t, 12, 8, 9, 6, 6))
	for _, test := range []struct {
		name                             string
		sharingRevision, contractVersion int64
		evaluatedAt                      time.Time
		changed, stale                   bool
	}{
		{name: "evaluation instant is not intent", sharingRevision: 6, contractVersion: 2, evaluatedAt: simulationTime().Add(time.Minute)},
		{name: "contract successor changes provenance", sharingRevision: 6, contractVersion: 3, evaluatedAt: simulationTime(), changed: true},
		{name: "future Consumer authority rejected", sharingRevision: 7, contractVersion: 2, evaluatedAt: simulationTime(), stale: true},
		{name: "older proposed Consumer authority rejected", sharingRevision: 5, contractVersion: 2, evaluatedAt: simulationTime(), stale: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver.value = simulationImportedResolution(t, test.sharingRevision, test.contractVersion, test.evaluatedAt)
			reader := &simulationBaselineReader{values: []simulation.Baseline{baseline, baseline}}
			result, err := simulationService(t, reader, compiler).Simulate(t.Context(), simulationSession(t),
				simulationRequest(t, simulationScope(t), 7, []compilation.RuleIntent{intent}))
			if test.stale {
				if !errors.Is(err, simulation.ErrInvalidResult) {
					t.Fatalf("stale authority error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if test.changed {
				want = 1
			}
			if result.AddedImportedIntentCount() != want || result.RemovedImportedIntentCount() != want ||
				result.AddedRelationshipCount() != 0 || result.RemovedRelationshipCount() != 0 {
				t.Fatal("bilateral provenance change was lost or claimed packet authority")
			}
		})
	}
}

func TestServiceBoundsImportedEvidenceAndHashesUnreportedChanges(t *testing.T) {
	t.Parallel()
	count := simulation.MaximumReportedExplanations + 1
	intents := make([]compilation.RuleIntent, count)
	for index := range intents {
		intents[index] = simulationImportedIntent(t, index+1, 443, 443)
	}
	resolver := &simulationImportedResolver{value: simulationImportedResolution(t, 6, 2, simulationTime())}
	compiler := simulationImportedCompiler(t, resolver)
	baseline := simulationBaseline(t, simulationCandidate(t, simulationScope(t), 6, []policy.Rule{}),
		simulationVectorWithSharing(t, 12, 8, 9, 6, 6))
	simulate := func(rules []compilation.RuleIntent) simulation.Result {
		t.Helper()
		reader := &simulationBaselineReader{values: []simulation.Baseline{baseline, baseline}}
		result, err := simulationService(t, reader, compiler).Simulate(t.Context(), simulationSession(t),
			simulationRequest(t, simulationScope(t), 7, rules))
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	first := simulate(intents)
	if !first.Truncated() || first.AddedImportedIntentCount() != count ||
		len(first.AddedImportedIntents()) != simulation.MaximumReportedExplanations || first.AffectedDeviceCount() != 1 {
		t.Fatal("imported preview did not bound evidence while preserving complete counts")
	}
	if second := simulate(intents); first.ImpactHash() != second.ImpactHash() {
		t.Fatal("imported impact hash is nondeterministic")
	}
	intents[count-1] = simulationImportedIntent(t, count, 444, 444)
	changed := simulate(intents)
	if changed.ImpactHash() == first.ImpactHash() || changed.AddedImportedIntentCount() != count {
		t.Fatal("unreported imported traffic change did not bind the complete impact digest")
	}
}

func TestServiceAllowsOldReleaseProvenanceButRequiresCurrentProposedSharing(t *testing.T) {
	t.Parallel()
	intent := simulationImportedIntent(t, 1, 443, 443)
	resolver := &simulationImportedResolver{value: simulationImportedResolution(t, 5, 2, simulationTime())}
	compiler := simulationImportedCompiler(t, resolver)
	current, err := compiler.Compile(t.Context(), simulationSession(t), simulationRequest(t, simulationScope(t), 6, []compilation.RuleIntent{intent}))
	if err != nil {
		t.Fatal(err)
	}
	baseline := simulationBaseline(t, current, simulationVectorWithSharing(t, 12, 8, 9, 6, 6))
	resolver.value = simulationImportedResolution(t, 6, 2, simulationTime())
	reader := &simulationBaselineReader{values: []simulation.Baseline{baseline, baseline}}
	result, err := simulationService(t, reader, compiler).Simulate(t.Context(), simulationSession(t), simulationRequest(t, simulationScope(t), 7, []compilation.RuleIntent{intent}))
	if err != nil {
		t.Fatal(err)
	}
	if result.AddedImportedIntentCount() != 1 || result.RemovedImportedIntentCount() != 1 ||
		result.RemovedImportedIntents()[0].Resolution().ConsumerSharingRevision() != 5 ||
		result.AddedImportedIntents()[0].Resolution().ConsumerSharingRevision() != 6 {
		t.Fatal("old release provenance was lost instead of explicitly refreshed")
	}
}

type simulationImportedResolver struct {
	simulationDestinationResolver
	value sharing.PolicyDestination
}

func simulationImportedCompiler(t *testing.T, resolver *simulationImportedResolver) *simulationCompilerStub {
	t.Helper()
	delegate, err := compilation.NewService(resolver, resolver)
	if err != nil {
		t.Fatal(err)
	}
	return &simulationCompilerStub{delegate: delegate}
}

func (resolver *simulationImportedResolver) ResolveImportedPolicyDestinations(
	_ context.Context, _ accountsession.Session, _ network.Scope, _ []sharing.ImportedResourceID,
) ([]sharing.PolicyDestination, error) {
	return []sharing.PolicyDestination{resolver.value}, nil
}

func simulationImportedIntent(t *testing.T, sequence int, first, last uint16) compilation.RuleIntent {
	t.Helper()
	importedID, _ := sharing.ParseImportedResourceID("01890f00-0000-7000-8000-000000000825")
	intent, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
		ID: simulationRuleID(t, sequence), Scope: simulationScope(t), SourceNodeID: simulationNodeID(t, 301),
		DestinationImportedResourceID: importedID, Protocol: policy.ProtocolTCP,
		DestinationPortRanges: simulationPortRanges(t, policy.ProtocolTCP, first, last),
	})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func simulationImportedResolution(t *testing.T, consumerRevision, contractVersion int64, evaluatedAt time.Time) sharing.PolicyDestination {
	t.Helper()
	providerWS, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000102")
	providerNet, _ := network.ParseID("01890f00-0000-7000-8000-000000000202")
	providerScope, _ := network.NewScope(providerWS, providerNet)
	resourceID, _ := resource.ParseID("01890f00-0000-7000-8000-000000000901")
	resourceHash, _ := resource.NewSemanticHash([32]byte{1})
	binding, _ := sharing.NewResourceBinding(providerScope, resourceID, 3, 2, resourceHash)
	port, _ := policy.NewPortRange(80, 500)
	constraint, _ := sharing.NewTrafficConstraint(sharing.TrafficConstraintParams{
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{port},
	})
	traffic, _ := sharing.NewTrafficSet([]sharing.TrafficConstraint{constraint})
	importedID, _ := sharing.ParseImportedResourceID("01890f00-0000-7000-8000-000000000825")
	contractID, _ := sharing.ParseContractID("01890f00-0000-7000-8000-000000000824")
	offerID, _ := sharing.ParseOfferID("01890f00-0000-7000-8000-000000000823")
	exportID, _ := sharing.ParseExportID("01890f00-0000-7000-8000-000000000822")
	contract, err := sharing.NewContract(sharing.ContractParams{
		ID: contractID, ImportedResourceID: importedID, OfferID: offerID, ExportID: exportID,
		ProviderScope: providerScope, ConsumerScope: simulationScope(t), Resource: binding, MaximumTraffic: traffic,
		ProviderAuthorityGeneration: 2, ConsumerAuthorityGeneration: 3, RecoveryEpoch: 4,
		ExpiresAt: simulationTime().Add(time.Hour), State: sharing.ContractStateActive, Version: contractVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	value, err := sharing.NewPolicyDestination(sharing.PolicyDestinationParams{
		ImportedResourceID: importedID, ImportedResourceVersion: 2, Contract: contract, ExportVersion: 1,
		ProviderInventoryRevision: 8, ProviderSharingRevision: 50, ConsumerSharingRevision: consumerRevision,
		EvaluatedAt: evaluatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}
