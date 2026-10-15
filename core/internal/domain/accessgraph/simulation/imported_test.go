package simulation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/accessgraph/simulation"
	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/internal/domain/workspace"
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
				result.RemovedExplanationCount() != 0 || len(result.UnsupportedCapabilities()) != 5 {
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

// Simulation reports guardrails exactly as publication applies them: both
// the publishing Workspace's and the provider's, blocking only new paths,
// and never naming the provider's guardrail.
func TestServiceEvaluatesBothSidesGuardrails(t *testing.T) {
	t.Parallel()
	providerWS, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000102")
	providerNet, _ := network.ParseID("01890f00-0000-7000-8000-000000000202")
	ownID, _ := publicid.Parse("01890f00-0000-7000-8000-00000000e001")
	providerID, _ := publicid.Parse("01890f00-0000-7000-8000-00000000e002")
	own := guardrail.Guardrail{ID: ownID, Version: 1, Spec: guardrail.Spec{
		Kind: guardrail.KindExternalSharing, Name: "No imports", Mode: guardrail.ModeEnforce,
		External: guardrail.ExternalSharingParams{Direction: guardrail.DirectionIncoming},
	}}
	provider := guardrail.Guardrail{ID: providerID, Version: 3, Spec: guardrail.Spec{
		Kind: guardrail.KindNetworkSharing, Name: "Provider secret", Mode: guardrail.ModeEnforce,
		Sharing: guardrail.NetworkSharingParams{Networks: []network.ID{providerNet}, Direction: guardrail.DirectionOutgoing},
	}}
	for _, existing := range []bool{false, true} {
		resolver := &simulationImportedResolver{value: simulationImportedResolution(t, 6, 2, simulationTime())}
		compiler := simulationImportedCompiler(t, resolver)
		currentIntents := []compilation.RuleIntent{}
		if existing {
			currentIntents = []compilation.RuleIntent{simulationImportedIntent(t, 1, 443, 443)}
		}
		current, err := compiler.Compile(t.Context(), simulationSession(t),
			simulationRequest(t, simulationScope(t), 6, currentIntents))
		if err != nil {
			t.Fatal(err)
		}
		releaseID, _ := publication.ParseReleaseID("01890f00-0000-7000-8000-000000000901")
		baseline, err := simulation.NewBaseline(simulation.BaselineParams{
			Scope: current.Snapshot().Scope(), RevisionVector: simulationVectorWithSharing(t, 12, 8, 9, 6, 6),
			HasActiveRelease: true, ReleaseID: releaseID, SemanticHash: current.SemanticHash(), Candidate: current,
			Guardrails:         []guardrail.Guardrail{own},
			ProviderGuardrails: map[workspace.ID][]guardrail.Guardrail{providerWS: {provider}},
		})
		if err != nil {
			t.Fatal(err)
		}
		reader := &simulationBaselineReader{values: []simulation.Baseline{baseline, baseline}}
		result, err := simulationService(t, reader, compiler).Simulate(t.Context(), simulationSession(t),
			simulationRequest(t, simulationScope(t), 7, []compilation.RuleIntent{simulationImportedIntent(t, 1, 443, 443)}))
		if err != nil {
			t.Fatal(err)
		}
		// The provider's guardrail is reported only where it blocks, as
		// publication reveals; on an existing path it is not reported at all.
		findings := result.GuardrailFindings()
		if want := map[bool]int{false: 2, true: 1}[existing]; len(findings) != want {
			t.Fatalf("existing=%t findings = %+v, want %d", existing, findings, want)
		}
		if !existing && findings[0].Side != simulation.GuardrailSideProvider && !findings[0].Blocks {
			t.Fatalf("a blocking finding does not come first: %+v", findings)
		}
		for _, finding := range findings {
			switch finding.Side {
			case simulation.GuardrailSideActing:
				if finding.Guardrail == nil || finding.Guardrail.Name != "No imports" || finding.Blocks == existing {
					t.Fatalf("existing=%t own finding = %+v", existing, finding)
				}
			case simulation.GuardrailSideProvider:
				if finding.Guardrail != nil || !finding.Blocks || existing {
					t.Fatalf("provider finding exposes or misreports: %+v", finding)
				}
			}
		}
		for _, capability := range result.UnsupportedCapabilities() {
			if capability == simulation.UnsupportedCapabilityGuardrailEvaluation {
				t.Fatal("simulation still reports guardrails as unsupported")
			}
		}
	}
}

// Like publication, simulation never takes an unknown provider to have no
// guardrail.
func TestServiceFailsClosedWithoutTheProvidersGuardrails(t *testing.T) {
	t.Parallel()
	resolver := &simulationImportedResolver{value: simulationImportedResolution(t, 6, 2, simulationTime())}
	compiler := simulationImportedCompiler(t, resolver)
	current, err := compiler.Compile(t.Context(), simulationSession(t),
		simulationRequest(t, simulationScope(t), 6, []compilation.RuleIntent{}))
	if err != nil {
		t.Fatal(err)
	}
	releaseID, _ := publication.ParseReleaseID("01890f00-0000-7000-8000-000000000901")
	baseline, err := simulation.NewBaseline(simulation.BaselineParams{
		Scope: current.Snapshot().Scope(), RevisionVector: simulationVectorWithSharing(t, 12, 8, 9, 6, 6),
		HasActiveRelease: true, ReleaseID: releaseID, SemanticHash: current.SemanticHash(), Candidate: current,
	})
	if err != nil {
		t.Fatal(err)
	}
	reader := &simulationBaselineReader{values: []simulation.Baseline{baseline, baseline}}
	if _, err := simulationService(t, reader, compiler).Simulate(t.Context(), simulationSession(t),
		simulationRequest(t, simulationScope(t), 7, []compilation.RuleIntent{simulationImportedIntent(t, 1, 443, 443)}),
	); !errors.Is(err, simulation.ErrInvalidBaseline) {
		t.Fatalf("Simulate() without the provider's guardrails = %v, want invalid baseline", err)
	}
}
