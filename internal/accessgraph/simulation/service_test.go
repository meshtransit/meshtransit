package simulation_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/policy/compilation"
	"github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/resource/catalog"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func TestServiceDerivesExactOverlappingPortDeltaWithPublicationCompiler(t *testing.T) {
	t.Parallel()

	scope := simulationScope(t)
	currentRule := simulationRule(t, scope, 1, 301, 302, policy.ProtocolTCP, 80, 90)
	current := simulationCandidate(t, scope, 6, []policy.Rule{currentRule})
	baseline := simulationBaseline(t, current, simulationVector(t, 12, 8, 9, 6))
	request := simulationRequest(t, scope, 7, []compilation.RuleIntent{
		simulationDirectIntent(t, scope, 1, 301, 302, policy.ProtocolTCP, 85, 95),
	})
	compiler := simulationCompiler(t, &simulationDestinationResolver{})
	reader := &simulationBaselineReader{values: []simulation.Baseline{baseline, baseline}}
	service := simulationService(t, reader, compiler)

	result, err := service.Simulate(t.Context(), simulationSession(t), request)
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}
	added := result.AddedRelationships()
	removed := result.RemovedRelationships()
	addedFirst, addedLast, addedHasPorts := added[0].DestinationPortRange()
	removedFirst, removedLast, removedHasPorts := removed[0].DestinationPortRange()
	if !result.IsValid() || reader.calls != 2 || compiler.calls != 1 ||
		result.ProposedRevisionVector().NetworkRevision() != 13 ||
		result.ProposedRevisionVector().PolicyRevision() != 7 ||
		result.AddedRelationshipCount() != 1 || len(added) != 1 ||
		!addedHasPorts || addedFirst != 91 || addedLast != 95 ||
		result.RemovedRelationshipCount() != 1 || len(removed) != 1 ||
		!removedHasPorts || removedFirst != 80 || removedLast != 84 ||
		result.AddedExplanationCount() != 1 || result.RemovedExplanationCount() != 1 ||
		result.AffectedDeviceCount() != 2 || result.Truncated() || result.StaleInputs() ||
		result.Uncertain() || !result.ImpactHash().IsValid() ||
		len(result.UnsupportedCapabilities()) != 6 {
		t.Fatalf("result = %+v, added = %+v, removed = %+v", result, added, removed)
	}

	secondReader := &simulationBaselineReader{values: []simulation.Baseline{baseline, baseline}}
	secondCompiler := simulationCompiler(t, &simulationDestinationResolver{})
	second, err := simulationService(t, secondReader, secondCompiler).Simulate(
		t.Context(),
		simulationSession(t),
		request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if second.ImpactHash() != result.ImpactHash() {
		t.Fatal("identical inputs produced different impact hashes")
	}
}

func TestServiceSeparatesEffectiveRelationshipFromResourceExplanation(t *testing.T) {
	t.Parallel()

	scope := simulationScope(t)
	destination := simulationNodeID(t, 302)
	currentRule := simulationRule(t, scope, 1, 301, 302, policy.ProtocolTCP, 443, 443)
	current := simulationCandidate(t, scope, 6, []policy.Rule{currentRule})
	baseline := simulationBaseline(t, current, simulationVector(t, 12, 8, 9, 6))
	value := simulationResource(t, scope, destination)
	intent, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
		ID: currentRule.ID(), Scope: scope, SourceNodeID: currentRule.SourceNodeID(),
		DestinationResourceID: value.ID(), Protocol: policy.ProtocolTCP,
		DestinationPortRanges: simulationPortRanges(t, policy.ProtocolTCP, 443, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := simulationRequest(t, scope, 7, []compilation.RuleIntent{intent})
	resolver := &simulationDestinationResolver{resources: []catalog.Resource{value}}
	compiler := simulationCompiler(t, resolver)
	reader := &simulationBaselineReader{values: []simulation.Baseline{baseline, baseline}}

	result, err := simulationService(t, reader, compiler).Simulate(
		t.Context(),
		simulationSession(t),
		request,
	)
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}
	added := result.AddedExplanations()
	resourceID, version, generation, inventoryRevision, semanticHash, found :=
		added[0].ResourceEvidence()
	if result.AddedRelationshipCount() != 0 || result.RemovedRelationshipCount() != 0 ||
		result.AddedExplanationCount() != 1 || result.RemovedExplanationCount() != 1 ||
		len(added) != 1 || added[0].SelectorKind() != accessgraph.SelectorKindResource ||
		!found || resourceID != value.ID() || version != value.Version() ||
		generation != value.TargetGeneration() || inventoryRevision != value.InventoryRevision() ||
		semanticHash != value.SemanticHash() || result.AffectedResourceCount() != 1 ||
		result.AffectedResources()[0] != value.ID() || resolver.calls != 1 {
		t.Fatalf("result = %+v, added explanation = %+v", result, added)
	}
}

func TestServicePreservesExpandedResourceGroupExplanation(t *testing.T) {
	t.Parallel()

	scope := simulationScope(t)
	current := simulationCandidate(t, scope, 6, []policy.Rule{})
	baseline := simulationBaseline(t, current, simulationVector(t, 12, 8, 9, 6))
	value := simulationResource(t, scope, simulationNodeID(t, 302))
	group := simulationGroup(t, scope, []catalog.Resource{value})
	intent, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
		ID: simulationRuleID(t, 1), Scope: scope, SourceNodeID: simulationNodeID(t, 301),
		DestinationGroupID: group.ID(), Protocol: policy.ProtocolTCP,
		DestinationPortRanges: simulationPortRanges(t, policy.ProtocolTCP, 8443, 8443),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := simulationRequest(t, scope, 7, []compilation.RuleIntent{intent})
	resolver := &simulationDestinationResolver{
		resources: []catalog.Resource{value}, groups: []catalog.Group{group},
	}
	reader := &simulationBaselineReader{values: []simulation.Baseline{baseline, baseline}}

	result, err := simulationService(
		t,
		reader,
		simulationCompiler(t, resolver),
	).Simulate(t.Context(), simulationSession(t), request)
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}
	added := result.AddedExplanations()
	groupID, version, definitionVersion, groupRevision, semanticHash, found :=
		added[0].GroupEvidence()
	if result.AddedRelationshipCount() != 1 || result.AddedExplanationCount() != 1 ||
		len(added) != 1 || added[0].SelectorKind() != accessgraph.SelectorKindResourceGroup ||
		!found || groupID != group.ID() || version != group.Version() ||
		definitionVersion != group.DefinitionVersion() || groupRevision != group.GroupRevision() ||
		semanticHash != group.SemanticHash() || result.AffectedResourceCount() != 1 ||
		result.AffectedGroupCount() != 1 || result.AffectedGroups()[0] != group.ID() {
		t.Fatalf("result = %+v, added explanation = %+v", result, added)
	}
}

func TestServiceRejectsAuthorityDriftAroundCompilation(t *testing.T) {
	t.Parallel()

	scope := simulationScope(t)
	current := simulationCandidate(t, scope, 6, []policy.Rule{})
	before := simulationBaseline(t, current, simulationVector(t, 12, 8, 9, 6))
	after := simulationBaseline(t, current, simulationVectorWithSharing(t, 13, 8, 9, 6, 10))
	request := simulationRequest(t, scope, 7, []compilation.RuleIntent{
		simulationDirectIntent(t, scope, 1, 301, 302, policy.ProtocolICMP, 0, 0),
	})
	compiler := simulationCompiler(t, &simulationDestinationResolver{})
	reader := &simulationBaselineReader{values: []simulation.Baseline{before, after}}

	_, err := simulationService(t, reader, compiler).Simulate(
		t.Context(),
		simulationSession(t),
		request,
	)
	if !errors.Is(err, simulation.ErrStaleInputs) || reader.calls != 2 || compiler.calls != 1 {
		t.Fatalf("Simulate() error = %v, reader calls = %d, compiler calls = %d", err, reader.calls, compiler.calls)
	}
}

func TestServiceSupportsCanonicalDefaultDenyBootstrap(t *testing.T) {
	t.Parallel()

	scope := simulationScope(t)
	current := simulationCandidate(t, scope, 1, []policy.Rule{})
	vector := simulationVector(t, 5, 2, 2, 1)
	baseline, err := simulation.NewBaseline(simulation.BaselineParams{
		Scope: scope, RevisionVector: vector, Candidate: current,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := simulationRequest(t, scope, 2, []compilation.RuleIntent{
		simulationDirectIntent(t, scope, 1, 301, 302, policy.ProtocolICMP, 0, 0),
	})
	reader := &simulationBaselineReader{values: []simulation.Baseline{baseline, baseline}}
	result, err := simulationService(
		t,
		reader,
		simulationCompiler(t, &simulationDestinationResolver{}),
	).Simulate(t.Context(), simulationSession(t), request)
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}
	if result.AddedRelationshipCount() != 1 || result.RemovedRelationshipCount() != 0 ||
		result.ProposedRevisionVector().NetworkRevision() != 6 ||
		result.ProposedRevisionVector().PolicyRevision() != 2 {
		t.Fatalf("result = %+v", result)
	}
}

func TestServiceBoundsReportedEvidenceButHashesCompleteImpact(t *testing.T) {
	t.Parallel()

	scope := simulationScope(t)
	current := simulationCandidate(t, scope, 6, []policy.Rule{})
	baseline := simulationBaseline(t, current, simulationVector(t, 12, 8, 9, 6))
	intents := make([]compilation.RuleIntent, simulation.MaximumReportedRelationships+1)
	for index := range intents {
		intents[index] = simulationDirectIntent(
			t,
			scope,
			index+1,
			301,
			1_000+index,
			policy.ProtocolICMP,
			0,
			0,
		)
	}
	request := simulationRequest(t, scope, 7, intents)
	reader := &simulationBaselineReader{values: []simulation.Baseline{baseline, baseline}}

	result, err := simulationService(
		t,
		reader,
		simulationCompiler(t, &simulationDestinationResolver{}),
	).Simulate(t.Context(), simulationSession(t), request)
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}
	if result.AddedRelationshipCount() != simulation.MaximumReportedRelationships+1 ||
		len(result.AddedRelationships()) != simulation.MaximumReportedRelationships ||
		result.AddedExplanationCount() != simulation.MaximumReportedExplanations+1 ||
		len(result.AddedExplanations()) != simulation.MaximumReportedExplanations ||
		result.AffectedDeviceCount() != simulation.MaximumReportedEntities+2 ||
		len(result.AffectedDevices()) != simulation.MaximumReportedEntities ||
		!result.Truncated() || !result.IsValid() {
		t.Fatalf("bounded result = %+v", result)
	}
}

func TestServicePreservesCompilerFailureWithoutSecondRead(t *testing.T) {
	t.Parallel()

	scope := simulationScope(t)
	current := simulationCandidate(t, scope, 6, []policy.Rule{})
	baseline := simulationBaseline(t, current, simulationVector(t, 12, 8, 9, 6))
	request := simulationRequest(t, scope, 7, []compilation.RuleIntent{
		simulationDirectIntent(t, scope, 1, 301, 302, policy.ProtocolICMP, 0, 0),
	})
	reader := &simulationBaselineReader{values: []simulation.Baseline{baseline}}
	compiler := &simulationCompilerStub{err: compilation.ErrResourceConflict}

	_, err := simulationService(t, reader, compiler).Simulate(
		t.Context(),
		simulationSession(t),
		request,
	)
	if !errors.Is(err, compilation.ErrResourceConflict) || reader.calls != 1 || compiler.calls != 1 {
		t.Fatalf("Simulate() error = %v, reader calls = %d, compiler calls = %d", err, reader.calls, compiler.calls)
	}
}

func TestImpactHashBindsNonPolicyAuthorityRevision(t *testing.T) {
	t.Parallel()

	scope := simulationScope(t)
	current := simulationCandidate(t, scope, 6, []policy.Rule{})
	request := simulationRequest(t, scope, 7, []compilation.RuleIntent{
		simulationDirectIntent(t, scope, 1, 301, 302, policy.ProtocolICMP, 0, 0),
	})
	firstBaseline := simulationBaseline(t, current, simulationVector(t, 12, 8, 9, 6))
	secondBaseline := simulationBaseline(t, current, simulationVector(t, 12, 7, 9, 6))
	first, err := simulationService(
		t,
		&simulationBaselineReader{values: []simulation.Baseline{firstBaseline, firstBaseline}},
		simulationCompiler(t, &simulationDestinationResolver{}),
	).Simulate(t.Context(), simulationSession(t), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := simulationService(
		t,
		&simulationBaselineReader{values: []simulation.Baseline{secondBaseline, secondBaseline}},
		simulationCompiler(t, &simulationDestinationResolver{}),
	).Simulate(t.Context(), simulationSession(t), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.ImpactHash() == second.ImpactHash() {
		t.Fatal("impact hash did not bind inventory revision")
	}
}

func TestBaselineRejectsReleaseSemanticHashMismatch(t *testing.T) {
	t.Parallel()

	scope := simulationScope(t)
	candidate := simulationCandidate(t, scope, 6, []policy.Rule{})
	releaseID, err := publication.ParseReleaseID("01890f00-0000-7000-8000-000000000901")
	if err != nil {
		t.Fatal(err)
	}
	mismatchedHash, err := publication.NewSemanticHash([32]byte{31: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, err = simulation.NewBaseline(simulation.BaselineParams{
		Scope: scope, RevisionVector: simulationVector(t, 12, 8, 9, 6),
		HasActiveRelease: true, ReleaseID: releaseID,
		SemanticHash: mismatchedHash, Candidate: candidate,
	})
	if !errors.Is(err, simulation.ErrInvalidBaseline) {
		t.Fatalf("NewBaseline() error = %v, want ErrInvalidBaseline", err)
	}
}

type simulationBaselineReader struct {
	values []simulation.Baseline
	calls  int
}

func (reader *simulationBaselineReader) ReadSimulationBaseline(
	_ context.Context,
	_ accountsession.Session,
	_ network.Scope,
	_ time.Time,
) (simulation.Baseline, error) {
	if reader.calls >= len(reader.values) {
		return simulation.Baseline{}, simulation.ErrUnavailable
	}
	value := reader.values[reader.calls]
	reader.calls++
	return value, nil
}

type simulationCompilerStub struct {
	delegate *compilation.Service
	err      error
	calls    int
}

func (compiler *simulationCompilerStub) Compile(
	ctx context.Context,
	session accountsession.Session,
	request compilation.Request,
) (publication.Candidate, error) {
	compiler.calls++
	if compiler.err != nil {
		return publication.Candidate{}, compiler.err
	}
	return compiler.delegate.Compile(ctx, session, request)
}

type simulationDestinationResolver struct {
	resources []catalog.Resource
	groups    []catalog.Group
	calls     int
}

func (resolver *simulationDestinationResolver) ResolvePolicyDestinations(
	_ context.Context,
	_ accountsession.Session,
	_ network.Scope,
	_ []resource.ID,
	_ []resource.GroupID,
) ([]catalog.Resource, []catalog.Group, error) {
	resolver.calls++
	return resolver.resources, resolver.groups, nil
}

func simulationService(
	t *testing.T,
	reader simulation.BaselineReader,
	compiler simulation.Compiler,
) *simulation.Service {
	t.Helper()
	service, err := simulation.NewService(simulation.Dependencies{
		Baselines: reader,
		Compiler:  compiler,
		Clock:     simulation.SystemClock{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func simulationCompiler(
	t *testing.T,
	resolver compilation.DestinationResolver,
) *simulationCompilerStub {
	t.Helper()
	delegate, err := compilation.NewService(resolver)
	if err != nil {
		t.Fatal(err)
	}
	return &simulationCompilerStub{delegate: delegate}
}

func simulationBaseline(
	t *testing.T,
	candidate publication.Candidate,
	vector accessgraph.RevisionVector,
) simulation.Baseline {
	t.Helper()
	releaseID, err := publication.ParseReleaseID("01890f00-0000-7000-8000-000000000901")
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := simulation.NewBaseline(simulation.BaselineParams{
		Scope: candidate.Snapshot().Scope(), RevisionVector: vector,
		HasActiveRelease: true, ReleaseID: releaseID,
		SemanticHash: candidate.SemanticHash(), Candidate: candidate,
	})
	if err != nil {
		t.Fatal(err)
	}
	return baseline
}

func simulationCandidate(
	t *testing.T,
	scope network.Scope,
	revision int64,
	rules []policy.Rule,
) publication.Candidate {
	t.Helper()
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: scope, Revision: revision, Rules: rules,
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := publication.NewCandidate(snapshot, 1)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func simulationRequest(
	t *testing.T,
	scope network.Scope,
	revision int64,
	intents []compilation.RuleIntent,
) compilation.Request {
	t.Helper()
	request, err := compilation.NewRequest(compilation.RequestParams{
		Scope: scope, Revision: revision, Rules: intents,
	})
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func simulationDirectIntent(
	t *testing.T,
	scope network.Scope,
	ruleSequence,
	sourceSequence,
	destinationSequence int,
	protocol policy.Protocol,
	first,
	last uint16,
) compilation.RuleIntent {
	t.Helper()
	intent, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
		ID: simulationRuleID(t, ruleSequence), Scope: scope,
		SourceNodeID:      simulationNodeID(t, sourceSequence),
		DestinationNodeID: simulationNodeID(t, destinationSequence), Protocol: protocol,
		DestinationPortRanges: simulationPortRanges(t, protocol, first, last),
	})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func simulationRule(
	t *testing.T,
	scope network.Scope,
	ruleSequence,
	sourceSequence,
	destinationSequence int,
	protocol policy.Protocol,
	first,
	last uint16,
) policy.Rule {
	t.Helper()
	rule, err := policy.NewRule(policy.RuleParams{
		ID: simulationRuleID(t, ruleSequence), Scope: scope,
		SourceNodeID:      simulationNodeID(t, sourceSequence),
		DestinationNodeID: simulationNodeID(t, destinationSequence), Protocol: protocol,
		DestinationPortRanges: simulationPortRanges(t, protocol, first, last),
	})
	if err != nil {
		t.Fatal(err)
	}
	return rule
}

func simulationPortRanges(
	t *testing.T,
	protocol policy.Protocol,
	first,
	last uint16,
) []policy.PortRange {
	t.Helper()
	if protocol == policy.ProtocolICMP {
		return []policy.PortRange{}
	}
	portRange, err := policy.NewPortRange(first, last)
	if err != nil {
		t.Fatal(err)
	}
	return []policy.PortRange{portRange}
}

func simulationResource(t *testing.T, scope network.Scope, deviceID node.ID) catalog.Resource {
	t.Helper()
	name, err := resource.ParseDisplayName("payments-api")
	if err != nil {
		t.Fatal(err)
	}
	ownerID, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := resource.NewDeviceDefinition(resource.DeviceDefinitionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: ownerID,
		CustodianPrincipalID: ownerID, DeviceID: deviceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceID, err := resource.ParseID("01890f00-0000-7000-8000-000000000601")
	if err != nil {
		t.Fatal(err)
	}
	now := simulationTime()
	value, err := catalog.NewResource(catalog.ResourceParams{
		ID: resourceID, Scope: scope, DisplayName: name,
		OwnerPrincipalID: ownerID, CustodianPrincipalID: ownerID,
		DeviceID: deviceID, State: resource.StateActive, Provenance: resource.ProvenanceManual,
		Version: 1, TargetGeneration: 1, SemanticHash: definition.SemanticHash(),
		ActivatedNetworkRevision: 7, InventoryRevision: 7,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func simulationGroup(
	t *testing.T,
	scope network.Scope,
	values []catalog.Resource,
) catalog.Group {
	t.Helper()
	name, err := resource.ParseDisplayName("production-services")
	if err != nil {
		t.Fatal(err)
	}
	ownerID, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	if err != nil {
		t.Fatal(err)
	}
	members := make([]resource.Reference, len(values))
	for index, value := range values {
		members[index], err = resource.NewReference(
			scope,
			value.ID(),
			value.Version(),
			value.TargetGeneration(),
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	definition, err := resource.NewGroupDefinition(resource.GroupDefinitionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: ownerID,
		CustodianPrincipalID: ownerID, Members: members,
	})
	if err != nil {
		t.Fatal(err)
	}
	groupID, err := resource.ParseGroupID("01890f00-0000-7000-8000-000000000951")
	if err != nil {
		t.Fatal(err)
	}
	now := simulationTime()
	group, err := catalog.NewGroup(catalog.GroupParams{
		ID: groupID, Scope: scope, DisplayName: name,
		OwnerPrincipalID: ownerID, CustodianPrincipalID: ownerID,
		State: resource.StateActive, Version: 2, DefinitionVersion: 2,
		SemanticHash: definition.SemanticHash(), ActivatedNetworkRevision: 9,
		GroupRevision: 9, Members: definition.Members(), CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return group
}

func simulationVector(
	t *testing.T,
	networkRevision,
	inventoryRevision,
	groupRevision,
	policyRevision int64,
) accessgraph.RevisionVector {
	t.Helper()
	return simulationVectorWithSharing(
		t,
		networkRevision,
		inventoryRevision,
		groupRevision,
		policyRevision,
		2,
	)
}

func simulationVectorWithSharing(
	t *testing.T,
	networkRevision,
	inventoryRevision,
	groupRevision,
	policyRevision,
	sharingRevision int64,
) accessgraph.RevisionVector {
	t.Helper()
	vector, err := accessgraph.NewRevisionVector(accessgraph.RevisionVectorParams{
		NetworkRevision: networkRevision, InventoryRevision: inventoryRevision,
		GroupRevision: groupRevision, PolicyRevision: policyRevision,
		DNSRevision: 2, RouteRevision: 2, SharingRevision: sharingRevision,
		IsolationGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return vector
}

func simulationScope(t *testing.T) network.Scope {
	t.Helper()
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000201")
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func simulationNodeID(t *testing.T, sequence int) node.ID {
	t.Helper()
	id, err := node.ParseID(fmt.Sprintf("01890f00-0000-7000-8000-%012d", sequence))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func simulationRuleID(t *testing.T, sequence int) policy.RuleID {
	t.Helper()
	id, err := policy.ParseRuleID(fmt.Sprintf("01890f00-0000-7000-8000-%012d", 20_000+sequence))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func simulationSession(t *testing.T) accountsession.Session {
	t.Helper()
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	principalID, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	sessionID, _ := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	subjectID, _ := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000611")
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	now := simulationTime()
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID,
		IdentitySubjectID: subjectID, LoginWorkspaceID: workspaceID, HasLoginWorkspace: true,
		AuthenticationTime: now.Add(-time.Hour), ACR: "urn:meshtransit:test", AMR: []string{"mfa"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func simulationTime() time.Time {
	return time.Date(2026, time.September, 29, 12, 0, 0, 0, time.UTC)
}
