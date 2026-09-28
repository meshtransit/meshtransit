package postgres

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/meshtransit/meshtransit/internal/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func TestPolicySimulationBaselineRecordReconstructsFormatThreeCandidate(t *testing.T) {
	t.Parallel()

	scope := postgresPolicySimulationScope(t)
	record := policySimulationBaselineRecord{
		NetworkRevision: 12, InventoryRevision: 8, GroupRevision: 9,
		PolicyRevision: 6, DNSRevision: 2, RouteRevision: 2,
		SharingRevision: 2, IsolationGeneration: 1, HasActiveRelease: true,
		Rules: []policyPublicationRulePayload{
			postgresPolicySimulationDirectRule(),
			postgresPolicySimulationGroupRule(502, 702, 303, 602),
			postgresPolicySimulationGroupRule(502, 703, 304, 603),
		},
	}
	releaseID := "01890f00-0000-7000-8000-000000000901"
	compilerFormat := 3
	record.ReleaseID = &releaseID
	record.CompilerFormatVersion = &compilerFormat
	candidate, err := reconstructPolicySimulationCandidate(
		scope,
		record.PolicyRevision,
		compilerFormat,
		record.Rules,
	)
	if err != nil {
		t.Fatalf("reconstructPolicySimulationCandidate() error = %v", err)
	}
	hash := candidate.SemanticHash().Bytes()
	record.SemanticHash = hash[:]

	baseline, err := record.baseline(scope)
	if err != nil {
		t.Fatalf("baseline() error = %v", err)
	}
	actual := baseline.Candidate()
	groups := actual.ResourceGroupDestinations()
	if !baseline.IsValid() || actual.CompilerFormatVersion() != 3 ||
		len(actual.Snapshot().Rules()) != 3 || len(actual.ResourceDestinations()) != 1 ||
		len(groups) != 1 || len(groups[0].Members()) != 2 ||
		actual.SemanticHash() != candidate.SemanticHash() {
		t.Fatalf("baseline = %+v, candidate = %+v", baseline, actual)
	}
}

func TestPolicySimulationBaselineRecordConstructsDefaultDenyBootstrap(t *testing.T) {
	t.Parallel()

	scope := postgresPolicySimulationScope(t)
	record := policySimulationBaselineRecord{
		NetworkRevision: 5, InventoryRevision: 2, GroupRevision: 2,
		PolicyRevision: 1, DNSRevision: 2, RouteRevision: 2,
		SharingRevision: 2, IsolationGeneration: 1, Rules: []policyPublicationRulePayload{},
	}
	baseline, err := record.baseline(scope)
	if err != nil {
		t.Fatalf("baseline() error = %v", err)
	}
	if !baseline.IsValid() || baseline.Candidate().CompilerFormatVersion() != 1 ||
		len(baseline.Candidate().Snapshot().Rules()) != 0 {
		t.Fatalf("baseline = %+v", baseline)
	}
}

func TestPolicySimulationBaselineRecordRejectsSemanticHashMismatch(t *testing.T) {
	t.Parallel()

	scope := postgresPolicySimulationScope(t)
	releaseID := "01890f00-0000-7000-8000-000000000901"
	compilerFormat := 2
	record := policySimulationBaselineRecord{
		NetworkRevision: 12, InventoryRevision: 8, GroupRevision: 9,
		PolicyRevision: 6, DNSRevision: 2, RouteRevision: 2,
		SharingRevision: 2, IsolationGeneration: 1, HasActiveRelease: true,
		ReleaseID: &releaseID, CompilerFormatVersion: &compilerFormat,
		SemanticHash: append(make([]byte, 31), 1),
		Rules:        []policyPublicationRulePayload{postgresPolicySimulationDirectRule()},
	}
	if _, err := record.baseline(scope); !errors.Is(err, simulation.ErrInvalidBaseline) {
		t.Fatalf("baseline() error = %v, want ErrInvalidBaseline", err)
	}
}

func TestPolicySimulationCandidateRejectsMixedProvenance(t *testing.T) {
	t.Parallel()

	record := postgresPolicySimulationDirectRule()
	record.DestinationResourceGroupPublicID = "01890f00-0000-7000-8000-000000000651"
	if _, err := reconstructPolicySimulationCandidate(
		postgresPolicySimulationScope(t),
		6,
		3,
		[]policyPublicationRulePayload{record},
	); !errors.Is(err, simulation.ErrInvalidBaseline) {
		t.Fatalf("reconstructPolicySimulationCandidate() error = %v, want ErrInvalidBaseline", err)
	}
}

func TestPolicySimulationDatabaseErrorConcealsAuthorizationFailure(t *testing.T) {
	t.Parallel()

	err := policySimulationDatabaseError(t.Context(), &pgconn.PgError{Code: "42501"})
	if !errors.Is(err, simulation.ErrForbidden) {
		t.Fatalf("policySimulationDatabaseError() = %v, want ErrForbidden", err)
	}
}

func postgresPolicySimulationScope(t *testing.T) network.Scope {
	t.Helper()
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatal(err)
	}
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000201")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func postgresPolicySimulationDirectRule() policyPublicationRulePayload {
	return policyPublicationRulePayload{
		ProjectionPublicID:      "01890f00-0000-7000-8000-000000000701",
		AccessRulePublicID:      "01890f00-0000-7000-8000-000000000501",
		SourceNodePublicID:      "01890f00-0000-7000-8000-000000000301",
		DestinationNodePublicID: "01890f00-0000-7000-8000-000000000302",
		Protocol:                "tcp", PortRangeFirst: []int{443}, PortRangeLast: []int{443},
		DestinationResourcePublicID:     "01890f00-0000-7000-8000-000000000601",
		DestinationResourceVersion:      4,
		DestinationTargetGeneration:     2,
		DestinationInventoryRevision:    8,
		DestinationResourceSemanticHash: postgresPolicySimulationHash(1),
	}
}

func postgresPolicySimulationGroupRule(
	ruleSuffix,
	projectionSuffix,
	destinationSuffix,
	resourceSuffix int,
) policyPublicationRulePayload {
	return policyPublicationRulePayload{
		ProjectionPublicID:      postgresPolicySimulationID(projectionSuffix),
		AccessRulePublicID:      postgresPolicySimulationID(ruleSuffix),
		SourceNodePublicID:      postgresPolicySimulationID(301),
		DestinationNodePublicID: postgresPolicySimulationID(destinationSuffix),
		Protocol:                "tcp", PortRangeFirst: []int{8443}, PortRangeLast: []int{8443},
		DestinationResourceGroupPublicID:           postgresPolicySimulationID(651),
		DestinationResourceGroupVersion:            5,
		DestinationGroupDefinitionVersion:          3,
		DestinationGroupRevision:                   9,
		DestinationResourceGroupSemanticHash:       postgresPolicySimulationHash(2),
		DestinationGroupMemberResourcePublicID:     postgresPolicySimulationID(resourceSuffix),
		DestinationGroupMemberResourceVersion:      4,
		DestinationGroupMemberTargetGeneration:     2,
		DestinationGroupMemberInventoryRevision:    8,
		DestinationGroupMemberResourceSemanticHash: postgresPolicySimulationHash(resourceSuffix - 600),
	}
}

func postgresPolicySimulationID(suffix int) string {
	return fmt.Sprintf("01890f00-0000-7000-8000-000000000%03d", suffix)
}

func postgresPolicySimulationHash(value int) string {
	return fmt.Sprintf("%064x", value)
}
