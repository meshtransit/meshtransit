package postgres

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
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

func TestPolicySimulationBaselineRecordReconstructsFormatFourCandidate(t *testing.T) {
	t.Parallel()

	scope := postgresPolicySimulationScope(t)
	record := policySimulationBaselineRecord{
		NetworkRevision: 13, InventoryRevision: 8, GroupRevision: 9,
		PolicyRevision: 7, DNSRevision: 2, RouteRevision: 2,
		SharingRevision: 3, IsolationGeneration: 1, HasActiveRelease: true,
		Rules: []policyPublicationRulePayload{
			postgresPolicySimulationDirectRule(),
			postgresPolicySimulationImportedRule(t),
		},
	}
	releaseID := "01890f00-0000-7000-8000-000000000902"
	compilerFormat := 4
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
	if !baseline.IsValid() || actual.CompilerFormatVersion() != 4 ||
		len(actual.Snapshot().Rules()) != 1 || len(actual.ResourceDestinations()) != 1 ||
		len(actual.ResourceGroupDestinations()) != 0 ||
		len(actual.ImportedResourceDestinations()) != 1 ||
		actual.SemanticHash() != candidate.SemanticHash() {
		t.Fatalf("baseline = %+v, candidate = %+v", baseline, actual)
	}
}

func TestPolicySimulationCandidateRejectsImportedPacketEdge(t *testing.T) {
	t.Parallel()

	record := postgresPolicySimulationImportedRule(t)
	record.DestinationNodePublicID = postgresPolicySimulationID(399)
	if _, err := reconstructPolicySimulationCandidate(
		postgresPolicySimulationScope(t),
		7,
		4,
		[]policyPublicationRulePayload{record},
	); !errors.Is(err, simulation.ErrInvalidBaseline) {
		t.Fatalf("reconstructPolicySimulationCandidate() error = %v, want ErrInvalidBaseline", err)
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

func postgresPolicySimulationImportedRule(t *testing.T) policyPublicationRulePayload {
	t.Helper()
	constraints := []resourceSharingTrafficRecord{{
		Protocol: "tcp",
		Ranges:   [][2]int64{{443, 443}, {8443, 8443}},
	}}
	traffic, err := resourceSharingTrafficSet(constraints)
	if err != nil {
		t.Fatal(err)
	}
	return policyPublicationRulePayload{
		ProjectionPublicID:                      postgresPolicySimulationID(704),
		AccessRulePublicID:                      postgresPolicySimulationID(504),
		SourceNodePublicID:                      postgresPolicySimulationID(305),
		Protocol:                                "tcp",
		PortRangeFirst:                          []int{443},
		PortRangeLast:                           []int{443},
		DestinationImportedResourcePublicID:     postgresPolicySimulationID(801),
		DestinationImportedResourceVersion:      2,
		DestinationTrustContractPublicID:        postgresPolicySimulationID(802),
		DestinationTrustContractVersion:         2,
		DestinationShareOfferPublicID:           postgresPolicySimulationID(803),
		DestinationResourceExportPublicID:       postgresPolicySimulationID(804),
		DestinationResourceExportVersion:        1,
		DestinationProviderWorkspacePublicID:    postgresPolicySimulationID(102),
		DestinationProviderNetworkPublicID:      postgresPolicySimulationID(202),
		DestinationProviderResourcePublicID:     postgresPolicySimulationID(604),
		DestinationProviderResourceVersion:      4,
		DestinationProviderTargetGeneration:     2,
		DestinationProviderResourceSemanticHash: postgresPolicySimulationHash(4),
		DestinationProviderInventoryRevision:    8,
		DestinationProviderSharingRevision:      3,
		DestinationConsumerSharingRevision:      3,
		DestinationProviderAuthorityGeneration:  2,
		DestinationConsumerAuthorityGeneration:  2,
		DestinationRecoveryEpoch:                2,
		DestinationContractExpiresAt:            "2030-01-02T00:00:00Z",
		DestinationConstraintHash:               fmt.Sprintf("%x", traffic.Hash()),
		DestinationAuthorityEvaluatedAt:         "2030-01-01T00:00:00Z",
		DestinationContractConstraints:          constraints,
	}
}

func postgresPolicySimulationID(suffix int) string {
	return fmt.Sprintf("01890f00-0000-7000-8000-000000000%03d", suffix)
}

func postgresPolicySimulationHash(value int) string {
	return fmt.Sprintf("%064x", value)
}
