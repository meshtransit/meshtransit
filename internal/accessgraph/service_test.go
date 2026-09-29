package accessgraph_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/sharing"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func TestServiceExplainsMatchingResourceGroupPath(t *testing.T) {
	t.Parallel()

	query := accessGraphQueryFixture(t, true, policy.ProtocolTCP, 443)
	snapshot := accessGraphSnapshotFixture(t, query, []accessgraph.Path{
		accessGraphPathFixture(t, 1, policy.ProtocolTCP, 443, 443),
	})
	reader := &accessGraphReaderFixture{snapshot: snapshot}
	service, err := accessgraph.NewService(accessgraph.Dependencies{
		Reader: reader,
		Clock:  fixedAccessGraphClock{value: accessGraphTime()},
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := service.Explain(t.Context(), accessGraphSessionFixture(t), query)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	paths := result.Paths()
	if reader.calls != 1 || !reader.evaluatedAt.Equal(accessGraphTime()) || !result.IsValid() ||
		result.Decision() != accessgraph.DecisionAllow ||
		result.Reason() != accessgraph.ReasonMatchingActiveRule || result.Truncated() ||
		len(paths) != 1 || paths[0].SelectorKind() != accessgraph.SelectorKindResourceGroup ||
		paths[0].DestinationResourceID() != query.DestinationResourceID() ||
		!paths[0].DestinationGroupID().IsValid() {
		t.Fatalf("result = %+v, paths = %+v, reader = %+v", result, paths, reader)
	}
}

func TestServiceExplainsDefaultDenyWithoutActiveRelease(t *testing.T) {
	t.Parallel()

	query := accessGraphQueryFixture(t, false, policy.ProtocolICMP, 0)
	params := accessGraphSnapshotParams(t, query, nil)
	params.PolicyRevision = 1
	params.HasActiveRelease = false
	params.ReleaseID = publication.ReleaseID{}
	params.CompilerFormatVersion = 0
	params.SemanticHash = publication.SemanticHash{}
	params.TargetNodeID = node.ID{}
	snapshot, err := accessgraph.NewSnapshot(params)
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

	result, err := service.Explain(t.Context(), accessGraphSessionFixture(t), query)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	if result.Decision() != accessgraph.DecisionDeny ||
		result.Reason() != accessgraph.ReasonNoMatchingActiveRule || len(result.Paths()) != 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestServiceExplainsImportedResourceAsFailClosedProvenance(t *testing.T) {
	t.Parallel()

	query := accessGraphImportedResourceQueryFixture(t)
	params := accessGraphSnapshotParams(t, query, nil)
	params.CompilerFormatVersion = 4
	params.TargetNodeID = node.ID{}
	snapshot, err := accessgraph.NewSnapshot(params)
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

	result, err := service.Explain(t.Context(), accessGraphSessionFixture(t), query)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	if !result.IsValid() || result.Decision() != accessgraph.DecisionDeny ||
		result.Reason() != accessgraph.ReasonNoMatchingActiveRule ||
		len(result.Paths()) != 0 || result.Snapshot().TargetNodeID().IsValid() ||
		result.Query().DestinationImportedResourceID() != query.DestinationImportedResourceID() {
		t.Fatalf("result = %+v", result)
	}
}

func TestServiceRejectsReaderPathThatDoesNotMatchQuery(t *testing.T) {
	t.Parallel()

	query := accessGraphQueryFixture(t, true, policy.ProtocolTCP, 443)
	snapshot := accessGraphSnapshotFixture(t, query, []accessgraph.Path{
		accessGraphPathFixture(t, 1, policy.ProtocolUDP, 443, 443),
	})
	service, err := accessgraph.NewService(accessgraph.Dependencies{
		Reader: &accessGraphReaderFixture{snapshot: snapshot},
		Clock:  fixedAccessGraphClock{value: accessGraphTime()},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Explain(t.Context(), accessGraphSessionFixture(t), query)
	if !errors.Is(err, accessgraph.ErrInvalidSnapshot) {
		t.Fatalf("Explain() error = %v, want ErrInvalidSnapshot", err)
	}
}

func TestServiceBoundsMatchingExplanationPaths(t *testing.T) {
	t.Parallel()

	query := accessGraphQueryFixture(t, true, policy.ProtocolTCP, 443)
	paths := make([]accessgraph.Path, accessgraph.MaximumExplanationPaths+1)
	for index := range paths {
		paths[index] = accessGraphPathFixture(t, index+1, policy.ProtocolTCP, 443, 443)
	}
	snapshot := accessGraphSnapshotFixture(t, query, paths)
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
	if result.Decision() != accessgraph.DecisionAllow || !result.Truncated() ||
		len(result.Paths()) != accessgraph.MaximumExplanationPaths {
		t.Fatalf("bounded result = %+v", result)
	}
}

func TestServicePreservesForbiddenReaderFailure(t *testing.T) {
	t.Parallel()

	service, err := accessgraph.NewService(accessgraph.Dependencies{
		Reader: &accessGraphReaderFixture{err: accessgraph.ErrForbidden},
		Clock:  fixedAccessGraphClock{value: accessGraphTime()},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Explain(
		t.Context(),
		accessGraphSessionFixture(t),
		accessGraphQueryFixture(t, true, policy.ProtocolTCP, 443),
	)
	if !errors.Is(err, accessgraph.ErrForbidden) {
		t.Fatalf("Explain() error = %v, want ErrForbidden", err)
	}
}

func TestSnapshotRejectsSubsystemRevisionAheadOfNetwork(t *testing.T) {
	t.Parallel()

	query := accessGraphQueryFixture(t, true, policy.ProtocolTCP, 443)
	params := accessGraphSnapshotParams(t, query, nil)
	params.PolicyRevision = params.NetworkRevision + 1
	if _, err := accessgraph.NewSnapshot(params); !errors.Is(err, accessgraph.ErrInvalidSnapshot) {
		t.Fatalf("NewSnapshot() error = %v, want ErrInvalidSnapshot", err)
	}
}

func TestSnapshotRejectsDuplicateProjectionIdentity(t *testing.T) {
	t.Parallel()

	query := accessGraphQueryFixture(t, true, policy.ProtocolTCP, 443)
	first := accessGraphPathFixture(t, 1, policy.ProtocolTCP, 443, 443)
	second := accessGraphPathFixture(t, 2, policy.ProtocolTCP, 443, 443)
	duplicate, err := accessgraph.NewPath(accessgraph.PathParams{
		ProjectionID: first.ProjectionID(), RuleID: second.RuleID(),
		SourceNodeID: second.SourceNodeID(), DestinationNodeID: second.DestinationNodeID(),
		Protocol: second.Protocol(), DestinationPortRanges: second.DestinationPortRanges(),
		SelectorKind:          second.SelectorKind(),
		DestinationResourceID: second.DestinationResourceID(),
		DestinationGroupID:    second.DestinationGroupID(),
	})
	if err != nil {
		t.Fatal(err)
	}
	params := accessGraphSnapshotParams(t, query, []accessgraph.Path{first, duplicate})
	if _, err := accessgraph.NewSnapshot(params); !errors.Is(err, accessgraph.ErrInvalidSnapshot) {
		t.Fatalf("NewSnapshot() error = %v, want ErrInvalidSnapshot", err)
	}
}

func TestServiceRejectsMismatchedResolvedDeviceTarget(t *testing.T) {
	t.Parallel()

	query := accessGraphQueryFixture(t, false, policy.ProtocolICMP, 0)
	params := accessGraphSnapshotParams(t, query, nil)
	params.TargetNodeID = accessGraphNodeID(t, 303)
	snapshot, err := accessgraph.NewSnapshot(params)
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
	if _, err := service.Explain(t.Context(), accessGraphSessionFixture(t), query); !errors.Is(err, accessgraph.ErrInvalidSnapshot) {
		t.Fatalf("Explain() error = %v, want ErrInvalidSnapshot", err)
	}
}

type accessGraphReaderFixture struct {
	snapshot    accessgraph.Snapshot
	err         error
	calls       int
	evaluatedAt time.Time
}

func (reader *accessGraphReaderFixture) ReadActive(
	_ context.Context,
	_ accountsession.Session,
	_ accessgraph.Query,
	evaluatedAt time.Time,
) (accessgraph.Snapshot, error) {
	reader.calls++
	reader.evaluatedAt = evaluatedAt
	return reader.snapshot, reader.err
}

type fixedAccessGraphClock struct{ value time.Time }

func (clock fixedAccessGraphClock) Now() time.Time { return clock.value }

func accessGraphQueryFixture(
	t *testing.T,
	resourceTarget bool,
	protocol policy.Protocol,
	port uint16,
) accessgraph.Query {
	t.Helper()
	params := accessgraph.QueryParams{
		Scope: accessGraphScopeFixture(t), SourceNodeID: accessGraphNodeID(t, 301),
		Protocol: protocol, DestinationPort: port,
	}
	if resourceTarget {
		params.DestinationResourceID = accessGraphResourceID(t)
	} else {
		params.DestinationNodeID = accessGraphNodeID(t, 302)
	}
	query, err := accessgraph.NewQuery(params)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func accessGraphImportedResourceQueryFixture(t *testing.T) accessgraph.Query {
	t.Helper()
	importedID, err := sharing.ParseImportedResourceID(
		"01890f00-0000-7000-8000-000000000801",
	)
	if err != nil {
		t.Fatal(err)
	}
	query, err := accessgraph.NewQuery(accessgraph.QueryParams{
		Scope: accessGraphScopeFixture(t), SourceNodeID: accessGraphNodeID(t, 301),
		DestinationImportedResourceID: importedID,
		Protocol:                      policy.ProtocolTCP, DestinationPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func accessGraphSnapshotFixture(
	t *testing.T,
	query accessgraph.Query,
	paths []accessgraph.Path,
) accessgraph.Snapshot {
	t.Helper()
	snapshot, err := accessgraph.NewSnapshot(accessGraphSnapshotParams(t, query, paths))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func accessGraphSnapshotParams(
	t *testing.T,
	query accessgraph.Query,
	paths []accessgraph.Path,
) accessgraph.SnapshotParams {
	t.Helper()
	releaseID, err := publication.ParseReleaseID("01890f00-0000-7000-8000-000000000901")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := publication.NewSemanticHash([32]byte{31: 1})
	if err != nil {
		t.Fatal(err)
	}
	return accessgraph.SnapshotParams{
		Scope: query.Scope(), NetworkRevision: 12, InventoryRevision: 8,
		GroupRevision: 9, PolicyRevision: 6, DNSRevision: 2, RouteRevision: 2,
		SharingRevision: 2, IsolationGeneration: 1, HasActiveRelease: true,
		ReleaseID: releaseID, CompilerFormatVersion: 3, SemanticHash: hash,
		TargetNodeID: accessGraphNodeID(t, 302), Paths: paths,
	}
}

func accessGraphPathFixture(
	t *testing.T,
	sequence int,
	protocol policy.Protocol,
	first uint16,
	last uint16,
) accessgraph.Path {
	t.Helper()
	projectionID, err := publication.ParseProjectionID(
		fmt.Sprintf("01890f00-0000-7000-8000-%012d", 1_000+sequence),
	)
	if err != nil {
		t.Fatal(err)
	}
	ruleID, err := policy.ParseRuleID(
		fmt.Sprintf("01890f00-0000-7000-8000-%012d", 2_000+sequence),
	)
	if err != nil {
		t.Fatal(err)
	}
	var ranges []policy.PortRange
	if protocol != policy.ProtocolICMP {
		portRange, rangeErr := policy.NewPortRange(first, last)
		if rangeErr != nil {
			t.Fatal(rangeErr)
		}
		ranges = []policy.PortRange{portRange}
	} else {
		ranges = []policy.PortRange{}
	}
	groupID, err := resource.ParseGroupID("01890f00-0000-7000-8000-000000000951")
	if err != nil {
		t.Fatal(err)
	}
	path, err := accessgraph.NewPath(accessgraph.PathParams{
		ProjectionID: projectionID, RuleID: ruleID,
		SourceNodeID: accessGraphNodeID(t, 301), DestinationNodeID: accessGraphNodeID(t, 302),
		Protocol: protocol, DestinationPortRanges: ranges,
		SelectorKind:          accessgraph.SelectorKindResourceGroup,
		DestinationResourceID: accessGraphResourceID(t), DestinationGroupID: groupID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func accessGraphScopeFixture(t *testing.T) network.Scope {
	t.Helper()
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000201")
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func accessGraphNodeID(t *testing.T, sequence int) node.ID {
	t.Helper()
	id, err := node.ParseID(fmt.Sprintf("01890f00-0000-7000-8000-%012d", sequence))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func accessGraphResourceID(t *testing.T) resource.ID {
	t.Helper()
	id, err := resource.ParseID("01890f00-0000-7000-8000-000000000601")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func accessGraphSessionFixture(t *testing.T) accountsession.Session {
	t.Helper()
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	principalID, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	sessionID, _ := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	subjectID, _ := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000611")
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	now := accessGraphTime()
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

func accessGraphTime() time.Time {
	return time.Date(2026, time.September, 29, 10, 0, 0, 0, time.UTC)
}
