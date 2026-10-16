//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
)

// memberOwnedFixtureDevice returns an active Device of Network 203 whose
// owner is an active member of Workspace 103, and that owner.
func memberOwnedFixtureDevice(ctx context.Context, t *testing.T, admin *pgx.Conn) (node.ID, publicid.ID) {
	t.Helper()
	var deviceText, ownerText string
	if err := admin.QueryRow(ctx, `SELECT device.public_id::TEXT, principal.public_id::TEXT
FROM mesh.device AS device
JOIN mesh.principal AS principal
  ON principal.id = device.owner_principal_id AND principal.state = 'active' AND principal.deleted_at IS NULL
JOIN mesh.workspace_membership AS membership
  ON membership.workspace_id = device.workspace_id AND membership.principal_id = principal.id
 AND membership.state = 'active' AND (membership.expires_at IS NULL OR membership.expires_at > now())
WHERE device.workspace_id = 103 AND device.network_id = 203 AND device.state = 'active'
  AND device.deleted_at IS NULL AND device.expires_at > now()
ORDER BY device.public_id LIMIT 1`).Scan(&deviceText, &ownerText); err != nil {
		t.Fatalf("member-owned fixture Device: %v", err)
	}
	device, err := node.ParseID(deviceText)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := publicid.Parse(ownerText)
	if err != nil {
		t.Fatal(err)
	}
	return device, owner
}

// publishIntegrationRules compiles and publishes rules over base and
// returns the candidate.
func publishIntegrationRules(ctx context.Context, t *testing.T, runtimePool *postgresadapter.Pool,
	owner accountsession.Session, scope network.Scope, base int64, rules []compilation.RuleIntent) publication.Candidate {
	t.Helper()
	request, err := compilation.NewRequest(compilation.RequestParams{Scope: scope, Revision: base + 1, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := newIntegrationPolicyCompiler(t, runtimePool).Compile(ctx, owner, request)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	reason, err := publication.NewAuditReason("integration identity and tag rules")
	if err != nil {
		t.Fatal(err)
	}
	command, err := publication.NewManagementCommand(publication.ManagementCommandParams{
		Candidate: candidate, BasePolicyRevision: base, AccountSession: owner, AuditReason: reason,
	})
	if err != nil {
		t.Fatal(err)
	}
	published := publishPolicyOverBrowserManagement(ctx, t, runtimePool,
		newIntegrationManagementPolicyPublicationService(t, runtimePool), command)
	if published.PolicyRevision() != base+1 || published.SemanticHash() != candidate.SemanticHash() {
		t.Fatalf("publication = %+v, base %d", published, base)
	}
	return candidate
}

// assertPostgreSQLIdentityTagPolicy qualifies schema 122: a rule from an
// Identity Group to a tag simulates, publishes and reads back with its
// selectors; the owner's untagged Devices reach the tagged Device without a
// republish, and Explain names both selectors; tagging the source Device
// makes it a service Device that the Identity Group no longer selects;
// removing the member advances the Network and drops the edges; the group
// and the tag the release selects cannot be deleted. It runs after the
// Device Group policy test and leaves a deny-all policy and no catalog rows.
func assertPostgreSQLIdentityTagPolicy(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	groups, tags := newIntegrationIdentityCatalog(t, runtimePool)
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	networkID, err := network.ParseID(guardrailFixtureNetwork)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	client, person := memberOwnedFixtureDevice(ctx, t, admin)
	var server node.ID
	for _, candidate := range activeFixtureDevices(ctx, t, admin, 2) {
		if candidate != client {
			server = candidate
			break
		}
	}

	created, err := groups.Create(ctx, owner, workspaceID, identitygroup.Definition{Name: "Operators"}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	group := created.Group.ID
	joined, err := groups.ChangeMembers(ctx, owner, workspaceID, group, 1, []publicid.ID{person}, nil, newCorrelationID(t))
	if err != nil || joined.AccessAffecting() {
		t.Fatalf("join before any rule = %+v, error = %v", joined, err)
	}
	tagCreated, err := tags.Create(ctx, owner, workspaceID, devicetag.Definition{Name: "ssh-servers"}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	tag := tagCreated.Tag.ID
	if _, err := tags.ChangeAssignments(ctx, owner, scope, server, []devicetag.ID{tag}, nil, newCorrelationID(t)); err != nil {
		t.Fatalf("tag the server: %v", err)
	}

	ruleID, err := policy.ParseRuleID(newCorrelationID(t).String())
	if err != nil {
		t.Fatal(err)
	}
	ssh, err := policy.NewPortRange(22, 22)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
		ID: ruleID, Scope: scope, SourceIdentityGroupID: group, DestinationTagID: tag,
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{ssh},
	})
	if err != nil {
		t.Fatalf("identity group rule intent: %v", err)
	}
	base := fixturePolicyRevision(ctx, t, admin)
	request, err := compilation.NewRequest(compilation.RequestParams{
		Scope: scope, Revision: base + 1, Rules: []compilation.RuleIntent{intent},
	})
	if err != nil {
		t.Fatal(err)
	}
	simulated, err := newIntegrationPolicySimulator(t, runtimePool).Simulate(ctx, owner, request)
	if err != nil || simulated.AddedRelationshipCount() == 0 {
		t.Fatalf("simulate identity group rule = %d added, error = %v", simulated.AddedRelationshipCount(), err)
	}
	candidate := publishIntegrationRules(ctx, t, runtimePool, owner, scope, base, []compilation.RuleIntent{intent})
	edges := resolvedGroupEdges(ctx, t, admin)
	if !edges[client.String()+">"+server.String()] {
		t.Fatalf("resolved edges = %v, want the member's Device to reach the tagged server", edges)
	}
	for edge := range edges {
		if edge[len(edge)-len(server.String()):] != server.String() {
			t.Fatalf("edge %s does not end at the tagged server", edge)
		}
	}

	catalogStore, err := postgresadapter.NewActivePolicyStore(runtimePool, postgresadapter.PolicySimulationOptions{
		StatementTimeout: 5 * time.Second, LockTimeout: time.Second, IdleTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	active, err := catalogStore.ReadActivePolicy(ctx, owner, scope)
	if err != nil || len(active.Rows()) != 1 || !active.DeviceRulesOnly() ||
		active.Rows()[0].Intent.SourceIdentityGroupID() != group ||
		active.Rows()[0].Intent.DestinationTagID() != tag ||
		active.SemanticHash() != candidate.SemanticHash() {
		t.Fatalf("catalog of an identity group rule = %+v, error = %v", active, err)
	}
	query, err := accessgraph.NewQuery(accessgraph.QueryParams{
		Scope: scope, SourceNodeID: client, DestinationNodeID: server, Protocol: policy.ProtocolTCP, DestinationPort: 22,
	})
	if err != nil {
		t.Fatal(err)
	}
	explained, err := newIntegrationPolicyExplainer(t, runtimePool).Explain(ctx, owner, query)
	if err != nil || explained.Decision() != accessgraph.DecisionAllow || len(explained.Paths()) != 1 ||
		explained.Paths()[0].SourceIdentityGroupID() != group || explained.Paths()[0].DestinationTagID() != tag ||
		explained.Paths()[0].SourceDeviceGroupID().IsValid() {
		t.Fatalf("explain through an identity group and a tag = %+v, error = %v", explained, err)
	}

	edge := listedGroupEdge(ctx, t, runtimePool, owner, scope, node.ID{}, client, server)
	if edge.SourceIdentityGroupID() != group || edge.DestinationTagID() != tag ||
		edge.SelectorKind() != accessgraph.SelectorKindDevice {
		t.Fatalf("listed group edge = %+v", edge)
	}
	if again := listedGroupEdge(ctx, t, runtimePool, owner, scope, client, client, server); again.ProjectionID() !=
		edge.ProjectionID() {
		t.Fatalf("group edge projection %s then %s, want one stable identity", edge.ProjectionID(), again.ProjectionID())
	}

	// Tagging the client makes it a service Device: the group no longer selects it.
	networkBefore, _ := fixtureNetworkRevisions(ctx, t, admin)
	if _, err := tags.ChangeAssignments(ctx, owner, scope, client, []devicetag.ID{tag}, nil, newCorrelationID(t)); err != nil {
		t.Fatalf("tag the client: %v", err)
	}
	if edges := resolvedGroupEdges(ctx, t, admin); edges[client.String()+">"+server.String()] {
		t.Fatalf("a tagged Device still matched through its owner's group: %v", edges)
	}
	assertNetworkMapsMatchDirectRead(ctx, t, admin, runtimePool, guardrailFixtureNetwork)
	if _, err := tags.ChangeAssignments(ctx, owner, scope, client, nil, []devicetag.ID{tag}, newCorrelationID(t)); err != nil {
		t.Fatalf("untag the client: %v", err)
	}
	if !resolvedGroupEdges(ctx, t, admin)[client.String()+">"+server.String()] {
		t.Fatal("an untagged Device must match through its owner's group again")
	}
	assertNetworkMapsMatchDirectRead(ctx, t, admin, runtimePool, guardrailFixtureNetwork)
	if networkAfter, _ := fixtureNetworkRevisions(ctx, t, admin); networkAfter != networkBefore+2 {
		t.Fatalf("Network revision %d -> %d, want one advance per tag change", networkBefore, networkAfter)
	}

	// Removing the member rebuilds the Network and drops the edges.
	left, err := groups.ChangeMembers(ctx, owner, workspaceID, group, joined.Group.Version, nil,
		[]publicid.ID{person}, newCorrelationID(t))
	if err != nil || !left.AccessAffecting() || len(left.Networks) != 1 || left.Networks[0].NetworkID != networkID {
		t.Fatalf("leave a selected group = %+v, error = %v", left, err)
	}
	if edges := resolvedGroupEdges(ctx, t, admin); len(edges) != 0 {
		t.Fatalf("edges after the only member left = %v", edges)
	}
	if fixturePolicyRevision(ctx, t, admin) != base+1 {
		t.Fatal("catalog changes republished policy")
	}
	if _, err := groups.Delete(ctx, owner, workspaceID, group, left.Group.Version,
		newCorrelationID(t)); !errors.Is(err, identitygroup.ErrInUse) {
		t.Fatalf("deleting a selected group: %v", err)
	}
	if _, err := tags.Delete(ctx, owner, workspaceID, tag, tagCreated.Tag.Version,
		newCorrelationID(t)); !errors.Is(err, devicetag.ErrInUse) {
		t.Fatalf("deleting a selected tag: %v", err)
	}

	// A deny-all policy releases both selectors.
	publishIntegrationRules(ctx, t, runtimePool, owner, scope, base+1, []compilation.RuleIntent{})
	if _, err := tags.Delete(ctx, owner, workspaceID, tag, tagCreated.Tag.Version, newCorrelationID(t)); err != nil {
		t.Fatalf("delete released tag: %v", err)
	}
	if _, err := groups.Delete(ctx, owner, workspaceID, group, left.Group.Version, newCorrelationID(t)); err != nil {
		t.Fatalf("delete released group: %v", err)
	}
}

// listedGroupEdge lists the Access Graph, filtered to one Device when given,
// and returns the edge from source to destination.
func listedGroupEdge(ctx context.Context, t *testing.T, runtimePool *postgresadapter.Pool,
	session accountsession.Session, scope network.Scope, filter, source, destination node.ID) accessgraph.Path {
	t.Helper()
	query, err := accessgraph.NewGraphQuery(accessgraph.GraphQueryParams{
		Scope: scope, DeviceID: filter, PageSize: accessgraph.MaximumGraphPageSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	page, err := newIntegrationPolicyExplainer(t, runtimePool).Graph(ctx, session, query)
	if err != nil {
		t.Fatalf("list Access Graph: %v", err)
	}
	for _, path := range page.Paths() {
		if path.SourceNodeID() == source && path.DestinationNodeID() == destination {
			return path
		}
	}
	t.Fatalf("Access Graph lacks %s -> %s among %d edges", source, destination, len(page.Paths()))
	return accessgraph.Path{}
}
