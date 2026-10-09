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
	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
)

func newIntegrationDeviceGroupService(t *testing.T, runtimePool *postgresadapter.Pool) *devicegroup.Service {
	t.Helper()
	store, err := postgresadapter.NewDeviceGroupStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := devicegroup.NewService(store, accountsession.SystemClock{}, devicegroup.SystemIDs{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// activeFixtureDevices returns up to count active Devices of Network 203.
func activeFixtureDevices(ctx context.Context, t *testing.T, admin *pgx.Conn, count int) []node.ID {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT public_id::TEXT FROM mesh.device
WHERE workspace_id = 103 AND network_id = 203 AND state = 'active' AND deleted_at IS NULL
  AND expires_at > now()
ORDER BY public_id LIMIT $1`, count)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []node.ID
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			t.Fatal(err)
		}
		id, err := node.ParseID(text)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil || len(ids) < count {
		t.Fatalf("active fixture Devices = %v, error = %v; want %d", ids, err, count)
	}
	return ids
}

func fixtureNetworkRevisions(ctx context.Context, t *testing.T, admin *pgx.Conn) (int64, int64) {
	t.Helper()
	var networkRevision, groupRevision int64
	if err := admin.QueryRow(ctx, `SELECT network_revision, group_revision FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 203`).Scan(&networkRevision, &groupRevision); err != nil {
		t.Fatal(err)
	}
	return networkRevision, groupRevision
}

// assertPostgreSQLDeviceGroups qualifies schema 120 groups through the
// production store: device_group.read gates the list, device_group.manage
// the definition, device_group.members.manage membership; names are unique
// per Network, only active Devices of the Network join, stale versions are
// refused, membership pages are bounded, and every membership change
// advances the Network and group revisions with one audit event that wakes
// map sessions. It leaves no group or role behind.
func assertPostgreSQLDeviceGroups(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	service := newIntegrationDeviceGroupService(t, runtimePool)
	roleService := newIntegrationRoleService(t, runtimePool)
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	member := authorityConfirmerAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	networkID, err := network.ParseID(guardrailFixtureNetwork)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	devices := activeFixtureDevices(ctx, t, admin, 2)

	listing, err := service.List(ctx, owner, scope)
	if err != nil || len(listing.Groups) != 0 || !listing.CanManage || !listing.CanManageMembers {
		t.Fatalf("owner groups = %+v, error = %v", listing, err)
	}
	if _, err := service.List(ctx, member, scope); !errors.Is(err, devicegroup.ErrForbidden) {
		t.Fatalf("plain member listed groups: %v", err)
	}
	servers := devicegroup.Definition{Name: "Servers", Description: "Production hosts"}
	if _, err := service.Create(ctx, member, scope, servers, newCorrelationID(t)); !errors.Is(err, devicegroup.ErrForbidden) {
		t.Fatalf("plain member created a group: %v", err)
	}
	created, err := service.Create(ctx, owner, scope, servers, newCorrelationID(t))
	if err != nil || created.Group.Version != 1 || created.Group.MemberCount != 0 {
		t.Fatalf("create group = %+v, error = %v", created, err)
	}
	group := created.Group.ID
	if _, err := service.Create(ctx, owner, scope, devicegroup.Definition{Name: "servers"},
		newCorrelationID(t)); !errors.Is(err, devicegroup.ErrNameTaken) {
		t.Fatalf("duplicate name differing in case: %v", err)
	}

	networkBefore, groupBefore := fixtureNetworkRevisions(ctx, t, admin)
	auditBefore := countDeviceGroupAudit(ctx, t, admin)
	stranger := node.ID(newCorrelationID(t))
	if _, err := service.ChangeMembers(ctx, owner, scope, group, 1, []node.ID{devices[0], stranger}, nil,
		newCorrelationID(t)); !errors.Is(err, devicegroup.ErrIneligibleDevice) {
		t.Fatalf("Device outside the Network joined: %v", err)
	}
	added, err := service.ChangeMembers(ctx, owner, scope, group, 1, devices, nil, newCorrelationID(t))
	if err != nil || added.Added != 2 || added.Group.MemberCount != 2 || added.Group.Version != 2 || added.AccessAffecting {
		t.Fatalf("add members = %+v, error = %v", added, err)
	}
	networkAfter, groupAfter := fixtureNetworkRevisions(ctx, t, admin)
	if networkAfter != networkBefore+1 || groupAfter != groupBefore+1 {
		t.Fatalf("revisions %d/%d -> %d/%d, want each advanced once", networkBefore, groupBefore, networkAfter, groupAfter)
	}
	if countDeviceGroupAudit(ctx, t, admin) != auditBefore+1 || !latestDeviceGroupEventWakesMaps(ctx, t, admin, group) {
		t.Fatal("membership change must be one audit event carrying the revision wakeup")
	}
	if _, err := service.ChangeMembers(ctx, owner, scope, group, 1, nil, devices[:1],
		newCorrelationID(t)); !errors.Is(err, devicegroup.ErrVersionConflict) {
		t.Fatalf("stale membership change: %v", err)
	}
	unchanged, err := service.ChangeMembers(ctx, owner, scope, group, 2, devices[:1], nil, newCorrelationID(t))
	if err != nil || unchanged.Added != 0 || unchanged.Group.Version != 2 {
		t.Fatalf("re-adding a member = %+v, error = %v; want a no-op", unchanged, err)
	}

	first, err := service.Members(ctx, owner, scope, group, node.ID{}, 1)
	if err != nil || len(first.Members) != 1 || !first.HasMore || !first.Members[0].Active {
		t.Fatalf("first member page = %+v, error = %v", first, err)
	}
	second, err := service.Members(ctx, owner, scope, group, first.Members[0].DeviceID, 1)
	if err != nil || len(second.Members) != 1 || second.HasMore || second.Members[0].DeviceID == first.Members[0].DeviceID {
		t.Fatalf("second member page = %+v, error = %v", second, err)
	}

	// network_admin on this Network now manages groups (schema 120 grant).
	networkAdmin := newAssignCommand(t, owner, workspaceID, publicid.ID(member.PrincipalID()),
		authorization.BuiltinRoleNetworkAdmin, networkID)
	if _, err := roleService.Assign(ctx, networkAdmin); err != nil {
		t.Fatalf("assign network_admin: %v", err)
	}
	renamed, err := service.Update(ctx, member, scope, group, 2,
		devicegroup.Definition{Name: "Production servers"}, newCorrelationID(t))
	if err != nil || renamed.Group.Version != 3 || renamed.Previous == nil || renamed.Previous.Name != "Servers" {
		t.Fatalf("network_admin rename = %+v, error = %v", renamed, err)
	}
	removed, err := service.ChangeMembers(ctx, member, scope, group, 3, nil, devices, newCorrelationID(t))
	if err != nil || removed.Removed != 2 || removed.Group.MemberCount != 0 {
		t.Fatalf("network_admin remove members = %+v, error = %v", removed, err)
	}
	if _, err := roleService.Revoke(ctx, newRevokeCommand(t, owner, workspaceID, networkAdmin.AssignmentID, 1)); err != nil {
		t.Fatalf("revoke network_admin: %v", err)
	}

	deleted, err := service.Delete(ctx, owner, scope, group, 4, newCorrelationID(t))
	if err != nil || !deleted.Deleted {
		t.Fatalf("delete group = %+v, error = %v", deleted, err)
	}
	if _, err := service.Delete(ctx, owner, scope, group, 5, newCorrelationID(t)); !errors.Is(err, devicegroup.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if listing, err := service.List(ctx, owner, scope); err != nil || len(listing.Groups) != 0 {
		t.Fatalf("groups after delete = %+v, error = %v", listing, err)
	}
}

func countDeviceGroupAudit(ctx context.Context, t *testing.T, admin *pgx.Conn) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event
WHERE target_kind = 'device_group'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// latestDeviceGroupEventWakesMaps checks the newest group event is on the
// Network stream and queued a network.revision.advanced outbox event.
func latestDeviceGroupEventWakesMaps(ctx context.Context, t *testing.T, admin *pgx.Conn, group devicegroup.ID) bool {
	t.Helper()
	var action string
	var networkScoped, wakes bool
	if err := admin.QueryRow(ctx, `SELECT event.action, event.network_id IS NOT NULL,
    EXISTS (SELECT 1 FROM mesh_ops.outbox_event AS outbox
            WHERE outbox.event_class = 'network.revision.advanced'
              AND outbox.payload->>'group_id' = $1::TEXT)
FROM mesh_audit.audit_event AS event
WHERE event.target_kind = 'device_group' AND event.target_public_id = $1::UUID
ORDER BY event.event_identity_id DESC LIMIT 1`, group.String()).Scan(&action, &networkScoped, &wakes); err != nil {
		t.Fatal(err)
	}
	return action == "device_group.members_changed" && networkScoped && wakes
}

func fixturePolicyRevision(ctx context.Context, t *testing.T, admin *pgx.Conn) int64 {
	t.Helper()
	var revision int64
	if err := admin.QueryRow(ctx, `SELECT policy_revision FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 203`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	return revision
}

// resolvedGroupEdges returns the "source>destination" Device pairs the
// active release's group rules resolve to, read as the runtime role.
func resolvedGroupEdges(ctx context.Context, t *testing.T, admin *pgx.Conn) map[string]bool {
	t.Helper()
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	setIntegrationScope(ctx, t, transaction, 103, 203)
	if _, err := transaction.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
		t.Fatal(err)
	}
	rows, err := transaction.Query(ctx, `SELECT source.public_id::TEXT || '>' || destination.public_id::TEXT
FROM mesh_ops.resolve_group_policy_edges_v1(NULL) AS edge
JOIN mesh.device AS source ON source.id = edge.source_device_id
JOIN mesh.device AS destination ON destination.id = edge.destination_device_id`)
	if err != nil {
		t.Fatalf("resolve group edges: %v", err)
	}
	defer rows.Close()
	edges := map[string]bool{}
	for rows.Next() {
		var edge string
		if err := rows.Scan(&edge); err != nil {
			t.Fatal(err)
		}
		edges[edge] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return edges
}

// assertPostgreSQLGroupPolicy qualifies group rules end to end: a rule from
// one Device Group to another compiles, simulates and publishes once; the
// catalog keeps its group selectors; a Device added to the source group
// reaches the destination without republishing, and Explain names the
// groups; a group the active release selects cannot be deleted. It runs
// after the fixed-revision publication tests and leaves a deny-all policy.
func assertPostgreSQLGroupPolicy(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	groups := newIntegrationDeviceGroupService(t, runtimePool)
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
	devices := activeFixtureDevices(ctx, t, admin, 2)
	client, server := devices[0], devices[1]
	clients, err := groups.Create(ctx, owner, scope, devicegroup.Definition{Name: "Clients"}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	servers, err := groups.Create(ctx, owner, scope, devicegroup.Definition{Name: "Servers"}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := groups.ChangeMembers(ctx, owner, scope, servers.Group.ID, 1, []node.ID{server}, nil,
		newCorrelationID(t)); err != nil {
		t.Fatal(err)
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
		ID: ruleID, Scope: scope, SourceGroupID: clients.Group.ID, DestinationDeviceGroupID: servers.Group.ID,
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{ssh},
	})
	if err != nil {
		t.Fatalf("group rule intent: %v", err)
	}
	base := fixturePolicyRevision(ctx, t, admin)
	request, err := compilation.NewRequest(compilation.RequestParams{
		Scope: scope, Revision: base + 1, Rules: []compilation.RuleIntent{intent},
	})
	if err != nil {
		t.Fatal(err)
	}
	simulated, err := newIntegrationPolicySimulator(t, runtimePool).Simulate(ctx, owner, request)
	if err != nil || simulated.AddedRelationshipCount() != 0 {
		t.Fatalf("simulate a rule from an empty group = %d added, error = %v", simulated.AddedRelationshipCount(), err)
	}
	candidate, err := newIntegrationPolicyCompiler(t, runtimePool).Compile(ctx, owner, request)
	if err != nil || len(candidate.GroupRules()) != 1 || len(candidate.Snapshot().Rules()) != 0 {
		t.Fatalf("compile group rule = %+v, error = %v", candidate, err)
	}
	reason, err := publication.NewAuditReason("integration group rule")
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
		t.Fatalf("group rule publication = %+v, base %d, candidate hash %x", published, base, candidate.SemanticHash().Bytes())
	}
	if edges := resolvedGroupEdges(ctx, t, admin); len(edges) != 0 {
		t.Fatalf("an empty source group resolved to %v", edges)
	}

	catalogStore, err := postgresadapter.NewActivePolicyStore(runtimePool, postgresadapter.PolicySimulationOptions{
		StatementTimeout: 5 * time.Second, LockTimeout: time.Second, IdleTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	active, err := catalogStore.ReadActivePolicy(ctx, owner, scope, time.Now().UTC())
	if err != nil || len(active.Rows()) != 1 || !active.DeviceRulesOnly() ||
		active.Rows()[0].Intent.SourceGroupID() != clients.Group.ID ||
		active.Rows()[0].Intent.DestinationDeviceGroupID() != servers.Group.ID ||
		active.SemanticHash() != candidate.SemanticHash() {
		t.Fatalf("catalog of a group rule = %+v, error = %v", active, err)
	}

	// The client joins the source group: it reaches the server at once.
	networkBefore, _ := fixtureNetworkRevisions(ctx, t, admin)
	joined, err := groups.ChangeMembers(ctx, owner, scope, clients.Group.ID, 1, []node.ID{client}, nil, newCorrelationID(t))
	if err != nil || !joined.AccessAffecting || joined.Group.RuleCount != 1 {
		t.Fatalf("join source group = %+v, error = %v", joined, err)
	}
	if networkAfter, _ := fixtureNetworkRevisions(ctx, t, admin); networkAfter != networkBefore+1 {
		t.Fatal("membership change did not advance the Network revision")
	}
	if fixturePolicyRevision(ctx, t, admin) != base+1 {
		t.Fatal("membership change republished policy")
	}
	if edges := resolvedGroupEdges(ctx, t, admin); len(edges) != 1 || !edges[client.String()+">"+server.String()] {
		t.Fatalf("resolved edges after join = %v", edges)
	}
	query, err := accessgraph.NewQuery(accessgraph.QueryParams{
		Scope: scope, SourceNodeID: client, DestinationNodeID: server, Protocol: policy.ProtocolTCP, DestinationPort: 22,
	})
	if err != nil {
		t.Fatal(err)
	}
	explained, err := newIntegrationPolicyExplainer(t, runtimePool).Explain(ctx, owner, query)
	if err != nil || explained.Decision() != accessgraph.DecisionAllow || len(explained.Paths()) != 1 ||
		explained.Paths()[0].SourceDeviceGroupID() != clients.Group.ID ||
		explained.Paths()[0].DestinationDeviceGroupID() != servers.Group.ID {
		t.Fatalf("explain through groups = %+v, error = %v", explained, err)
	}
	if _, err := groups.Delete(ctx, owner, scope, servers.Group.ID, 2, newCorrelationID(t)); !errors.Is(err, devicegroup.ErrInUse) {
		t.Fatalf("deleting a group in use: %v", err)
	}

	// A deny-all policy releases the groups, which can then be deleted.
	empty, err := compilation.NewRequest(compilation.RequestParams{
		Scope: scope, Revision: base + 2, Rules: []compilation.RuleIntent{},
	})
	if err != nil {
		t.Fatal(err)
	}
	denyAll, err := newIntegrationPolicyCompiler(t, runtimePool).Compile(ctx, owner, empty)
	if err != nil {
		t.Fatal(err)
	}
	clearCommand, err := publication.NewManagementCommand(publication.ManagementCommandParams{
		Candidate: denyAll, BasePolicyRevision: base + 1, AccountSession: owner, AuditReason: reason,
	})
	if err != nil {
		t.Fatal(err)
	}
	publishPolicyOverBrowserManagement(ctx, t, runtimePool, newIntegrationManagementPolicyPublicationService(t, runtimePool), clearCommand)
	if _, err := groups.Delete(ctx, owner, scope, servers.Group.ID, 2, newCorrelationID(t)); err != nil {
		t.Fatalf("delete released group: %v", err)
	}
	if _, err := groups.Delete(ctx, owner, scope, clients.Group.ID, 2, newCorrelationID(t)); err != nil {
		t.Fatalf("delete released group: %v", err)
	}
}
