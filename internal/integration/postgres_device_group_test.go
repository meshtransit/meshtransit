//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/authorization"
	"github.com/meshtransit/meshtransit/internal/devicegroup"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
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
