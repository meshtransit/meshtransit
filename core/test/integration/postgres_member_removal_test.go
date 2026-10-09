//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/memberlifecycle"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

const integrationRemovedMemberID = "01890f00-0000-7000-8000-000000001971"

// assertPostgreSQLMemberRemoval qualifies schema 130 through the production
// store with a member created for this check who owns three Devices (one
// suspended by an administrator), is the pending recipient of a fourth, holds
// an auditor role, a Network membership, an Identity Group membership and an
// enrollment key. A plain member cannot remove anyone, nobody removes the
// owner or themselves, a plan naming someone else's Device or an unknown new
// owner changes nothing, and the removal moves, hands over and revokes the
// Devices as planned (revoking the unnamed one with its keys), cancels the
// handover, revokes the key, group, role and memberships, advances the
// Network once and records the Workspace and Network evidence. The fixture is
// undone afterwards.
func assertPostgreSQLMemberRemoval(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewMemberLifecycleStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	members, err := memberlifecycle.NewService(store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	plain := authorityConfirmerAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	fixture := activeFixtureDevices(ctx, t, admin, 4)
	moved, handed, unnamed, incoming := fixture[0], fixture[1], fixture[2], fixture[3]
	restore := seedRemovableMember(ctx, t, admin, fixture)
	defer restore()
	memberID, err := publicid.Parse(integrationRemovedMemberID)
	if err != nil {
		t.Fatal(err)
	}
	ownerID := publicid.ID(owner.PrincipalID())
	remove := func(session accountsession.Session, member publicid.ID, plans ...memberlifecycle.DevicePlan) (
		memberlifecycle.RemovalResult, error) {
		return members.Remove(ctx, session, memberlifecycle.RemovalRequest{
			WorkspaceID: workspaceID, MemberID: member, Reason: "Integration check", Devices: plans,
			CorrelationID: newCorrelationID(t),
		})
	}
	plan := []memberlifecycle.DevicePlan{
		{DeviceID: moved, Action: memberlifecycle.DeviceTransferWorkspace},
		{DeviceID: handed, Action: memberlifecycle.DeviceTransferMember, NewOwnerID: ownerID},
	}

	if _, err := remove(plain, memberID); !errors.Is(err, memberlifecycle.ErrForbidden) {
		t.Fatalf("plain member removed a member: %v", err)
	}
	if _, err := remove(owner, ownerID); !errors.Is(err, memberlifecycle.ErrProtected) {
		t.Fatalf("owner removed themselves: %v", err)
	}
	if _, err := remove(owner, memberID, memberlifecycle.DevicePlan{
		DeviceID: incoming, Action: memberlifecycle.DeviceTransferWorkspace,
	}); !errors.Is(err, memberlifecycle.ErrPlan) {
		t.Fatalf("plan with someone else's Device = %v", err)
	}
	stranger, _ := publicid.Parse("01890f00-0000-7000-8000-00000000197f")
	if _, err := remove(owner, memberID, memberlifecycle.DevicePlan{
		DeviceID: handed, Action: memberlifecycle.DeviceTransferMember, NewOwnerID: stranger,
	}); !errors.Is(err, memberlifecycle.ErrNewOwner) {
		t.Fatalf("handover to a stranger = %v", err)
	}
	if row := readIntegrationDevice(ctx, t, admin, unnamed); row.state != "suspended" {
		t.Fatalf("a refused removal changed a Device: %+v", row)
	}

	networkBefore, _ := fixtureNetworkRevisions(ctx, t, admin)
	removed, err := remove(owner, memberID, plan...)
	if err != nil || removed.After.State != "revoked" || len(removed.Devices) != 3 || len(removed.Networks) != 1 ||
		removed.HandoversCancelled != 1 || removed.KeysRevoked != 1 || removed.GroupsLeft != 1 ||
		removed.RolesRevoked != 1 {
		t.Fatalf("remove = %+v, %v", removed, err)
	}
	if networkAfter, _ := fixtureNetworkRevisions(ctx, t, admin); networkAfter != networkBefore+1 {
		t.Fatalf("member removal advanced the Network %d → %d, want once", networkBefore, networkAfter)
	}
	if row := readIntegrationDevice(ctx, t, admin, moved); row.ownership != "workspace" || row.state != "active" {
		t.Fatalf("Device moved to the Workspace = %+v", row)
	}
	if row := readIntegrationDevice(ctx, t, admin, handed); row.state != "suspended" || row.reason == nil ||
		*row.reason != "handover" || row.handover == nil || *row.handover != ownerID.String() {
		t.Fatalf("Device handed over = %+v", row)
	}
	if row := readIntegrationDevice(ctx, t, admin, unnamed); row.state != "revoked" || row.reason != nil {
		t.Fatalf("unnamed Device = %+v, want revoked", row)
	}
	if active := activeKeyEpochs(ctx, t, admin, unnamed); active != 0 {
		t.Fatalf("revoked Device kept %d active keys", active)
	}
	if row := readIntegrationDevice(ctx, t, admin, incoming); row.state != "suspended" || row.reason == nil ||
		*row.reason != "admin" || row.handover != nil {
		t.Fatalf("Device waiting for the member = %+v, want suspended for an administrator", row)
	}
	assertRemovedMemberRows(ctx, t, admin)
	// One event on the Workspace stream and one on the Network's stream.
	if count := countRemovalAudit(ctx, t, admin); count != 2 {
		t.Fatalf("member removal recorded %d events, want the Workspace one and the Network one", count)
	}
	if _, err := remove(owner, memberID); !errors.Is(err, memberlifecycle.ErrNotFound) {
		t.Fatalf("removed a removed member: %v", err)
	}
}

func activeKeyEpochs(ctx context.Context, t *testing.T, admin *pgx.Conn, device node.ID) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT count(*) FROM mesh.device_machine_key_epoch AS key_epoch JOIN mesh.device AS device
       ON device.id = key_epoch.device_id WHERE device.public_id = $1::UUID AND key_epoch.state = 'active')
  + (SELECT count(*) FROM mesh.device_node_key_epoch AS key_epoch JOIN mesh.device AS device
       ON device.id = key_epoch.device_id WHERE device.public_id = $1::UUID AND key_epoch.state = 'active')`,
		device.String()).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// assertRemovedMemberRows checks that nothing the member held stays active.
func assertRemovedMemberRows(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var membership, networkMembership, assignment, credential string
	var groupMembers, groupCount int64
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT state FROM mesh.workspace_membership WHERE id = 1973),
    (SELECT state FROM mesh.network_membership WHERE id = 1974),
    (SELECT state FROM mesh.workspace_role_assignment WHERE id = 1975),
    (SELECT state FROM mesh.enrollment_credential WHERE issuer_principal_id = 1971),
    (SELECT count(*) FROM mesh.identity_group_member WHERE principal_id = 1971),
    (SELECT member_count FROM mesh.identity_group WHERE id = 1976)`).Scan(&membership, &networkMembership,
		&assignment, &credential, &groupMembers, &groupCount); err != nil {
		t.Fatal(err)
	}
	if membership != "revoked" || networkMembership != "revoked" || assignment != "revoked" ||
		credential != "revoked" || groupMembers != 0 || groupCount != 0 {
		t.Fatalf("removed member rows = %s %s %s %s %d %d", membership, networkMembership, assignment, credential,
			groupMembers, groupCount)
	}
}

func countRemovalAudit(ctx context.Context, t *testing.T, admin *pgx.Conn) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event
WHERE target_kind = 'workspace_membership' AND target_public_id = $1::UUID AND action = 'member.removed'`,
		integrationRemovedMemberID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// seedRemovableMember adds an account member to Workspace 103 who owns the
// first three Devices (the third suspended by an administrator) and is the
// pending recipient of the fourth, with an auditor role, a Network
// membership, an Identity Group membership and an enrollment key of Network
// 203. It returns the function that puts every Device and key epoch back. Triggers are bypassed only for this fixture, never
// for the code under test.
func seedRemovableMember(ctx context.Context, t *testing.T, admin *pgx.Conn, devices []node.ID) func() {
	t.Helper()
	ids := make([]string, len(devices))
	for index, device := range devices {
		ids[index] = device.String()
	}
	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{
		{sql: `CREATE TEMP TABLE removal_device_backup AS SELECT * FROM mesh.device WHERE public_id = ANY ($1::UUID[])`, args: []any{ids}},
		{sql: `CREATE TEMP TABLE removal_machine_backup AS SELECT key_epoch.* FROM mesh.device_machine_key_epoch AS key_epoch
JOIN mesh.device AS device ON device.id = key_epoch.device_id WHERE device.public_id = ANY ($1::UUID[])`, args: []any{ids}},
		{sql: `CREATE TEMP TABLE removal_node_backup AS SELECT key_epoch.* FROM mesh.device_node_key_epoch AS key_epoch
JOIN mesh.device AS device ON device.id = key_epoch.device_id WHERE device.public_id = ANY ($1::UUID[])`, args: []any{ids}},
		{sql: `INSERT INTO mesh.principal (id, public_id, deployment_id, kind, state) OVERRIDING SYSTEM VALUE
VALUES (1971, '` + integrationRemovedMemberID + `', 1, 'account', 'active')`},
		{sql: `INSERT INTO mesh.account (id, public_id, deployment_id, principal_id, display_name, session_generation, recovery_state)
OVERRIDING SYSTEM VALUE VALUES (1972, '01890f00-0000-7000-8000-000000001972', 1, 1971, 'Removable Member', 1, 'verified')`},
		{sql: `INSERT INTO mesh.workspace_membership (id, public_id, deployment_id, workspace_id, principal_id, state,
    authority_generation, valid_from) OVERRIDING SYSTEM VALUE
VALUES (1973, '01890f00-0000-7000-8000-000000001973', 1, 103, 1971, 'active', 1, now() - INTERVAL '1 minute')`},
		{sql: `INSERT INTO mesh.network_membership (id, public_id, deployment_id, workspace_id, network_id, principal_id,
    workspace_membership_id, state, authority_generation, valid_from) OVERRIDING SYSTEM VALUE
VALUES (1974, '01890f00-0000-7000-8000-000000001974', 1, 103, 203, 1971, 1973, 'active', 1, now() - INTERVAL '1 minute')`},
		{sql: `INSERT INTO mesh.workspace_role_assignment (id, public_id, deployment_id, workspace_id, principal_id,
    workspace_membership_id, role_key, state, authority_generation, valid_from, version, created_at, updated_at)
OVERRIDING SYSTEM VALUE VALUES (1975, '01890f00-0000-7000-8000-000000001975', 1, 103, 1971, 1973, 'auditor',
    'active', 1, now() - INTERVAL '1 minute', 1, now() - INTERVAL '1 minute', now() - INTERVAL '1 minute')`},
		{sql: `INSERT INTO mesh.identity_group (id, public_id, deployment_id, workspace_id, name, name_key, member_count,
    created_at, updated_at) OVERRIDING SYSTEM VALUE
VALUES (1976, '01890f00-0000-7000-8000-000000001976', 1, 103, 'Removal check', 'removal check', 1, now(), now())`},
		{sql: `INSERT INTO mesh.identity_group_member (id, public_id, workspace_id, identity_group_id, principal_id, created_at)
OVERRIDING SYSTEM VALUE VALUES (1977, '01890f00-0000-7000-8000-000000001977', 103, 1976, 1971, now())`},
		{sql: `INSERT INTO mesh.enrollment_credential (id, public_id, workspace_id, network_id, enrollment_profile_id,
    issuer_principal_id, digest_algorithm, digest_key_id, token_digest, token_fingerprint, issued_recovery_epoch,
    use_limit_kind, max_uses, used_count, valid_from, expires_at, state)
OVERRIDING SYSTEM VALUE SELECT 1978, '01890f00-0000-7000-8000-000000001978', 103, 203, profile.id, 1971,
    'hmac-sha256-v1', 'removal-check', pg_catalog.sha256('removal-check'::BYTEA),
    pg_catalog.substr(pg_catalog.sha256('removal-check-fingerprint'::BYTEA), 1, 16), 1,
    'bounded', 1, 0, now() - INTERVAL '1 minute', now() + INTERVAL '1 hour', 'active'
FROM mesh.enrollment_profile AS profile WHERE profile.workspace_id = 103 AND profile.network_id = 203
ORDER BY profile.id LIMIT 1`},
		{sql: `UPDATE mesh.device SET ownership = 'member', owner_principal_id = 1971, custodian_principal_id = 1971
WHERE public_id = ANY ($1::UUID[]) AND public_id <> ($1::UUID[])[4]`, args: []any{ids}},
		{sql: `UPDATE mesh.device SET state = 'suspended', suspended_reason = 'admin' WHERE public_id = ($1::UUID[])[3]`, args: []any{ids}},
		{sql: `UPDATE mesh.device SET state = 'suspended', suspended_reason = 'handover', handover_principal_id = 1971
WHERE public_id = ($1::UUID[])[4]`, args: []any{ids}},
	})
	return func() {
		runRemovalFixture(ctx, t, admin, []removalFixtureStatement{
			{sql: `UPDATE mesh.device AS device SET ownership = backup.ownership, owner_principal_id = backup.owner_principal_id,
    custodian_principal_id = backup.custodian_principal_id, state = backup.state,
    suspended_reason = backup.suspended_reason, handover_principal_id = backup.handover_principal_id,
    expires_at = backup.expires_at
FROM removal_device_backup AS backup WHERE device.id = backup.id`},
			{sql: `UPDATE mesh.device_machine_key_epoch AS key_epoch SET state = backup.state, valid_until = backup.valid_until,
    revocation_reason = backup.revocation_reason
FROM removal_machine_backup AS backup WHERE key_epoch.id = backup.id`},
			{sql: `UPDATE mesh.device_node_key_epoch AS key_epoch SET state = backup.state, valid_until = backup.valid_until,
    revocation_reason = backup.revocation_reason
FROM removal_node_backup AS backup WHERE key_epoch.id = backup.id`},
			{sql: `DROP TABLE removal_device_backup, removal_machine_backup, removal_node_backup`},
		})
	}
}

// removalFixtureStatement is one fixture statement and its arguments.
type removalFixtureStatement struct {
	sql  string
	args []any
}

// runRemovalFixture runs fixture statements with triggers bypassed.
func runRemovalFixture(ctx context.Context, t *testing.T, admin *pgx.Conn, statements []removalFixtureStatement) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `RESET ROLE; SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("member removal fixture: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
