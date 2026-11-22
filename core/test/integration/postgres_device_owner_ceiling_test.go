//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/devicelifecycle"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/revocation"
)

const (
	ceilingAdminHolderID = "01890f00-0000-7000-8000-000000009301"
	ceilingPlainHolderID = "01890f00-0000-7000-8000-000000009302"
)

// assertDeviceOwnerCeiling qualifies schema 295 (TD-SEC-87): acting on a
// member's Device needs the delegation ceiling over every role its owner
// holds, and only the Workspace owner acts on the owner's Devices. An
// it_admin (who grants only it_admin) changes and revokes nothing on the
// owner's or an admin's Device, but still acts on a plain member's; the
// owner acts on every Device. Device leaves with its original owner. Schema
// 317 (TD-SEC-97): a Workspace exit node also needs route.withdraw.
func assertDeviceOwnerCeiling(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, lifecycle *devicelifecycle.Service, scope network.Scope,
	owner, itAdmin accountsession.Session, device node.ID) {
	t.Helper()
	var ownership string
	var ownerID, custodianID int64
	if err := admin.QueryRow(ctx, `SELECT ownership, owner_principal_id, custodian_principal_id
FROM mesh.device WHERE public_id = $1::UUID`, device.String()).Scan(&ownership, &ownerID, &custodianID); err != nil {
		t.Fatal(err)
	}
	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{
		{sql: `INSERT INTO mesh.principal (id, public_id, deployment_id, kind, state)
OVERRIDING SYSTEM VALUE VALUES (9301, $1::UUID, 1, 'account', 'active'), (9302, $2::UUID, 1, 'account', 'active')`,
			args: []any{ceilingAdminHolderID, ceilingPlainHolderID}},
		{sql: `INSERT INTO mesh.workspace_membership (id, public_id, deployment_id, workspace_id, principal_id, state,
    valid_from)
OVERRIDING SYSTEM VALUE VALUES
    (9301, pg_catalog.uuidv7(), 1, 103, 9301, 'active', now() - INTERVAL '1 hour'),
    (9302, pg_catalog.uuidv7(), 1, 103, 9302, 'active', now() - INTERVAL '1 hour')`},
		{sql: `INSERT INTO mesh.workspace_role_assignment (id, public_id, deployment_id, workspace_id, principal_id,
    workspace_membership_id, role_key, state, authority_generation, valid_from, version, created_at, updated_at)
OVERRIDING SYSTEM VALUE VALUES (9301, pg_catalog.uuidv7(), 1, 103, 9301, 9301, 'admin', 'active', 1,
    now() - INTERVAL '1 minute', 1, now() - INTERVAL '1 minute', now() - INTERVAL '1 minute')`},
	})
	removeITAdmin := seedEnrollmentKeyRole(ctx, t, admin, itAdmin, 1998, "it_admin")
	defer func() {
		removeITAdmin()
		runRemovalFixture(ctx, t, admin, []removalFixtureStatement{
			{sql: `UPDATE mesh.device SET ownership = $2, owner_principal_id = $3, custodian_principal_id = $4
WHERE public_id = $1::UUID`, args: []any{device.String(), ownership, ownerID, custodianID}},
			{sql: `DELETE FROM mesh.workspace_role_assignment WHERE id = 9301`},
			{sql: `DELETE FROM mesh.workspace_membership WHERE id IN (9301, 9302)`},
			{sql: `DELETE FROM mesh.principal WHERE id IN (9301, 9302)`},
		})
	}()
	ownedBy := func(principal int64) {
		t.Helper()
		runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{sql: `UPDATE mesh.device
SET ownership = 'member', owner_principal_id = $2, custodian_principal_id = $2 WHERE public_id = $1::UUID`,
			args: []any{device.String(), principal}}})
	}
	act := func(session accountsession.Session, action devicelifecycle.Action) error {
		t.Helper()
		_, err := lifecycle.Change(ctx, session, devicelifecycle.Request{Scope: scope, DeviceID: device,
			Action: action, Reason: "Ceiling", ExpectedVersion: readIntegrationDevice(ctx, t, admin, device).version,
			CorrelationID: newCorrelationID(t)})
		return err
	}
	revocations := newIntegrationDeviceRevocationService(t, runtimePool)

	for _, holder := range []struct {
		name      string
		principal int64
	}{{"the owner's", 11}, {"an admin's", 9301}} {
		ownedBy(holder.principal)
		before := readIntegrationDevice(ctx, t, admin, device)
		if err := act(itAdmin, devicelifecycle.ActionSuspend); !errors.Is(err, devicelifecycle.ErrForbidden) {
			t.Fatalf("it_admin suspended %s Device: %v", holder.name, err)
		}
		if err := act(itAdmin, devicelifecycle.ActionTransferWorkspace); !errors.Is(err, devicelifecycle.ErrForbidden) {
			t.Fatalf("it_admin took %s Device for the Workspace: %v", holder.name, err)
		}
		if _, err := revocations.Revoke(ctx, deviceOwnerCeilingRevocation(t, scope, device, before.version,
			itAdmin)); !errors.Is(err, revocation.ErrForbidden) {
			t.Fatalf("it_admin revoked %s Device: %v", holder.name, err)
		}
		// Schema 296: the database refuses too, without the Go store.
		assertDirectRevocation(t, "it_admin on "+holder.name+" Device",
			directDeviceRevocations(ctx, t, admin, scope, itAdmin, device, directRevocation{})[0],
			"42501", "Device is beyond the actor's ceiling")
		if after := readIntegrationDevice(ctx, t, admin, device); after.version != before.version ||
			after.state != "active" {
			t.Fatalf("%s Device changed: %+v, want %+v", holder.name, after, before)
		}
	}
	// The owner acts on an admin's Device.
	if err := act(owner, devicelifecycle.ActionSuspend); err != nil {
		t.Fatalf("owner suspended an admin's Device: %v", err)
	}
	if err := act(owner, devicelifecycle.ActionResume); err != nil {
		t.Fatalf("owner resumed an admin's Device: %v", err)
	}
	// A Workspace Device is anyone's with the permission.
	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{sql: `UPDATE mesh.device SET ownership = 'workspace'
WHERE public_id = $1::UUID`, args: []any{device.String()}}})
	if err := act(itAdmin, devicelifecycle.ActionSuspend); err != nil {
		t.Fatalf("it_admin suspended a Workspace Device: %v", err)
	}
	if err := act(itAdmin, devicelifecycle.ActionResume); err != nil {
		t.Fatalf("it_admin resumed a Workspace Device: %v", err)
	}
	// Schema 317 (TD-SEC-97): a Workspace Device that is an exit node or a
	// site router is the Network's infrastructure: it_admin, who may not
	// withdraw routes, no longer takes it out; the owner still does. The rows
	// skip their pool and site foreign keys and leave at the end.
	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{sql: `INSERT INTO mesh.network_exit_node (public_id,
    workspace_id, network_id, pool_id, device_id, priority, state, added_by_principal_id, created_at, updated_at)
SELECT pg_catalog.uuidv7(), device.workspace_id, device.network_id, 0, device.id, 0, 'active', 11, now(), now()
FROM mesh.device AS device WHERE device.public_id = $1::UUID`, args: []any{device.String()}}})
	defer runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{sql: `DELETE FROM mesh.network_exit_node
WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID)`, args: []any{device.String()}}})
	exitNode := readIntegrationDevice(ctx, t, admin, device)
	if err := act(itAdmin, devicelifecycle.ActionSuspend); !errors.Is(err, devicelifecycle.ErrForbidden) {
		t.Fatalf("it_admin suspended a Workspace exit node: %v", err)
	}
	if _, err := revocations.Revoke(ctx, deviceOwnerCeilingRevocation(t, scope, device, exitNode.version,
		itAdmin)); !errors.Is(err, revocation.ErrForbidden) {
		t.Fatalf("it_admin revoked a Workspace exit node: %v", err)
	}
	assertDirectRevocation(t, "it_admin on a Workspace exit node",
		directDeviceRevocations(ctx, t, admin, scope, itAdmin, device, directRevocation{})[0],
		"42501", "Device is beyond the actor's ceiling")
	if err := act(owner, devicelifecycle.ActionSuspend); err != nil {
		t.Fatalf("owner suspended a Workspace exit node: %v", err)
	}
	if err := act(owner, devicelifecycle.ActionResume); err != nil {
		t.Fatalf("owner resumed a Workspace exit node: %v", err)
	}
	// The same for a site router alone (pool and site rows are not needed:
	// the fixture bypasses their foreign keys and is removed at the end).
	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{
		{sql: `DELETE FROM mesh.network_exit_node WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID)`,
			args: []any{device.String()}},
		{sql: `INSERT INTO mesh.network_site_router (public_id, workspace_id, network_id, site_id, device_id, priority,
    state, added_by_principal_id, created_at, updated_at)
SELECT pg_catalog.uuidv7(), device.workspace_id, device.network_id, 0, device.id, 0, 'active', 11, now(), now()
FROM mesh.device AS device WHERE device.public_id = $1::UUID`, args: []any{device.String()}}})
	defer runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{sql: `DELETE FROM mesh.network_site_router
WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID)`, args: []any{device.String()}}})
	if err := act(itAdmin, devicelifecycle.ActionSuspend); !errors.Is(err, devicelifecycle.ErrForbidden) {
		t.Fatalf("it_admin suspended a Workspace site router: %v", err)
	}
	if err := act(owner, devicelifecycle.ActionSuspend); err != nil {
		t.Fatalf("owner suspended a Workspace site router: %v", err)
	}
	if err := act(owner, devicelifecycle.ActionResume); err != nil {
		t.Fatalf("owner resumed a Workspace site router: %v", err)
	}
	// it_admin still acts on a plain member's Device.
	ownedBy(9302)
	// Schema 296 directly: the plain member's Device is revoked, then a
	// second call finds it revoked; unknown Networks and Devices and stale
	// versions are refused. All of it rolls back.
	other := mustPublicID(t).String()
	outcomes := directDeviceRevocations(ctx, t, admin, scope, itAdmin, device,
		directRevocation{change: func(arguments []any) { arguments[10] = other }},
		directRevocation{change: func(arguments []any) { arguments[11] = other }},
		directRevocation{change: func(arguments []any) { arguments[12] = arguments[12].(int64) + 1 }},
		directRevocation{},
		directRevocation{})
	assertDirectRevocation(t, "naming an unknown Network", outcomes[0], "42501", "Device revocation names another Network")
	assertDirectRevocation(t, "for an unknown Device", outcomes[1], "P0002", "Device is unavailable")
	assertDirectRevocation(t, "with a stale version", outcomes[2], "40001", "Device changed")
	assertDirectRevocation(t, "of a plain member's Device", outcomes[3], "", "")
	assertDirectRevocation(t, "of a revoked Device", outcomes[4], "MTM03", "Device cannot be revoked")
	if err := act(itAdmin, devicelifecycle.ActionSuspend); err != nil {
		t.Fatalf("it_admin suspended a plain member's Device: %v", err)
	}
	if err := act(itAdmin, devicelifecycle.ActionResume); err != nil {
		t.Fatalf("it_admin resumed a plain member's Device: %v", err)
	}
}

func deviceOwnerCeilingRevocation(t *testing.T, scope network.Scope, device node.ID, version int64,
	session accountsession.Session) revocation.Command {
	t.Helper()
	reason, err := revocation.NewReason("Ceiling check")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := integrationDeviceRevocationDigester(t).Proof(integrationDeviceRevocationIdempotencyKey(0x95))
	if err != nil {
		t.Fatal(err)
	}
	command, err := revocation.NewCommand(revocation.CommandParams{
		Scope: scope, NodeID: device, ExpectedVersion: version, AccountSession: session,
		Reason: reason, IdempotencyEvidence: proof,
	})
	if err != nil {
		t.Fatal(err)
	}
	return command
}

// directRevocation is one direct call of mesh_ops.revoke_device_v2 as the
// runtime role, bypassing the Go store: the Device's current rows, changed by
// change when it is not nil (index 9 the Workspace, 10 the Network, 11 the
// Device public id, 12 the expected Device version).
type directRevocation struct {
	change func(arguments []any)
}

// directDeviceRevocations runs calls in order in one transaction as the
// runtime role and returns, for each, the SQLSTATE and message it failed
// with ("" when it revoked). It always rolls back.
func directDeviceRevocations(ctx context.Context, t *testing.T, admin *pgx.Conn, scope network.Scope,
	session accountsession.Session, device node.ID, calls ...directRevocation) [][2]string {
	t.Helper()
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if _, err := transaction.Exec(ctx, legacyRuntimeSQL(`SET LOCAL ROLE mesh_runtime`)); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, `SELECT * FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`,
		scope.WorkspaceID().String(), scope.NetworkID().String()); err != nil {
		t.Fatal(err)
	}
	outcomes := make([][2]string, 0, len(calls))
	for index, call := range calls {
		var version, generation, machineEpoch, machineVersion, nodeEpoch, nodeVersion int64
		if err := transaction.QueryRow(ctx, `SELECT device.version, device.session_generation,
    machine.epoch, machine.version, node_key.epoch, node_key.version
FROM mesh.device AS device
JOIN mesh.device_machine_key_epoch AS machine ON machine.device_id = device.id
 AND machine.epoch = device.current_machine_key_epoch
JOIN mesh.device_node_key_epoch AS node_key ON node_key.device_id = device.id
 AND node_key.epoch = device.current_node_key_epoch
WHERE device.public_id = $1::UUID`, device.String()).Scan(&version, &generation, &machineEpoch, &machineVersion,
			&nodeEpoch, &nodeVersion); err != nil {
			t.Fatal(err)
		}
		arguments := []any{session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
			session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
			session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
			scope.WorkspaceID().String(), scope.NetworkID().String(), device.String(),
			version, generation, machineEpoch, machineVersion, nodeEpoch, nodeVersion}
		if call.change != nil {
			call.change(arguments)
		}
		savepoint := fmt.Sprintf("direct_revocation_%d", index)
		if _, err := transaction.Exec(ctx, "SAVEPOINT "+savepoint); err != nil {
			t.Fatal(err)
		}
		_, err := transaction.Exec(ctx, `SELECT * FROM mesh_ops.revoke_device_v2(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::UUID, $13::BIGINT, $14::BIGINT, $15::BIGINT, $16::BIGINT, $17::BIGINT, $18::BIGINT,
    'Direct call', pg_catalog.uuidv7(), pg_catalog.transaction_timestamp())`, arguments...)
		var pgError *pgconn.PgError
		switch {
		case errors.As(err, &pgError):
			outcomes = append(outcomes, [2]string{pgError.Code, pgError.Message})
			if _, err := transaction.Exec(ctx, "ROLLBACK TO SAVEPOINT "+savepoint); err != nil {
				t.Fatal(err)
			}
		case err != nil:
			t.Fatal(err)
		default:
			outcomes = append(outcomes, [2]string{"", ""})
		}
	}
	return outcomes
}

func assertDirectRevocation(t *testing.T, name string, got [2]string, code, message string) {
	t.Helper()
	if got[0] != code || message != "" && got[1] != message {
		t.Errorf("revoke_device_v2 %s = (%q, %q), want (%q, %q)", name, got[0], got[1], code, message)
	}
}
