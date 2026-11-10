//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/node"
)

// activeFixtureDeviceKeys returns an active fixture Device with the public
// keys of its current machine and node key epochs.
func activeFixtureDeviceKeys(ctx context.Context, t *testing.T, admin *pgx.Conn) (node.ID, node.MachineKey, node.Key) {
	t.Helper()
	var deviceText string
	var machine, nodeKey []byte
	if err := admin.QueryRow(ctx, `SELECT device.public_id::TEXT, machine.public_key, node_key.public_key
FROM mesh.device AS device
JOIN mesh.device_machine_key_epoch AS machine
  ON machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch AND machine.state = 'active'
JOIN mesh.device_node_key_epoch AS node_key
  ON node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch AND node_key.state = 'active'
WHERE device.workspace_id = 103 AND device.network_id = 203 AND device.state = 'active'
  AND device.deleted_at IS NULL AND device.expires_at > now()
ORDER BY device.public_id LIMIT 1`).Scan(&deviceText, &machine, &nodeKey); err != nil {
		t.Fatalf("no active fixture Device with current keys: %v", err)
	}
	device, err := node.ParseID(deviceText)
	if err != nil || len(machine) != 32 || len(nodeKey) != 32 {
		t.Fatal("fixture Device keys are malformed")
	}
	return device, node.MachineKey(machine), node.Key(nodeKey)
}

// assertPostgreSQLDeviceLogout qualifies schema 138: a node logs out only
// the active Device whose current machine and node keys it holds; the
// Device and its keys are revoked, the Network advances once and
// device.logged_out is sealed with the owner as the actor.
func assertPostgreSQLDeviceLogout(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool, workerPool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewDeviceLogoutStore(runtimePool, postgresadapter.AccountSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := control.NewDeviceLogoutService(store)
	if err != nil {
		t.Fatal(err)
	}
	device, machineKey, nodeKey := activeFixtureDeviceKeys(ctx, t, admin)
	machine, err := control.NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatal(err)
	}
	var otherKey node.Key
	copy(otherKey[:], nodeKey[:])
	otherKey[0] ^= 0xff
	if _, err := service.Logout(ctx, machine, otherKey, true, false); !errors.Is(err, control.ErrDeviceLogoutNotFound) {
		t.Fatalf("logout with another node key: %v", err)
	}
	networkBefore, groupBefore := fixtureNetworkRevisions(ctx, t, admin)
	logout, err := service.Logout(ctx, machine, nodeKey, true, false)
	if err != nil || logout.DeviceID != device {
		t.Fatalf("logout = %+v, %v", logout, err)
	}
	networkAfter, groupAfter := fixtureNetworkRevisions(ctx, t, admin)
	if networkAfter != networkBefore+1 || groupAfter != groupBefore+1 || logout.NetworkRevision != networkAfter {
		t.Fatalf("revisions %d→%d, groups %d→%d; want one advance", networkBefore, networkAfter, groupBefore, groupAfter)
	}
	if row := readIntegrationDevice(ctx, t, admin, device); row.state != "revoked" {
		t.Fatalf("Device state %q after logout", row.state)
	}
	if countDeviceAudit(ctx, t, admin, device, "device.logged_out") != 1 {
		t.Fatal("logout must seal exactly one device.logged_out")
	}
	var activeKeys int
	var actorIsOwner bool
	if err := admin.QueryRow(ctx, `SELECT
  (SELECT count(*) FROM mesh.device_node_key_epoch AS key_epoch JOIN mesh.device AS device ON device.id = key_epoch.device_id
   WHERE device.public_id = $1::UUID AND key_epoch.state = 'active')
+ (SELECT count(*) FROM mesh.device_machine_key_epoch AS key_epoch JOIN mesh.device AS device ON device.id = key_epoch.device_id
   WHERE device.public_id = $1::UUID AND key_epoch.state = 'active'),
  EXISTS (SELECT 1 FROM mesh_audit.audit_event AS event
          JOIN mesh.device AS device ON device.public_id = event.target_public_id
          JOIN mesh.principal AS owner ON owner.id = device.owner_principal_id
          WHERE event.target_public_id = $1::UUID AND event.action = 'device.logged_out'
            AND event.actor_principal_public_id = owner.public_id)`, device.String()).
		Scan(&activeKeys, &actorIsOwner); err != nil {
		t.Fatal(err)
	}
	if activeKeys != 0 || !actorIsOwner {
		t.Fatalf("after logout: %d active keys, actor is owner %t", activeKeys, actorIsOwner)
	}
	// A logged-out Device cannot log out again or open a map; its keys were
	// revoked with it, so the node is told it may erase them (schema 282).
	if _, err := service.Logout(ctx, machine, nodeKey, true, false); !errors.Is(err, control.ErrDeviceLogoutRevoked) {
		t.Fatalf("second logout: %v", err)
	}
	// Keys Core never knew stay ambiguous: the node keeps them.
	var unknownMachine node.MachineKey
	copy(unknownMachine[:], machineKey[:])
	unknownMachine[0] ^= 0xff
	stranger, err := control.NewAuthenticatedMachine(unknownMachine)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Logout(ctx, stranger, nodeKey, true, false); !errors.Is(err, control.ErrDeviceLogoutNotFound) {
		t.Fatalf("logout with unknown keys: %v", err)
	}
	assertPostgreSQLExpiredDeviceLogout(ctx, t, admin, service)
	assertPostgreSQLDeviceSignOut(ctx, t, admin, service, workerPool)
	assertPostgreSQLSignedOutRemoval(ctx, t, admin, service)
}

// assertPostgreSQLDeviceSignOut qualifies schema 283: signing out keeps the
// Device and its address, leaves no map, seals device.signed_out once; a
// repeat writes nothing; a path that raises the expiry keeps it signed out.
func assertPostgreSQLDeviceSignOut(ctx context.Context, t *testing.T, admin *pgx.Conn,
	service *control.DeviceLogoutService, workerPool *postgresadapter.Pool) {
	t.Helper()
	device, machineKey, nodeKey := activeFixtureDeviceKeys(ctx, t, admin)
	machine, err := control.NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatal(err)
	}
	leases := func() int {
		var count int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh.node_address_lease AS lease
JOIN mesh.device AS device ON device.id = lease.device_id
WHERE device.public_id = $1::UUID AND lease.state = 'active'`, device.String()).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	leasesBefore := leases()
	networkBefore, _ := fixtureNetworkRevisions(ctx, t, admin)
	logout, err := service.Logout(ctx, machine, nodeKey, true, true)
	if err != nil || logout.DeviceID != device || logout.Outcome != control.LogoutSignedOut {
		t.Fatalf("sign out = %+v, %v", logout, err)
	}
	networkAfter, _ := fixtureNetworkRevisions(ctx, t, admin)
	var state string
	var signedOut, live bool
	if err := admin.QueryRow(ctx, `SELECT state, signed_out_at IS NOT NULL, expires_at > now()
FROM mesh.device WHERE public_id = $1::UUID`, device.String()).Scan(&state, &signedOut, &live); err != nil {
		t.Fatal(err)
	}
	if state != "active" || !signedOut || live || networkAfter != networkBefore+1 || leases() != leasesBefore ||
		leasesBefore == 0 {
		t.Fatalf("after sign out: state %q, signed out %t, live %t, revision %d→%d, leases %d→%d",
			state, signedOut, live, networkBefore, networkAfter, leasesBefore, leases())
	}
	if countDeviceAudit(ctx, t, admin, device, "device.signed_out") != 1 ||
		countDeviceAudit(ctx, t, admin, device, "device.logged_out") != 0 {
		t.Fatal("a sign out must seal exactly one device.signed_out and no device.logged_out")
	}
	// Only logout_device_v2 starts a sign-out: the runtime role cannot.
	func() {
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT * FROM mesh_ops.set_network_scope(
'01890f00-0000-7000-8000-000000000103'::UUID,'01890f00-0000-7000-8000-000000000203'::UUID)`); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `UPDATE mesh.device SET signed_out_at = now() + INTERVAL '1 day'
WHERE public_id = $1::UUID`, device.String())
		var pgError *pgconn.PgError
		if !errors.As(err, &pgError) || pgError.Code != "42501" {
			t.Fatalf("a runtime UPDATE of signed_out_at = %v, want 42501", err)
		}
	}()
	// A repeat changes nothing.
	again, err := service.Logout(ctx, machine, nodeKey, true, true)
	if err != nil || again.Outcome != control.LogoutUnchanged {
		t.Fatalf("second sign out = %+v, %v", again, err)
	}
	if repeated, _ := fixtureNetworkRevisions(ctx, t, admin); repeated != networkAfter ||
		countDeviceAudit(ctx, t, admin, device, "device.signed_out") != 1 {
		t.Fatalf("a repeated sign out wrote: revision %d→%d", networkAfter, repeated)
	}
	// A path that raises the expiry (as transfer to the Workspace does)
	// leaves it signed out.
	version := readIntegrationDevice(ctx, t, admin, device).version
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: "01890f01-0000-7000-8000-000000002831",
		eventPublicID:  "01890f02-0000-7000-8000-000000002831",
		outboxPublicID: "01890f03-0000-7000-8000-000000002831",
		streamID:       203, aggregateKind: "device", aggregatePublicID: device.String(),
		aggregateVersion: version + 1, networkRevision: networkAfter + 1,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "device.expiry.fixture", permission: "system.bootstrap",
		outboxEventClass: "device.expiry.fixture",
	}, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `UPDATE mesh.device
SET expires_at = mesh_ops.device_never_expires_v1(), version = version + 1, updated_at = pg_catalog.now()
WHERE public_id = $1::UUID`, device.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT * FROM mesh_ops.set_network_scope(
'01890f00-0000-7000-8000-000000000103'::UUID,'01890f00-0000-7000-8000-000000000203'::UUID)`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT * FROM mesh_ops.advance_network_inventory_revision()`); err != nil {
			t.Fatal(err)
		}
	})
	if err := admin.QueryRow(ctx, `SELECT expires_at > now() FROM mesh.device WHERE public_id = $1::UUID`,
		device.String()).Scan(&live); err != nil || live {
		t.Fatalf("raising the expiry of a signed-out Device brought it back: live %t, %v", live, err)
	}
	assertPostgreSQLSignedOutRevocation(ctx, t, admin, workerPool, device)
}

// assertPostgreSQLSignedOutRevocation qualifies schema 284: the worker
// leaves a Device signed out for less than the hold, then removes it once
// due, with device.revoked under the system actor.
func assertPostgreSQLSignedOutRevocation(ctx context.Context, t *testing.T, admin *pgx.Conn,
	workerPool *postgresadapter.Pool, device node.ID) {
	t.Helper()
	worker, err := postgresadapter.NewSignedOutRevocationWorkerStore(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	installation := integrationDeploymentID(ctx, t, admin)
	if step, err := worker.Step(ctx, installation, 1); err != nil || step.Changed {
		t.Fatalf("step before the hold = %+v, %v", step, err)
	}
	// Signed out 29 days ago, then 31: only logout_device_v2's owner may
	// move it.
	shift := func(days int, change string) {
		t.Helper()
		version := readIntegrationDevice(ctx, t, admin, device).version
		revision, _ := fixtureNetworkRevisions(ctx, t, admin)
		commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
			changePublicID: "01890f01-0000-7000-8000-00000000" + change,
			eventPublicID:  "01890f02-0000-7000-8000-00000000" + change,
			outboxPublicID: "01890f03-0000-7000-8000-00000000" + change,
			streamID:       203, aggregateKind: "device", aggregatePublicID: device.String(),
			aggregateVersion: version + 1, networkRevision: revision + 1,
			actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
			action:                 "device.expiry.fixture", permission: "system.bootstrap",
			outboxEventClass: "device.expiry.fixture",
		}, func(tx pgx.Tx) {
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_migrator`); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `UPDATE mesh.device
SET created_at = created_at - make_interval(days => $2 + 1),
    signed_out_at = signed_out_at - make_interval(days => $2),
    expires_at = LEAST(expires_at, signed_out_at - make_interval(days => $2)),
    version = version + 1, updated_at = pg_catalog.now()
WHERE public_id = $1::UUID`, device.String(), days); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SELECT * FROM mesh_ops.set_network_scope(
'01890f00-0000-7000-8000-000000000103'::UUID,'01890f00-0000-7000-8000-000000000203'::UUID)`); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SELECT * FROM mesh_ops.advance_network_inventory_revision()`); err != nil {
				t.Fatal(err)
			}
		})
	}
	shift(29, "2841")
	if step, err := worker.Step(ctx, installation, 1); err != nil || step.Changed {
		t.Fatalf("step 29 days after the sign out = %+v, %v", step, err)
	}
	shift(2, "2842")
	if lag, err := worker.Lag(ctx, installation); err != nil || lag.Pending != 1 || lag.Oldest <= 0 {
		t.Fatalf("lag with one Device due = %+v, %v", lag, err)
	}
	step, err := worker.Step(ctx, installation, 1)
	if err != nil || !step.Changed || step.Revoked != 1 {
		t.Fatalf("step with one Device due = %+v, %v", step, err)
	}
	if row := readIntegrationDevice(ctx, t, admin, device); row.state != "revoked" {
		t.Fatalf("due Device state %q after the worker", row.state)
	}
	var systemEvents int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event AS event
WHERE event.target_public_id = $1::UUID AND event.action = 'device.revoked'
  AND event.actor_principal_public_id IS NULL AND event.permission = 'system.reconcile'`,
		device.String()).Scan(&systemEvents); err != nil || systemEvents != 1 {
		t.Fatalf("worker evidence: %d device.revoked by the system, %v", systemEvents, err)
	}
	if step, err := worker.Step(ctx, installation, 1); err != nil || step.Changed {
		t.Fatalf("step after the removal = %+v, %v", step, err)
	}
	if lag, err := worker.Lag(ctx, installation); err != nil || lag.Pending != 0 {
		t.Fatalf("lag after the removal = %+v, %v", lag, err)
	}
}

// assertPostgreSQLSignedOutRemoval: removing a signed-out Device works and
// seals device.logged_out.
func assertPostgreSQLSignedOutRemoval(ctx context.Context, t *testing.T, admin *pgx.Conn,
	service *control.DeviceLogoutService) {
	t.Helper()
	device, machineKey, nodeKey := activeFixtureDeviceKeys(ctx, t, admin)
	machine, err := control.NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := service.Logout(ctx, machine, nodeKey, true, true); err != nil ||
		result.Outcome != control.LogoutSignedOut {
		t.Fatalf("sign out = %+v, %v", result, err)
	}
	removed, err := service.Logout(ctx, machine, nodeKey, true, false)
	if err != nil || removed.Outcome != control.LogoutRemoved {
		t.Fatalf("removing a signed-out Device = %+v, %v", removed, err)
	}
	if row := readIntegrationDevice(ctx, t, admin, device); row.state != "revoked" ||
		countDeviceAudit(ctx, t, admin, device, "device.logged_out") != 1 {
		t.Fatalf("signed-out Device after removal = %+v", row)
	}
}

// assertPostgreSQLExpiredDeviceLogout qualifies schema 282 (TD-CORE-145):
// an expired Device logs out with its current keys and is revoked, rather
// than refused while it keeps its address.
func assertPostgreSQLExpiredDeviceLogout(ctx context.Context, t *testing.T, admin *pgx.Conn,
	service *control.DeviceLogoutService) {
	t.Helper()
	device, machineKey, nodeKey := activeFixtureDeviceKeys(ctx, t, admin)
	version := readIntegrationDevice(ctx, t, admin, device).version
	networkRevision, _ := fixtureNetworkRevisions(ctx, t, admin)
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: "01890f01-0000-7000-8000-000000002821",
		eventPublicID:  "01890f02-0000-7000-8000-000000002821",
		outboxPublicID: "01890f03-0000-7000-8000-000000002821",
		streamID:       203, aggregateKind: "device", aggregatePublicID: device.String(),
		aggregateVersion: version + 1, networkRevision: networkRevision + 1,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "device.expiry.fixture", permission: "system.bootstrap",
		outboxEventClass: "device.expiry.fixture",
	}, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `UPDATE mesh.device
SET expires_at = GREATEST(created_at + INTERVAL '1 microsecond', pg_catalog.now() - INTERVAL '1 minute'),
    version = version + 1, updated_at = pg_catalog.now()
WHERE public_id = $1::UUID`, device.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT * FROM mesh_ops.set_network_scope(
'01890f00-0000-7000-8000-000000000103'::UUID,'01890f00-0000-7000-8000-000000000203'::UUID)`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT * FROM mesh_ops.advance_network_inventory_revision()`); err != nil {
			t.Fatal(err)
		}
	})
	machine, err := control.NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatal(err)
	}
	// A node key only named in the hello still logs out no expired Device.
	if _, err := service.Logout(ctx, machine, nodeKey, false, false); !errors.Is(err, control.ErrDeviceLogoutNotFound) {
		t.Fatalf("expired Device logout without a proven key: %v", err)
	}
	logout, err := service.Logout(ctx, machine, nodeKey, true, false)
	if err != nil || logout.DeviceID != device {
		t.Fatalf("expired Device logout = %+v, %v", logout, err)
	}
	if row := readIntegrationDevice(ctx, t, admin, device); row.state != "revoked" {
		t.Fatalf("expired Device state %q after logout", row.state)
	}
	if countDeviceAudit(ctx, t, admin, device, "device.logged_out") != 1 {
		t.Fatal("an expired Device's logout must seal exactly one device.logged_out")
	}
}
