//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

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
	runtimePool *postgresadapter.Pool) {
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
	if _, err := service.Logout(ctx, machine, otherKey); !errors.Is(err, control.ErrDeviceLogoutNotFound) {
		t.Fatalf("logout with another node key: %v", err)
	}
	networkBefore, groupBefore := fixtureNetworkRevisions(ctx, t, admin)
	logout, err := service.Logout(ctx, machine, nodeKey)
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
	// A logged-out Device cannot log out again or open a map.
	if _, err := service.Logout(ctx, machine, nodeKey); !errors.Is(err, control.ErrDeviceLogoutNotFound) {
		t.Fatalf("second logout: %v", err)
	}
}
