//go:build integration

package integration

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
)

// assertGatewaySessionProof checks schema 226 against a live gateway Device:
// every path that resolves a session to it needs the node key marked proven
// in the same transaction, it cannot log out, its timestamp is written only
// after the proof, and its machine key is in the history.
func assertGatewaySessionProof(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn,
	runtimePool *postgresadapter.Pool, keys replicaKeys, deviceID string) {
	t.Helper()
	assertGatewayLogoutThroughCore(ctx, t, runtimePool, keys)
	assertGatewayMapThroughCore(ctx, t, runtimePool, keys)
	machine := keys.machine.Fingerprint()
	machineKey := keys.machine.Bytes()
	nodeKey := keys.node.Bytes()
	other := newReplicaKeys(t).node.Bytes()

	resolves := func(setup string, args ...any) bool {
		t.Helper()
		tx, err := runtime.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if setup != "" {
			if _, err := tx.Exec(ctx, setup, args...); err != nil {
				t.Fatalf("%s: %v", setup, err)
			}
		}
		var rows int
		if err := tx.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.resolve_map_session_scope($1, $2)`,
			machine[:], nodeKey[:]).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		return rows == 1
	}
	if resolves("") {
		t.Fatal("a gateway resolved without a proof")
	}
	if resolves(`SELECT mesh_ops.mark_session_proven_v1($1, $2)`, machine[:], other[:]) {
		t.Fatal("a gateway resolved with another key proven")
	}
	if resolves(`SELECT pg_catalog.set_config('mesh.session_proven_node_key', $1, TRUE)`,
		hex.EncodeToString(nodeKey[:])) {
		t.Fatal("a gateway resolved with a marker not bound to the transaction")
	}
	if resolves(`SELECT pg_catalog.set_config('mesh.session_proven_node_key', '', TRUE)`) {
		t.Fatal("a gateway resolved with an empty marker")
	}
	if !resolves(`SELECT mesh_ops.mark_session_proven_v1($1, $2)`, machine[:], nodeKey[:]) {
		t.Fatal("a gateway did not resolve with its node key proven")
	}
	unrelated := newReplicaKeys(t).machine.Fingerprint()
	if resolves(`SELECT mesh_ops.mark_session_proven_v1($1, $2)`, unrelated[:], nodeKey[:]) {
		t.Fatal("a gateway resolved with its node key proven for another machine key")
	}
	// A marker from an earlier transaction on the same connection is gone.
	earlier, err := runtime.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := earlier.Exec(ctx, `SELECT mesh_ops.mark_session_proven_v1($1, $2)`, machine[:], nodeKey[:]); err != nil {
		t.Fatal(err)
	}
	if err := earlier.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if resolves("") {
		t.Fatal("a marker outlived its transaction")
	}

	// Older Core's rotation and logout are closed too.
	var rotation int
	if err := runtime.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.resolve_node_key_rotation_scope($1, $2, $3, $4)`, machine[:], machineKey[:], nodeKey[:],
		other[:]).Scan(&rotation); err != nil || rotation != 0 {
		t.Fatalf("an unproven gateway resolved a rotation: %d, %v", rotation, err)
	}
	// New Core rotates a proven gateway: the mark must name the current key.
	rotates := func(proven []byte) bool {
		t.Helper()
		tx, err := runtime.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT mesh_ops.mark_session_proven_v1($1, $2)`, machine[:], proven); err != nil {
			t.Fatal(err)
		}
		var rows int
		if err := tx.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.resolve_node_key_rotation_scope($1, $2, $3, $4)`, machine[:], machineKey[:], nodeKey[:],
			other[:]).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		return rows == 1
	}
	if !rotates(nodeKey[:]) || rotates(other[:]) {
		t.Fatal("rotation scope does not follow the proven current node key")
	}
	assertGatewayLogoutRefused(ctx, t, runtime, machine[:], nodeKey[:])

	// Timestamps: compared before the proof, written only after it.
	check := func(node []byte, timestamp int64) (bool, bool, string, bool) {
		t.Helper()
		var accepted, gateway, current bool
		var state string
		if err := runtime.QueryRow(ctx, `SELECT accepted, gateway, machine_state, node_current
FROM mesh_ops.accept_mtcp_timestamp_v2($1, $2, $3)`, machine[:], node, timestamp).Scan(&accepted, &gateway,
			&state, &current); err != nil {
			t.Fatal(err)
		}
		return accepted, gateway, state, current
	}
	if accepted, gateway, state, current := check(nodeKey[:], 1_000); !accepted || !gateway || state != "current" ||
		!current {
		t.Fatalf("v2 = %t %t %s %t", accepted, gateway, state, current)
	}
	if _, _, _, current := check(other[:], 1_001); current {
		t.Fatal("another node key is current")
	}
	var stored int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.mtcp_machine_timestamp
WHERE machine_fingerprint = $1`, machine[:]).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("a gateway timestamp was written before the proof: %d, %v", stored, err)
	}
	commit := func(node []byte, timestamp int64) bool {
		t.Helper()
		var ok bool
		if err := runtime.QueryRow(ctx, `SELECT mesh_ops.commit_mtcp_gateway_timestamp_v1($1, $2, $3)`,
			machine[:], node, timestamp).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if commit(other[:], 2_000) || !commit(nodeKey[:], 2_000) || commit(nodeKey[:], 2_000) {
		t.Fatal("gateway timestamps are not compare-and-set on the current keys")
	}
	if accepted, _, _, _ := check(nodeKey[:], 2_000); accepted {
		t.Fatal("a replayed gateway timestamp was accepted")
	}
	unknown := newReplicaKeys(t)
	unknownFingerprint := unknown.machine.Fingerprint()
	var accepted, gateway, current bool
	var state string
	if err := runtime.QueryRow(ctx, `SELECT accepted, gateway, machine_state, node_current
FROM mesh_ops.accept_mtcp_timestamp_v2($1, $2, $3)`, unknownFingerprint[:], nodeKey[:], int64(5)).Scan(&accepted,
		&gateway, &state, &current); err != nil || !accepted || gateway || state != "unbound" || current {
		t.Fatalf("unknown machine key = %t %t %s %t, %v", accepted, gateway, state, current, err)
	}

	var history int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_machine_key_history
WHERE fingerprint = $1 AND device_id = (SELECT id FROM mesh.device WHERE public_id = $2::UUID)
  AND retired_at IS NULL`, machine[:], deviceID).Scan(&history); err != nil || history != 1 {
		t.Fatalf("gateway machine key history = %d, %v", history, err)
	}
}

func assertGatewayLogoutRefused(ctx context.Context, t *testing.T, runtime *pgx.Conn, machine, nodeKey []byte) {
	t.Helper()
	tx, err := runtime.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT mesh_ops.mark_session_proven_v1($1, $2)`, machine, nodeKey); err != nil {
		t.Fatal(err)
	}
	var workspaceID, networkID string
	if err := tx.QueryRow(ctx, `SELECT workspace_public_id::TEXT, network_public_id::TEXT
FROM mesh_ops.resolve_map_session_scope($1, $2)`, machine, nodeKey).Scan(&workspaceID, &networkID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT mesh_ops.set_network_scope($1::UUID, $2::UUID)`, workspaceID,
		networkID); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `SELECT mesh_ops.logout_device_v1($1, $2, pg_catalog.uuidv7(), pg_catalog.now())`,
		machine, nodeKey)
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != "MTK11" {
		t.Fatalf("a gateway logged out: %v", err)
	}
}

// Core's logout path: an unproven session does not find the gateway, a
// proven one is refused.
func assertGatewayLogoutThroughCore(ctx context.Context, t *testing.T, runtimePool *postgresadapter.Pool,
	keys replicaKeys) {
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
	machine, err := control.NewAuthenticatedMachine(keys.machine)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Logout(ctx, machine, keys.node); !errors.Is(err, control.ErrDeviceLogoutNotFound) {
		t.Fatalf("an unproven session found the gateway to log out: %v", err)
	}
	if _, err := service.Logout(ctx, machine.WithProvenNodeKey(keys.node), keys.node); !errors.Is(err,
		control.ErrDeviceLogoutNotPermitted) {
		t.Fatalf("a proven gateway session logged out: %v", err)
	}
}

// assertRetiredGatewayKey: once its Device is gone, a gateway's machine key
// is a retired gateway key to every handshake.
func assertRetiredGatewayKey(ctx context.Context, t *testing.T, runtime *pgx.Conn, keys replicaKeys) {
	t.Helper()
	machine := keys.machine.Fingerprint()
	nodeKey := keys.node.Bytes()
	var accepted, gateway, current bool
	var state string
	if err := runtime.QueryRow(ctx, `SELECT accepted, gateway, machine_state, node_current
FROM mesh_ops.accept_mtcp_timestamp_v2($1, $2, $3)`, machine[:], nodeKey[:], int64(9_000)).Scan(&accepted,
		&gateway, &state, &current); err != nil || !gateway || state != "retired" || current {
		t.Fatalf("removed gateway's key = %t %t %s %t, %v", accepted, gateway, state, current, err)
	}
}

// Core's map path serves a gateway to a session that proved its node key,
// and to no other.
func assertGatewayMapThroughCore(ctx context.Context, t *testing.T, runtimePool *postgresadapter.Pool,
	keys replicaKeys) {
	t.Helper()
	store, err := postgresadapter.NewMapSessionStore(runtimePool, postgresadapter.MapSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
		PeerCandidateLimit: mapsession.MaximumPeerCandidates, PolicyRuleLimit: mapsession.MaximumPacketPolicyRules,
		RelayDirectory: integrationRelayDirectory(t), RoutePeerLimit: mapsession.DefaultPeerLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	machine, err := control.NewAuthenticatedMachine(keys.machine)
	if err != nil {
		t.Fatal(err)
	}
	unproven, err := machine.BindNodeKey(keys.node)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx, unproven); err == nil {
		t.Fatal("an unproven session loaded the gateway's map")
	}
	proven, err := machine.WithProvenNodeKey(keys.node).BindNodeKey(keys.node)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Load(ctx, proven)
	if err != nil || snapshot.NodeKey() != keys.node {
		t.Fatalf("a proven gateway session = %v, %v", snapshot.NodeKey(), err)
	}
}
