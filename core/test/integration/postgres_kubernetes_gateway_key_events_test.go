//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
)

// gatewayKeyFingerprints reads the current machine key fingerprint of a
// gateway Device and one it retired.
func gatewayKeyFingerprints(ctx context.Context, t *testing.T, admin *pgx.Conn, deviceID string) (current,
	retired [32]byte) {
	t.Helper()
	var currentBytes, retiredBytes []byte
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT machine.fingerprint FROM mesh.device_machine_key_epoch AS machine
     WHERE machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch),
    (SELECT history.fingerprint FROM mesh_ops.kubernetes_gateway_machine_key_history AS history
     WHERE history.device_id = device.id AND history.retired_at IS NOT NULL
     ORDER BY history.retired_at LIMIT 1)
FROM mesh.device AS device WHERE device.public_id = $1::UUID`, deviceID).Scan(&currentBytes,
		&retiredBytes); err != nil || len(currentBytes) != 32 || len(retiredBytes) != 32 {
		t.Fatalf("gateway key fingerprints = %x, %x, %v", currentBytes, retiredBytes, err)
	}
	return [32]byte(currentBytes), [32]byte(retiredBytes)
}

// assertGatewayKeyEvents qualifies schema 229 on a joined gateway whose
// machine key rotated once: reports become sealed Network events bound to
// the gateway Device, limited per key, per (Device, action) and held back
// while another report of the gateway holds its lock; the cluster's read
// sums them for its administrators.
func assertGatewayKeyEvents(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool,
	service *kubecluster.Service, owner accountsession.Session, scope network.Scope, clusterID kubecluster.ID,
	deviceID string) {
	t.Helper()
	store, err := postgresadapter.NewKubernetesGatewayKeyEventStore(runtimePool)
	if err != nil {
		t.Fatal(err)
	}
	current, retired := gatewayKeyFingerprints(ctx, t, admin, deviceID)
	record := func(machine [32]byte, reason kubecluster.KeyEventReason, suppressed int,
		want kubecluster.KeyEventOutcome) {
		t.Helper()
		if outcome, err := store.Record(ctx, machine, reason, suppressed, ""); err != nil || outcome != want {
			t.Fatalf("Record(%x, %s) = %v, %v; want %v", machine[:4], reason, outcome, err, want)
		}
	}
	record(retired, kubecluster.KeyEventRetiredMachineKey, 0, kubecluster.KeyEventRecorded)
	// The same key and reason within ten minutes is limited.
	record(retired, kubecluster.KeyEventRetiredMachineKey, 0, kubecluster.KeyEventLimited)
	record(current, kubecluster.KeyEventStaleNodeKey, 3, kubecluster.KeyEventRecorded)
	record(current, kubecluster.KeyEventSessionFight, 0, kubecluster.KeyEventRecorded)
	// A key no gateway held, and an ordinary Device's key, are unknown.
	var unknown [32]byte
	if _, err := rand.Read(unknown[:]); err != nil {
		t.Fatal(err)
	}
	record(unknown, kubecluster.KeyEventRetiredMachineKey, 0, kubecluster.KeyEventNotGateway)
	var ordinary []byte
	if err := admin.QueryRow(ctx, `SELECT machine.fingerprint FROM mesh.device_machine_key_epoch AS machine
JOIN mesh.device AS device ON device.id = machine.device_id
WHERE device.kind <> 'kubernetes_gateway' ORDER BY machine.id LIMIT 1`).Scan(&ordinary); err != nil {
		t.Fatal(err)
	}
	record([32]byte(ordinary), kubecluster.KeyEventRetiredMachineKey, 0, kubecluster.KeyEventNotGateway)

	// Sealed events on the Network's stream, naming the Device and how its
	// key stands, never an address.
	rows, err := admin.Query(ctx, `SELECT event.action, event.payload::TEXT
FROM mesh_audit.audit_event AS event
WHERE event.target_kind = 'kubernetes_gateway_key_event' AND event.payload ->> 'device_id' = $1
ORDER BY event.event_identity_id`, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	var actions, payloads []string
	for rows.Next() {
		var action, payload string
		if err := rows.Scan(&action, &payload); err != nil {
			t.Fatal(err)
		}
		actions, payloads = append(actions, action), append(payloads, payload)
	}
	rows.Close()
	if len(actions) != 3 || actions[0] != "kubernetes_gateway.stale_key_presented" ||
		actions[2] != "kubernetes_gateway.keys_contested" ||
		!strings.Contains(payloads[0], `"key_state": "rotated"`) ||
		!strings.Contains(payloads[1], `"key_state": "current"`) || !strings.Contains(payloads[1], `"suppressed": 3`) ||
		!strings.Contains(payloads[0], `"cluster_id": "`+clusterID.String()+`"`) ||
		strings.Contains(strings.Join(payloads, ""), "address") {
		t.Fatalf("key events %v: %v", actions, payloads)
	}
	var outbox int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event
WHERE event_class LIKE 'kubernetes_gateway.%' AND payload ->> 'device_id' = $1`, deviceID).Scan(&outbox); err != nil ||
		outbox != 3 {
		t.Fatalf("outbox rows %d, %v", outbox, err)
	}

	// The cluster's read sums them for its administrators.
	detail, err := service.Read(ctx, owner, scope, clusterID)
	if err != nil || detail.KeyWarnings == nil || len(detail.KeyWarnings.Devices) != 1 ||
		detail.KeyWarnings.Truncated {
		t.Fatalf("Read() warnings = %+v, %v", detail.KeyWarnings, err)
	}
	warning := detail.KeyWarnings.Devices[0]
	if warning.DeviceID.String() != deviceID || warning.Last24h != 3 || warning.Last7Days != 3 ||
		warning.LastReason != kubecluster.KeyEventSessionFight || warning.KeyState != kubecluster.ReportedKeyCurrent {
		t.Fatalf("warning = %+v", warning)
	}

	// A report that waits on another report of the gateway gives way.
	held, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := held.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('meshtransit/gateway-key-event/' || $1, 0))`, deviceID); err != nil {
		t.Fatal(err)
	}
	record(current, kubecluster.KeyEventReplayedHandshake, 0, kubecluster.KeyEventBusy)
	if err := held.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// Stale keys spend their own daily budget: contested keys still record.
	if _, err := admin.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO mesh_ops.kubernetes_gateway_key_event (public_id, workspace_id, network_id,
    kubernetes_cluster_id, device_id, device_public_id, hostname, action, reason, machine_key_fingerprint, key_state,
    suppressed, network_revision, recorded_at)
SELECT pg_catalog.uuidv7(), device.workspace_id, device.network_id, device.kubernetes_cluster_id, device.id,
    device.public_id, device.hostname, 'kubernetes_gateway.stale_key_presented', 'retired_machine_key',
    pg_catalog.sha256(pg_catalog.convert_to(sequence.n::TEXT, 'UTF8')), 'rotated', 0, 1,
    pg_catalog.now() - INTERVAL '1 hour'
FROM mesh.device AS device CROSS JOIN pg_catalog.generate_series(1, 144) AS sequence (n)
WHERE device.public_id = $1::UUID`, deviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `SET session_replication_role = origin`); err != nil {
		t.Fatal(err)
	}
	record(retired, kubecluster.KeyEventStaleNodeKey, 0, kubecluster.KeyEventLimited)
	record(current, kubecluster.KeyEventReplayedHandshake, 0, kubecluster.KeyEventRecorded)
}

// assertRemovedGatewayKeyEvent: a removed gateway's old key still binds to
// its own Device, as removed.
func assertRemovedGatewayKeyEvent(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, deviceID string) {
	t.Helper()
	store, err := postgresadapter.NewKubernetesGatewayKeyEventStore(runtimePool)
	if err != nil {
		t.Fatal(err)
	}
	current, _ := gatewayKeyFingerprints(ctx, t, admin, deviceID)
	// Start from no recent events: the earlier fixture spent the budgets.
	if _, err := admin.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `DELETE FROM mesh_ops.kubernetes_gateway_key_event
WHERE device_public_id = $1::UUID`, deviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `SET session_replication_role = origin`); err != nil {
		t.Fatal(err)
	}
	if outcome, err := store.Record(ctx, current, kubecluster.KeyEventRetiredMachineKey, 0, ""); err != nil ||
		outcome != kubecluster.KeyEventRecorded {
		t.Fatalf("removed gateway's report = %v, %v", outcome, err)
	}
	var state string
	if err := admin.QueryRow(ctx, `SELECT event.key_state FROM mesh_ops.kubernetes_gateway_key_event AS event
WHERE event.device_public_id = $1::UUID ORDER BY event.recorded_at DESC, event.id DESC LIMIT 1`,
		deviceID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "device_removed" {
		t.Fatalf("removed gateway's key state %q", state)
	}
}
