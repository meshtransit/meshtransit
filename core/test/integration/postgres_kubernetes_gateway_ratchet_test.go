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
	"meshtransit.net/core/internal/domain/kubecluster"
)

// assertGatewayTokenRatchet checks schema 246 against a live gateway Device
// whose handshake timestamp stands at 2,000: the ratchet is read with the
// timestamp, written with it one Device at a time, and refuses sessions
// without a token once written; session refusals are their own audit
// action.
func assertGatewayTokenRatchet(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn,
	runtimePool *postgresadapter.Pool, keys replicaKeys, deviceID string,
) {
	t.Helper()
	store, err := postgresadapter.NewMTCPTimestampStore(runtimePool)
	if err != nil {
		t.Fatal(err)
	}
	if granted, err := store.GatewayTokensGranted(ctx); err != nil || !granted {
		t.Fatalf("GatewayTokensGranted() = %t, %v", granted, err)
	}
	machine := keys.machine.Fingerprint()
	nodeKey := keys.node.Bytes()
	other := newReplicaKeys(t).node.Bytes()
	accept := func(timestamp int64) postgresadapter.MTCPTimestampCheck {
		t.Helper()
		check, err := store.AcceptTimestampV3(ctx, machine, nodeKey[:], timestamp)
		if err != nil || !check.Gateway || check.MachineState != "current" || !check.NodeCurrent {
			t.Fatalf("AcceptTimestampV3(%d) = %+v, %v", timestamp, check, err)
		}
		return check
	}
	commit := func(node []byte, timestamp int64, proven bool, mode kubecluster.GatewayTokenMode,
		want kubecluster.GatewayTimestampResult, ratcheted bool,
	) {
		t.Helper()
		got, err := store.CommitGatewayTimestampV2(ctx, machine, node, timestamp, proven, mode)
		if err != nil || got.Result != want || got.Ratcheted != ratcheted {
			t.Fatalf("CommitGatewayTimestampV2(%d, %t, %s) = %+v, %v; want %s %t", timestamp, proven, mode, got,
				err, want, ratcheted)
		}
	}
	stored := func() int64 {
		t.Helper()
		var timestamp int64
		if err := admin.QueryRow(ctx, `SELECT last_timestamp_ms FROM mesh_ops.mtcp_machine_timestamp
WHERE machine_fingerprint = $1`, machine[:]).Scan(&timestamp); err != nil {
			t.Fatal(err)
		}
		return timestamp
	}
	proofs := func() int {
		t.Helper()
		var rows int
		if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_token_proof
WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID)`, deviceID).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}

	if accept(3_000).TokenRatcheted || proofs() != 0 {
		t.Fatal("a gateway is ratcheted before any token")
	}
	// Without a token and not ratcheted: ratchet goes on, required refuses
	// and writes nothing.
	commit(nodeKey[:], 3_000, false, kubecluster.GatewayTokenRatchet, kubecluster.GatewayTimestampCommitted, false)
	commit(nodeKey[:], 3_001, false, kubecluster.GatewayTokenRequired, kubecluster.GatewayTimestampTokenRequired,
		false)
	commit(other[:], 3_002, true, kubecluster.GatewayTokenRatchet, kubecluster.GatewayTimestampNotCommitted, false)
	commit(nodeKey[:], 3_000, true, kubecluster.GatewayTokenRatchet, kubecluster.GatewayTimestampNotCommitted, false)
	if stored() != 3_000 || proofs() != 0 {
		t.Fatalf("timestamp %d, proofs %d after refused commits", stored(), proofs())
	}
	if _, err := store.CommitGatewayTimestampV2(ctx, machine, nodeKey[:], 3_003, true, "enforce"); !errors.Is(err,
		postgresadapter.ErrMTCPTimestamp) {
		t.Fatalf("an unknown mode: %v", err)
	}
	var pgError *pgconn.PgError
	if _, err := runtime.Exec(ctx, `SELECT * FROM mesh_ops.commit_mtcp_gateway_timestamp_v2($1, $2, 3003, TRUE, 'off')`,
		machine[:], nodeKey[:]); !errors.As(err, &pgError) || pgError.Code != "22023" {
		t.Fatalf("the database took an unknown mode: %v", err)
	}

	// Two replicas: one ratchets in a transaction still open while the
	// other commits a session without a token. The second waits for the
	// Device's lock and then sees the ratchet.
	transaction, err := runtime.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var result string
	var ratcheted bool
	if err := transaction.QueryRow(ctx, `SELECT result, ratcheted
FROM mesh_ops.commit_mtcp_gateway_timestamp_v2($1, $2, 4000, TRUE, 'ratchet')`, machine[:], nodeKey[:]).Scan(&result,
		&ratcheted); err != nil || result != "committed" || !ratcheted {
		t.Fatalf("the proven commit = %s %t, %v", result, ratcheted, err)
	}
	raced := make(chan postgresadapter.GatewayTimestampCommit, 1)
	racedErr := make(chan error, 1)
	go func() {
		got, err := store.CommitGatewayTimestampV2(ctx, machine, nodeKey[:], 4_001, false,
			kubecluster.GatewayTokenRatchet)
		raced <- got
		racedErr <- err
	}()
	// The second must be waiting on the Device's lock before the first
	// commits, or the case would not test the race (t1 review M1).
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM pg_catalog.pg_stat_activity
WHERE wait_event_type = 'Lock' AND wait_event = 'advisory'
  AND query LIKE '%commit_mtcp_gateway_timestamp_v2%'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the racing commit never waited on the Device's lock (%d waiting)", waiting)
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case got := <-raced:
		t.Fatalf("the racing commit returned before the lock was released: %+v", got)
	default:
	}
	if err := transaction.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := <-raced, <-racedErr; err != nil || got.Result != kubecluster.GatewayTimestampTokenRequired ||
		!got.Ratcheted {
		t.Fatalf("the racing session without a token = %+v, %v", got, err)
	}
	if stored() != 4_000 || proofs() != 1 || !accept(5_000).TokenRatcheted {
		t.Fatalf("after the race: timestamp %d, proofs %d", stored(), proofs())
	}

	// Ratcheted: ratchet and required refuse a session without a token,
	// observe lets it through; a proven one commits without a second row.
	commit(nodeKey[:], 5_000, false, kubecluster.GatewayTokenRatchet, kubecluster.GatewayTimestampTokenRequired, true)
	commit(nodeKey[:], 5_000, false, kubecluster.GatewayTokenRequired, kubecluster.GatewayTimestampTokenRequired,
		true)
	commit(nodeKey[:], 5_000, false, kubecluster.GatewayTokenObserve, kubecluster.GatewayTimestampCommitted, true)
	commit(nodeKey[:], 6_000, true, kubecluster.GatewayTokenRatchet, kubecluster.GatewayTimestampCommitted, true)
	if stored() != 6_000 || proofs() != 1 {
		t.Fatalf("timestamp %d, proofs %d after ratcheted commits", stored(), proofs())
	}

	// At join: only the Device holding both keys, once.
	if ok, err := store.RatchetGatewayToken(ctx, machine, other[:]); err != nil || ok {
		t.Fatalf("RatchetGatewayToken(other node key) = %t, %v", ok, err)
	}
	if ok, err := store.RatchetGatewayToken(ctx, machine, nodeKey[:]); err != nil || !ok || proofs() != 1 {
		t.Fatalf("RatchetGatewayToken() = %t, %v; proofs %d", ok, err, proofs())
	}

	// A Device's lock held past 2 s: the commit fails instead of waiting.
	holder, err := runtime.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, `SELECT mesh_ops.ratchet_kubernetes_gateway_token_v1($1, $2)`, machine[:],
		nodeKey[:]); err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now()
	_, err = store.CommitGatewayTimestampV2(ctx, machine, nodeKey[:], 7_000, true, kubecluster.GatewayTokenRatchet)
	waited := time.Since(startedAt)
	if rollbackErr := holder.Rollback(ctx); rollbackErr != nil {
		t.Fatal(rollbackErr)
	}
	if !errors.Is(err, postgresadapter.ErrMTCPTimestamp) || waited < 1500*time.Millisecond || waited > 10*time.Second {
		t.Fatalf("a commit behind a held lock = %v after %v", err, waited)
	}

	// The table is the functions' alone.
	if _, err := runtime.Exec(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_token_proof`); !errors.As(
		err, &pgError) || pgError.Code != "42501" {
		t.Fatalf("the runtime role read the ratchet table: %v", err)
	}
	if _, err := runtime.Exec(ctx, `SELECT mesh_ops.lock_current_kubernetes_gateway_internal_v1($1, $2)`, machine[:],
		nodeKey[:]); !errors.As(err, &pgError) || pgError.Code != "42501" {
		t.Fatalf("the runtime role called the lock helper: %v", err)
	}
	// Older Core's v2 read and v1 commit still answer.
	var accepted bool
	if err := runtime.QueryRow(ctx, `SELECT accepted FROM mesh_ops.accept_mtcp_timestamp_v2($1, $2, 8000)`,
		machine[:], nodeKey[:]).Scan(&accepted); err != nil || !accepted {
		t.Fatalf("v2 = %t, %v", accepted, err)
	}

	assertGatewaySessionTokenEvents(ctx, t, admin, runtimePool, machine, deviceID)
}

// assertGatewaySessionTokenEvents: a session refusal is
// kubernetes_gateway.session_token_refused, a kid only with a key the
// trust lacks.
func assertGatewaySessionTokenEvents(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, machine [32]byte, deviceID string,
) {
	t.Helper()
	events, err := postgresadapter.NewKubernetesGatewayKeyEventStore(runtimePool)
	if err != nil {
		t.Fatal(err)
	}
	for _, report := range []struct {
		reason kubecluster.KeyEventReason
		kid    string
		want   kubecluster.KeyEventOutcome
	}{
		{kubecluster.KeyEventSessionTokenMissing, "", kubecluster.KeyEventRecorded},
		{kubecluster.KeyEventSessionTokenMissing, "", kubecluster.KeyEventLimited},
		{kubecluster.KeyEventSessionClockSkew, "", kubecluster.KeyEventRecorded},
		{kubecluster.KeyEventSessionTokenUnknownKey, "k1c-t-kid", kubecluster.KeyEventRecorded},
	} {
		if outcome, err := events.Record(ctx, machine, report.reason, 0, report.kid); err != nil ||
			outcome != report.want {
			t.Fatalf("Record(%s) = %v, %v; want %v", report.reason, outcome, err, report.want)
		}
	}
	if _, err := events.Record(ctx, machine, kubecluster.KeyEventSessionTokenMissing, 0, "k1c-t-kid"); !errors.Is(err,
		postgresadapter.ErrInvalidKubernetesGatewayKeyEventStore) {
		t.Fatalf("a kid with session_token_missing: %v", err)
	}
	var sealed, kids int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_audit.audit_event AS event
WHERE event.target_kind = 'kubernetes_gateway_key_event' AND event.payload ->> 'device_id' = $1
  AND event.action = 'kubernetes_gateway.session_token_refused'`, deviceID).Scan(&sealed); err != nil || sealed != 3 {
		t.Fatalf("sealed session token events = %d, %v", sealed, err)
	}
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_key_event
WHERE device_public_id = $1::UUID AND token_kid = 'k1c-t-kid' AND reason = 'session_token_unknown_key'`,
		deviceID).Scan(&kids); err != nil || kids != 1 {
		t.Fatalf("session events naming a kid = %d, %v", kids, err)
	}
	// The table refuses a session reason under another action.
	var pgError *pgconn.PgError
	if _, err := admin.Exec(ctx, `UPDATE mesh_ops.kubernetes_gateway_key_event
SET action = 'kubernetes_gateway.rotation_token_refused'
WHERE device_public_id = $1::UUID AND reason = 'session_clock_skew'`, deviceID); !errors.As(err, &pgError) ||
		pgError.Code != "23514" {
		t.Fatalf("a session reason under the rotation action: %v", err)
	}
}
