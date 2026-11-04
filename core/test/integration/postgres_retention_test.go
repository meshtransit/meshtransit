//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
)

// assertRetention qualifies schema 274 on the rows earlier fixtures wrote:
// the worker's retention functions remove exactly what is past its time,
// keep what an idempotency record still answers with, record each pass,
// drop Activity months past twelve, and nothing else may delete evidence.
func assertRetention(ctx context.Context, t *testing.T, admin *pgx.Conn, workerPool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewRetentionStore(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	passCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	// Three pending events nothing answers with: one finished ten days ago
	// with an attempt, one two days ago, one forty days ago as terminal.
	rows, err := admin.Query(ctx, `SELECT event.id FROM mesh_ops.outbox_event AS event
WHERE event.state = 'pending' AND NOT EXISTS (
    SELECT 1 FROM mesh_ops.idempotency_record AS record WHERE record.outbox_public_id = event.public_id)
ORDER BY event.id LIMIT 3`)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil || len(ids) != 3 {
		t.Fatalf("pending outbox events for retention = %v, %v; want 3", ids, err)
	}
	old, recent, failed := ids[0], ids[1], ids[2]
	finish := func(id int64, state string, ago string) {
		t.Helper()
		if _, err := admin.Exec(ctx, `UPDATE mesh_ops.outbox_event SET state = $2,
    claim_token = pg_catalog.uuidv7(), claimed_by = 'retention-test',
    claimed_at = pg_catalog.now() - $3::INTERVAL - INTERVAL '1 minute',
    claim_expires_at = pg_catalog.now() - $3::INTERVAL + INTERVAL '1 minute',
    completed_at = pg_catalog.now() - $3::INTERVAL,
    last_error_class = CASE WHEN $2 = 'terminal' THEN 'retention_test' END
WHERE id = $1`, id, state, ago); err != nil {
			t.Fatal(err)
		}
	}
	finish(old, "delivered", "10 days")
	finish(recent, "delivered", "2 days")
	finish(failed, "terminal", "40 days")
	// A retried event is pending again with attempts of its own: this one
	// follows them.
	if _, err := admin.Exec(ctx, `INSERT INTO mesh_ops.outbox_attempt
    (outbox_event_id, attempt_number, worker_id, started_at, finished_at, result)
SELECT $1, COALESCE(pg_catalog.max(attempt_number), 0) + 1, 'retention-test',
    pg_catalog.now() - INTERVAL '10 days 1 minute', pg_catalog.now() - INTERVAL '10 days', 'delivered'
FROM mesh_ops.outbox_attempt WHERE outbox_event_id = $1`, old); err != nil {
		t.Fatal(err)
	}
	var attempts int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.outbox_attempt
WHERE outbox_event_id = ANY($1::BIGINT[])`, []int64{old, failed}).Scan(&attempts); err != nil {
		t.Fatal(err)
	}

	// An event an idempotency record answers with stays even when old.
	var answered int64
	if err := admin.QueryRow(ctx, `SELECT event.id FROM mesh_ops.outbox_event AS event
JOIN mesh_ops.idempotency_record AS record ON record.outbox_public_id = event.public_id
WHERE event.state = 'pending' ORDER BY event.id LIMIT 1`).Scan(&answered); err != nil {
		t.Fatalf("an outbox event an idempotency record answers with: %v", err)
	}
	finish(answered, "delivered", "10 days")

	// Nobody but mesh_retention deletes evidence, and nobody updates it:
	// not the migrator login with the purge mark set by itself, not the
	// worker, not a superuser.
	for _, attempt := range []struct {
		role, statement, code string
	}{
		{"mesh_migrator", `DELETE FROM mesh_ops.outbox_attempt WHERE outbox_event_id = $1`, "23514"},
		{"mesh_migrator", `UPDATE mesh_ops.outbox_attempt SET worker_id = 'changed' WHERE outbox_event_id = $1`, "23514"},
		{"mesh_worker", `DELETE FROM mesh_ops.outbox_attempt WHERE outbox_event_id = $1`, "42501"},
		{"", `DELETE FROM mesh_ops.outbox_attempt WHERE outbox_event_id = $1`, "23514"},
	} {
		transaction, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if attempt.role != "" {
			if _, err := transaction.Exec(ctx, `SET LOCAL ROLE `+attempt.role); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := transaction.Exec(ctx, `SELECT pg_catalog.set_config('mesh.retention_purge', 'on', TRUE)`); err != nil {
			t.Fatal(err)
		}
		_, err = transaction.Exec(ctx, attempt.statement, old)
		assertPostgreSQLCode(t, err, attempt.code)
		_ = transaction.Rollback(ctx)
	}
	for _, call := range []string{
		`SELECT mesh_ops.prune_outbox_events_v1(7, 30, 10)`,
		`SELECT mesh_ops.prune_idempotency_records_v1(86400, 10)`,
		`SELECT mesh_ops.drop_audit_event_partitions_v1(12)`,
		`SELECT mesh_ops.prune_audit_rows_v1(12, 10)`,
	} {
		runtime, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runtime.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
			t.Fatal(err)
		}
		_, err = runtime.Exec(ctx, call)
		assertPostgreSQLCode(t, err, "42501")
		_ = runtime.Rollback(ctx)
	}

	removed, err := store.PruneOutbox(passCtx, 7, 30, 1000)
	if err != nil || removed.Events != 2 || removed.Attempts != attempts {
		t.Fatalf("outbox retention = %+v, %v; want the old delivered and the old terminal event, %d attempts",
			removed, err, attempts)
	}
	var left int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event
WHERE id = ANY($1::BIGINT[])`, []int64{old, recent, failed, answered}).Scan(&left); err != nil || left != 2 {
		t.Fatalf("outbox events left = %d, %v; want the recent one and the answered one", left, err)
	}
	if removed, err := store.PruneOutbox(passCtx, 7, 30, 1000); err != nil || removed.Events != 0 {
		t.Fatalf("repeat outbox retention = %+v, %v; want nothing", removed, err)
	}

	// An idempotency record past expiry by more than a day goes; then the
	// event it answered with is free to go too.
	// The record's own trigger forbids moving its times; the fixture ages it
	// with triggers off for this one transaction.
	aging, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aging.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := aging.Exec(ctx, `UPDATE mesh_ops.idempotency_record SET
    created_at = created_at - INTERVAL '30 days', updated_at = updated_at - INTERVAL '30 days',
    completed_at = completed_at - INTERVAL '30 days', expires_at = expires_at - INTERVAL '30 days'
WHERE outbox_public_id = (SELECT public_id FROM mesh_ops.outbox_event WHERE id = $1)`, answered); err != nil {
		t.Fatal(err)
	}
	if err := aging.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if records, err := store.PruneIdempotency(passCtx, 24*time.Hour, 1000); err != nil || records < 1 {
		t.Fatalf("idempotency retention = %d, %v; want at least the aged record", records, err)
	}
	if removed, err := store.PruneOutbox(passCtx, 7, 30, 1000); err != nil || removed.Events != 1 {
		t.Fatalf("outbox retention after its record = %+v, %v; want the answered event", removed, err)
	}

	// An Activity month fourteen months back is dropped; this year's stay.
	var month string
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.to_char(pg_catalog.date_trunc('month',
    pg_catalog.now() AT TIME ZONE 'UTC') - INTERVAL '14 months', 'YYYY_MM')`).Scan(&month); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `SELECT mesh_ops.ensure_audit_event_partitions_v1(1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `CREATE TABLE mesh_audit.audit_event_`+month+` PARTITION OF mesh_audit.audit_event
FOR VALUES FROM (pg_catalog.to_date('`+month+`', 'YYYY_MM')::TIMESTAMP AT TIME ZONE 'UTC')
TO ((pg_catalog.to_date('`+month+`', 'YYYY_MM') + INTERVAL '1 month')::TIMESTAMP AT TIME ZONE 'UTC')`); err != nil {
		t.Fatal(err)
	}
	dropped, err := store.DropAuditPartitions(passCtx, 12)
	if err != nil || len(dropped) != 1 || dropped[0] != "audit_event_"+month {
		t.Fatalf("audit partition retention = %v, %v; want audit_event_%s dropped", dropped, err, month)
	}
	if rows, err := store.PruneAudit(passCtx, 12, 1000); err != nil || rows.Defaults != 0 {
		t.Fatalf("audit row retention = %+v, %v; want nothing left by a month with no events", rows, err)
	}
	var kept, present int
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event),
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class WHERE relname = 'audit_event_'||$1)`, month).Scan(
		&kept, &present); err != nil || kept == 0 || present != 0 {
		t.Fatalf("after audit retention: %d events kept, old month present %d, %v", kept, present, err)
	}

	// Every pass that removed something recorded itself, and the record is
	// immutable.
	var runs int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(DISTINCT kind) FROM mesh_audit.retention_run`).Scan(
		&runs); err != nil || runs != 3 {
		t.Fatalf("retention run kinds = %d, %v; want audit, outbox and idempotency", runs, err)
	}
	_, err = admin.Exec(ctx, `DELETE FROM mesh_audit.retention_run`)
	assertPostgreSQLCode(t, err, "23514")
}
