//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
)

// assertAuditPartitionsAndStreams qualifies schema 115: monthly audit
// partitions exist ahead with the same row-level security, the worker can
// extend them idempotently, every Workspace has its own stream, and stream
// identities cannot change.
func assertAuditPartitionsAndStreams(ctx context.Context, t *testing.T, admin *pgx.Conn, workerPool *postgresadapter.Pool) {
	t.Helper()
	var ahead int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM pg_catalog.pg_inherits AS inheritance
JOIN pg_catalog.pg_class AS child ON child.oid = inheritance.inhrelid
WHERE inheritance.inhparent = 'mesh_audit.audit_event'::REGCLASS
  AND child.relname >= 'audit_event_' || pg_catalog.to_char(pg_catalog.date_trunc('month', pg_catalog.now() AT TIME ZONE 'UTC'), 'YYYY_MM')
  AND child.relname <> 'audit_event_default' AND child.relrowsecurity AND child.relforcerowsecurity`).Scan(&ahead); err != nil {
		t.Fatal(err)
	}
	if ahead < 25 {
		t.Fatalf("audit partitions from this month = %d, want at least 25", ahead)
	}
	store, err := postgresadapter.NewAuditPartitionStore(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	extendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if created, err := store.EnsurePartitions(extendCtx, 30); err != nil || created != 6 {
		t.Fatalf("extend audit partitions = %d, %v; want 6 new months", created, err)
	}
	if created, err := store.EnsurePartitions(extendCtx, 30); err != nil || created != 0 {
		t.Fatalf("repeat audit partitions = %d, %v; want none", created, err)
	}
	var missing, streams int
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh.workspace AS workspace WHERE NOT EXISTS (
        SELECT 1 FROM mesh_audit.audit_stream AS stream
        WHERE stream.scope_kind = 'workspace' AND stream.workspace_id = workspace.id
          AND stream.deployment_id = workspace.deployment_id)),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_stream WHERE scope_kind = 'workspace')`).Scan(&missing, &streams); err != nil {
		t.Fatal(err)
	}
	if missing != 0 || streams == 0 {
		t.Fatalf("Workspace streams: %d Workspaces without one, %d streams", missing, streams)
	}
	_, err = admin.Exec(ctx, `UPDATE mesh_audit.audit_stream SET public_id = pg_catalog.uuidv7() WHERE scope_kind = 'deployment'`)
	assertPostgreSQLCode(t, err, "23514")
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if _, err := transaction.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
		t.Fatal(err)
	}
	var ignored int
	err = transaction.QueryRow(ctx, `SELECT mesh_ops.ensure_audit_event_partitions_v1(1)`).Scan(&ignored)
	assertPostgreSQLCode(t, err, "42501")
}
