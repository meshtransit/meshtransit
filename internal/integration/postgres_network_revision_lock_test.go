//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

const networkRevisionFieldCount = 8

func assertRuntimeNetworkRevisionLock(
	ctx context.Context,
	t *testing.T,
	primary *pgx.Conn,
	contender *pgx.Conn,
) {
	t.Helper()

	assertNetworkRevisionLockRequiresScope(ctx, t, primary)

	primaryTransaction, err := primary.Begin(ctx)
	if err != nil {
		t.Fatalf("begin primary Network revision transaction: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, primaryTransaction)
	assertResolvedNetworkScope(
		ctx,
		t,
		primaryTransaction,
		firstWorkspacePublicID,
		firstNetworkPublicID,
		101,
		201,
	)
	primaryRevision := lockNetworkRevision(ctx, t, primaryTransaction)

	contendingTransaction, err := contender.Begin(ctx)
	if err != nil {
		t.Fatalf("begin contending Network revision transaction: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, contendingTransaction)
	assertResolvedNetworkScope(
		ctx,
		t,
		contendingTransaction,
		firstWorkspacePublicID,
		firstNetworkPublicID,
		101,
		201,
	)
	if _, err := contendingTransaction.Exec(ctx, "SET LOCAL lock_timeout = '100ms'"); err != nil {
		t.Fatalf("bound contending Network revision lock: %v", err)
	}
	var blockedRevision [networkRevisionFieldCount]int64
	err = scanNetworkRevision(
		contendingTransaction.QueryRow(ctx, "SELECT * FROM mesh_ops.lock_network_revision()"),
		&blockedRevision,
	)
	assertPostgreSQLCode(t, err, "55P03")

	if err := contendingTransaction.Rollback(ctx); err != nil {
		t.Fatalf("rollback contending Network revision transaction: %v", err)
	}
	if err := primaryTransaction.Rollback(ctx); err != nil {
		t.Fatalf("rollback primary Network revision transaction: %v", err)
	}

	afterRelease, err := contender.Begin(ctx)
	if err != nil {
		t.Fatalf("begin Network revision transaction after lock release: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, afterRelease)
	assertResolvedNetworkScope(
		ctx,
		t,
		afterRelease,
		firstWorkspacePublicID,
		firstNetworkPublicID,
		101,
		201,
	)
	if revision := lockNetworkRevision(ctx, t, afterRelease); revision != primaryRevision {
		t.Fatalf(
			"Network revision changed while lock transactions rolled back: got %v, want %v",
			revision,
			primaryRevision,
		)
	}
}

func assertNetworkRevisionLockRequiresScope(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) {
	t.Helper()

	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin unscoped Network revision lock transaction: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, transaction)

	var revision [networkRevisionFieldCount]int64
	err = scanNetworkRevision(
		transaction.QueryRow(ctx, "SELECT * FROM mesh_ops.lock_network_revision()"),
		&revision,
	)
	assertPostgreSQLCode(t, err, "42501")
}

func lockNetworkRevision(
	ctx context.Context,
	t *testing.T,
	transaction pgx.Tx,
) [networkRevisionFieldCount]int64 {
	t.Helper()

	var revision [networkRevisionFieldCount]int64
	if err := scanNetworkRevision(
		transaction.QueryRow(ctx, "SELECT * FROM mesh_ops.lock_network_revision()"),
		&revision,
	); err != nil {
		t.Fatalf("lock scoped Network revision: %v", err)
	}
	for index, value := range revision {
		if value <= 0 {
			t.Fatalf("locked Network revision field %d = %d, want positive", index, value)
		}
	}
	return revision
}

func scanNetworkRevision(row pgx.Row, revision *[networkRevisionFieldCount]int64) error {
	return row.Scan(
		&revision[0],
		&revision[1],
		&revision[2],
		&revision[3],
		&revision[4],
		&revision[5],
		&revision[6],
		&revision[7],
	)
}

func assertWorkerCannotLockNetworkRevision(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) {
	t.Helper()

	var canExecute bool
	if err := connection.QueryRow(ctx, `SELECT COALESCE((
    SELECT pg_catalog.bool_or(
        pg_catalog.has_function_privilege(CURRENT_USER, procedure.oid, 'EXECUTE')
    )
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'mesh_ops'
      AND procedure.proname = 'lock_network_revision'
), FALSE)`).Scan(&canExecute); err != nil {
		t.Fatalf("query worker Network revision lock privilege: %v", err)
	}
	if canExecute {
		t.Fatal("worker can lock Network revision")
	}

	var revision [networkRevisionFieldCount]int64
	err := scanNetworkRevision(
		connection.QueryRow(ctx, "SELECT * FROM mesh_ops.lock_network_revision()"),
		&revision,
	)
	assertPostgreSQLCode(t, err, "42501")
}
