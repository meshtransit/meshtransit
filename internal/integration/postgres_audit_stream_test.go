//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/jackc/pgx/v5"
)

func assertRuntimeNetworkAuditStreamHead(
	ctx context.Context,
	t *testing.T,
	primary *pgx.Conn,
	contender *pgx.Conn,
) {
	t.Helper()

	assertAuditStreamHeadRequiresScope(ctx, t, primary)

	primaryTransaction, err := primary.Begin(ctx)
	if err != nil {
		t.Fatalf("begin primary audit stream transaction: %v", err)
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
	assertLockedNetworkAuditStream(ctx, t, primaryTransaction, 201)

	contendingTransaction, err := contender.Begin(ctx)
	if err != nil {
		t.Fatalf("begin contending audit stream transaction: %v", err)
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
		t.Fatalf("bound contending audit stream lock: %v", err)
	}
	err = contendingTransaction.QueryRow(
		ctx,
		"SELECT * FROM mesh_audit.lock_network_stream_head()",
	).Scan(new(int64), new(int64), new([]byte))
	assertPostgreSQLCode(t, err, "55P03")

	if err := contendingTransaction.Rollback(ctx); err != nil {
		t.Fatalf("rollback contending audit stream transaction: %v", err)
	}
	if err := primaryTransaction.Rollback(ctx); err != nil {
		t.Fatalf("rollback primary audit stream transaction: %v", err)
	}

	afterRelease, err := contender.Begin(ctx)
	if err != nil {
		t.Fatalf("begin audit stream transaction after lock release: %v", err)
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
	assertLockedNetworkAuditStream(ctx, t, afterRelease, 201)
}

func assertAuditStreamHeadRequiresScope(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) {
	t.Helper()

	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin unscoped audit stream transaction: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, transaction)

	err = transaction.QueryRow(
		ctx,
		"SELECT * FROM mesh_audit.lock_network_stream_head()",
	).Scan(new(int64), new(int64), new([]byte))
	assertPostgreSQLCode(t, err, "42501")
}

func assertLockedNetworkAuditStream(
	ctx context.Context,
	t *testing.T,
	transaction pgx.Tx,
	wantStreamID int64,
) {
	t.Helper()

	var streamID, sequence int64
	var latestHash []byte
	if err := transaction.QueryRow(
		ctx,
		"SELECT * FROM mesh_audit.lock_network_stream_head()",
	).Scan(&streamID, &sequence, &latestHash); err != nil {
		t.Fatalf("lock scoped Network audit stream head: %v", err)
	}
	if streamID != wantStreamID {
		t.Fatalf("locked audit stream ID = %d, want %d", streamID, wantStreamID)
	}
	if sequence < 2 {
		t.Fatalf("locked audit stream sequence = %d, want at least 2", sequence)
	}
	if len(latestHash) != sha256.Size || bytes.Equal(latestHash, make([]byte, sha256.Size)) {
		t.Fatalf("locked audit stream hash = %x, want a non-zero SHA-256 hash", latestHash)
	}
}

func assertWorkerCannotLockNetworkAuditStream(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) {
	t.Helper()

	var canUseSchema, canExecute bool
	if err := connection.QueryRow(ctx, `SELECT
    pg_catalog.has_schema_privilege(CURRENT_USER, 'mesh_audit', 'USAGE'),
    COALESCE((
        SELECT pg_catalog.bool_or(
            pg_catalog.has_function_privilege(CURRENT_USER, procedure.oid, 'EXECUTE')
        )
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname = 'mesh_audit'
          AND procedure.proname = 'lock_network_stream_head'
    ), FALSE)`).Scan(&canUseSchema, &canExecute); err != nil {
		t.Fatalf("query worker Network audit stream privileges: %v", err)
	}
	if canUseSchema || canExecute {
		t.Fatalf(
			"worker Network audit privileges: schema usage=%t function execute=%t, want false/false",
			canUseSchema,
			canExecute,
		)
	}

	err := connection.QueryRow(
		ctx,
		"SELECT * FROM mesh_audit.lock_network_stream_head()",
	).Scan(new(int64), new(int64), new([]byte))
	assertPostgreSQLCode(t, err, "42501")
}
