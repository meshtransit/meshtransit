//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func assertRuntimeNetworkInventoryRevision(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) {
	t.Helper()

	assertInventoryAdvanceRequiresScope(ctx, t, connection)

	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin Network inventory revision transaction: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, transaction)
	assertResolvedNetworkScope(
		ctx,
		t,
		transaction,
		firstWorkspacePublicID,
		firstNetworkPublicID,
		101,
		201,
	)

	var canUpdateDirectly bool
	if err := transaction.QueryRow(ctx, `SELECT pg_catalog.has_table_privilege(
    CURRENT_USER,
    'mesh_ops.network_revision',
    'UPDATE'
)`).Scan(&canUpdateDirectly); err != nil {
		t.Fatalf("query direct Network revision privilege: %v", err)
	}
	if canUpdateDirectly {
		t.Fatal("runtime can update the Network revision table directly")
	}

	var beforeNetwork, beforeInventory int64
	if err := transaction.QueryRow(ctx, `SELECT network_revision, inventory_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 101 AND network_id = 201`).Scan(&beforeNetwork, &beforeInventory); err != nil {
		t.Fatalf("read Network revision before advance: %v", err)
	}

	var afterNetwork, afterInventory int64
	if err := transaction.QueryRow(
		ctx,
		"SELECT * FROM mesh_ops.advance_network_inventory_revision()",
	).Scan(&afterNetwork, &afterInventory); err != nil {
		t.Fatalf("advance Network inventory revision: %v", err)
	}
	if afterNetwork != beforeNetwork+1 || afterInventory != beforeInventory+1 {
		t.Fatalf(
			"advanced revisions = (%d, %d), want (%d, %d)",
			afterNetwork,
			afterInventory,
			beforeNetwork+1,
			beforeInventory+1,
		)
	}

	if err := transaction.Rollback(ctx); err != nil {
		t.Fatalf("rollback Network inventory revision transaction: %v", err)
	}

	verification, err := connection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin Network revision rollback verification: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, verification)
	assertResolvedNetworkScope(
		ctx,
		t,
		verification,
		firstWorkspacePublicID,
		firstNetworkPublicID,
		101,
		201,
	)

	var durableNetwork, durableInventory int64
	if err := verification.QueryRow(ctx, `SELECT network_revision, inventory_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 101 AND network_id = 201`).Scan(
		&durableNetwork,
		&durableInventory,
	); err != nil {
		t.Fatalf("read Network revision after rollback: %v", err)
	}
	if durableNetwork != beforeNetwork || durableInventory != beforeInventory {
		t.Fatalf(
			"durable revisions after rollback = (%d, %d), want (%d, %d)",
			durableNetwork,
			durableInventory,
			beforeNetwork,
			beforeInventory,
		)
	}
}

func assertInventoryAdvanceRequiresScope(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) {
	t.Helper()

	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin unscoped Network revision transaction: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, transaction)

	err = transaction.QueryRow(
		ctx,
		"SELECT * FROM mesh_ops.advance_network_inventory_revision()",
	).Scan(new(int64), new(int64))
	assertPostgreSQLCode(t, err, "42501")
}

func assertWorkerCannotAdvanceNetworkInventoryRevision(
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
      AND procedure.proname = 'advance_network_inventory_revision'
), FALSE)`).Scan(&canExecute); err != nil {
		t.Fatalf("query worker Network inventory revision privilege: %v", err)
	}
	if canExecute {
		t.Fatal("worker can advance Network inventory revision")
	}

	err := connection.QueryRow(
		ctx,
		"SELECT * FROM mesh_ops.advance_network_inventory_revision()",
	).Scan(new(int64), new(int64))
	assertPostgreSQLCode(t, err, "42501")
}
