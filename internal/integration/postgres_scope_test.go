//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

const (
	firstWorkspacePublicID  = "01890f00-0000-7000-8000-000000000101"
	firstNetworkPublicID    = "01890f00-0000-7000-8000-000000000201"
	secondWorkspacePublicID = "01890f00-0000-7000-8000-000000000102"
	secondNetworkPublicID   = "01890f00-0000-7000-8000-000000000202"
)

func assertRuntimePublicNetworkScope(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) {
	t.Helper()

	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin public scope transaction: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, transaction)

	assertResolvedNetworkScope(ctx, t, transaction, firstWorkspacePublicID, firstNetworkPublicID, 101, 201)
	assertResolvedNetworkScope(ctx, t, transaction, firstWorkspacePublicID, firstNetworkPublicID, 101, 201)

	var workspaces, networks, revisions int64
	if err := transaction.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh.workspace),
    (SELECT pg_catalog.count(*) FROM mesh.network),
    (SELECT pg_catalog.count(*) FROM mesh_ops.network_revision)`).Scan(
		&workspaces,
		&networks,
		&revisions,
	); err != nil {
		t.Fatalf("query public scoped rows: %v", err)
	}
	if workspaces != 1 || networks != 1 || revisions != 1 {
		t.Fatalf(
			"public scoped rows: workspaces=%d networks=%d revisions=%d, want 1/1/1",
			workspaces,
			networks,
			revisions,
		)
	}

	err = transaction.QueryRow(
		ctx,
		"SELECT * FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)",
		secondWorkspacePublicID,
		secondNetworkPublicID,
	).Scan(new(int64), new(int64))
	assertPostgreSQLCode(t, err, "42501")
}

func assertRuntimeRejectsInvalidPublicNetworkScope(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) {
	t.Helper()

	tests := []struct {
		name        string
		workspaceID string
		networkID   string
	}{
		{
			name:        "cross Workspace pair",
			workspaceID: firstWorkspacePublicID,
			networkID:   secondNetworkPublicID,
		},
		{
			name:        "unknown exact pair",
			workspaceID: "01890f00-0000-7000-8000-000000000901",
			networkID:   "01890f00-0000-7000-8000-000000000902",
		},
		{
			name:        "non UUIDv7 Workspace",
			workspaceID: "01890f00-0000-6000-8000-000000000101",
			networkID:   firstNetworkPublicID,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transaction, err := connection.Begin(ctx)
			if err != nil {
				t.Fatalf("begin invalid public scope transaction: %v", err)
			}
			defer rollbackIntegrationTransaction(ctx, t, transaction)

			err = transaction.QueryRow(
				ctx,
				"SELECT * FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)",
				test.workspaceID,
				test.networkID,
			).Scan(new(int64), new(int64))
			assertPostgreSQLCode(t, err, "23503")
		})
	}
}

func assertResolvedNetworkScope(
	ctx context.Context,
	t *testing.T,
	transaction pgx.Tx,
	workspacePublicID string,
	networkPublicID string,
	wantWorkspaceID int64,
	wantNetworkID int64,
) {
	t.Helper()

	var workspaceID, networkID int64
	if err := transaction.QueryRow(
		ctx,
		"SELECT * FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)",
		workspacePublicID,
		networkPublicID,
	).Scan(&workspaceID, &networkID); err != nil {
		t.Fatalf("set public Network scope: %v", err)
	}
	if workspaceID != wantWorkspaceID || networkID != wantNetworkID {
		t.Fatalf(
			"resolved public Network scope = (%d, %d), want (%d, %d)",
			workspaceID,
			networkID,
			wantWorkspaceID,
			wantNetworkID,
		)
	}
}

func assertWorkerCannotSetPublicNetworkScope(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) {
	t.Helper()

	var canExecute bool
	if err := connection.QueryRow(ctx, `SELECT pg_catalog.has_function_privilege(
    CURRENT_USER,
    'mesh_ops.set_network_scope(uuid,uuid)',
    'EXECUTE'
)`).Scan(&canExecute); err != nil {
		t.Fatalf("query worker public scope privilege: %v", err)
	}
	if canExecute {
		t.Fatal("worker can set a public Network scope")
	}

	err := connection.QueryRow(
		ctx,
		"SELECT * FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)",
		firstWorkspacePublicID,
		firstNetworkPublicID,
	).Scan(new(int64), new(int64))
	assertPostgreSQLCode(t, err, "42501")
}
