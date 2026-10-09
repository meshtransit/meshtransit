//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph/simulation"
)

func assertImportedBaselineReaderConfinement(ctx context.Context, t *testing.T, admin *pgx.Conn, baseline simulation.Baseline) {
	t.Helper()
	releaseID, _, hasRelease := baseline.ActiveRelease()
	if !hasRelease {
		t.Fatal("reader qualification requires a persisted release")
	}
	var projectionID, workspaceID, networkID, providerWorkspaceID, providerNetworkID int64
	if err := admin.QueryRow(ctx, `SELECT projection.id, projection.workspace_id, projection.network_id,
    projection.provider_workspace_id, projection.provider_network_id
FROM mesh.compiled_policy_imported_resource_destination AS projection
JOIN mesh.policy_release AS release ON release.id = projection.policy_release_id
WHERE release.public_id = $1::UUID`, releaseID.String()).Scan(
		&projectionID, &workspaceID, &networkID, &providerWorkspaceID, &providerNetworkID,
	); err != nil {
		t.Fatal("select synthetic baseline projection", err)
	}

	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setIntegrationScope(ctx, t, transaction, workspaceID, networkID)
	if _, err := transaction.Exec(ctx, `SET LOCAL ROLE mesh_migrator`); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, `SELECT
    pg_catalog.set_config('mesh.share_provider_workspace_id', '901', TRUE),
    pg_catalog.set_config('mesh.share_provider_network_id', '902', TRUE),
    pg_catalog.set_config('mesh.share_consumer_workspace_id', '903', TRUE),
    pg_catalog.set_config('mesh.share_consumer_network_id', '904', TRUE)`); err != nil {
		t.Fatal(err)
	}
	var contractID string
	if err := transaction.QueryRow(ctx, `SELECT
    mesh_ops.read_compiled_imported_policy_evidence_internal_v1($1)->>'destination_trust_contract_public_id'`, projectionID).Scan(&contractID); err != nil {
		t.Fatal("read exact immutable provenance through migration-owned baseline role", err)
	}
	if contractID != baseline.Candidate().ImportedResourceDestinations()[0].Resolution().Contract().ID().String() {
		t.Fatal("private reader returned another Contract")
	}
	var restored bool
	if err := transaction.QueryRow(ctx, `SELECT
    pg_catalog.current_setting('mesh.share_provider_workspace_id') = '901'
    AND pg_catalog.current_setting('mesh.share_provider_network_id') = '902'
    AND pg_catalog.current_setting('mesh.share_consumer_workspace_id') = '903'
    AND pg_catalog.current_setting('mesh.share_consumer_network_id') = '904'`).Scan(&restored); err != nil || !restored {
		t.Fatal("private reader leaked bilateral scope into following work", err)
	}
	if err := transaction.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	for _, testCase := range []struct {
		name, role, expectedCode string
		workspaceID, networkID   int64
	}{
		{name: "runtime cannot call private reader", role: "mesh_runtime", expectedCode: "42501", workspaceID: workspaceID, networkID: networkID},
		{name: "migration role cannot select foreign Consumer projection", role: "mesh_migrator", expectedCode: "23514", workspaceID: providerWorkspaceID, networkID: providerNetworkID},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			transaction, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			setIntegrationScope(ctx, t, transaction, testCase.workspaceID, testCase.networkID)
			// Role identifiers are closed test-owned literals, never request input.
			if _, err := transaction.Exec(ctx, `SET LOCAL ROLE `+testCase.role); err != nil {
				t.Fatal(err)
			}
			_, err = transaction.Exec(ctx, `SELECT mesh_ops.read_compiled_imported_policy_evidence_internal_v1($1)`, projectionID)
			var postgresErr *pgconn.PgError
			if !errors.As(err, &postgresErr) || postgresErr.Code != testCase.expectedCode {
				t.Fatalf("private provenance boundary returned %v, want SQLSTATE %s", err, testCase.expectedCode)
			}
			if err := transaction.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
	transaction, err = admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setIntegrationScope(ctx, t, transaction, providerWorkspaceID, providerNetworkID)
	if _, err := transaction.Exec(ctx, `SET LOCAL ROLE mesh_share_writer`); err != nil {
		t.Fatal(err)
	}
	var visible int
	if err := transaction.QueryRow(ctx, `SELECT count(*)::INTEGER
FROM mesh.compiled_policy_imported_resource_destination WHERE id = $1`, projectionID).Scan(&visible); err != nil || visible != 0 {
		t.Fatal("reader table RLS exposed a foreign Consumer projection", err)
	}
	if err := transaction.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
}
