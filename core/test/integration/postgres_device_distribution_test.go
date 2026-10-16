//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/workspace"
)

// assertPostgreSQLDeviceDistribution qualifies schema 133: the distribution
// read follows exactly the inventory's device.read authority, returns the
// Network's current revisions, lists only active or suspended Devices with
// three fields, and grants execution to the runtime role alone.
func assertPostgreSQLDeviceDistribution(ctx context.Context, t *testing.T,
	admin *pgx.Conn, runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	session := authorityConfirmerAccountSessionFixture(t)
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000103")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000203")
	scope, _ := network.NewScope(workspaceID, networkID)
	store, err := postgresadapter.NewDeviceDistributionStore(runtimePool, postgresadapter.AccountSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadDistribution(ctx, session, scope, node.ID{}, 2); !errors.Is(err, distribution.ErrForbidden) {
		t.Fatal("policy approval permission disclosed distribution", err)
	}
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	setIntegrationChange(ctx, t, transaction, "01890f00-0000-7000-8000-000000013300")
	if _, err := transaction.Exec(ctx, `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 13301, '01890f00-0000-7000-8000-000000013301'::UUID, 1, 103, 856, permission.id
FROM mesh.permission AS permission WHERE permission.permission_key='device.read'`); err != nil {
		t.Fatal("seed temporary device.read", err)
	}
	if _, err := transaction.Exec(ctx, "SET LOCAL ROLE mesh_runtime"); err != nil {
		t.Fatal(err)
	}
	read := func(networkPublicID string) *string {
		t.Helper()
		var encoded *string
		if err := transaction.QueryRow(ctx, `SELECT mesh_ops.read_device_distribution_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::TIMESTAMPTZ, NULL, 10
)::TEXT`, session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
			session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
			session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
			workspaceID.String(), networkPublicID, time.Now().UTC()).Scan(&encoded); err != nil {
			t.Fatal("runtime distribution read", err)
		}
		return encoded
	}
	encoded := read(networkID.String())
	if encoded == nil {
		t.Fatal("explicit device.read denied")
	}
	var page struct {
		WorkspaceID     string                       `json:"workspace_id"`
		NetworkID       string                       `json:"network_id"`
		NetworkRevision int64                        `json:"network_revision"`
		PolicyRevision  int64                        `json:"policy_revision"`
		Devices         []map[string]json.RawMessage `json:"devices"`
	}
	if json.Unmarshal([]byte(*encoded), &page) != nil || page.WorkspaceID != workspaceID.String() ||
		page.NetworkID != networkID.String() || page.NetworkRevision < 1 || page.PolicyRevision < 0 {
		t.Fatal("invalid distribution projection", *encoded)
	}
	var expected int
	if err := transaction.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.device
WHERE workspace_id=103 AND network_id=(SELECT id FROM mesh.network WHERE public_id=$1::UUID)
  AND deleted_at IS NULL AND state IN ('active','suspended')`, networkID.String()).Scan(&expected); err == nil &&
		len(page.Devices) != min(expected, 10) {
		t.Fatalf("distribution listed %d Devices, want %d", len(page.Devices), min(expected, 10))
	}
	for _, device := range page.Devices {
		var state string
		if len(device) != 3 || device["id"] == nil || device["hostname"] == nil ||
			json.Unmarshal(device["state"], &state) != nil || (state != "active" && state != "suspended") {
			t.Fatal("distribution Device whitelist changed", device)
		}
	}
	if read("01890f00-0000-7000-8000-000000000201") != nil {
		t.Fatal("cross-Network scope disclosed distribution")
	}
	if _, err := transaction.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, `UPDATE mesh.role_permission SET state='revoked', version=version+1,
updated_at=pg_catalog.now() WHERE id=13301`); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, "SET LOCAL ROLE mesh_runtime"); err != nil {
		t.Fatal(err)
	}
	if read(networkID.String()) != nil {
		t.Fatal("revoked device.read disclosed distribution")
	}
	if err := transaction.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var runtimeExecute, workerExecute, publicExecute bool
	if err := admin.QueryRow(ctx, `SELECT
    pg_catalog.has_function_privilege('mesh_runtime', procedure.oid, 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_worker', procedure.oid, 'EXECUTE'),
    EXISTS (SELECT 1 FROM pg_catalog.aclexplode(procedure.proacl) AS privilege
            WHERE privilege.grantee=0 AND privilege.privilege_type='EXECUTE')
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
WHERE namespace.nspname='mesh_ops' AND procedure.proname='read_device_distribution_v1'`).Scan(
		&runtimeExecute, &workerExecute, &publicExecute); err != nil || !runtimeExecute || workerExecute || publicExecute {
		t.Fatal("distribution privilege boundary changed", err)
	}
}
