//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/accessgraph/simulation"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/node/inventory"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func assertPostgreSQLConsoleDeviceInventory(ctx context.Context, t *testing.T,
	admin *pgx.Conn, runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	session := authorityConfirmerAccountSessionFixture(t)
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000103")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000203")
	scope, _ := network.NewScope(workspaceID, networkID)
	store, err := postgresadapter.NewConsoleDeviceInventoryStore(runtimePool, postgresadapter.AccountSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadDevices(ctx, session, scope, node.ID{}, 2, time.Now().UTC()); !errors.Is(err, inventory.ErrForbidden) {
		t.Fatal("policy approval permission disclosed Device inventory", err)
	}
	policyStore, err := postgresadapter.NewActivePolicyStore(runtimePool, postgresadapter.PolicySimulationOptions{
		StatementTimeout: 5 * time.Second, LockTimeout: time.Second, IdleTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyStore.ReadActivePolicy(ctx, session, scope, time.Now().UTC()); !errors.Is(err, simulation.ErrForbidden) {
		t.Fatal("approval permission disclosed policy", err)
	}
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	setIntegrationChange(ctx, t, transaction, "01890f00-0000-7000-8000-000000012000")
	if _, err := transaction.Exec(ctx, `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT addition.id, addition.public_id::UUID, 1, 103, 856, permission.id
FROM (VALUES
    (12001, '01890f00-0000-7000-8000-000000012001', 'device.read'),
    (12002, '01890f00-0000-7000-8000-000000012002', 'network.read'),
    (12003, '01890f00-0000-7000-8000-000000012003', 'policy.read')
) AS addition(id, public_id, permission_key)
JOIN mesh.permission AS permission ON permission.permission_key=addition.permission_key`); err != nil {
		t.Fatal("seed temporary read-only permissions", err)
	}
	if _, err := transaction.Exec(ctx, "SELECT pg_catalog.set_config('plan_cache_mode', 'force_generic_plan', TRUE)"); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, "SET LOCAL ROLE mesh_runtime"); err != nil {
		t.Fatal(err)
	}
	read := func(networkPublicID string, after any) *string {
		t.Helper()
		var encoded *string
		if err := transaction.QueryRow(ctx, `SELECT mesh_ops.read_console_devices_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::TIMESTAMPTZ, $13::UUID, 2
)::TEXT`, session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
			session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
			session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
			workspaceID.String(), networkPublicID, time.Now().UTC(), after).Scan(&encoded); err != nil {
			t.Fatal("runtime Device read", err)
		}
		return encoded
	}
	for range 6 {
		if read(networkID.String(), nil) == nil {
			t.Fatal("generic plan lost current inventory authority")
		}
	}
	first := read(networkID.String(), nil)
	if first == nil {
		t.Fatal("explicit device.read denied")
	}
	var activePolicy *string
	if err := transaction.QueryRow(ctx, `SELECT mesh_ops.read_active_policy_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,$10::UUID,$11::UUID,$12::TIMESTAMPTZ
)::TEXT`, session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(), session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(), session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(), workspaceID.String(), networkID.String(), time.Now().UTC()).Scan(&activePolicy); err != nil {
		t.Fatal("active policy read", err)
	}
	if activePolicy == nil {
		t.Fatal("explicit policy.read denied")
	}
	var policyProjection map[string]json.RawMessage
	if json.Unmarshal([]byte(*activePolicy), &policyProjection) != nil || len(policyProjection) != 7 {
		t.Fatal("unexpected active policy fields")
	}
	for _, forbidden := range []string{"provider_workspace_id", "provider_network_id", "trust_contract_id", "sharing_revision"} {
		if _, found := policyProjection[forbidden]; found {
			t.Fatal("provider metadata disclosed")
		}
	}
	var page struct {
		WorkspaceID string                       `json:"workspace_id"`
		NetworkID   string                       `json:"network_id"`
		Revision    int64                        `json:"inventory_revision"`
		Devices     []map[string]json.RawMessage `json:"devices"`
	}
	if json.Unmarshal([]byte(*first), &page) != nil || page.WorkspaceID != workspaceID.String() ||
		page.NetworkID != networkID.String() || page.Revision < 1 || len(page.Devices) == 0 || len(page.Devices) > 2 {
		t.Fatal("invalid inventory projection")
	}
	for _, device := range page.Devices {
		if len(device) != 8 || device["id"] == nil || device["hostname"] == nil || device["state"] == nil ||
			device["is_ephemeral"] == nil || device["version"] == nil || device["created_at"] == nil ||
			device["updated_at"] == nil || device["expires_at"] == nil {
			t.Fatal("Device whitelist changed")
		}
	}
	var after string
	if json.Unmarshal(page.Devices[0]["id"], &after) != nil {
		t.Fatal("missing Device cursor")
	}
	if next := read(networkID.String(), after); next == nil {
		t.Fatal("keyset continuation denied")
	}
	if read("01890f00-0000-7000-8000-000000000201", nil) != nil {
		t.Fatal("cross-Network scope disclosed inventory")
	}
	if _, err := transaction.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, `UPDATE mesh.role_permission SET state='revoked', version=version+1, updated_at=pg_catalog.now()
WHERE id IN (12001,12003)`); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, "SELECT pg_catalog.set_config('plan_cache_mode', 'force_generic_plan', TRUE)"); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, "SET LOCAL ROLE mesh_runtime"); err != nil {
		t.Fatal(err)
	}
	if read(networkID.String(), nil) != nil {
		t.Fatal("revoked device.read disclosed inventory")
	}
	if err := transaction.QueryRow(ctx, `SELECT mesh_ops.read_active_policy_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,$10::UUID,$11::UUID,$12::TIMESTAMPTZ
)::TEXT`, session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(), session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(), session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(), workspaceID.String(), networkID.String(), time.Now().UTC()).Scan(&activePolicy); err != nil || activePolicy != nil {
		t.Fatal("generic plan retained revoked policy.read", err)
	}
	if err := transaction.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var runtimeExecute, workerExecute, publicExecute, forcedRLS bool
	if err := admin.QueryRow(ctx, `SELECT
    pg_catalog.has_function_privilege('mesh_runtime', procedure.oid, 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_worker', procedure.oid, 'EXECUTE'),
    EXISTS (SELECT 1 FROM pg_catalog.aclexplode(procedure.proacl) AS privilege
            WHERE privilege.grantee=0 AND privilege.privilege_type='EXECUTE'),
    (SELECT relrowsecurity AND relforcerowsecurity FROM pg_catalog.pg_class WHERE oid='mesh.device'::regclass)
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
WHERE namespace.nspname='mesh_ops' AND procedure.proname='read_console_devices_v1'`).Scan(
		&runtimeExecute, &workerExecute, &publicExecute, &forcedRLS); err != nil || !runtimeExecute ||
		workerExecute || publicExecute || !forcedRLS {
		t.Fatal("inventory privilege/RLS boundary changed", err)
	}
}
