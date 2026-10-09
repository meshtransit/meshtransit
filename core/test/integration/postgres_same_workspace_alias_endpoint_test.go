//go:build integration

package integration

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/domain/resource"
	"github.com/meshtransit/meshtransit/core/internal/domain/resource/authority"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing"
)

// assertSameWorkspaceAliasEndpoint proves that a same-Workspace share takes the
// alias endpoint: a Network-scoped Resource Alias from the alias realm, never a
// canonical-address direct readiness row.
func assertSameWorkspaceAliasEndpoint(
	ctx context.Context, t *testing.T, admin *pgx.Conn,
	importedID sharing.ImportedResourceID, wantState string, wantVersion int64, wantLeaseState string,
) {
	t.Helper()
	var state, leaseState string
	var version, directRows int64
	var bound bool
	if err := admin.QueryRow(ctx, `SELECT endpoint.state, endpoint.version, lease.state,
        endpoint.mode = 'federation_alias'
        AND endpoint.provider_workspace_id = endpoint.consumer_workspace_id
        AND endpoint.provider_network_id <> endpoint.consumer_network_id
        AND endpoint.resource_alias = lease.resource_alias
        AND lease.provider_network_id = endpoint.provider_network_id
        AND lease.consumer_network_id = endpoint.consumer_network_id
        AND realm.kind = 'federation_alias' AND pool.purpose = 'federation_resource_alias'
        AND pool.workspace_id IS NULL AND lease.resource_alias << pool.prefix
        AND NOT EXISTS (SELECT 1 FROM mesh.node_address_lease AS canonical
            WHERE canonical.address = endpoint.resource_alias)
        AND endpoint.contract_version = 2 AND endpoint.imported_resource_version = 2
        AND endpoint.expires_at = contract.expires_at,
        (SELECT count(*) FROM mesh.direct_device_endpoint AS direct
         WHERE direct.imported_resource_id = imported.id)
    FROM mesh.private_endpoint AS endpoint
    JOIN mesh.imported_resource AS imported ON imported.id = endpoint.imported_resource_id
    JOIN mesh.trust_contract AS contract ON contract.id = endpoint.trust_contract_id
    JOIN mesh.federation_alias_lease AS lease ON lease.id = endpoint.alias_lease_id
    JOIN mesh.address_pool AS pool ON pool.id = lease.address_pool_id
    JOIN mesh.address_realm AS realm ON realm.id = lease.address_realm_id
    WHERE imported.public_id = $1::UUID`, importedID.String()).Scan(
		&state, &version, &leaseState, &bound, &directRows,
	); err != nil {
		t.Fatalf("read same-Workspace alias endpoint: %v", err)
	}
	if state != wantState || version != wantVersion || leaseState != wantLeaseState || !bound || directRows != 0 {
		t.Fatalf("same-Workspace alias endpoint state=%s version=%d lease=%s bound=%t direct=%d",
			state, version, leaseState, bound, directRows)
	}
	for _, scope := range []struct {
		name      string
		networkID int
		want      int
	}{
		{name: "consumer", networkID: 204, want: 1},
		{name: "provider ordinary inventory", networkID: 203, want: 0},
		{name: "third Network", networkID: 202, want: 0},
		{name: "absent scope", networkID: 0, want: 0},
	} {
		t.Run(scope.name, func(t *testing.T) {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
				defer cancel()
				if rollbackErr := tx.Rollback(cleanupCtx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
					t.Errorf("roll back alias endpoint RLS check: %v", rollbackErr)
				}
			}()
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
				t.Fatal(err)
			}
			networkValue := ""
			if scope.networkID != 0 {
				networkValue = strconv.Itoa(scope.networkID)
			}
			if _, err := tx.Exec(ctx, `SELECT
                set_config('mesh.workspace_id', $1, TRUE),
                set_config('mesh.network_id', $2, TRUE)`, "103", networkValue); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*)::INTEGER
                FROM mesh.private_endpoint AS endpoint
                JOIN mesh.imported_resource AS imported ON imported.id = endpoint.imported_resource_id
                WHERE imported.public_id = $1::UUID`, importedID.String()).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != scope.want {
				t.Fatalf("alias endpoint ordinary visibility = %d, want %d", count, scope.want)
			}
		})
	}
}

// assertShareTargetFailures proves activation fails closed, before any alias is
// allocated, when the exported Device cannot hold an alias.
func assertShareTargetFailures(
	ctx context.Context, t *testing.T, admin *pgx.Conn,
	service *sharing.Service, command sharing.ActivateContract,
) {
	t.Helper()
	var deviceID, nodeEpoch int64
	var expiry time.Time
	if err := admin.QueryRow(ctx, `SELECT device.id, device.current_node_key_epoch, device.expires_at
        FROM mesh.trust_contract AS contract
        JOIN mesh.resource_device_target AS target
          ON target.workspace_id = contract.provider_workspace_id
         AND target.network_id = contract.provider_network_id
         AND target.resource_id = contract.resource_id
         AND target.target_generation = contract.target_generation
        JOIN mesh.device AS device ON device.id = target.device_id
        WHERE contract.public_id = $1::UUID`, command.ContractID().String()).Scan(&deviceID, &nodeEpoch, &expiry); err != nil {
		t.Fatal(err)
	}
	// Only the disposable integration administrator injects invalid live inputs.
	// Production roles cannot bypass the evidence or lifecycle triggers.
	for _, fault := range []struct{ name, sql string }{
		{name: "expired target", sql: `UPDATE mesh.device SET expires_at = transaction_timestamp() - interval '1 microsecond' WHERE id = $1`},
		{name: "revoked target", sql: `UPDATE mesh.device SET state = 'revoked' WHERE id = $1`},
		{name: "missing current Node epoch", sql: `UPDATE mesh.device SET current_node_key_epoch = current_node_key_epoch + 1 WHERE id = $1`},
	} {
		t.Run(fault.name, func(t *testing.T) {
			if _, err := admin.Exec(ctx, `SET session_replication_role = replica`); err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
				defer cancel()
				if _, err := admin.Exec(cleanupCtx, `UPDATE mesh.device
                    SET state = 'active', expires_at = $2, current_node_key_epoch = $3 WHERE id = $1`, deviceID, expiry, nodeEpoch); err != nil {
					t.Errorf("restore share target: %v", err)
				}
				if _, err := admin.Exec(cleanupCtx, `SET session_replication_role = origin`); err != nil {
					t.Errorf("restore share target triggers: %v", err)
				}
			}()
			if _, err := admin.Exec(ctx, fault.sql, deviceID); err != nil {
				t.Fatal(err)
			}
			if _, err := service.ActivateContract(ctx, command); !errors.Is(err, sharing.ErrConflict) {
				t.Fatalf("activate unavailable share target: %v, want conflict", err)
			}
			var untouched bool
			if err := admin.QueryRow(ctx, `SELECT contract.state = 'activating' AND contract.version = 1
                AND imported.state = 'activating' AND imported.version = 1
                AND NOT EXISTS (SELECT 1 FROM mesh.private_endpoint AS endpoint
                    WHERE endpoint.trust_contract_id = contract.id)
                AND NOT EXISTS (SELECT 1 FROM mesh.federation_alias_lease AS lease
                    WHERE lease.imported_resource_id = imported.id)
                AND NOT EXISTS (SELECT 1 FROM mesh.direct_device_endpoint AS endpoint
                    WHERE endpoint.trust_contract_id = contract.id)
                FROM mesh.trust_contract AS contract
                JOIN mesh.imported_resource AS imported ON imported.trust_contract_id = contract.id
                WHERE contract.public_id = $1::UUID`, command.ContractID().String()).Scan(&untouched); err != nil {
				t.Fatal(err)
			}
			if !untouched {
				t.Fatal("failed share activation changed durable authority")
			}
		})
	}
}

func createDirectDeviceResourceFixture(ctx context.Context, t *testing.T, admin *pgx.Conn, pool *postgresadapter.Pool) resource.ID {
	t.Helper()
	session := managementRBACAccountSessionFixture(t)
	scope := resourceAuthorityScope(t, 103, 203)
	inventory, _ := resourceAuthorityRevisions(ctx, t, admin, 103, 203)
	definition := resourceAuthorityDeviceDefinition(t, scope, session.PrincipalID(), resourceAuthorityNodeID(t, 910), "Direct sharing qualification Device")
	command, err := authority.NewCreateDeviceCommand(definition, inventory, session,
		resourceAuthorityReason(t, "create direct sharing fixture with current Device keys"), resourceAuthorityProof(t, 211))
	if err != nil {
		t.Fatal(err)
	}
	result, err := newIntegrationResourceAuthorityService(t, pool).Create(ctx, command)
	if err != nil {
		t.Fatalf("create direct sharing Resource fixture: %v", err)
	}
	return result.ResourceID()
}

// assertLegacyRevokeWithdrawsSameWorkspaceAlias proves the supported rollback
// writer still withdraws a same-Workspace alias endpoint with both revisions.
func assertLegacyRevokeWithdrawsSameWorkspaceAlias(ctx context.Context, t *testing.T, admin *pgx.Conn, contract sharing.Contract) {
	t.Helper()
	var providerRevision, consumerRevision, providerSharing, consumerSharing int64
	if err := admin.QueryRow(ctx, `SELECT provider.network_revision, consumer.network_revision,
        provider.sharing_revision, consumer.sharing_revision
        FROM mesh_ops.network_revision AS provider, mesh_ops.network_revision AS consumer
        WHERE provider.workspace_id = 103 AND provider.network_id = 203
          AND consumer.workspace_id = 103 AND consumer.network_id = 204`).Scan(
		&providerRevision, &consumerRevision, &providerSharing, &consumerSharing,
	); err != nil {
		t.Fatal(err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		if rollbackErr := tx.Rollback(cleanupCtx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			t.Errorf("roll back legacy alias withdrawal check: %v", rollbackErr)
		}
	}()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT
        set_config('mesh.workspace_id', '103', TRUE),
        set_config('mesh.network_id', '204', TRUE),
        set_config('mesh.change_public_id', '01890f94-0000-7000-8000-000000000079', TRUE)`); err != nil {
		t.Fatal(err)
	}
	var advancedProvider, advancedConsumer, legacyEndpointVersion, legacyAliasVersion int64
	if err := tx.QueryRow(ctx, `SELECT provider_network_revision, consumer_network_revision,
            private_endpoint_version, alias_lease_version
        FROM mesh_ops.revoke_resource_share_v4(
            103,203,103,204,$1::UUID,$2::BIGINT,$3::BIGINT,$4::BIGINT,clock_timestamp()
        )`, contract.ID().String(), contract.Version(), providerSharing, consumerSharing).Scan(
		&advancedProvider, &advancedConsumer, &legacyEndpointVersion, &legacyAliasVersion,
	); err != nil {
		t.Fatalf("legacy writer cannot revoke same-Workspace alias contract: %v", err)
	}
	var withdrawn bool
	if err := tx.QueryRow(ctx, `SELECT endpoint.state = 'revoked' AND endpoint.version = 2
        AND endpoint.ended_at = contract.ended_at AND contract.state = 'revoked'
        AND lease.state = 'withdrawn' AND lease.version = 2
        FROM mesh.private_endpoint AS endpoint
        JOIN mesh.trust_contract AS contract ON contract.id = endpoint.trust_contract_id
        JOIN mesh.federation_alias_lease AS lease ON lease.id = endpoint.alias_lease_id
        WHERE contract.public_id = $1::UUID`, contract.ID().String()).Scan(&withdrawn); err != nil {
		t.Fatal(err)
	}
	if !withdrawn || advancedProvider != providerRevision+1 || advancedConsumer != consumerRevision+1 ||
		legacyEndpointVersion != 2 || legacyAliasVersion != 2 {
		t.Fatal("legacy writer did not withdraw the alias endpoint with both Network revisions")
	}
	// This is a rollback-only compatibility check. The management service below
	// performs the committed revocation with both audit/outbox streams.
}
