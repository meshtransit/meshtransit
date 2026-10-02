//go:build integration

package integration

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/resource/authority"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

func assertDirectDeviceEndpoint(
	ctx context.Context, t *testing.T, admin *pgx.Conn,
	importedID sharing.ImportedResourceID, wantState string, wantVersion int64,
) {
	t.Helper()
	var state string
	var version, aliases, aliasEndpoints int64
	var bound bool
	if err := admin.QueryRow(ctx, `SELECT endpoint.state, endpoint.version,
        endpoint.provider_workspace_id = endpoint.consumer_workspace_id
        AND endpoint.provider_network_id <> endpoint.consumer_network_id
        AND endpoint.resource_id = target.resource_id
        AND endpoint.target_generation = target.target_generation
        AND endpoint.target_device_id = target.device_id
        AND endpoint.target_session_generation = device.session_generation
        AND endpoint.target_machine_key_epoch = device.current_machine_key_epoch
        AND endpoint.target_node_key_epoch = device.current_node_key_epoch
        AND endpoint.target_address_lease_id = lease.id
        AND endpoint.target_address_generation = lease.generation
        AND endpoint.resource_address = lease.address
        AND endpoint.contract_version = 2 AND endpoint.imported_resource_version = 2
        AND endpoint.expires_at <= contract.expires_at
        AND endpoint.expires_at <= device.expires_at,
        (SELECT count(*) FROM mesh.federation_alias_lease AS alias
         WHERE alias.imported_resource_id = imported.id),
        (SELECT count(*) FROM mesh.private_endpoint AS alias_endpoint
         WHERE alias_endpoint.imported_resource_id = imported.id)
    FROM mesh.direct_device_endpoint AS endpoint
    JOIN mesh.imported_resource AS imported ON imported.id = endpoint.imported_resource_id
    JOIN mesh.trust_contract AS contract ON contract.id = endpoint.trust_contract_id
    JOIN mesh.resource_device_target AS target
      ON target.workspace_id = endpoint.provider_workspace_id
     AND target.network_id = endpoint.provider_network_id
     AND target.resource_id = endpoint.resource_id
     AND target.target_generation = endpoint.target_generation
    JOIN mesh.device AS device ON device.id = target.device_id
    JOIN mesh.node_address_lease AS lease ON lease.id = endpoint.target_address_lease_id
    WHERE imported.public_id = $1::UUID`, importedID.String()).Scan(
		&state, &version, &bound, &aliases, &aliasEndpoints,
	); err != nil {
		t.Fatalf("read direct endpoint readiness: %v", err)
	}
	if state != wantState || version != wantVersion || !bound || aliases != 0 || aliasEndpoints != 0 {
		t.Fatalf("direct readiness state=%s version=%d bound=%t aliases=%d alias_endpoints=%d",
			state, version, bound, aliases, aliasEndpoints)
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
					t.Errorf("roll back direct endpoint RLS check: %v", rollbackErr)
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
                FROM mesh.direct_device_endpoint AS endpoint
                JOIN mesh.imported_resource AS imported ON imported.id = endpoint.imported_resource_id
                WHERE imported.public_id = $1::UUID`, importedID.String()).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != scope.want {
				t.Fatalf("direct endpoint ordinary visibility = %d, want %d", count, scope.want)
			}
		})
	}
}

func assertDirectReadinessFailures(
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
					t.Errorf("restore direct readiness target: %v", err)
				}
				if _, err := admin.Exec(cleanupCtx, `SET session_replication_role = origin`); err != nil {
					t.Errorf("restore direct readiness triggers: %v", err)
				}
			}()
			if _, err := admin.Exec(ctx, fault.sql, deviceID); err != nil {
				t.Fatal(err)
			}
			if _, err := service.ActivateContract(ctx, command); !errors.Is(err, sharing.ErrConflict) {
				t.Fatalf("activate unavailable direct target: %v, want conflict", err)
			}
			var untouched bool
			if err := admin.QueryRow(ctx, `SELECT contract.state = 'activating' AND contract.version = 1
                AND imported.state = 'activating' AND imported.version = 1
                AND NOT EXISTS (SELECT 1 FROM mesh.direct_device_endpoint AS endpoint
                    WHERE endpoint.trust_contract_id = contract.id)
                FROM mesh.trust_contract AS contract
                JOIN mesh.imported_resource AS imported ON imported.trust_contract_id = contract.id
                WHERE contract.public_id = $1::UUID`, command.ContractID().String()).Scan(&untouched); err != nil {
				t.Fatal(err)
			}
			if !untouched {
				t.Fatal("failed direct activation changed durable authority")
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

func assertLegacyDirectContractWithdrawal(ctx context.Context, t *testing.T, admin *pgx.Conn, contract sharing.Contract) {
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
			t.Errorf("roll back legacy direct withdrawal check: %v", rollbackErr)
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
	var advancedProvider, advancedConsumer, legacyEndpointVersion int64
	if err := tx.QueryRow(ctx, `SELECT provider_network_revision, consumer_network_revision, private_endpoint_version
        FROM mesh_ops.revoke_resource_share_v4(
            103,203,103,204,$1::UUID,$2::BIGINT,$3::BIGINT,$4::BIGINT,clock_timestamp()
        )`, contract.ID().String(), contract.Version(), providerSharing, consumerSharing).Scan(
		&advancedProvider, &advancedConsumer, &legacyEndpointVersion,
	); err != nil {
		t.Fatalf("legacy writer cannot revoke direct contract: %v", err)
	}
	var withdrawn bool
	if err := tx.QueryRow(ctx, `SELECT endpoint.state = 'revoked' AND endpoint.version = 2
        AND endpoint.ended_at = contract.ended_at AND contract.state = 'revoked'
        FROM mesh.direct_device_endpoint AS endpoint
        JOIN mesh.trust_contract AS contract ON contract.id = endpoint.trust_contract_id
        WHERE contract.public_id = $1::UUID`, contract.ID().String()).Scan(&withdrawn); err != nil {
		t.Fatal(err)
	}
	if !withdrawn || advancedProvider != providerRevision+1 || advancedConsumer != consumerRevision+1 || legacyEndpointVersion != 0 {
		t.Fatal("legacy writer did not withdraw direct authority with both Network revisions")
	}
	// This is a rollback-only compatibility check. The management service below
	// performs the committed revocation with both audit/outbox streams.
}
