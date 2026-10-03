//go:build integration

package integration

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

//go:embed testdata/device_alias_map_intent.sql
var seedAliasMapIntentSQL string

const insertAliasReadinessSQL = `INSERT INTO mesh.device_alias_client_readiness(public_id,deployment_id,provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id,private_endpoint_id,endpoint_generation,
 consumer_device_id,provider_device_id,contract_version,imported_resource_version,resource_version,target_generation,recovery_epoch,lease_public_ids,expires_at,state,created_at,updated_at,
 provider_network_revision,provider_sharing_revision,consumer_network_revision,consumer_sharing_revision)
SELECT '01890fb0-0000-7000-8000-000000004004',endpoint.deployment_id,endpoint.provider_workspace_id,endpoint.provider_network_id,endpoint.consumer_workspace_id,endpoint.consumer_network_id,endpoint.id,endpoint.generation,
 consumer.id,target.device_id,contract.version,endpoint.imported_resource_version,contract.resource_version,contract.target_generation,endpoint.recovery_epoch,
 ARRAY(SELECT lease.public_id FROM mesh.device_alias_lease AS lease WHERE lease.private_endpoint_id=endpoint.id AND (lease.alias_role='resource' OR lease.owner_device_id=consumer.id) ORDER BY lease.public_id),
 LEAST(endpoint.expires_at,consumer.expires_at,provider.expires_at),'ready',transaction_timestamp(),transaction_timestamp(),provider_revision.network_revision,provider_revision.sharing_revision,consumer_revision.network_revision,consumer_revision.sharing_revision
FROM mesh.private_endpoint AS endpoint JOIN mesh.trust_contract AS contract ON contract.id=endpoint.trust_contract_id
JOIN mesh.resource_device_target AS target ON target.resource_id=contract.resource_id AND target.target_generation=contract.target_generation AND target.state='active'
JOIN mesh.device AS provider ON provider.id=target.device_id JOIN mesh.device AS consumer ON consumer.public_id=$2::UUID
JOIN mesh_ops.network_revision AS provider_revision ON provider_revision.workspace_id=endpoint.provider_workspace_id AND provider_revision.network_id=endpoint.provider_network_id
JOIN mesh_ops.network_revision AS consumer_revision ON consumer_revision.workspace_id=endpoint.consumer_workspace_id AND consumer_revision.network_id=endpoint.consumer_network_id
WHERE endpoint.public_id=$1::UUID`

type aliasMapIdentity struct {
	workspace, network int64
	machine, key       []byte
	id                 string
}

func assertDeviceAliasMapReadiness(ctx context.Context, t *testing.T, admin *pgx.Conn, endpointID, consumerID string) {
	t.Helper()
	assertAliasMapPrivileges(ctx, t, admin)
	for _, mode := range []string{"consumer_only", "wrong_batch", "both"} {
		t.Run("alias map readiness "+mode, func(t *testing.T) {
			tx := beginDeviceAliasTransaction(ctx, t, admin, 4000)
			if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, seedAliasMapIntentSQL, pgx.QueryExecModeSimpleProtocol, endpointID, consumerID); err != nil {
				t.Fatal(err)
			}
			var provider, consumer aliasMapIdentity
			if err := tx.QueryRow(ctx, `SELECT provider.workspace_id,provider.network_id,provider.public_id::TEXT,provider_machine.fingerprint,provider_node.public_key,
     consumer.workspace_id,consumer.network_id,consumer.public_id::TEXT,consumer_machine.fingerprint,consumer_node.public_key
     FROM mesh.private_endpoint AS endpoint JOIN mesh.trust_contract AS contract ON contract.id=endpoint.trust_contract_id
     JOIN mesh.resource_device_target AS target ON target.resource_id=contract.resource_id AND target.target_generation=contract.target_generation
     JOIN mesh.device AS provider ON provider.id=target.device_id JOIN mesh.device_machine_key_epoch AS provider_machine ON provider_machine.device_id=provider.id AND provider_machine.epoch=provider.current_machine_key_epoch
     JOIN mesh.device_node_key_epoch AS provider_node ON provider_node.device_id=provider.id AND provider_node.epoch=provider.current_node_key_epoch
     JOIN mesh.device AS consumer ON consumer.public_id=$2::UUID JOIN mesh.device_machine_key_epoch AS consumer_machine ON consumer_machine.device_id=consumer.id AND consumer_machine.epoch=consumer.current_machine_key_epoch
     JOIN mesh.device_node_key_epoch AS consumer_node ON consumer_node.device_id=consumer.id AND consumer_node.epoch=consumer.current_node_key_epoch
     WHERE endpoint.public_id=$1::UUID`, endpointID, consumerID).Scan(&provider.workspace, &provider.network, &provider.id, &provider.machine, &provider.key, &consumer.workspace, &consumer.network, &consumer.id, &consumer.machine, &consumer.key); err != nil {
				t.Fatal(err)
			}
			if mode == "both" {
				assertSharingDependenciesBeforeRule(ctx, t, tx, provider, consumer)
				assertDeviceAliasGuardedWorker(ctx, t, tx, endpointID, consumerID, provider, consumer)
			}
			assertAliasMapCount(ctx, t, tx, consumer, 0)
			if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, insertAliasReadinessSQL, endpointID, consumerID); err != nil {
				t.Fatal(err)
			}
			if mode == "both" {
				assertAliasMapCount(ctx, t, tx, consumer, 1)
				assertAliasMapCount(ctx, t, tx, provider, 1)
				assertAliasMapAuthentication(ctx, t, tx, consumer)
				assertAliasMapNegativePins(ctx, t, tx, endpointID, consumer)
			}
			appendDeviceAliasReadinessEvidence(ctx, t, tx, endpointID, 4000, mode)
			_, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
			if mode == "both" {
				if err != nil {
					t.Fatalf("complete readiness evidence rejected: %v", err)
				}
			} else {
				requireDeviceAliasCode(t, err, "23514")
			}
			rollbackIntegrationTransaction(ctx, t, tx)
		})
	}
}

func assertAliasMapCount(ctx context.Context, t *testing.T, tx pgx.Tx, self aliasMapIdentity, want int) {
	t.Helper()
	if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	setIntegrationScope(ctx, t, tx, self.workspace, self.network)
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime; SELECT set_config('mesh.alias_map_provider_workspace_id','999',TRUE),set_config('mesh.alias_map_provider_network_id','999',TRUE),set_config('mesh.alias_map_consumer_workspace_id','999',TRUE),set_config('mesh.alias_map_consumer_network_id','999',TRUE),set_config('mesh.alias_map_endpoint_id','999',TRUE)`); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query(ctx, `SELECT edge::TEXT FROM mesh_ops.load_device_alias_map_edges_v1($1::BYTEA,$2::BYTEA,257) AS edge`, self.machine, self.key)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for rows.Next() {
		count++
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		var record struct {
			EvaluatedAt time.Time `json:"evaluated_at"`
			Peer        struct {
				Addresses []string `json:"addresses"`
			} `json:"peer"`
			Aliases struct {
				LocalAddresses  []string  `json:"local_addresses"`
				RemoteAddresses []string  `json:"remote_addresses"`
				ExpiresAt       time.Time `json:"expires_at"`
			} `json:"aliases"`
		}
		if err := json.Unmarshal([]byte(encoded), &record); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if len(record.Aliases.LocalAddresses) != 2 || len(record.Aliases.RemoteAddresses) != 2 ||
			!slices.Equal(record.Peer.Addresses, record.Aliases.RemoteAddresses) ||
			!record.Aliases.ExpiresAt.After(record.EvaluatedAt) {
			rows.Close()
			t.Fatal("incomplete or inconsistent alias map proof")
		}
		for _, address := range record.Peer.Addresses {
			if address != "100.96.0.1/32" && address != "100.96.0.9/32" && address != "fd00:feed::1/128" && address != "fd00:feed:1::1/128" {
				rows.Close()
				t.Fatal("foreign canonical or unexpected address escaped reader")
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("alias map count=%d want=%d", count, want)
	}
	var restored bool
	if err := tx.QueryRow(ctx, `SELECT current_setting('mesh.alias_map_provider_workspace_id')='999' AND current_setting('mesh.alias_map_provider_network_id')='999' AND current_setting('mesh.alias_map_consumer_workspace_id')='999' AND current_setting('mesh.alias_map_consumer_network_id')='999' AND current_setting('mesh.alias_map_endpoint_id')='999'`).Scan(&restored); err != nil || !restored {
		t.Fatalf("alias scope restore=%t error=%v", restored, err)
	}
	var foreign int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM mesh.device WHERE workspace_id<>mesh_ops.current_workspace_id() OR network_id<>mesh_ops.current_network_id()`).Scan(&foreign); err != nil || foreign != 0 {
		t.Fatal("reader widened ordinary Device inventory")
	}
}

func assertAliasMapNegativePins(ctx context.Context, t *testing.T, tx pgx.Tx, endpointID string, self aliasMapIdentity) {
	t.Helper()
	for _, fault := range []struct{ name, sql string }{
		{"no compatibility", `UPDATE mesh.device_alias_client_version SET alias_version=0`},
		{"stale peer key", `UPDATE mesh.device SET current_node_key_epoch=current_node_key_epoch+1 WHERE id IN (SELECT owner_device_id FROM mesh.device_alias_lease WHERE alias_role='resource')`},
		{"stale peer session", `UPDATE mesh.device SET session_generation=session_generation+1 WHERE id IN (SELECT owner_device_id FROM mesh.device_alias_lease WHERE alias_role='resource')`},
		{"withdrawn readiness", `UPDATE mesh.device_alias_client_readiness SET state='withdrawn'`},
		{"changed policy", `UPDATE mesh_ops.network_revision SET policy_revision=policy_revision+1 WHERE workspace_id=102 AND network_id=202`},
		{"changed recovery", `UPDATE mesh.deployment SET recovery_epoch=recovery_epoch+1`},
		{"Resource lease differs from legacy", `UPDATE mesh.device_alias_lease SET address='fd00:feed::2' WHERE alias_role='resource' AND family=6`},
		{"disabled alias pool", `UPDATE mesh.address_pool SET state='quarantined' WHERE id=2297`},
		{"old endpoint generation", `UPDATE mesh.private_endpoint SET generation=generation+1 WHERE public_id=$1::UUID`},
		{"expired readiness", `UPDATE mesh.device_alias_client_readiness SET created_at=transaction_timestamp()-interval '1 hour',updated_at=transaction_timestamp()-interval '1 hour',expires_at=transaction_timestamp()-interval '1 microsecond'`},
	} {
		t.Run(fault.name, func(t *testing.T) {
			if _, err := tx.Exec(ctx, `RESET ROLE; SAVEPOINT alias_map_fault; SET LOCAL session_replication_role=replica`); err != nil {
				t.Fatal(err)
			}
			var arguments []any
			if fault.name == "old endpoint generation" {
				arguments = []any{endpointID}
			}
			if _, err := tx.Exec(ctx, fault.sql, arguments...); err != nil {
				t.Fatal(err)
			}
			assertAliasMapCount(ctx, t, tx, self, 0)
			if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT alias_map_fault`); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func appendDeviceAliasReadinessEvidence(ctx context.Context, t *testing.T, tx pgx.Tx, endpointID string, marker int64, evidenceMode string) {
	t.Helper()
	var members string
	if err := tx.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_object('public_id',lease.public_id,
        'version',mutation.after_version) ORDER BY lease.public_id)::TEXT
        FROM mesh_audit.authority_mutation AS mutation
        JOIN mesh.device_alias_client_readiness AS lease ON lease.public_id=mutation.row_public_id
        JOIN mesh.private_endpoint AS endpoint ON endpoint.id=lease.private_endpoint_id
        WHERE endpoint.public_id=$1::UUID AND mutation.aggregate_kind='device_alias_client_readiness'
          AND mutation.transaction_id=(pg_current_xact_id()::TEXT)::BIGINT`, endpointID).Scan(&members); err != nil {
		t.Fatal(err)
	}
	if evidenceMode == "wrong_batch" {
		members = "[]"
	}
	// Lock audit streams in Network scope order, after all authority/address locks.
	for index, streamID := range []int64{202, 203} {
		if evidenceMode == "consumer_only" && index == 1 {
			break
		}
		var revision, sharingRevision, version int64
		var aggregateID string
		column, sharingColumn := "consumer_network_revision", "consumer_sharing_revision"
		if streamID == 203 {
			column, sharingColumn = "provider_network_revision", "provider_sharing_revision"
		}
		// Identifiers are a fixed internal allowlist, never request input.
		query := fmt.Sprintf(`SELECT lease.%s, lease.%s, lease.public_id::TEXT, lease.version FROM mesh.device_alias_client_readiness AS lease
            JOIN mesh.private_endpoint AS endpoint ON endpoint.id=lease.private_endpoint_id
            JOIN mesh_audit.authority_mutation AS mutation ON mutation.row_public_id=lease.public_id
                AND mutation.aggregate_kind='device_alias_client_readiness' AND mutation.after_version=lease.version
                AND mutation.transaction_id=(pg_current_xact_id()::TEXT)::BIGINT
            WHERE endpoint.public_id=$1::UUID ORDER BY lease.id LIMIT 1`, column, sharingColumn)
		if err := tx.QueryRow(ctx, query, endpointID).Scan(&revision, &sharingRevision, &aggregateID, &version); err != nil {
			t.Fatal(err)
		}
		auditPayload, err := json.Marshal(map[string]any{
			"endpoint_public_id": endpointID, "mutated_readiness": json.RawMessage(members),
			"network_revision": revision, "sharing_revision": sharingRevision,
		})
		if err != nil {
			t.Fatal(err)
		}
		outboxPayload, err := json.Marshal(map[string]any{
			"endpoint_public_id": endpointID, "network_revision": revision,
			"subsystem": "sharing", "subsystem_revision": sharingRevision,
		})
		if err != nil {
			t.Fatal(err)
		}
		appendIntegrationAuthorityEvidence(ctx, t, tx, authorityEvidenceFixture{
			changePublicID: integrationPublicID("01890fa3-0000-7000-8000-", marker),
			eventPublicID:  integrationPublicID("01890fa4-0000-7000-8000-", marker+int64(index)),
			outboxPublicID: integrationPublicID("01890fa5-0000-7000-8000-", marker+int64(index)),
			streamID:       streamID, aggregateKind: "device_alias_client_readiness", aggregatePublicID: aggregateID,
			aggregateVersion: version, networkRevision: revision, action: "device_alias.client_ready",
			permission: "system.reconcile", outboxEventClass: "network.revision.advanced",
			auditPayload:  string(auditPayload),
			outboxPayload: string(outboxPayload),
		})
	}
}

func assertAliasMapPrivileges(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var safe bool
	if err := admin.QueryRow(ctx, `SELECT NOT role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolbypassrls
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid=role.oid OR member=role.oid)
 FROM pg_roles AS role WHERE rolname='mesh_device_alias_map_reader'`).Scan(&safe); err != nil || !safe {
		t.Fatal("alias map owner is not isolated")
	}
	for _, role := range []string{"mesh_runtime", "mesh_worker", "mesh_observer", "mesh_share_writer", "mesh_direct_map_reader"} {
		var read, write, execute bool
		if err := admin.QueryRow(ctx, `SELECT has_table_privilege($1,'mesh.device_alias_client_readiness','SELECT'),
 has_table_privilege($1,'mesh.device_alias_client_readiness','INSERT,UPDATE,DELETE'),
 has_function_privilege($1,'mesh_ops.load_device_alias_map_edges_v1(bytea,bytea,integer)','EXECUTE')`, role).Scan(&read, &write, &execute); err != nil {
			t.Fatal(err)
		}
		if read || write || execute != (role == "mesh_runtime") {
			t.Fatalf("excess alias readiness capability for %s", role)
		}
	}
}

func assertAliasMapAuthentication(ctx context.Context, t *testing.T, tx pgx.Tx, self aliasMapIdentity) {
	t.Helper()
	for _, fault := range []struct {
		name, role, scope, query, code string
		machine, key                   []byte
		limit                          int
	}{
		{name: "invalid limit", code: "22023", machine: self.machine, key: self.key, limit: 0},
		{name: "invalid key length", code: "22023", machine: self.machine, key: []byte{1}, limit: 257},
		{name: "unknown machine", code: "42501", machine: make([]byte, 32), key: self.key, limit: 257},
		{name: "foreign node key", code: "42501", machine: self.machine, key: make([]byte, 32), limit: 257},
		{name: "foreign ordinary scope", scope: "SELECT set_config('mesh.workspace_id','101',TRUE),set_config('mesh.network_id','201',TRUE)", code: "42501", machine: self.machine, key: self.key, limit: 257},
		{name: "missing ordinary scope", scope: "SELECT set_config('mesh.workspace_id','',TRUE),set_config('mesh.network_id','',TRUE)", code: "22023", machine: self.machine, key: self.key, limit: 257},
		{name: "worker cannot read map", role: "mesh_worker", code: "42501", machine: self.machine, key: self.key, limit: 257},
		{name: "runtime cannot read readiness", query: "SELECT count(*) FROM mesh.device_alias_client_readiness", code: "42501"},
		{name: "runtime cannot update readiness", query: "UPDATE mesh.device_alias_client_readiness SET state='withdrawn'", code: "42501"},
	} {
		t.Run(fault.name, func(t *testing.T) {
			if _, err := tx.Exec(ctx, `RESET ROLE; SAVEPOINT alias_auth_fault`); err != nil {
				t.Fatal(err)
			}
			setIntegrationScope(ctx, t, tx, self.workspace, self.network)
			role := "mesh_runtime"
			if fault.role == "mesh_worker" {
				role = "mesh_worker"
			}
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+role); err != nil {
				t.Fatal(err)
			}
			if fault.scope != "" {
				if _, err := tx.Exec(ctx, fault.scope); err != nil {
					t.Fatal(err)
				}
			}
			var err error
			if fault.query != "" {
				_, err = tx.Exec(ctx, fault.query)
			} else {
				_, err = tx.Exec(ctx, `SELECT count(*) FROM mesh_ops.load_device_alias_map_edges_v1($1::BYTEA,$2::BYTEA,$3::INTEGER)`, fault.machine, fault.key, fault.limit)
			}
			requireDeviceAliasCode(t, err, fault.code)
			if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT alias_auth_fault`); err != nil {
				t.Fatal(err)
			}
		})
	}
}
