//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

// Probe the authenticated reader inside the publication transaction, before its
// fixture rollback. Production roles cannot bypass triggers or spoof evidence.
func assertDirectMapSQLProjection(ctx context.Context, t *testing.T, tx pgx.Tx, destination sharing.PolicyDestination) {
	t.Helper()
	type identity struct {
		machine, key []byte
		id           string
		network      int64
	}
	var provider, consumer identity
	if err := tx.QueryRow(ctx, `SELECT provider.public_id::TEXT, provider_machine.fingerprint, provider_node.public_key,
        consumer.public_id::TEXT, consumer_machine.fingerprint, consumer_node.public_key
        FROM mesh.compiled_policy_imported_resource_destination AS rule
        JOIN mesh.resource_device_target AS target ON target.resource_id = rule.destination_resource_id
         AND target.target_generation = rule.target_generation
        JOIN mesh.device AS provider ON provider.id = target.device_id
        JOIN mesh.device_machine_key_epoch AS provider_machine ON provider_machine.device_id = provider.id
         AND provider_machine.epoch = provider.current_machine_key_epoch
        JOIN mesh.device_node_key_epoch AS provider_node ON provider_node.device_id = provider.id
         AND provider_node.epoch = provider.current_node_key_epoch
        JOIN mesh.device AS consumer ON consumer.id = rule.source_device_id
        JOIN mesh.device_machine_key_epoch AS consumer_machine ON consumer_machine.device_id = consumer.id
         AND consumer_machine.epoch = consumer.current_machine_key_epoch
        JOIN mesh.device_node_key_epoch AS consumer_node ON consumer_node.device_id = consumer.id
         AND consumer_node.epoch = consumer.current_node_key_epoch
        JOIN mesh.imported_resource AS imported ON imported.id = rule.imported_resource_id
        WHERE imported.public_id = $1::UUID`, destination.ImportedResourceID().String()).Scan(
		&provider.id, &provider.machine, &provider.key, &consumer.id, &consumer.machine, &consumer.key,
	); err != nil {
		t.Fatal(err)
	}
	provider.network, consumer.network = 203, 204
	for _, perspective := range []struct {
		self identity
		peer string
	}{
		{provider, consumer.id}, {consumer, provider.id},
	} {
		setIntegrationScope(ctx, t, tx, 103, perspective.self.network)
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('mesh.direct_map_remote_network_id', '999999', TRUE)`); err != nil {
			t.Fatal(err)
		}
		var encoded, restored string
		if err := tx.QueryRow(ctx, `SELECT edge::TEXT
            FROM mesh_ops.load_direct_share_map_edges_v1($1::BYTEA,$2::BYTEA,257) AS edge`,
			perspective.self.machine, perspective.self.key).Scan(&encoded); err != nil {
			t.Fatalf("load direct edges Network %d: %v", perspective.self.network, err)
		}
		var record struct {
			CeilingProfile string `json:"ceiling_profile"`
			Peer           struct {
				ID string `json:"id"`
			} `json:"peer"`
			Rule struct {
				SourceID string   `json:"source_id"`
				Protocol string   `json:"protocol"`
				Ranges   [][2]int `json:"ranges"`
			} `json:"rule"`
		}
		if err := json.Unmarshal([]byte(encoded), &record); err != nil {
			t.Fatal(err)
		}
		if record.CeilingProfile != "no-additional-traffic-ceilings-v1" || record.Peer.ID != perspective.peer ||
			record.Rule.SourceID != consumer.id || record.Rule.Protocol != "tcp" || len(record.Rule.Ranges) != 1 || record.Rule.Ranges[0] != [2]int{443, 443} {
			t.Fatal("reader widened or substituted the directed consumer grant")
		}
		if err := tx.QueryRow(ctx, `SELECT current_setting('mesh.direct_map_remote_network_id')`).Scan(&restored); err != nil {
			t.Fatal(err)
		}
		if restored != "999999" {
			t.Fatal("reader leaked its derived remote scope")
		}
		var foreignDevices int
		if err := tx.QueryRow(ctx, `SELECT count(*)::INTEGER FROM mesh.device WHERE network_id <> mesh_ops.current_network_id()`).Scan(&foreignDevices); err != nil {
			t.Fatal(err)
		}
		if foreignDevices != 0 {
			t.Fatal("bilateral reader widened ordinary inventory RLS")
		}
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE NONE`); err != nil {
			t.Fatal(err)
		}
	}
	setIntegrationScope(ctx, t, tx, 103, 204)
	for _, fault := range []struct{ name, query string }{
		{"profile blocked", `UPDATE mesh.deployment SET direct_sharing_ceiling_profile = 'blocked'`},
		{"Resource retargeted", `UPDATE mesh.resource SET target_generation = target_generation + 1 WHERE id = (SELECT resource_id FROM mesh.trust_contract WHERE public_id = $1::UUID)`},
		{"consumer release changed", `UPDATE mesh_ops.network_revision SET policy_revision = policy_revision + 1 WHERE workspace_id = 103 AND network_id = 204`},
		{"provider Node epoch changed", `UPDATE mesh.device SET current_node_key_epoch = current_node_key_epoch + 1 WHERE id = (SELECT target_device_id FROM mesh.direct_device_endpoint WHERE trust_contract_id = (SELECT id FROM mesh.trust_contract WHERE public_id = $1::UUID))`},
		{"provider session changed", `UPDATE mesh.device SET session_generation = session_generation + 1 WHERE id = (SELECT target_device_id FROM mesh.direct_device_endpoint WHERE trust_contract_id = (SELECT id FROM mesh.trust_contract WHERE public_id = $1::UUID))`},
		{"provider expired", `UPDATE mesh.device SET expires_at = transaction_timestamp() - interval '1 microsecond' WHERE id = (SELECT target_device_id FROM mesh.direct_device_endpoint WHERE trust_contract_id = (SELECT id FROM mesh.trust_contract WHERE public_id = $1::UUID))`},
		{"lease generation changed", `UPDATE mesh.node_address_lease SET generation = generation + 1 WHERE id = (SELECT target_address_lease_id FROM mesh.direct_device_endpoint WHERE trust_contract_id = (SELECT id FROM mesh.trust_contract WHERE public_id = $1::UUID))`},
		{"provider authority changed", `UPDATE mesh.network SET authority_generation = authority_generation + 1 WHERE id = 203`},
		{"recovery epoch changed", `UPDATE mesh.deployment SET recovery_epoch = recovery_epoch + 1`},
		{"import version changed", `UPDATE mesh.imported_resource SET version = version + 1 WHERE trust_contract_id = (SELECT id FROM mesh.trust_contract WHERE public_id = $1::UUID)`},
	} {
		t.Run(fault.name, func(t *testing.T) {
			if _, err := tx.Exec(ctx, `SAVEPOINT direct_map_fault`); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
				t.Fatal(err)
			}
			var arguments []any
			if fault.name != "profile blocked" && fault.name != "consumer release changed" && fault.name != "provider authority changed" && fault.name != "recovery epoch changed" {
				arguments = []any{destination.Contract().ID().String()}
			}
			if _, err := tx.Exec(ctx, fault.query, arguments...); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*)::INTEGER
                FROM mesh_ops.load_direct_share_map_edges_v1($1::BYTEA,$2::BYTEA,257)`, consumer.machine, consumer.key).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatal("stale bilateral authority retained an edge")
			}
			if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT direct_map_fault`); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, invalid := range []struct {
		name    string
		network int64
		key     []byte
		limit   int
	}{
		{"spoofed Network scope", 203, consumer.key, 257},
		{"mismatched Node key", 204, provider.key, 257},
		{"over limit", 204, consumer.key, 258},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			if _, err := tx.Exec(ctx, `SAVEPOINT direct_map_auth`); err != nil {
				t.Fatal(err)
			}
			setIntegrationScope(ctx, t, tx, 103, invalid.network)
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*)::INTEGER FROM mesh_ops.load_direct_share_map_edges_v1($1::BYTEA,$2::BYTEA,$3::INTEGER)`, consumer.machine, invalid.key, invalid.limit).Scan(&count); err == nil {
				t.Fatal("unauthenticated or unbounded bilateral read succeeded")
			}
			if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT direct_map_auth`); err != nil {
				t.Fatal(err)
			}
		})
	}
}
