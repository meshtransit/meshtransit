//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing"
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
		// The share took the alias endpoint, so the canonical-address reader has no
		// readiness row and must not project the peer from either perspective.
		var edges int
		var restored string
		if err := tx.QueryRow(ctx, `SELECT count(*)::INTEGER
            FROM mesh_ops.load_direct_share_map_edges_v1($1::BYTEA,$2::BYTEA,257)`,
			perspective.self.machine, perspective.self.key).Scan(&edges); err != nil {
			t.Fatalf("load direct edges Network %d: %v", perspective.self.network, err)
		}
		if edges != 0 {
			t.Fatalf("direct reader projected %d canonical edges for an alias share, peer %s", edges, perspective.peer)
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
