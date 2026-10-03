//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
)

func assertSharingDependenciesBeforeRule(ctx context.Context, t *testing.T, tx pgx.Tx, provider, consumer aliasMapIdentity) {
	t.Helper()
	if _, err := tx.Exec(ctx, `RESET ROLE; SAVEPOINT dependencies_without_rule; SET LOCAL session_replication_role=replica;
 DELETE FROM mesh.compiled_policy_imported_resource_destination WHERE workspace_id=102 AND network_id=202;
 SET LOCAL session_replication_role=origin`); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []struct {
		name         string
		machine, key []byte
	}{
		{"wrong machine", provider.machine, consumer.key},
		{"wrong node key", consumer.machine, provider.key},
	} {
		if _, err := tx.Exec(ctx, `RESET ROLE; SAVEPOINT dependency_auth`); err != nil {
			t.Fatal(err)
		}
		setIntegrationScope(ctx, t, tx, consumer.workspace, consumer.network)
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
			t.Fatal(err)
		}
		_, err := tx.Exec(ctx, `SELECT count(*) FROM mesh_ops.load_device_sharing_dependencies_v1($1::BYTEA,$2::BYTEA,257)`, invalid.machine, invalid.key)
		requireDeviceAliasCode(t, err, "42501")
		if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT dependency_auth`); err != nil {
			t.Fatal(err)
		}
	}
	for _, self := range []aliasMapIdentity{provider, consumer} {
		want := 1
		if self.workspace == provider.workspace && self.network == provider.network {
			want = 2
		}
		assertSharingDependencyCount(ctx, t, tx, self, want)
		assertAliasMapCount(ctx, t, tx, self, 0)
	}
	if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT dependencies_without_rule`); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []struct{ name, sql string }{
		{"stale export constraint", `UPDATE mesh.resource_export SET constraint_hash=decode(repeat('f1',32),'hex')`},
		{"stale Resource", `UPDATE mesh.resource SET version=version+1`},
		{"expired contract", `UPDATE mesh.trust_contract SET expires_at=transaction_timestamp()-interval '1 microsecond'`},
		{"changed consumer authority", `UPDATE mesh.network SET authority_generation=authority_generation+1 WHERE id=202`},
		{"quarantined recovery", `UPDATE mesh.deployment SET recovery_state='quarantined'`},
		{"withdrawn import", `UPDATE mesh.imported_resource SET state='invalidated',ended_at=transaction_timestamp()`},
	} {
		t.Run("sharing dependency "+fault.name, func(t *testing.T) {
			if _, err := tx.Exec(ctx, `RESET ROLE; SAVEPOINT dependency_fault; SET LOCAL session_replication_role=replica`); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, fault.sql); err != nil {
				t.Fatal(err)
			}
			if fault.name == "quarantined recovery" {
				setIntegrationScope(ctx, t, tx, consumer.workspace, consumer.network)
				if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
					t.Fatal(err)
				}
				_, err := tx.Exec(ctx, `SELECT count(*) FROM mesh_ops.load_device_sharing_dependencies_v1($1::BYTEA,$2::BYTEA,257)`, consumer.machine, consumer.key)
				requireDeviceAliasCode(t, err, "42501")
			} else {
				assertSharingDependencyCount(ctx, t, tx, consumer, 0)
			}
			if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT dependency_fault`); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func assertSharingDependencyCount(ctx context.Context, t *testing.T, tx pgx.Tx, self aliasMapIdentity, want int) {
	t.Helper()
	if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{}
	if want > 0 {
		networks := []int64{203}
		if self.network == 203 {
			networks = []int64{202, 204}
		}
		rows, err := tx.Query(ctx, `SELECT workspace.public_id::TEXT,network.public_id::TEXT FROM mesh.network AS network JOIN mesh.workspace AS workspace ON workspace.id=network.workspace_id WHERE network.id=ANY($1::BIGINT[])`, networks)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var workspace, network string
			if err := rows.Scan(&workspace, &network); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			expected[network] = workspace
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if len(expected) != want {
			t.Fatal("invalid dependency expectation")
		}
	}
	setIntegrationScope(ctx, t, tx, self.workspace, self.network)
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime;
 SELECT set_config('mesh.alias_map_provider_workspace_id','999',TRUE),set_config('mesh.alias_map_provider_network_id','999',TRUE),
 set_config('mesh.alias_map_consumer_workspace_id','999',TRUE),set_config('mesh.alias_map_consumer_network_id','999',TRUE),set_config('mesh.alias_map_endpoint_id','999',TRUE),set_config('mesh.direct_map_remote_network_id','999',TRUE)`); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query(ctx, `SELECT dependency::TEXT FROM mesh_ops.load_device_sharing_dependencies_v1($1::BYTEA,$2::BYTEA,257) AS dependency`, self.machine, self.key)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			t.Fatal(err)
		}
		var record struct {
			WorkspaceID string `json:"workspace_id"`
			NetworkID   string `json:"network_id"`
		}
		if err := json.Unmarshal([]byte(encoded), &record); err != nil {
			t.Fatal(err)
		}
		if workspace, ok := expected[record.NetworkID]; !ok || workspace != record.WorkspaceID {
			t.Fatal("unexpected or duplicate dependency scope")
		}
		delete(expected, record.NetworkID)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != want || len(expected) != 0 {
		t.Fatalf("sharing dependencies=%d want=%d", count, want)
	}
	rows.Close()
	var restored bool
	if err := tx.QueryRow(ctx, `SELECT current_setting('mesh.alias_map_provider_workspace_id')='999' AND current_setting('mesh.alias_map_provider_network_id')='999'
 AND current_setting('mesh.alias_map_consumer_workspace_id')='999' AND current_setting('mesh.alias_map_consumer_network_id')='999' AND current_setting('mesh.alias_map_endpoint_id')='999' AND current_setting('mesh.direct_map_remote_network_id')='999'`).Scan(&restored); err != nil || !restored {
		t.Fatal("dependency reader leaked scope")
	}
	var foreign int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM mesh.device WHERE workspace_id<>mesh_ops.current_workspace_id() OR network_id<>mesh_ops.current_network_id()`).Scan(&foreign); err != nil || foreign != 0 {
		t.Fatal(fmt.Sprintf("dependency reader widened Device inventory: foreign=%d", foreign), err)
	}
}
