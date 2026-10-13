//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// assertMapNetworkDirectEndpoints proves schema 154: for every Network,
// map_network_has_direct_endpoints_v1 says whether it holds a ready legacy
// direct endpoint on either side, as the table does, and only the runtime may
// run it.
func assertMapNetworkDirectEndpoints(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT network.workspace_id, network.id, EXISTS (
            SELECT 1 FROM mesh.direct_device_endpoint AS endpoint
            WHERE endpoint.state = 'ready'
              AND ((endpoint.provider_workspace_id = network.workspace_id AND endpoint.provider_network_id = network.id)
                OR (endpoint.consumer_workspace_id = network.workspace_id AND endpoint.consumer_network_id = network.id)))
        FROM mesh.network AS network ORDER BY 1, 2`)
	if err != nil {
		t.Fatalf("list Networks: %v", err)
	}
	type networkEndpoints struct {
		workspace, network int64
		want               bool
	}
	networks, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (networkEndpoints, error) {
		var value networkEndpoints
		return value, row.Scan(&value.workspace, &value.network, &value.want)
	})
	if err != nil {
		t.Fatal(err)
	}
	holding := 0
	for _, network := range networks {
		transaction, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var got bool
		err = transaction.QueryRow(ctx, `SELECT pg_catalog.set_config('mesh.workspace_id', $1::BIGINT::TEXT, TRUE),
            pg_catalog.set_config('mesh.network_id', $2::BIGINT::TEXT, TRUE)`, network.workspace, network.network).Scan(
			new(string), new(string))
		if err == nil {
			err = transaction.QueryRow(ctx, `SELECT mesh_ops.map_network_has_direct_endpoints_v1()`).Scan(&got)
		}
		rollbackIntegrationTransaction(ctx, t, transaction)
		if err != nil || got != network.want {
			t.Fatalf("Network %d/%d: direct endpoints = %t (err %v), want %t",
				network.workspace, network.network, got, err, network.want)
		}
		if got {
			holding++
		}
	}
	t.Logf("direct endpoints: %d of %d Networks hold one", holding, len(networks))
	for _, check := range []struct {
		role string
		want bool
	}{{"mesh_runtime", true}, {"mesh_worker", false}, {"mesh_share_writer", false}} {
		var got bool
		if err := admin.QueryRow(ctx, `SELECT pg_catalog.has_function_privilege($1,
            'mesh_ops.map_network_has_direct_endpoints_v1()', 'EXECUTE')`, check.role).Scan(&got); err != nil ||
			got != check.want {
			t.Fatalf("%s may run the direct endpoint reader: %t (err %v), want %t", check.role, got, err, check.want)
		}
	}
}
