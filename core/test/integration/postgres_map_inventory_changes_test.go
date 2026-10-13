//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
)

// mapInventoryChangeTriggers are schema 153's triggers, fired here at each
// statement instead of at commit so a transaction that rolls back can watch
// them; every other deferred check keeps its commit-time behaviour.
const mapInventoryChangeTriggers = `mesh.device_map_inventory_change_write, mesh.device_map_inventory_change_update,
    mesh.device_machine_key_epoch_map_inventory_change_write, mesh.device_machine_key_epoch_map_inventory_change_update,
    mesh.device_node_key_epoch_map_inventory_change_write, mesh.device_node_key_epoch_map_inventory_change_update,
    mesh.node_address_lease_map_inventory_change_write, mesh.node_address_lease_map_inventory_change_update,
    mesh.principal_map_inventory_change_update`

type mapInventoryChange struct {
	seq      int64
	listed   bool
	hostname string
}

// assertMapInventoryChanges proves schema 153: writes that change what the
// inventory lists number the Network's change counter once per transaction
// and record their Devices; the change reader lists each such Device as the
// inventory does, or as removed; other writes record nothing; and only the
// runtime may read the changes. Its writes roll back.
func assertMapInventoryChanges(ctx context.Context, t *testing.T) {
	t.Helper()
	adminConfig := loadIntegrationAdminConfig(t)
	admin := openIntegrationPostgreSQLConnection(ctx, t, adminConfig.PostgreSQL.Address,
		adminConfig.PostgreSQL.Database, adminConfig.PostgreSQL.User, adminConfig.PostgreSQL.PasswordFile,
		adminConfig.PostgreSQL.CAFile, adminConfig.ConnectTimeout)
	assertMapInventoryChangePrivileges(ctx, t, admin)

	seed := newShareScaleSeed(ctx, t, admin, 3)
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin map inventory change check: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, transaction)
	if _, err := transaction.Exec(ctx, "SET CONSTRAINTS "+mapInventoryChangeTriggers+" IMMEDIATE"); err != nil {
		t.Fatalf("fire the change triggers immediately: %v", err)
	}
	if _, err := transaction.Exec(ctx, `SELECT pg_catalog.set_config('mesh.workspace_id', $1::BIGINT::TEXT, TRUE),
        pg_catalog.set_config('mesh.network_id', $2::BIGINT::TEXT, TRUE)`, shareScaleWorkspace, shareScaleProvider); err != nil {
		t.Fatalf("set map inventory scope: %v", err)
	}
	head := func() int64 {
		t.Helper()
		var value int64
		if err := transaction.QueryRow(ctx, `SELECT mesh_ops.read_map_inventory_change_head_v1()`).Scan(&value); err != nil {
			t.Fatalf("read the change counter: %v", err)
		}
		return value
	}
	changes := func(since int64) map[int64]mapInventoryChange {
		t.Helper()
		rows, err := transaction.Query(ctx, `SELECT change_seq, numeric_node_id, listed, COALESCE(hostname, '')
            FROM mesh_ops.load_map_network_device_changes_v1($1, 1000)`, since)
		if err != nil {
			t.Fatalf("read the changes after %d: %v", since, err)
		}
		defer rows.Close()
		found := map[int64]mapInventoryChange{}
		for rows.Next() {
			var device int64
			var change mapInventoryChange
			if err := rows.Scan(&change.seq, &device, &change.listed, &change.hostname); err != nil {
				t.Fatal(err)
			}
			found[device] = change
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return found
	}
	// Each step stands for its own transaction: one number per transaction.
	// A session setting cannot make a transaction reuse another's number.
	nextTransaction := func() {
		t.Helper()
		setIntegrationChange(ctx, t, transaction, shareScaleUUID(t))
		// As if another transaction had numbered the last change.
		if _, err := transaction.Exec(ctx, `UPDATE mesh_ops.map_inventory_change_head SET numbered_by = '1'::XID8
            WHERE workspace_id = $1 AND network_id = $2`, shareScaleWorkspace, shareScaleProvider); err != nil {
			t.Fatal(err)
		}
	}
	exec := func(query string, arguments ...any) {
		t.Helper()
		if _, err := transaction.Exec(ctx, query, arguments...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	providers := seed.providers

	before := head()
	nextTransaction()
	exec(`SELECT pg_catalog.set_config('mesh.map_inventory_seq_' || $1::BIGINT::TEXT || '_' || $2::BIGINT::TEXT,
        $3::BIGINT::TEXT, TRUE)`, shareScaleWorkspace, shareScaleProvider, before)
	seed.sides[0].insert(ctx, t, transaction)
	registered := head()
	joined := changes(before)
	if registered <= before || len(joined) != len(providers) {
		t.Fatalf("registration: counter %d -> %d, %d changes, want one number for %d Devices",
			before, registered, len(joined), len(providers))
	}
	for _, provider := range providers {
		if change := joined[provider.id]; !change.listed || change.seq != registered {
			t.Fatalf("registered Device %d: %+v", provider.id, change)
		}
	}
	var differing int
	if err := transaction.QueryRow(ctx, `SELECT count(*)
        FROM mesh_ops.load_map_network_device_changes_v1($1, 1000) AS change
        LEFT JOIN mesh_ops.load_map_network_devices_v1(200001) AS listed
          ON listed.numeric_node_id = change.numeric_node_id
        WHERE change.listed AND (listed.numeric_node_id IS NULL OR
            (change.numeric_owner_id, change.node_public_id, change.owner_public_id, change.hostname, change.machine_key,
             change.node_key, change.session_generation, change.created_at, change.key_expiry, change.addresses)
            IS DISTINCT FROM
            (listed.numeric_owner_id, listed.node_public_id, listed.owner_public_id, listed.hostname, listed.machine_key,
             listed.node_key, listed.session_generation, listed.created_at, listed.key_expiry, listed.addresses))`,
		before).Scan(&differing); err != nil || differing != 0 {
		t.Fatalf("%d listed changes differ from the inventory (err %v)", differing, err)
	}

	nextTransaction()
	exec(`UPDATE mesh.device SET updated_at = updated_at + interval '1 millisecond', version = version + 1
        WHERE id = $1`, providers[0].id)
	if got := head(); got != registered {
		t.Fatalf("a write the inventory does not read moved the counter %d -> %d", registered, got)
	}

	nextTransaction()
	renamed := fmt.Sprintf("renamed-%d.example", providers[0].id)
	exec(`UPDATE mesh.device SET hostname = $2, hostname_key = $2, version = version + 1 WHERE id = $1`,
		providers[0].id, renamed)
	afterRename := head()
	if got := changes(registered); afterRename <= registered || len(got) != 1 ||
		!got[providers[0].id].listed || got[providers[0].id].hostname != renamed {
		t.Fatalf("rename: counter %d, changes %+v", afterRename, got)
	}

	nextTransaction()
	exec(`UPDATE mesh.node_address_lease SET state = 'released', released_at = clock_timestamp(),
        version = version + 1, updated_at = clock_timestamp()
        WHERE device_id = $1 AND state = 'active' AND lease_role = 'primary'`, providers[1].id)
	afterRelease := head()
	if got := changes(afterRename); len(got) != 1 || got[providers[1].id].listed {
		t.Fatalf("a Device without an address must be removed: %+v", got)
	}

	nextTransaction()
	exec(`UPDATE mesh.principal SET state = 'suspended', version = version + 1,
        updated_at = GREATEST(clock_timestamp(), updated_at) WHERE id = 11`)
	if got := changes(afterRelease); got[providers[2].id].listed || got[providers[2].id].seq <= afterRelease {
		t.Fatalf("a suspended owner's Device must be removed: %+v", got[providers[2].id])
	}
}

func assertMapInventoryChangePrivileges(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	for _, check := range []struct {
		query string
		want  bool
	}{
		{`SELECT pg_catalog.has_function_privilege('mesh_runtime',
            'mesh_ops.load_map_network_device_changes_v1(bigint,integer)', 'EXECUTE')`, true},
		{`SELECT pg_catalog.has_function_privilege('mesh_runtime',
            'mesh_ops.read_map_inventory_change_head_v1()', 'EXECUTE')`, true},
		{`SELECT pg_catalog.has_function_privilege('mesh_worker',
            'mesh_ops.load_map_network_device_changes_v1(bigint,integer)', 'EXECUTE')`, false},
		{`SELECT pg_catalog.has_function_privilege('mesh_runtime',
            'mesh_ops.stamp_map_inventory_change_internal_v1(bigint,bigint,bigint[])', 'EXECUTE')`, false},
		{`SELECT pg_catalog.has_table_privilege('mesh_runtime', 'mesh_ops.map_inventory_change', 'SELECT')`, false},
		{`SELECT pg_catalog.has_table_privilege('mesh_runtime', 'mesh_ops.map_inventory_change_head', 'UPDATE')`, false},
	} {
		var got bool
		if err := admin.QueryRow(ctx, check.query).Scan(&got); err != nil || got != check.want {
			t.Fatalf("%s = %t (err %v), want %t", check.query, got, err, check.want)
		}
	}
}
