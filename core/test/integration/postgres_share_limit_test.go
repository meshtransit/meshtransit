//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// assertShareLimitGuardPrivileges checks the schema 147 acceptance guard:
// runtime accepts through decide v5 and cannot count contracts itself; the
// share writer can, and below the limit nothing is reached.
func assertShareLimitGuardPrivileges(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	for _, check := range []struct {
		role, function string
		want           bool
	}{
		{"mesh_runtime", "mesh_ops.decide_resource_share_offer_v5(bigint,bigint,bigint,bigint,uuid,uuid,uuid,uuid,uuid,bigint,bytea,text,uuid,uuid,text,uuid,text,bigint,bigint,bigint,bigint,bigint,timestamp with time zone)", true},
		{"mesh_worker", "mesh_ops.decide_resource_share_offer_v5(bigint,bigint,bigint,bigint,uuid,uuid,uuid,uuid,uuid,bigint,bytea,text,uuid,uuid,text,uuid,text,bigint,bigint,bigint,bigint,bigint,timestamp with time zone)", false},
		{"mesh_runtime", "mesh_ops.share_limit_reached_v1(bigint,bigint,bigint,bigint,bigint)", false},
		{"mesh_worker", "mesh_ops.share_limit_reached_v1(bigint,bigint,bigint,bigint,bigint)", false},
		{"mesh_share_writer", "mesh_ops.share_limit_reached_v1(bigint,bigint,bigint,bigint,bigint)", true},
		{"mesh_worker", "mesh_ops.prepare_device_alias_change_v3(uuid,uuid,uuid,bigint,bigint,bigint,uuid[],uuid,uuid,text)", true},
		{"mesh_runtime", "mesh_ops.prepare_device_alias_change_v3(uuid,uuid,uuid,bigint,bigint,bigint,uuid[],uuid,uuid,text)", false},
		{"mesh_runtime", "mesh_ops.load_device_alias_map_edges_v5(bytea,bytea,integer)", true},
		{"mesh_runtime", "mesh_ops.load_device_sharing_dependencies_v3(bytea,bytea,integer)", true},
		{"mesh_runtime", "mesh_ops.load_device_alias_map_edges_v6(bytea,bytea,integer)", true},
		{"mesh_runtime", "mesh_ops.load_device_sharing_dependencies_v4(bytea,bytea,integer)", true},
		{"mesh_worker", "mesh_ops.load_device_alias_map_edges_v6(bytea,bytea,integer)", false},
		{"mesh_share_writer", "mesh_ops.load_device_sharing_dependencies_v4(bytea,bytea,integer)", false},
		{"mesh_worker", "mesh_ops.load_device_alias_map_edges_v5(bytea,bytea,integer)", false},
		{"mesh_device_alias_writer", "mesh_ops.load_device_alias_map_endpoint_edges_v1(bytea,bytea,uuid)", true},
		{"mesh_runtime", "mesh_ops.load_device_alias_map_endpoint_edges_v1(bytea,bytea,uuid)", false},
		{"mesh_worker", "mesh_ops.load_device_alias_map_endpoint_edges_v1(bytea,bytea,uuid)", false},
	} {
		var allowed bool
		if err := admin.QueryRow(ctx, `SELECT has_function_privilege($1, $2, 'EXECUTE')`, check.role, check.function).Scan(&allowed); err != nil {
			t.Fatalf("%s on %s: %v", check.role, check.function, err)
		}
		if allowed != check.want {
			t.Fatalf("%s EXECUTE on %s = %t, want %t", check.role, check.function, allowed, check.want)
		}
	}
	var reached *string
	if err := admin.QueryRow(ctx, `SELECT mesh_ops.share_limit_reached_v1(1, 1, 1, 2, NULL)`).Scan(&reached); err != nil {
		t.Fatal(err)
	}
	if reached != nil {
		t.Fatalf("an empty deployment reached the %s share limit", *reached)
	}
}

// assertPolicyImportedResourceScalePrivileges checks the schema 148
// publication chain: runtime publishes and resolves through v2; the internal
// helpers stay closed to it.
func assertPolicyImportedResourceScalePrivileges(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	const (
		publish = "mesh_ops.publish_compiled_policy_v2(uuid,bigint,bytea,integer,timestamp with time zone,jsonb)"
		resolve = "mesh_ops.resolve_imported_policy_destinations_v2(bigint,bigint,bigint,bigint,uuid,uuid,uuid,uuid,uuid[],timestamp with time zone)"
		lock    = "mesh_ops.lock_and_resolve_policy_imported_resources_internal_v2(jsonb,timestamp with time zone)"
		attach  = "mesh_ops.attach_policy_imported_resource_destinations_internal_v2(uuid,timestamp with time zone,jsonb,jsonb)"
	)
	for _, check := range []struct {
		role, function string
		want           bool
	}{
		{"mesh_runtime", publish, true}, {"mesh_worker", publish, false},
		{"mesh_runtime", resolve, true}, {"mesh_worker", resolve, false},
		{"mesh_runtime", lock, false}, {"mesh_migrator", lock, true},
		{"mesh_runtime", attach, false}, {"mesh_share_writer", attach, false},
	} {
		var allowed bool
		if err := admin.QueryRow(ctx, `SELECT has_function_privilege($1, $2, 'EXECUTE')`, check.role, check.function).Scan(&allowed); err != nil {
			t.Fatalf("%s on %s: %v", check.role, check.function, err)
		}
		if allowed != check.want {
			t.Fatalf("%s EXECUTE on %s = %t, want %t", check.role, check.function, allowed, check.want)
		}
	}
}
