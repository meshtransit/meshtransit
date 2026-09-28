//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func assertCompiledPacketPolicyPrivilegeContract(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) {
	t.Helper()

	var runtimeReleaseRead, runtimeRuleRead, runtimeReleaseWrite, runtimeRuleWrite bool
	var workerReleaseAccess, workerRuleAccess, runtimeAdvance, workerAdvance bool
	var runtimePublish, workerPublish, runtimeLockRelease, workerLockRelease bool
	var runtimeGroupRead, runtimeGroupWrite, workerGroupAccess bool
	var runtimeAttachGroup, workerAttachGroup bool
	if err := connection.QueryRow(ctx, `SELECT
    pg_catalog.has_table_privilege('mesh_runtime', 'mesh.policy_release', 'SELECT'),
    pg_catalog.has_table_privilege('mesh_runtime', 'mesh.compiled_policy_rule', 'SELECT'),
    pg_catalog.has_table_privilege('mesh_runtime', 'mesh.policy_release', 'INSERT')
        OR pg_catalog.has_table_privilege('mesh_runtime', 'mesh.policy_release', 'UPDATE')
        OR pg_catalog.has_table_privilege('mesh_runtime', 'mesh.policy_release', 'DELETE'),
    pg_catalog.has_table_privilege('mesh_runtime', 'mesh.compiled_policy_rule', 'INSERT')
        OR pg_catalog.has_table_privilege('mesh_runtime', 'mesh.compiled_policy_rule', 'UPDATE')
        OR pg_catalog.has_table_privilege('mesh_runtime', 'mesh.compiled_policy_rule', 'DELETE'),
    pg_catalog.has_table_privilege('mesh_worker', 'mesh.policy_release', 'SELECT')
        OR pg_catalog.has_table_privilege('mesh_worker', 'mesh.policy_release', 'INSERT')
        OR pg_catalog.has_table_privilege('mesh_worker', 'mesh.policy_release', 'UPDATE')
        OR pg_catalog.has_table_privilege('mesh_worker', 'mesh.policy_release', 'DELETE'),
    pg_catalog.has_table_privilege('mesh_worker', 'mesh.compiled_policy_rule', 'SELECT')
        OR pg_catalog.has_table_privilege('mesh_worker', 'mesh.compiled_policy_rule', 'INSERT')
        OR pg_catalog.has_table_privilege('mesh_worker', 'mesh.compiled_policy_rule', 'UPDATE')
        OR pg_catalog.has_table_privilege('mesh_worker', 'mesh.compiled_policy_rule', 'DELETE'),
    pg_catalog.has_function_privilege(
        'mesh_runtime',
        'mesh_ops.advance_network_policy_revision()',
        'EXECUTE'
    ),
    pg_catalog.has_function_privilege(
        'mesh_worker',
        'mesh_ops.advance_network_policy_revision()',
        'EXECUTE'
    ),
    pg_catalog.has_function_privilege(
        'mesh_runtime',
        'mesh_ops.publish_compiled_policy(UUID,BIGINT,BYTEA,INTEGER,TIMESTAMPTZ,JSONB)',
        'EXECUTE'
    ),
    pg_catalog.has_function_privilege(
        'mesh_worker',
        'mesh_ops.publish_compiled_policy(UUID,BIGINT,BYTEA,INTEGER,TIMESTAMPTZ,JSONB)',
        'EXECUTE'
    ),
    pg_catalog.has_function_privilege(
        'mesh_runtime',
        'mesh_ops.lock_active_policy_release()',
        'EXECUTE'
    ),
    pg_catalog.has_function_privilege(
        'mesh_worker',
        'mesh_ops.lock_active_policy_release()',
        'EXECUTE'
    ),
    pg_catalog.has_table_privilege(
        'mesh_runtime',
        'mesh.compiled_policy_resource_group_destination',
        'SELECT'
    ),
    pg_catalog.has_table_privilege(
        'mesh_runtime',
        'mesh.compiled_policy_resource_group_destination',
        'INSERT,UPDATE,DELETE'
    ),
    pg_catalog.has_table_privilege(
        'mesh_worker',
        'mesh.compiled_policy_resource_group_destination',
        'SELECT,INSERT,UPDATE,DELETE'
    ),
    pg_catalog.has_function_privilege(
        'mesh_runtime',
        'mesh_ops.attach_policy_resource_group_destinations(UUID,TIMESTAMPTZ,JSONB)',
        'EXECUTE'
    ),
    pg_catalog.has_function_privilege(
        'mesh_worker',
        'mesh_ops.attach_policy_resource_group_destinations(UUID,TIMESTAMPTZ,JSONB)',
        'EXECUTE'
    )`).Scan(
		&runtimeReleaseRead,
		&runtimeRuleRead,
		&runtimeReleaseWrite,
		&runtimeRuleWrite,
		&workerReleaseAccess,
		&workerRuleAccess,
		&runtimeAdvance,
		&workerAdvance,
		&runtimePublish,
		&workerPublish,
		&runtimeLockRelease,
		&workerLockRelease,
		&runtimeGroupRead,
		&runtimeGroupWrite,
		&workerGroupAccess,
		&runtimeAttachGroup,
		&workerAttachGroup,
	); err != nil {
		t.Fatalf("query compiled packet policy privilege contract: %v", err)
	}
	if !runtimeReleaseRead || !runtimeRuleRead || runtimeReleaseWrite || runtimeRuleWrite ||
		workerReleaseAccess || workerRuleAccess || !runtimeAdvance || workerAdvance ||
		!runtimePublish || workerPublish || !runtimeLockRelease || workerLockRelease ||
		!runtimeGroupRead || runtimeGroupWrite || workerGroupAccess ||
		!runtimeAttachGroup || workerAttachGroup {
		t.Fatalf(
			"compiled policy privileges: runtime read=%t/%t write=%t/%t "+
				"worker access=%t/%t revision execute=%t/%t publish execute=%t/%t "+
				"release lock execute=%t/%t group read/write/worker=%t/%t/%t "+
				"group attach execute=%t/%t",
			runtimeReleaseRead,
			runtimeRuleRead,
			runtimeReleaseWrite,
			runtimeRuleWrite,
			workerReleaseAccess,
			workerRuleAccess,
			runtimeAdvance,
			workerAdvance,
			runtimePublish,
			workerPublish,
			runtimeLockRelease,
			workerLockRelease,
			runtimeGroupRead,
			runtimeGroupWrite,
			workerGroupAccess,
			runtimeAttachGroup,
			workerAttachGroup,
		)
	}
}

func assertCompiledPacketPolicyRuleImmutability(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) {
	t.Helper()

	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin compiled policy immutability transaction: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, transaction)
	setIntegrationScope(ctx, t, transaction, 103, 203)
	_, err = transaction.Exec(ctx, `UPDATE mesh.compiled_policy_rule
SET destination_ports = '{[53,54)}'::INT4MULTIRANGE
WHERE workspace_id = 103 AND network_id = 203`)
	assertPostgreSQLCode(t, err, "23514")
}
