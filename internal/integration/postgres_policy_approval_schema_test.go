//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func assertPolicyApprovalPersistencePrivilegeContract(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) {
	t.Helper()

	var tableCount int
	var forcedRLS, runtimeTableAccess, nonRuntimeTableAccess bool
	if err := connection.QueryRow(ctx, `SELECT
    pg_catalog.count(*),
    pg_catalog.bool_and(relation.relrowsecurity AND relation.relforcerowsecurity),
    pg_catalog.bool_or(
        pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'SELECT')
        OR pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'INSERT')
        OR pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'UPDATE')
        OR pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'DELETE')
    ),
    pg_catalog.bool_or(
        pg_catalog.has_table_privilege('mesh_worker', relation.oid, 'SELECT,INSERT,UPDATE,DELETE')
        OR pg_catalog.has_table_privilege('mesh_observer', relation.oid, 'SELECT,INSERT,UPDATE,DELETE')
        OR pg_catalog.has_table_privilege('mesh_audit_writer', relation.oid, 'SELECT,INSERT,UPDATE,DELETE')
        OR pg_catalog.has_table_privilege('mesh_share_writer', relation.oid, 'SELECT,INSERT,UPDATE,DELETE')
    )
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = 'mesh'
  AND relation.relname IN ('policy_approval_request', 'policy_approval_evidence')`).Scan(
		&tableCount,
		&forcedRLS,
		&runtimeTableAccess,
		&nonRuntimeTableAccess,
	); err != nil {
		t.Fatalf("query Policy approval table privileges: %v", err)
	}
	if tableCount != 2 || !forcedRLS || runtimeTableAccess || nonRuntimeTableAccess {
		t.Fatalf(
			"Policy approval tables count=%d forced-RLS=%t runtime-access=%t non-runtime-access=%t",
			tableCount,
			forcedRLS,
			runtimeTableAccess,
			nonRuntimeTableAccess,
		)
	}

	var functionCount int
	var runtimeFunctions, nonRuntimeFunctions bool
	if err := connection.QueryRow(ctx, `SELECT
    pg_catalog.count(*),
    pg_catalog.bool_and(pg_catalog.has_function_privilege(
        'mesh_runtime', procedure.oid, 'EXECUTE'
    )),
    pg_catalog.bool_or(
        pg_catalog.has_function_privilege('mesh_worker', procedure.oid, 'EXECUTE')
        OR pg_catalog.has_function_privilege('mesh_observer', procedure.oid, 'EXECUTE')
        OR pg_catalog.has_function_privilege('mesh_audit_writer', procedure.oid, 'EXECUTE')
        OR pg_catalog.has_function_privilege('mesh_share_writer', procedure.oid, 'EXECUTE')
    )
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
WHERE namespace.nspname = 'mesh_ops'
  AND procedure.proname IN (
      'create_policy_approval_request_v1',
      'lock_policy_approval_request_v1',
      'load_policy_approval_request_v1',
      'approve_policy_approval_request_v1',
      'load_policy_approval_evidence_v1',
      'lock_policy_approval_for_publication_v1',
      'consume_policy_approval_for_publication_v1'
  )`).Scan(&functionCount, &runtimeFunctions, &nonRuntimeFunctions); err != nil {
		t.Fatalf("query Policy approval function privileges: %v", err)
	}
	if functionCount != 7 || !runtimeFunctions || nonRuntimeFunctions {
		t.Fatalf(
			"Policy approval functions count=%d runtime-execute=%t non-runtime-execute=%t",
			functionCount,
			runtimeFunctions,
			nonRuntimeFunctions,
		)
	}

	var securityDefinerCount int
	if err := connection.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
WHERE namespace.nspname = 'mesh_ops'
  AND procedure.proname IN (
      'lock_policy_approval_for_publication_v1',
      'consume_policy_approval_for_publication_v1'
  )
  AND procedure.prosecdef
  AND NOT EXISTS (
      SELECT 1
      FROM pg_catalog.aclexplode(COALESCE(
          procedure.proacl,
          pg_catalog.acldefault('f', procedure.proowner)
      )) AS privilege
      WHERE privilege.grantee = 0
        AND privilege.privilege_type = 'EXECUTE'
  )`).Scan(
		&securityDefinerCount,
	); err != nil {
		t.Fatalf("query Policy approval publication function security: %v", err)
	}
	if securityDefinerCount != 2 {
		t.Fatalf("Policy approval publication secured function count = %d, want 2", securityDefinerCount)
	}

	var catalogFunctionCount int
	var runtimeCatalogContract, nonRuntimeCatalogAccess, publicCatalogAccess bool
	var catalogSecurityDefiner bool
	if err := connection.QueryRow(ctx, `SELECT
    pg_catalog.count(*),
    pg_catalog.bool_and(CASE
        WHEN procedure.proname = 'policy_approval_request_payload_v1'
            THEN NOT pg_catalog.has_function_privilege('mesh_runtime', procedure.oid, 'EXECUTE')
        ELSE pg_catalog.has_function_privilege('mesh_runtime', procedure.oid, 'EXECUTE')
    END),
    pg_catalog.bool_or(
        pg_catalog.has_function_privilege('mesh_worker', procedure.oid, 'EXECUTE')
        OR pg_catalog.has_function_privilege('mesh_observer', procedure.oid, 'EXECUTE')
        OR pg_catalog.has_function_privilege('mesh_audit_writer', procedure.oid, 'EXECUTE')
        OR pg_catalog.has_function_privilege('mesh_share_writer', procedure.oid, 'EXECUTE')
    ),
    pg_catalog.bool_or(EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(COALESCE(
            procedure.proacl,
            pg_catalog.acldefault('f', procedure.proowner)
        )) AS privilege
        WHERE privilege.grantee = 0
          AND privilege.privilege_type = 'EXECUTE'
    )),
    pg_catalog.bool_and(procedure.prosecdef)
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
WHERE namespace.nspname = 'mesh_ops'
  AND procedure.proname IN (
      'policy_approval_request_payload_v1',
      'read_policy_approval_request_management_v1',
      'list_policy_approval_requests_management_v1'
  )`).Scan(
		&catalogFunctionCount,
		&runtimeCatalogContract,
		&nonRuntimeCatalogAccess,
		&publicCatalogAccess,
		&catalogSecurityDefiner,
	); err != nil {
		t.Fatalf("query Policy approval catalog function security: %v", err)
	}
	if catalogFunctionCount != 3 || !runtimeCatalogContract || nonRuntimeCatalogAccess ||
		publicCatalogAccess || !catalogSecurityDefiner {
		t.Fatalf(
			"Policy approval catalog functions count=%d runtime-contract=%t non-runtime=%t public=%t security-definer=%t",
			catalogFunctionCount,
			runtimeCatalogContract,
			nonRuntimeCatalogAccess,
			publicCatalogAccess,
			catalogSecurityDefiner,
		)
	}

	var catalogIndexCount int
	if err := connection.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM pg_catalog.pg_indexes
WHERE schemaname = 'mesh'
  AND tablename = 'policy_approval_request'
  AND indexname IN (
      'policy_approval_request_management_cursor_idx',
      'policy_approval_request_management_state_cursor_idx'
  )`).Scan(&catalogIndexCount); err != nil {
		t.Fatalf("query Policy approval management indexes: %v", err)
	}
	if catalogIndexCount != 2 {
		t.Fatalf("Policy approval management index count = %d, want 2", catalogIndexCount)
	}

	var triggerCount int
	if err := connection.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM pg_catalog.pg_trigger AS trigger_row
JOIN pg_catalog.pg_class AS relation ON relation.oid = trigger_row.tgrelid
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = 'mesh'
  AND relation.relname IN ('policy_approval_request', 'policy_approval_evidence')
  AND trigger_row.tgname IN (
      'policy_approval_request_transition',
      'policy_approval_evidence_transition',
      'policy_approval_request_authority_mutation',
      'policy_approval_evidence_authority_mutation'
  )
  AND trigger_row.tgenabled = 'O'`).Scan(&triggerCount); err != nil {
		t.Fatalf("query Policy approval retention triggers: %v", err)
	}
	if triggerCount != 4 {
		t.Fatalf("Policy approval enabled trigger count = %d, want 4", triggerCount)
	}
}
