//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func assertResourceSharingPrivilegeContract(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()

	var tableCount int
	var allRLS, allForceRLS, runtimeMutation, runtimeReadBounded, publicDML, writerBounded bool
	if err := admin.QueryRow(ctx, `SELECT
    pg_catalog.count(*)::INTEGER,
    pg_catalog.bool_and(class.relrowsecurity),
    pg_catalog.bool_and(class.relforcerowsecurity),
    pg_catalog.bool_or(
        pg_catalog.has_table_privilege('mesh_runtime', class.oid, 'INSERT,UPDATE,DELETE')
    ),
    pg_catalog.bool_and(
        pg_catalog.has_table_privilege('mesh_runtime', class.oid, 'SELECT')
    ),
    pg_catalog.bool_or(EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(COALESCE(
            class.relacl,
            pg_catalog.acldefault('r', class.relowner)
        )) AS privilege
        WHERE privilege.grantee = 0
          AND privilege.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
    )),
    pg_catalog.bool_and(CASE
        WHEN class.relname = 'share_offer_locator' THEN
            pg_catalog.has_table_privilege('mesh_share_writer', class.oid, 'SELECT,INSERT,UPDATE')
            AND NOT pg_catalog.has_table_privilege('mesh_share_writer', class.oid, 'DELETE')
        ELSE
            pg_catalog.has_table_privilege('mesh_share_writer', class.oid, 'SELECT,INSERT,UPDATE')
            AND NOT pg_catalog.has_table_privilege('mesh_share_writer', class.oid, 'DELETE')
        END
    )
FROM pg_catalog.pg_class AS class
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
WHERE namespace.nspname = 'mesh'
  AND class.relname = ANY(ARRAY[
      'resource_export', 'resource_export_constraint', 'share_offer', 'share_offer_locator',
      'trust_contract', 'imported_resource', 'imported_resource_access_name'
  ]::TEXT[])`).Scan(
		&tableCount,
		&allRLS,
		&allForceRLS,
		&runtimeMutation,
		&runtimeReadBounded,
		&publicDML,
		&writerBounded,
	); err != nil {
		t.Fatal("query Resource Sharing table privileges", err)
	}
	if tableCount != 7 || !allRLS || !allForceRLS || runtimeMutation || !runtimeReadBounded ||
		publicDML || !writerBounded {
		t.Fatalf(
			"Resource Sharing tables count=%d rls=%t force=%t runtime_mutation=%t runtime_read=%t public_dml=%t writer=%t",
			tableCount,
			allRLS,
			allForceRLS,
			runtimeMutation,
			runtimeReadBounded,
			publicDML,
			writerBounded,
		)
	}

	var functionCount int
	var runtimeExecute, foreignExecute, publicExecute, securityDefiner, volatile bool
	var dedicatedOwner, fixedSearchPath bool
	if err := admin.QueryRow(ctx, `SELECT
    pg_catalog.count(*)::INTEGER,
    pg_catalog.bool_and(pg_catalog.has_function_privilege(
        'mesh_runtime', procedure.oid, 'EXECUTE'
    )),
    pg_catalog.bool_or(
        pg_catalog.has_function_privilege('mesh_worker', procedure.oid, 'EXECUTE')
        OR pg_catalog.has_function_privilege('mesh_observer', procedure.oid, 'EXECUTE')
        OR pg_catalog.has_function_privilege('mesh_audit_writer', procedure.oid, 'EXECUTE')
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
    pg_catalog.bool_and(procedure.prosecdef),
    pg_catalog.bool_and(procedure.provolatile = 'v'),
    pg_catalog.bool_and(owner.rolname = 'mesh_share_writer'),
    pg_catalog.bool_and(procedure.proconfig @> ARRAY['search_path=pg_catalog, mesh, mesh_ops'])
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
JOIN pg_catalog.pg_roles AS owner ON owner.oid = procedure.proowner
WHERE namespace.nspname = 'mesh_ops'
  AND procedure.proname = ANY(ARRAY[
		'create_resource_share_offer_v1',
		'decide_resource_share_offer_v2',
		'activate_resource_share_v1',
		'revoke_resource_share_v2'
  ]::TEXT[])`).Scan(
		&functionCount,
		&runtimeExecute,
		&foreignExecute,
		&publicExecute,
		&securityDefiner,
		&volatile,
		&dedicatedOwner,
		&fixedSearchPath,
	); err != nil {
		t.Fatal("query Resource Sharing function privileges", err)
	}
	if functionCount != 4 || !runtimeExecute || foreignExecute || publicExecute ||
		!securityDefiner || !volatile || !dedicatedOwner || !fixedSearchPath {
		t.Fatalf(
			"Resource Sharing functions count=%d runtime=%t foreign=%t public=%t definer=%t volatile=%t owner=%t path=%t",
			functionCount,
			runtimeExecute,
			foreignExecute,
			publicExecute,
			securityDefiner,
			volatile,
			dedicatedOwner,
			fixedSearchPath,
		)
	}

	var ownerNoLogin, ownerNoBypass, migratorNotMember, helperClosed bool
	var migratorScopeClosed, legacyDecideClosed, legacyRevokeClosed, schemaUsage bool
	if err := admin.QueryRow(ctx, `SELECT
    NOT owner.rolcanlogin,
    NOT owner.rolbypassrls,
    NOT pg_catalog.pg_has_role('mesh_migrator', 'mesh_share_writer', 'MEMBER'),
    NOT pg_catalog.has_function_privilege(
        'mesh_runtime',
        'mesh_ops.set_share_scope_v1(bigint,bigint,bigint,bigint)',
        'EXECUTE'
    ),
    NOT pg_catalog.has_function_privilege(
        'mesh_migrator',
        'mesh_ops.set_share_scope_v1(bigint,bigint,bigint,bigint)',
        'EXECUTE'
    ),
    NOT pg_catalog.has_function_privilege(
        'mesh_runtime',
        'mesh_ops.decide_resource_share_offer_v1(bigint,bigint,bigint,bigint,uuid,uuid,uuid,uuid,uuid,bigint,bytea,text,uuid,uuid,text,bigint,bigint,bigint,bigint,bigint,timestamptz)',
        'EXECUTE'
    ),
    NOT pg_catalog.has_function_privilege(
        'mesh_runtime',
        'mesh_ops.revoke_resource_share_v1(bigint,bigint,bigint,bigint,uuid,bigint,bigint,bigint,timestamptz)',
        'EXECUTE'
    ),
    pg_catalog.has_schema_privilege('mesh_share_writer', 'mesh', 'USAGE')
    AND pg_catalog.has_schema_privilege('mesh_share_writer', 'mesh_ops', 'USAGE')
FROM pg_catalog.pg_roles AS owner
WHERE owner.rolname = 'mesh_share_writer'`).Scan(
		&ownerNoLogin,
		&ownerNoBypass,
		&migratorNotMember,
		&helperClosed,
		&migratorScopeClosed,
		&legacyDecideClosed,
		&legacyRevokeClosed,
		&schemaUsage,
	); err != nil {
		t.Fatal("query Resource Sharing owner isolation", err)
	}
	if !ownerNoLogin || !ownerNoBypass || !migratorNotMember || !helperClosed ||
		!migratorScopeClosed || !legacyDecideClosed || !legacyRevokeClosed || !schemaUsage {
		t.Fatalf(
			"Resource Sharing owner nologin=%t nobypass=%t isolated=%t helper_closed=%t migrator_scope_closed=%t legacy_decide_closed=%t legacy_revoke_closed=%t schema_usage=%t",
			ownerNoLogin,
			ownerNoBypass,
			migratorNotMember,
			helperClosed,
			migratorScopeClosed,
			legacyDecideClosed,
			legacyRevokeClosed,
			schemaUsage,
		)
	}

	var scopedPolicyCount int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*)::INTEGER
FROM pg_catalog.pg_policies
WHERE schemaname IN ('mesh', 'mesh_ops')
  AND policyname = ANY(ARRAY[
      'resource_export_share_writer_policy',
      'resource_export_constraint_share_writer_policy',
      'share_offer_share_writer_policy',
      'share_offer_runtime_policy',
      'share_offer_locator_share_writer_policy',
      'share_offer_locator_runtime_policy',
      'resource_export_runtime_policy',
      'resource_export_constraint_runtime_policy',
      'trust_contract_share_writer_policy',
      'trust_contract_runtime_policy',
      'imported_resource_share_writer_policy',
      'imported_resource_runtime_policy',
      'imported_resource_access_name_migrator_policy',
      'imported_resource_access_name_share_writer_policy',
      'imported_resource_access_name_runtime_policy',
      'deployment_share_writer_policy',
      'workspace_share_writer_policy',
      'network_share_writer_policy',
      'resource_share_writer_policy',
      'resource_device_target_share_writer_policy',
      'network_revision_share_writer_policy'
  ]::TEXT[])`).Scan(&scopedPolicyCount); err != nil {
		t.Fatal("query Resource Sharing RLS policies", err)
	}
	if scopedPolicyCount != 21 {
		t.Fatalf("Resource Sharing scoped policy count = %d, want 21", scopedPolicyCount)
	}

	assertImportedPolicyPrivilegeContract(ctx, t, admin)
}

func assertImportedPolicyPrivilegeContract(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()

	var rls, forceRLS, runtimeRead, runtimeWrite, foreignAccess, publicAccess bool
	if err := admin.QueryRow(ctx, `SELECT
    class.relrowsecurity,
    class.relforcerowsecurity,
    pg_catalog.has_table_privilege('mesh_runtime', class.oid, 'SELECT'),
    pg_catalog.has_table_privilege('mesh_runtime', class.oid, 'INSERT,UPDATE,DELETE'),
    pg_catalog.has_table_privilege('mesh_worker', class.oid, 'SELECT,INSERT,UPDATE,DELETE')
    OR pg_catalog.has_table_privilege('mesh_observer', class.oid, 'SELECT,INSERT,UPDATE,DELETE')
    OR pg_catalog.has_table_privilege('mesh_audit_writer', class.oid, 'SELECT,INSERT,UPDATE,DELETE')
    OR pg_catalog.has_table_privilege('mesh_share_writer', class.oid, 'SELECT,INSERT,UPDATE,DELETE'),
    EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(COALESCE(
            class.relacl,
            pg_catalog.acldefault('r', class.relowner)
        )) AS privilege
        WHERE privilege.grantee = 0
          AND privilege.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
    )
FROM pg_catalog.pg_class AS class
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
WHERE namespace.nspname = 'mesh'
  AND class.relname = 'compiled_policy_imported_resource_destination'`).Scan(
		&rls,
		&forceRLS,
		&runtimeRead,
		&runtimeWrite,
		&foreignAccess,
		&publicAccess,
	); err != nil {
		t.Fatal("query Imported Resource policy table privileges", err)
	}
	if !rls || !forceRLS || !runtimeRead || runtimeWrite || foreignAccess || publicAccess {
		t.Fatalf(
			"Imported Resource policy table rls=%t force=%t runtime_read=%t runtime_write=%t foreign=%t public=%t",
			rls,
			forceRLS,
			runtimeRead,
			runtimeWrite,
			foreignAccess,
			publicAccess,
		)
	}

	var sequenceAccess bool
	if err := admin.QueryRow(ctx, `SELECT
    pg_catalog.has_sequence_privilege('mesh_runtime', class.oid, 'USAGE,SELECT,UPDATE')
    OR pg_catalog.has_sequence_privilege('mesh_worker', class.oid, 'USAGE,SELECT,UPDATE')
    OR pg_catalog.has_sequence_privilege('mesh_observer', class.oid, 'USAGE,SELECT,UPDATE')
    OR pg_catalog.has_sequence_privilege('mesh_audit_writer', class.oid, 'USAGE,SELECT,UPDATE')
    OR pg_catalog.has_sequence_privilege('mesh_share_writer', class.oid, 'USAGE,SELECT,UPDATE')
FROM pg_catalog.pg_class AS class
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
WHERE namespace.nspname = 'mesh'
  AND class.relname = 'compiled_policy_imported_resource_destination_id_seq'`).Scan(
		&sequenceAccess,
	); err != nil {
		t.Fatal("query Imported Resource policy sequence privileges", err)
	}
	if sequenceAccess {
		t.Fatal("application roles retain Imported Resource policy sequence privilege")
	}

	var functionCount int
	var runtimeContract, migratorContract, foreignExecute, publicExecute, securityContract bool
	var ownerContract bool
	var fixedSearchPath, volatile, obsoleteAbsent, legacyExplainClosed bool
	if err := admin.QueryRow(ctx, `SELECT
    pg_catalog.count(*)::INTEGER,
    pg_catalog.bool_and(CASE
        WHEN procedure.proname IN (
            'publish_compiled_policy',
            'resolve_imported_policy_destinations_v1',
            'read_policy_simulation_baseline_v2',
            'explain_active_policy_v2'
        ) THEN pg_catalog.has_function_privilege('mesh_runtime', procedure.oid, 'EXECUTE')
        ELSE NOT pg_catalog.has_function_privilege('mesh_runtime', procedure.oid, 'EXECUTE')
    END),
    pg_catalog.bool_and(CASE
        WHEN procedure.proname = 'lock_and_resolve_policy_imported_resources_internal_v1'
            THEN pg_catalog.has_function_privilege('mesh_migrator', procedure.oid, 'EXECUTE')
        ELSE TRUE
    END),
    pg_catalog.bool_or(
        pg_catalog.has_function_privilege('mesh_worker', procedure.oid, 'EXECUTE')
        OR pg_catalog.has_function_privilege('mesh_observer', procedure.oid, 'EXECUTE')
        OR pg_catalog.has_function_privilege('mesh_audit_writer', procedure.oid, 'EXECUTE')
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
    pg_catalog.bool_and(CASE
        WHEN procedure.proname = 'attach_policy_imported_resource_destinations_internal_v1'
            THEN NOT procedure.prosecdef
        ELSE procedure.prosecdef
    END),
    pg_catalog.bool_and(CASE
        WHEN procedure.proname IN (
            'resolve_imported_policy_destinations_v1',
            'lock_and_resolve_policy_imported_resources_internal_v1'
        )
            THEN owner.rolname = 'mesh_share_writer'
        ELSE owner.rolname = 'mesh_migrator'
    END),
    pg_catalog.bool_and(
        procedure.proconfig @> ARRAY['search_path=pg_catalog, mesh, mesh_ops']
    ),
    pg_catalog.bool_and(procedure.provolatile = 'v'),
    pg_catalog.to_regprocedure(
        'mesh_ops.publish_compiled_policy_v2(uuid,bigint,bytea,integer,timestamptz,jsonb)'
    ) IS NULL,
    NOT pg_catalog.has_function_privilege(
        'mesh_runtime',
        'mesh_ops.explain_active_policy_v1(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,uuid,uuid,uuid,uuid,uuid,text,integer,timestamptz,integer)',
        'EXECUTE'
    )
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
JOIN pg_catalog.pg_roles AS owner ON owner.oid = procedure.proowner
WHERE namespace.nspname = 'mesh_ops'
  AND procedure.proname = ANY(ARRAY[
      'attach_policy_imported_resource_destinations_internal_v1',
      'publish_compiled_policy_local_v1',
      'publish_compiled_policy',
      'resolve_imported_policy_destinations_v1',
      'lock_and_resolve_policy_imported_resources_internal_v1',
      'read_policy_simulation_baseline_v2',
      'explain_active_policy_v2'
  ]::TEXT[])`).Scan(
		&functionCount,
		&runtimeContract,
		&migratorContract,
		&foreignExecute,
		&publicExecute,
		&securityContract,
		&ownerContract,
		&fixedSearchPath,
		&volatile,
		&obsoleteAbsent,
		&legacyExplainClosed,
	); err != nil {
		t.Fatal("query Imported Resource policy function privileges", err)
	}
	if functionCount != 7 || !runtimeContract || !migratorContract || foreignExecute || publicExecute ||
		!securityContract || !ownerContract || !fixedSearchPath || !volatile || !obsoleteAbsent ||
		!legacyExplainClosed {
		t.Fatalf(
			"Imported Resource policy functions count=%d runtime=%t migrator=%t foreign=%t public=%t security=%t owner=%t path=%t volatile=%t obsolete_absent=%t legacy_explain_closed=%t",
			functionCount,
			runtimeContract,
			migratorContract,
			foreignExecute,
			publicExecute,
			securityContract,
			ownerContract,
			fixedSearchPath,
			volatile,
			obsoleteAbsent,
			legacyExplainClosed,
		)
	}
}
