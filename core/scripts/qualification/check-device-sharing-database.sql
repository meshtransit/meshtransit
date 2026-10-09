-- Read-only qualification gate. Run as the database operator after all schema
-- migrations and operator ownership scripts, before enabling Device sharing.
BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';
DO $gate$
DECLARE
    expected RECORD;
    observed RECORD;
BEGIN
    IF (SELECT COALESCE(max(version), 0) FROM mesh_ops.schema_migration) < 94 THEN
        RAISE EXCEPTION 'Device sharing requires schema 94 or later';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'mesh_share_writer'
          AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
          AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication
    ) OR pg_catalog.pg_has_role('mesh_runtime', 'mesh_share_writer', 'MEMBER')
      OR pg_catalog.pg_has_role('mesh_migrator', 'mesh_share_writer', 'MEMBER')
      OR pg_catalog.pg_has_role('mesh_worker', 'mesh_share_writer', 'MEMBER')
      OR pg_catalog.pg_has_role('mesh_observer', 'mesh_share_writer', 'MEMBER') THEN
        RAISE EXCEPTION 'Device sharing writer role confinement failed';
    END IF;
    FOR expected IN SELECT * FROM (VALUES
        ('create_resource_share_offer_v1', FALSE),
        ('create_resource_share_offer_v2', TRUE),
        ('create_resource_share_offer_v3', TRUE),
        ('decide_resource_share_offer_v2', FALSE),
        ('decide_resource_share_offer_base_v2', FALSE),
        ('decide_resource_share_offer_v3', TRUE),
        ('decide_resource_share_offer_v4', TRUE),
        ('activate_resource_share_v2', TRUE),
        ('activate_resource_share_v3', FALSE),
        ('activate_resource_share_v4', TRUE),
        ('revoke_resource_share_v4', TRUE),
        ('revoke_resource_share_v5', FALSE),
        ('revoke_resource_share_v6', TRUE),
        ('resolve_imported_policy_destinations_v1', TRUE),
        ('set_share_scope_v1', FALSE),
        ('decide_resource_share_offer_v1', FALSE),
        ('activate_resource_share_v1', FALSE),
        ('revoke_resource_share_v1', FALSE),
        ('revoke_resource_share_v2', FALSE),
        ('revoke_resource_share_v3', FALSE),
        ('lock_and_resolve_policy_imported_resources_internal_v1', FALSE),
        ('read_compiled_imported_policy_evidence_internal_v1', FALSE),
        ('assert_private_endpoint_scope_internal_v1', FALSE)
    ) AS functions(name, runtime_execute) LOOP
        SELECT count(*) AS count,
            bool_and(owner.rolname = 'mesh_share_writer' AND procedure.prosecdef
                AND procedure.provolatile = 'v'
                AND procedure.proconfig @> ARRAY[CASE WHEN expected.name = 'set_share_scope_v1'
                    THEN 'search_path=pg_catalog' ELSE 'search_path=pg_catalog, mesh, mesh_ops' END]
                AND pg_catalog.has_function_privilege('mesh_runtime', procedure.oid, 'EXECUTE') = expected.runtime_execute
                AND NOT pg_catalog.has_function_privilege('mesh_worker', procedure.oid, 'EXECUTE')
                AND NOT pg_catalog.has_function_privilege('mesh_observer', procedure.oid, 'EXECUTE')
                AND NOT pg_catalog.has_function_privilege('mesh_audit_writer', procedure.oid, 'EXECUTE')
                AND NOT EXISTS (
                    SELECT 1 FROM pg_catalog.aclexplode(COALESCE(procedure.proacl,
                        pg_catalog.acldefault('f', procedure.proowner))) AS privilege
                    WHERE privilege.grantee = 0 AND privilege.privilege_type = 'EXECUTE'
                )) AS confined
        INTO observed
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
        JOIN pg_catalog.pg_roles AS owner ON owner.oid = procedure.proowner
        WHERE namespace.nspname = 'mesh_ops' AND procedure.proname = expected.name;
        IF observed.count <> 1 OR observed.confined IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'Device sharing function profile failed: %', expected.name;
        END IF;
    END LOOP;
    FOR expected IN SELECT name FROM (VALUES
        ('resource_export'), ('resource_export_constraint'), ('share_offer'),
        ('share_offer_locator'), ('trust_contract'), ('imported_resource'),
        ('imported_resource_access_name'), ('direct_device_endpoint'),
        ('compiled_policy_imported_resource_destination')
    ) AS tables(name) LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = 'mesh' AND relation.relname = expected.name
              AND relation.relrowsecurity AND relation.relforcerowsecurity
              AND pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'SELECT')
              AND NOT pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'INSERT,UPDATE,DELETE,TRUNCATE')
        ) THEN
            RAISE EXCEPTION 'Device sharing table confinement failed: %', expected.name;
        END IF;
    END LOOP;
    IF NOT pg_catalog.has_table_privilege('mesh_share_writer',
        'mesh.compiled_policy_imported_resource_destination', 'SELECT')
      OR pg_catalog.has_table_privilege('mesh_share_writer',
        'mesh.compiled_policy_imported_resource_destination', 'INSERT,UPDATE,DELETE,TRUNCATE')
      OR NOT pg_catalog.has_function_privilege('mesh_migrator',
        'mesh_ops.read_compiled_imported_policy_evidence_internal_v1(bigint)', 'EXECUTE') THEN
        RAISE EXCEPTION 'Imported policy baseline reader confinement failed';
    END IF;
END;
$gate$;
SELECT 'Device sharing database preflight passed' AS qualification;
ROLLBACK;
