-- Role isolation S2.3 tests: at schema 299, before migration 300 narrows mesh_runtime, copy every privilege it holds
-- directly to mesh_it_legacy and add mesh_it_legacy to its policies. The schema assertions on retired versions run as
-- mesh_it_legacy (legacyRuntimeSQL), and the group checks compare the groups with it: what mesh_runtime held before
-- S2.3 took it away.
DO $narrow$
DECLARE
    v_source OID := (SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = 'mesh_runtime');
    v_entry RECORD;
BEGIN
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog', TRUE);
    IF v_source IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42704', MESSAGE = 'mesh_runtime is missing';
    END IF;
    FOR v_entry IN
        SELECT routine.oid::REGPROCEDURE AS routine
        FROM pg_catalog.pg_proc AS routine CROSS JOIN LATERAL pg_catalog.aclexplode(routine.proacl) AS acl
        WHERE acl.grantee = v_source AND acl.privilege_type = 'EXECUTE'
    LOOP
        EXECUTE pg_catalog.format('GRANT EXECUTE ON FUNCTION %s TO mesh_it_legacy', v_entry.routine);
    END LOOP;
    FOR v_entry IN
        SELECT relation.oid::REGCLASS AS relation, relation.relkind, acl.privilege_type
        FROM pg_catalog.pg_class AS relation CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) AS acl
        WHERE acl.grantee = v_source
    LOOP
        EXECUTE pg_catalog.format('GRANT %s ON %s %s TO mesh_it_legacy', v_entry.privilege_type,
            CASE WHEN v_entry.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END, v_entry.relation);
    END LOOP;
    FOR v_entry IN
        SELECT attribute.attrelid::REGCLASS AS relation, attribute.attname, acl.privilege_type
        FROM pg_catalog.pg_attribute AS attribute CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS acl
        WHERE acl.grantee = v_source
    LOOP
        EXECUTE pg_catalog.format('GRANT %s (%I) ON TABLE %s TO mesh_it_legacy', v_entry.privilege_type,
            v_entry.attname, v_entry.relation);
    END LOOP;
    FOR v_entry IN
        SELECT namespace.nspname, acl.privilege_type
        FROM pg_catalog.pg_namespace AS namespace CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) AS acl
        WHERE acl.grantee = v_source
    LOOP
        EXECUTE pg_catalog.format('GRANT %s ON SCHEMA %I TO mesh_it_legacy', v_entry.privilege_type, v_entry.nspname);
    END LOOP;
    FOR v_entry IN
        SELECT acl.privilege_type
        FROM pg_catalog.pg_database AS database CROSS JOIN LATERAL pg_catalog.aclexplode(database.datacl) AS acl
        WHERE database.datname = pg_catalog.current_database() AND acl.grantee = v_source
    LOOP
        EXECUTE pg_catalog.format('GRANT %s ON DATABASE %I TO mesh_it_legacy', v_entry.privilege_type,
            pg_catalog.current_database());
    END LOOP;
    FOR v_entry IN
        SELECT policy.polname, policy.polrelid::REGCLASS AS relation,
            (SELECT pg_catalog.string_agg(pg_catalog.quote_ident(role.rolname), ', ' ORDER BY role.rolname)
             FROM pg_catalog.pg_roles AS role
             WHERE role.oid = ANY(policy.polroles) OR role.rolname = 'mesh_it_legacy')
            || CASE WHEN 0::OID = ANY(policy.polroles) THEN ', PUBLIC' ELSE '' END AS roles
        FROM pg_catalog.pg_policy AS policy
        WHERE v_source = ANY(policy.polroles)
          AND NOT ((SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = 'mesh_it_legacy')
              = ANY(policy.polroles))
    LOOP
        EXECUTE pg_catalog.format('ALTER POLICY %I ON %s TO %s', v_entry.polname, v_entry.relation, v_entry.roles);
    END LOOP;
END;
$narrow$;
