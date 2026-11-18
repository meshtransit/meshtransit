-- Role isolation S2.1 (docs/role-isolation-design.md §3.5): the state step S2.3 reaches, simulated on a test database
-- by its superuser. mesh_runtime keeps only what it inherits from mesh_api_rights; mesh_control only what it inherits
-- from mesh_control_rights. Every direct privilege mesh_runtime held moves to mesh_it_legacy (a test role, member of no
-- MeshTransit role), which the schema assertions' raw SQL runs as, since those test objects the code no longer uses.
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
        EXECUTE pg_catalog.format('REVOKE EXECUTE ON FUNCTION %s FROM mesh_runtime', v_entry.routine);
    END LOOP;
    FOR v_entry IN
        SELECT relation.oid::REGCLASS AS relation, relation.relkind, acl.privilege_type
        FROM pg_catalog.pg_class AS relation CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) AS acl
        WHERE acl.grantee = v_source
    LOOP
        EXECUTE pg_catalog.format('GRANT %s ON %s %s TO mesh_it_legacy', v_entry.privilege_type,
            CASE WHEN v_entry.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END, v_entry.relation);
        EXECUTE pg_catalog.format('REVOKE %s ON %s %s FROM mesh_runtime', v_entry.privilege_type,
            CASE WHEN v_entry.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END, v_entry.relation);
    END LOOP;
    FOR v_entry IN
        SELECT attribute.attrelid::REGCLASS AS relation, attribute.attname, acl.privilege_type
        FROM pg_catalog.pg_attribute AS attribute CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS acl
        WHERE acl.grantee = v_source
    LOOP
        EXECUTE pg_catalog.format('GRANT %s (%I) ON TABLE %s TO mesh_it_legacy', v_entry.privilege_type,
            v_entry.attname, v_entry.relation);
        EXECUTE pg_catalog.format('REVOKE %s (%I) ON TABLE %s FROM mesh_runtime', v_entry.privilege_type,
            v_entry.attname, v_entry.relation);
    END LOOP;
    FOR v_entry IN
        SELECT namespace.nspname, acl.privilege_type
        FROM pg_catalog.pg_namespace AS namespace CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) AS acl
        WHERE acl.grantee = v_source
    LOOP
        EXECUTE pg_catalog.format('GRANT %s ON SCHEMA %I TO mesh_it_legacy', v_entry.privilege_type, v_entry.nspname);
        EXECUTE pg_catalog.format('REVOKE %s ON SCHEMA %I FROM mesh_runtime', v_entry.privilege_type, v_entry.nspname);
    END LOOP;
    FOR v_entry IN
        SELECT acl.privilege_type
        FROM pg_catalog.pg_database AS database CROSS JOIN LATERAL pg_catalog.aclexplode(database.datacl) AS acl
        WHERE database.datname = pg_catalog.current_database() AND acl.grantee = v_source
    LOOP
        EXECUTE pg_catalog.format('GRANT %s ON DATABASE %I TO mesh_it_legacy', v_entry.privilege_type,
            pg_catalog.current_database());
        EXECUTE pg_catalog.format('REVOKE %s ON DATABASE %I FROM mesh_runtime', v_entry.privilege_type,
            pg_catalog.current_database());
    END LOOP;
    FOR v_entry IN
        SELECT policy.polname, policy.polrelid::REGCLASS AS relation,
            (SELECT pg_catalog.string_agg(pg_catalog.quote_ident(role.rolname), ', ' ORDER BY role.rolname)
             FROM pg_catalog.pg_roles AS role
             WHERE (role.oid = ANY(policy.polroles) AND role.oid <> v_source) OR role.rolname = 'mesh_it_legacy')
            || CASE WHEN 0::OID = ANY(policy.polroles) THEN ', PUBLIC' ELSE '' END AS roles
        FROM pg_catalog.pg_policy AS policy
        WHERE v_source = ANY(policy.polroles)
    LOOP
        EXECUTE pg_catalog.format('ALTER POLICY %I ON %s TO %s', v_entry.polname, v_entry.relation, v_entry.roles);
    END LOOP;
END;
$narrow$;
REVOKE mesh_runtime FROM mesh_control;
