-- Schema 300: role isolation step S2.3 (docs/role-isolation-design.md §3.5, TD-SEC-90).
--
-- Since schema 298 the group roles mesh_api_rights and mesh_control_rights hold what the api and control use, and
-- since schema 299 every row-level security policy names them. mesh_runtime, the api's login, is a member of
-- mesh_api_rights; control's login mesh_control is a member of mesh_control_rights. This schema takes away every
-- privilege mesh_runtime still holds directly on objects the migrator owns (functions, tables, columns, sequences,
-- schemas, the database) and drops it from every policy, so the api reaches only what its group holds and control
-- no longer inherits the api's rights through mesh_runtime. Functions an owner role holds lose mesh_runtime in
-- operator step 000300; the operator command removes mesh_control's and mesh_all's membership of mesh_runtime.
--
-- Contract step. The previous release (schema 299 code) runs on its groups alone: the role split integration run
-- (S2.1) passes on a database narrowed exactly like this. Rolling back the image to that release needs no reverse
-- step (§10.5).

DO $narrow$
DECLARE
    v_runtime OID := (SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = 'mesh_runtime');
    v_migrator OID := (SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = CURRENT_USER);
    v_groups OID[] := ARRAY(SELECT role.oid FROM pg_catalog.pg_roles AS role
        WHERE role.rolname IN ('mesh_api_rights', 'mesh_control_rights'));
    v_entry RECORD;
    v_revoked INTEGER := 0;
    v_policies INTEGER := 0;
BEGIN
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog', TRUE);
    IF v_runtime IS NULL OR pg_catalog.cardinality(v_groups) <> 2 THEN
        RAISE EXCEPTION USING ERRCODE = '42704', MESSAGE = 'mesh_runtime or a group role is missing';
    END IF;
    -- The groups must already be what the api and control reach rows through: a policy naming mesh_runtime
    -- without both groups means schema 299 did not hold.
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy AS policy
        WHERE v_runtime = ANY(policy.polroles) AND NOT (v_groups <@ policy.polroles)) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'a policy names mesh_runtime without the group roles';
    END IF;

    FOR v_entry IN
        SELECT DISTINCT routine.oid::REGPROCEDURE AS routine
        FROM pg_catalog.pg_proc AS routine CROSS JOIN LATERAL pg_catalog.aclexplode(routine.proacl) AS acl
        WHERE acl.grantee = v_runtime AND routine.proowner = v_migrator
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM mesh_runtime', v_entry.routine);
        v_revoked := v_revoked + 1;
    END LOOP;
    FOR v_entry IN
        SELECT DISTINCT relation.oid::REGCLASS AS relation, relation.relkind
        FROM pg_catalog.pg_class AS relation
        WHERE relation.relowner = v_migrator
          AND (EXISTS (SELECT 1 FROM pg_catalog.aclexplode(relation.relacl) AS acl WHERE acl.grantee = v_runtime)
              OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute AS attribute
                  CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS acl
                  WHERE attribute.attrelid = relation.oid AND acl.grantee = v_runtime))
    LOOP
        -- REVOKE ALL on a table also takes away the role's column privileges.
        EXECUTE pg_catalog.format('REVOKE ALL ON %s %s FROM mesh_runtime',
            CASE WHEN v_entry.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END, v_entry.relation);
        v_revoked := v_revoked + 1;
    END LOOP;
    FOR v_entry IN
        SELECT namespace.nspname FROM pg_catalog.pg_namespace AS namespace
        WHERE namespace.nspowner = v_migrator
          AND EXISTS (SELECT 1 FROM pg_catalog.aclexplode(namespace.nspacl) AS acl WHERE acl.grantee = v_runtime)
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON SCHEMA %I FROM mesh_runtime', v_entry.nspname);
        v_revoked := v_revoked + 1;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_database AS database
        CROSS JOIN LATERAL pg_catalog.aclexplode(database.datacl) AS acl
        WHERE database.datname = pg_catalog.current_database() AND acl.grantee = v_runtime) THEN
        EXECUTE pg_catalog.format('REVOKE ALL ON DATABASE %I FROM mesh_runtime', pg_catalog.current_database());
        v_revoked := v_revoked + 1;
    END IF;

    FOR v_entry IN
        SELECT policy.polname, policy.polrelid::REGCLASS AS relation,
            (SELECT pg_catalog.string_agg(pg_catalog.quote_ident(role.rolname), ', ' ORDER BY role.rolname)
             FROM pg_catalog.pg_roles AS role
             WHERE role.oid = ANY(policy.polroles) AND role.oid <> v_runtime)
            || CASE WHEN 0::OID = ANY(policy.polroles) THEN ', PUBLIC' ELSE '' END AS roles
        FROM pg_catalog.pg_policy AS policy
        WHERE v_runtime = ANY(policy.polroles)
        ORDER BY policy.polrelid, policy.polname
    LOOP
        EXECUTE pg_catalog.format('ALTER POLICY %I ON %s TO %s', v_entry.polname, v_entry.relation, v_entry.roles);
        v_policies := v_policies + 1;
    END LOOP;
    -- Nothing the migrator owns may still name mesh_runtime: a grant another grantor made survives the owner's
    -- REVOKE, and the database stays as it was if the migrator does not own it. Stop rather than narrow by half.
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc AS routine CROSS JOIN LATERAL pg_catalog.aclexplode(routine.proacl) AS acl
            WHERE routine.proowner = v_migrator AND acl.grantee = v_runtime)
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_class AS relation
            CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) AS acl
            WHERE relation.relowner = v_migrator AND acl.grantee = v_runtime)
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute AS attribute
            JOIN pg_catalog.pg_class AS relation ON relation.oid = attribute.attrelid
            CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS acl
            WHERE relation.relowner = v_migrator AND acl.grantee = v_runtime)
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace AS namespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) AS acl
            WHERE namespace.nspowner = v_migrator AND acl.grantee = v_runtime)
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_database AS database
            CROSS JOIN LATERAL pg_catalog.aclexplode(database.datacl) AS acl
            WHERE database.datname = pg_catalog.current_database() AND acl.grantee = v_runtime)
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_policy AS policy WHERE v_runtime = ANY(policy.polroles)) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'mesh_runtime still holds a privilege the migrator could not take away';
    END IF;
    RAISE NOTICE 'role isolation S2.3: mesh_runtime lost direct privileges on % objects and left % policies',
        v_revoked, v_policies;
END;
$narrow$;
