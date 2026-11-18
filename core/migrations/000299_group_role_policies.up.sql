-- Schema 299: role isolation step S2.2 (docs/role-isolation-design.md §3.5, TD-SEC-90).
--
-- Every row-level security policy that applies to mesh_runtime also applies to the group roles mesh_api_rights and
-- mesh_control_rights, so a login that holds a table privilege only through its group still sees and writes exactly
-- the rows it does today (without a policy, RLS returns no row rather than an error). mesh_runtime stays in each
-- policy until step S2.3. Policies are found in the catalog, not listed: one that names mesh_runtime is the set.
--
-- Expand only: the policies keep their expressions and commands; only their roles grow.

DO $policies$
DECLARE
    v_source OID := (SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = 'mesh_runtime');
    v_groups OID[] := ARRAY(SELECT role.oid FROM pg_catalog.pg_roles AS role
        WHERE role.rolname IN ('mesh_api_rights', 'mesh_control_rights') ORDER BY role.rolname);
    v_policy RECORD;
    v_changed INTEGER := 0;
BEGIN
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog', TRUE);
    IF v_source IS NULL OR pg_catalog.cardinality(v_groups) <> 2 THEN
        RAISE EXCEPTION USING ERRCODE = '42704', MESSAGE = 'mesh_runtime or a group role is missing';
    END IF;
    FOR v_policy IN
        SELECT policy.polname, policy.polrelid::REGCLASS AS relation,
            (SELECT pg_catalog.string_agg(pg_catalog.quote_ident(role.rolname), ', ' ORDER BY role.rolname)
             FROM pg_catalog.pg_roles AS role
             WHERE role.oid = ANY(policy.polroles) OR role.oid = ANY(v_groups))
            -- PUBLIC (role 0) has no pg_roles row; a policy that names it keeps it.
            || CASE WHEN 0::OID = ANY(policy.polroles) THEN ', PUBLIC' ELSE '' END AS roles
        FROM pg_catalog.pg_policy AS policy
        WHERE v_source = ANY(policy.polroles)
          AND NOT (v_groups <@ policy.polroles)
        ORDER BY policy.polrelid, policy.polname
    LOOP
        EXECUTE pg_catalog.format('ALTER POLICY %I ON %s TO %s', v_policy.polname, v_policy.relation, v_policy.roles);
        v_changed := v_changed + 1;
    END LOOP;
    RAISE NOTICE 'role isolation S2.2: % policies apply to the group roles', v_changed;
END;
$policies$;
