-- Schema 301: no MeshTransit function is open to PUBLIC (TD-SEC-95, role isolation S2.3).
--
-- Migration 1 ran ALTER DEFAULT PRIVILEGES IN SCHEMA … REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC, but a per-schema
-- default can only add to the global default, which grants EXECUTE to PUBLIC: eight functions are still callable by
-- every role, among them four SECURITY DEFINER functions of schema 42. Since schema 300 no serving role reaches
-- anything through mesh_runtime, so PUBLIC is the last way in that bypasses the group roles.
--
-- * The api's group gets the four schema 42 functions the api calls (role_grants.json), before PUBLIC loses them.
-- * device_never_expires_v1 returns a constant the CHECK constraints and definers of the Device tables use: every
--   serving group and the worker keep it.
-- * The three trigger functions need no EXECUTE to fire.
-- * From now on a function the migrator creates is not executable by PUBLIC unless a migration grants it.
--
-- Contract step, safe to roll back from: the previous release reaches the same functions through its groups.

GRANT EXECUTE ON FUNCTION mesh_ops.preview_resource_authority_change_v1(UUID, TEXT, UUID) TO mesh_api_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_resource_authority_change_v1(UUID, TEXT, UUID) TO mesh_api_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.preview_resource_group_authority_change_v1(UUID, TEXT, UUID) TO mesh_api_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_resource_group_authority_change_v1(UUID, TEXT, UUID) TO mesh_api_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.device_never_expires_v1() TO mesh_api_rights, mesh_control_rights, mesh_worker;

REVOKE EXECUTE ON FUNCTION mesh_ops.preview_resource_authority_change_v1(UUID, TEXT, UUID) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION mesh_ops.lock_resource_authority_change_v1(UUID, TEXT, UUID) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION mesh_ops.preview_resource_group_authority_change_v1(UUID, TEXT, UUID) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION mesh_ops.lock_resource_group_authority_change_v1(UUID, TEXT, UUID) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION mesh_ops.device_never_expires_v1() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION mesh_ops.enforce_share_offer_locator_transition() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION mesh_ops.enforce_resource_sharing_transition() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION mesh_ops.enforce_workspace_invitation_transition_v1() FROM PUBLIC;

ALTER DEFAULT PRIVILEGES FOR ROLE mesh_migrator REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- No function in the MeshTransit schemas may be left open to PUBLIC, whoever created it.
DO $public$
BEGIN
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog', TRUE);
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc AS routine
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = routine.pronamespace
        WHERE namespace.nspname IN ('mesh', 'mesh_ops', 'mesh_audit')
          AND (routine.proacl IS NULL OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(routine.proacl) AS acl
              WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'))) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'a MeshTransit function is still executable by PUBLIC';
    END IF;
END;
$public$;
