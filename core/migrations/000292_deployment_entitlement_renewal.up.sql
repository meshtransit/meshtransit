-- Schema 292: the api role renews its own Cloud entitlement (docs/auto-renewal-design.md §3, approved
-- 2026-11-14).
--
-- read_current_deployment_entitlement_v1 holds the Deployment row (FOR UPDATE) for the caller's transaction and
-- returns the current generation's claims. record_deployment_entitlement_v1 locks the same row, so the generation
-- the renewal signs (current + 1) cannot be taken by another writer before the renewal commits. It also returns the
-- database's clock: a renewal dates the next generation by it, since Workspace creation and sign-up compare
-- not_before with that clock, never with an api pod's. A Deployment without an entitlement returns no row. Only
-- mesh_runtime (the api role, which records entitlements) may call it.

CREATE FUNCTION mesh_ops.read_current_deployment_entitlement_v1(p_deployment_public_id UUID)
RETURNS TABLE (
    current_generation BIGINT,
    current_profile TEXT,
    current_max_active_workspaces BIGINT,
    current_max_owned_workspaces_per_account BIGINT,
    current_capabilities TEXT[],
    current_not_before TIMESTAMPTZ,
    current_expires_at TIMESTAMPTZ,
    current_signer_key_id TEXT,
    database_now TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
DECLARE
    target_deployment mesh.deployment%ROWTYPE;
BEGIN
    IF p_deployment_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Deployment entitlement input';
    END IF;

    SELECT * INTO target_deployment
    FROM mesh.deployment
    WHERE installation_public_id = p_deployment_public_id
    FOR UPDATE;
    IF NOT FOUND OR target_deployment.state <> 'active' OR target_deployment.deleted_at IS NOT NULL
        OR target_deployment.recovery_state <> 'verified' THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Deployment is unavailable';
    END IF;

    RETURN QUERY
    SELECT entitlement.generation, entitlement.profile, entitlement.max_active_workspaces,
        entitlement.max_owned_workspaces_per_account, entitlement.capabilities, entitlement.not_before,
        entitlement.expires_at, entitlement.signer_key_id, pg_catalog.clock_timestamp()
    FROM mesh.deployment_entitlement AS entitlement
    WHERE entitlement.deployment_id = target_deployment.id
    ORDER BY entitlement.generation DESC
    LIMIT 1;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_current_deployment_entitlement_v1(UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_current_deployment_entitlement_v1(UUID) TO mesh_runtime;
