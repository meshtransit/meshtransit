-- ADR-050 D7: a share creator targets a Network in another Workspace by its
-- 12-digit display code. Core resolves the code only for a caller holding
-- share.offer on the provider Network, and reveals nothing beyond existence:
-- the target Workspace and Network public IDs and display codes, never names.
--
-- The target rows are readable only while mesh.share_target_network_public_id
-- and mesh.share_target_workspace_id name them, which happens only inside
-- resolve_share_target_v1. The Workspace policy keys on the internal ID read
-- from the Network row, so neither policy queries the other table.

CREATE POLICY network_share_target_read ON mesh.network
    FOR SELECT TO mesh_migrator
    USING (public_id = NULLIF(pg_catalog.current_setting('mesh.share_target_network_public_id', TRUE), '')::UUID);

CREATE POLICY workspace_share_target_read ON mesh.workspace
    FOR SELECT TO mesh_migrator
    USING (id = NULLIF(pg_catalog.current_setting('mesh.share_target_workspace_id', TRUE), '')::BIGINT);

CREATE FUNCTION mesh_ops.resolve_share_target_v1(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT,
    p_provider_workspace_public_id UUID,
    p_provider_network_public_id UUID,
    p_network_display_code TEXT
)
RETURNS TABLE (
    workspace_public_id UUID,
    network_public_id UUID,
    workspace_display_code TEXT,
    network_display_code TEXT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
#variable_conflict use_column
DECLARE
    provider_deployment_id BIGINT;
    target_network UUID;
    target_workspace_id BIGINT;
BEGIN
    IF p_network_display_code IS NULL OR p_network_display_code !~ '^[0-9]{12}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid share target';
    END IF;
    PERFORM mesh_ops.set_network_scope(p_provider_workspace_public_id, p_provider_network_public_id);
    PERFORM 1 FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_provider_workspace_public_id, p_provider_network_public_id, 'share.offer',
        pg_catalog.clock_timestamp());
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'share target resolution is not permitted';
    END IF;
    SELECT workspace.deployment_id INTO STRICT provider_deployment_id
    FROM mesh.workspace AS workspace WHERE workspace.id = mesh_ops.current_workspace_id();

    SELECT identity.network_public_id INTO target_network
    FROM mesh_ops.tenant_display_identity AS identity
    WHERE identity.display_code = p_network_display_code AND identity.network_public_id IS NOT NULL;
    IF target_network IS NULL THEN
        RETURN;
    END IF;

    PERFORM pg_catalog.set_config('mesh.share_target_network_public_id', target_network::TEXT, TRUE);
    BEGIN
        SELECT network.workspace_id INTO target_workspace_id
        FROM mesh.network AS network WHERE network.public_id = target_network;
        PERFORM pg_catalog.set_config('mesh.share_target_workspace_id', COALESCE(target_workspace_id::TEXT, ''), TRUE);
        RETURN QUERY
        SELECT workspace.public_id, network.public_id, workspace_identity.display_code, p_network_display_code
        FROM mesh.network AS network
        JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
        JOIN mesh_ops.tenant_display_identity AS workspace_identity
          ON workspace_identity.workspace_public_id = workspace.public_id
        WHERE network.public_id = target_network
          AND network.state = 'active' AND network.deleted_at IS NULL
          AND workspace.state = 'active' AND workspace.deleted_at IS NULL
          AND workspace.deployment_id = provider_deployment_id;
    EXCEPTION WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.share_target_network_public_id', '', TRUE);
        PERFORM pg_catalog.set_config('mesh.share_target_workspace_id', '', TRUE);
        RAISE;
    END;
    PERFORM pg_catalog.set_config('mesh.share_target_network_public_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_target_workspace_id', '', TRUE);
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.resolve_share_target_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.resolve_share_target_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT
) TO mesh_runtime;
