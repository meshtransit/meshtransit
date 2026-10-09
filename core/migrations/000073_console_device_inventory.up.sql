CREATE INDEX device_network_public_id_idx
    ON mesh.device (workspace_id, network_id, public_id);

-- This function owns the complete authorized read. Runtime callers cannot
-- substitute a navigation permission or disclose the result before RBAC.
CREATE FUNCTION mesh_ops.read_console_devices_v1(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ,
    p_after_device_public_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    resolved_workspace BIGINT;
    resolved_network BIGINT;
    revision BIGINT;
    result JSONB;
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 101 OR
       (p_after_device_public_id IS NOT NULL AND
        pg_catalog.get_byte(pg_catalog.uuid_send(p_after_device_public_id), 6) >> 4 <> 7) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Device inventory input';
    END IF;
    BEGIN
        SELECT workspace_internal_id, network_internal_id
        INTO resolved_workspace, resolved_network
        FROM mesh_ops.set_network_scope(p_workspace_public_id, p_network_public_id);
    EXCEPTION WHEN foreign_key_violation OR insufficient_privilege THEN
        RETURN NULL;
    END;
    IF NOT EXISTS (
        SELECT 1 FROM mesh_ops.resolve_network_permission_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version,
            p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'device.read', p_evaluated_at
        )
    ) THEN
        RETURN NULL;
    END IF;
    SELECT inventory_revision INTO revision
    FROM mesh_ops.network_revision
    WHERE workspace_id = resolved_workspace AND network_id = resolved_network
    FOR SHARE;
    IF revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Device inventory unavailable';
    END IF;
    SELECT pg_catalog.jsonb_build_object(
        'workspace_id', p_workspace_public_id, 'network_id', p_network_public_id,
        'inventory_revision', revision,
        'devices', COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'id', device.public_id, 'hostname', device.hostname,
            'state', device.state, 'is_ephemeral', device.is_ephemeral,
            'version', device.version, 'created_at', device.created_at,
            'updated_at', device.updated_at, 'expires_at', device.expires_at
        ) ORDER BY device.public_id), '[]'::JSONB)
    ) INTO result
    FROM (
        SELECT public_id, hostname, state, is_ephemeral, version, created_at, updated_at, expires_at
        FROM mesh.device
        WHERE workspace_id = resolved_workspace AND network_id = resolved_network
          AND (p_after_device_public_id IS NULL OR public_id > p_after_device_public_id)
        ORDER BY public_id LIMIT p_limit
    ) AS device;
    RETURN result;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_console_devices_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_console_devices_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) TO mesh_runtime;
