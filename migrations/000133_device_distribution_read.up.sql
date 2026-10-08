-- Schema 133: read model for policy distribution status (R1-65).
--
-- Returns, under the same exact-scope device.read authority as the Device
-- inventory, the Network's current network and policy revisions together with
-- one page of Devices that should hold them (active or suspended). The control
-- plane records what each Device last received outside PostgreSQL; the API
-- compares the two. network_revision is the intended value: group, tag and
-- inventory changes alter a Device's rules without a new policy revision.
--
-- Returns NULL when the scope or authority does not resolve, like the
-- inventory read, so a probe learns nothing about other Networks.

CREATE FUNCTION mesh_ops.read_device_distribution_v1(
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
    current_network_revision BIGINT;
    current_policy_revision BIGINT;
    result JSONB;
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 101 OR
       (p_after_device_public_id IS NOT NULL AND
        pg_catalog.get_byte(pg_catalog.uuid_send(p_after_device_public_id), 6) >> 4 <> 7) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Device distribution input';
    END IF;
    BEGIN
        SELECT workspace_internal_id, network_internal_id
        INTO resolved_workspace, resolved_network
        FROM mesh_ops.set_network_scope(p_workspace_public_id, p_network_public_id);
    EXCEPTION WHEN foreign_key_violation OR insufficient_privilege THEN
        RETURN NULL;
    END;
    IF NOT EXISTS (
        SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version,
            p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'device.read', p_evaluated_at
        )
    ) THEN
        RETURN NULL;
    END IF;
    SELECT network_revision, policy_revision
    INTO current_network_revision, current_policy_revision
    FROM mesh_ops.network_revision
    WHERE workspace_id = resolved_workspace AND network_id = resolved_network;
    IF current_network_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Device distribution unavailable';
    END IF;
    SELECT pg_catalog.jsonb_build_object(
        'workspace_id', p_workspace_public_id,
        'network_id', p_network_public_id,
        'network_revision', current_network_revision,
        'policy_revision', current_policy_revision,
        'devices', COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'id', device.public_id,
            'hostname', device.hostname,
            'state', device.state
        ) ORDER BY device.public_id), '[]'::JSONB)
    ) INTO result
    FROM (
        SELECT public_id, hostname, state
        FROM mesh.device
        WHERE workspace_id = resolved_workspace AND network_id = resolved_network
          AND deleted_at IS NULL AND state IN ('active', 'suspended')
          AND (p_after_device_public_id IS NULL OR public_id > p_after_device_public_id)
        ORDER BY public_id LIMIT p_limit
    ) AS device;
    RETURN result;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_device_distribution_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_device_distribution_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) TO mesh_runtime;
