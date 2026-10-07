-- Schema 124: the tags a person may apply in one Network.
--
-- A tag owner (a role or Identity Group named as owner) may apply its tag
-- without device_tag.read, which lists the whole catalog. To tag Devices from
-- the inventory such a person needs the tags they may apply, the names of the
-- tags already on the Network's Devices, and which Devices they own.
--
-- read_network_tag_options_v1 requires device.read in the bound Network and
-- returns, ordered by name, every active tag that is either applicable by the
-- caller here or assigned to a Device of this Network, each with apply =
--   any_device   device_tag.manage, or ownership with device.manage here;
--   own_devices  ownership only: the Devices the caller owns;
--   none         assigned here, but the caller may not change it;
-- the same rule change_device_tags_v1 enforces, plus the active Devices of
-- this Network the caller owns (at most 1,000). Nothing about tags the caller
-- may not apply and that no Device here carries is disclosed.

CREATE FUNCTION mesh_ops.read_network_tag_options_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_principal BIGINT;
    v_manage_any BOOLEAN;
    v_manage_devices BOOLEAN;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network scope is unavailable';
    END IF;
    PERFORM 1 FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device.read', p_evaluated_at
    );
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tag options are not readable';
    END IF;
    SELECT principal.id INTO v_principal FROM mesh.principal AS principal
    WHERE principal.public_id = p_principal_public_id AND principal.state = 'active';
    IF v_principal IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tag options are not readable';
    END IF;
    v_manage_any := mesh_ops.holds_workspace_permission_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'device_tag.manage', p_evaluated_at);
    v_manage_devices := mesh_ops.holds_device_group_permission_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device.manage', p_evaluated_at);

    RETURN pg_catalog.jsonb_build_object(
        'tags', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                       'tag_id', option.public_id, 'name', option.name,
                       'description', option.description, 'apply', option.apply
                   ) ORDER BY option.name)
            FROM (
                SELECT tag.public_id, tag.name, tag.description,
                       CASE
                           WHEN v_manage_any THEN 'any_device'
                           WHEN owned.value AND v_manage_devices THEN 'any_device'
                           WHEN owned.value THEN 'own_devices'
                           ELSE 'none'
                       END AS apply,
                       EXISTS (
                           SELECT 1 FROM mesh.device_tag_assignment AS assignment
                           WHERE assignment.workspace_id = v_workspace
                             AND assignment.network_id = v_network
                             AND assignment.device_tag_id = tag.id
                       ) AS assigned
                FROM mesh.device_tag AS tag
                CROSS JOIN LATERAL (
                    SELECT mesh_ops.device_tag_owned_by_internal_v1(
                        tag.id, v_workspace, v_network, v_principal, p_evaluated_at) AS value
                ) AS owned
                WHERE tag.workspace_id = v_workspace AND tag.state = 'active'
            ) AS option
            WHERE option.apply <> 'none' OR option.assigned
        ), '[]'::JSONB),
        'owned_device_ids', COALESCE((
            SELECT pg_catalog.jsonb_agg(owned_device.public_id ORDER BY owned_device.public_id)
            FROM (
                SELECT device.public_id FROM mesh.device AS device
                WHERE device.workspace_id = v_workspace AND device.network_id = v_network
                  AND device.owner_principal_id = v_principal AND device.state = 'active'
                  AND device.deleted_at IS NULL AND device.expires_at > p_evaluated_at
                ORDER BY device.public_id
                LIMIT 1000
            ) AS owned_device
        ), '[]'::JSONB)
    );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_network_tag_options_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_network_tag_options_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) TO mesh_runtime;
