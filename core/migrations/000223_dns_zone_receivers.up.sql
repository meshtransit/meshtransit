-- DNS zone receivers (TD-CORE-87, 2026-10-24).
--
-- A zone's page counts the Devices that hold the zone from the DNS index in
-- Redis, which keeps a Device that stopped being seen for up to 30 days. A
-- Device deleted, no longer active, moved to a Device Group the zone is not
-- sent to, or into an unmanaged Device Group while offline was counted
-- "Offline" all that time. The page now asks which of the Devices it would
-- count offline still receive the zone, at most 1,000 at a time, under the
-- caller's network.read, and leaves the others out.

CREATE FUNCTION mesh_ops.dns_zone_receivers_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_zone_public_id UUID, p_device_ids UUID[]
)
RETURNS UUID[]
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_zone mesh.network_dns_zone%ROWTYPE;
    v_unmanaged BIGINT[];
    v_receivers UUID[];
BEGIN
    -- 1,000: distribution.DNSZoneReceiversBatch in Core.
    IF p_zone_public_id IS NULL OR p_device_ids IS NULL
        OR pg_catalog.cardinality(p_device_ids) > 1000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS zone receivers request is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_dns_zone_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.read'
    );
    SELECT * INTO v_zone FROM mesh.network_dns_zone AS zone
    WHERE zone.workspace_id = v_scope.workspace_id AND zone.network_id = v_scope.network_id
      AND zone.public_id = p_zone_public_id AND zone.state = 'active';
    IF v_zone.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'DNS zone is unavailable';
    END IF;
    SELECT setting.unmanaged_group_ids INTO v_unmanaged
    FROM mesh.network_dns_setting AS setting
    WHERE setting.workspace_id = v_scope.workspace_id AND setting.network_id = v_scope.network_id;
    v_unmanaged := COALESCE(v_unmanaged, '{}');
    -- What the map sends the zone to: active Devices of the Network, in one
    -- of its Device Groups when it names any, neither its resolver Devices
    -- nor the Devices of an unmanaged Device Group.
    SELECT COALESCE(pg_catalog.array_agg(device.public_id), '{}') INTO v_receivers
    FROM mesh.device AS device
    WHERE device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
      AND device.public_id = ANY (p_device_ids)
      AND device.deleted_at IS NULL AND device.state = 'active'
      AND NOT v_zone.resolvers @> pg_catalog.jsonb_build_array(
          pg_catalog.jsonb_build_object('device_id', device.public_id::TEXT))
      AND (pg_catalog.cardinality(v_zone.distribution_group_ids) = 0 OR EXISTS (
          SELECT 1 FROM mesh.device_group_member AS member
          WHERE member.workspace_id = v_scope.workspace_id AND member.network_id = v_scope.network_id
            AND member.device_id = device.id
            AND member.device_group_id = ANY (v_zone.distribution_group_ids)))
      AND (pg_catalog.cardinality(v_unmanaged) = 0 OR NOT EXISTS (
          SELECT 1 FROM mesh.device_group_member AS unmanaged
          WHERE unmanaged.workspace_id = v_scope.workspace_id AND unmanaged.network_id = v_scope.network_id
            AND unmanaged.device_id = device.id
            AND unmanaged.device_group_id = ANY (v_unmanaged)));
    RETURN v_receivers;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.dns_zone_receivers_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID[]
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.dns_zone_receivers_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID[]
) TO mesh_runtime;
