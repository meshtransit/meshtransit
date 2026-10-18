-- An administrator gives an expired member Device a short extension, so it
-- reconnects until its user signs in again or a new key enrolls it.
--
-- Bounds: the Device is owned by a member (a Workspace Device never
-- expires), active or suspended, and already expired or expiring within a
-- day; the extension is one hour to seven days in whole minutes from the
-- database clock and must move the expiry later. The change returns the same document as
-- change_device_lifecycle_v1, so the caller audits it on the Network stream
-- and wakes the maps the same way.
CREATE FUNCTION mesh_ops.extend_device_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_device_public_id UUID,
    p_expected_version BIGINT, p_extension_seconds BIGINT,
    p_change_public_id UUID, p_evaluated_at TIMESTAMPTZ
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
    v_grant RECORD;
    v_device mesh.device%ROWTYPE;
    v_before JSONB;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_expires_at TIMESTAMPTZ;
    v_network_revision BIGINT;
    v_inventory_revision BIGINT;
    v_group_revision BIGINT;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL
        OR p_device_public_id IS NULL OR p_expected_version IS NULL OR p_expected_version < 1
        OR p_extension_seconds IS NULL OR p_extension_seconds NOT BETWEEN 3600 AND 604800
        OR p_extension_seconds % 60 <> 0
        OR p_change_public_id IS NULL OR p_evaluated_at IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device extension is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device.manage', p_evaluated_at
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Device extension is not authorized';
    END IF;

    -- Serializes with registration, publication and other map inputs.
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
    FOR UPDATE;
    SELECT * INTO v_device FROM mesh.device AS device
    WHERE device.workspace_id = v_workspace AND device.network_id = v_network
      AND device.public_id = p_device_public_id AND device.deleted_at IS NULL
    FOR UPDATE;
    IF v_device.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device is unavailable';
    END IF;
    IF v_device.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device changed';
    END IF;
    v_expires_at := v_now + pg_catalog.make_interval(secs => p_extension_seconds);
    IF v_device.state NOT IN ('active', 'suspended') OR v_device.ownership <> 'member'
        OR v_device.expires_at >= mesh_ops.device_never_expires_v1()
        OR v_device.expires_at > v_now + INTERVAL '1 day'
        OR v_expires_at <= v_device.expires_at THEN
        RAISE EXCEPTION USING ERRCODE = 'MTL01',
            MESSAGE = 'only a member Device that expired or expires within a day can be extended';
    END IF;
    v_before := mesh_ops.device_lifecycle_document_internal_v1(v_device);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.device SET expires_at = v_expires_at, version = version + 1, updated_at = v_now
    WHERE id = v_device.id RETURNING * INTO v_device;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        inventory_revision = revision.inventory_revision + 1,
        updated_at = v_now
    WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
    RETURNING revision.network_revision, revision.inventory_revision, revision.group_revision
    INTO v_network_revision, v_inventory_revision, v_group_revision;

    RETURN pg_catalog.jsonb_build_object(
        'before', v_before,
        'after', mesh_ops.device_lifecycle_document_internal_v1(v_device),
        'network_revision', v_network_revision,
        'inventory_revision', v_inventory_revision,
        'group_revision', v_group_revision,
        'role_binding_id', v_grant.role_binding_public_id,
        'permission', 'device.manage'
    );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.extend_device_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BIGINT, BIGINT,
    UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.extend_device_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BIGINT, BIGINT,
    UUID, TIMESTAMPTZ
) TO mesh_runtime;
