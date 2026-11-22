-- Schema 314 (TD-SEC-98): extend_device_v1 and
-- set_network_device_lifetime_v1 decide at the transaction's own time. Both
-- passed the caller's p_evaluated_at to resolve_network_permission_v2, so a
-- compromised api could pick a past time and act on a session, membership
-- or role binding that has expired but is not yet revoked. As schema 181 did
-- for the other lifecycle functions (change_device_lifecycle_v1 among them),
-- the permission is resolved at the transaction's time; p_evaluated_at stays
-- in the signatures. The bodies are schema 283's and 179's otherwise.

CREATE OR REPLACE FUNCTION mesh_ops.extend_device_v1(
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
        p_workspace_public_id, p_network_public_id, 'device.manage', pg_catalog.transaction_timestamp()
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
    -- Schema 283: a signed-out Device waits for its owner to sign in.
    IF v_device.state NOT IN ('active', 'suspended') OR v_device.ownership <> 'member'
        OR v_device.signed_out_at IS NOT NULL
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

CREATE OR REPLACE FUNCTION mesh_ops.set_network_device_lifetime_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID,
    p_expected_version BIGINT, p_device_lifetime_seconds BIGINT, p_device_never_expires BOOLEAN,
    p_change_public_id UUID, p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (
    changed BOOLEAN, role_binding_id UUID, network_revision BIGINT, name_key TEXT,
    before_version BIGINT, before_node_lifetime_seconds BIGINT,
    before_device_lifetime_seconds BIGINT, before_device_never_expires BOOLEAN,
    after_version BIGINT, after_node_lifetime_seconds BIGINT,
    after_device_lifetime_seconds BIGINT, after_device_never_expires BOOLEAN
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_revision BIGINT;
    v_profile mesh.enrollment_profile%ROWTYPE;
    v_mirror BIGINT;
BEGIN
    IF p_expected_version IS NULL OR p_expected_version < 1 OR p_device_never_expires IS NULL
        OR (p_device_never_expires AND p_device_lifetime_seconds IS NOT NULL)
        OR (NOT p_device_never_expires AND (p_device_lifetime_seconds IS NULL
            OR p_device_lifetime_seconds NOT BETWEEN 3600 AND 15552000))
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network Device lifetime request is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_network_alias_range_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.update', pg_catalog.transaction_timestamp()
    );
    SELECT revision.network_revision INTO v_revision FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    FOR UPDATE;
    IF v_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network Device lifetime scope is unavailable';
    END IF;
    SELECT * INTO v_profile FROM mesh.enrollment_profile AS profile
    WHERE profile.workspace_id = v_scope.workspace_id AND profile.network_id = v_scope.network_id
      AND profile.interactive_authorization_enabled
      AND profile.state = 'active' AND profile.deleted_at IS NULL
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'Network has no interactive enrollment profile';
    END IF;
    IF v_profile.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MTL02', MESSAGE = 'Network Device lifetime version changed';
    END IF;
    changed := v_profile.device_never_expires IS DISTINCT FROM p_device_never_expires
        OR v_profile.device_lifetime_seconds IS DISTINCT FROM p_device_lifetime_seconds;
    role_binding_id := v_scope.role_binding_public_id;
    network_revision := v_revision;
    name_key := v_profile.name_key;
    before_version := v_profile.version;
    before_node_lifetime_seconds := v_profile.node_lifetime_seconds;
    before_device_lifetime_seconds := v_profile.device_lifetime_seconds;
    before_device_never_expires := v_profile.device_never_expires;
    IF changed THEN
        -- Older binaries read only this column: never becomes 180 days.
        v_mirror := COALESCE(p_device_lifetime_seconds, 15552000);
        PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
        UPDATE mesh.enrollment_profile AS profile
        SET device_lifetime_seconds = p_device_lifetime_seconds,
            device_never_expires = p_device_never_expires,
            node_lifetime_seconds = v_mirror,
            version = profile.version + 1,
            updated_at = pg_catalog.transaction_timestamp()
        WHERE profile.id = v_profile.id
        RETURNING * INTO v_profile;
    END IF;
    after_version := v_profile.version;
    after_node_lifetime_seconds := v_profile.node_lifetime_seconds;
    after_device_lifetime_seconds := v_profile.device_lifetime_seconds;
    after_device_never_expires := v_profile.device_never_expires;
    RETURN NEXT;
END;
$function$;
