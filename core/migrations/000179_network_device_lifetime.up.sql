-- How long a Device that signs in through the browser lives, chosen per
-- Network on its interactive enrollment profile.
--
-- Both columns start empty, so no row changes and no authority evidence is
-- needed. Core reads them as: never expires, else the chosen seconds, else
-- 180 days for the "Interactive login" profile every Network gets, else the
-- profile's own node_lifetime_seconds. Binaries before this schema keep
-- reading node_lifetime_seconds only; the set function mirrors the choice
-- there, capped at 180 days, so they never grant a longer life.
ALTER TABLE mesh.enrollment_profile
    ADD COLUMN device_lifetime_seconds BIGINT,
    ADD COLUMN device_never_expires BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT enrollment_profile_device_lifetime_check CHECK (
        (device_lifetime_seconds IS NULL OR device_lifetime_seconds BETWEEN 3600 AND 15552000)
        AND NOT (device_never_expires AND device_lifetime_seconds IS NOT NULL)
    );

-- The Device lifetime of the Network's active interactive enrollment
-- profile, read under network.read.
CREATE FUNCTION mesh_ops.read_network_device_lifetime_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (
    profile_version BIGINT, name_key TEXT, node_lifetime_seconds BIGINT,
    device_lifetime_seconds BIGINT, device_never_expires BOOLEAN
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
BEGIN
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_network_alias_range_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.read', p_evaluated_at
    );
    RETURN QUERY
    SELECT profile.version, profile.name_key, profile.node_lifetime_seconds,
        profile.device_lifetime_seconds, profile.device_never_expires
    FROM mesh.enrollment_profile AS profile
    WHERE profile.workspace_id = v_scope.workspace_id AND profile.network_id = v_scope.network_id
      AND profile.interactive_authorization_enabled
      AND profile.state = 'active' AND profile.deleted_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'Network has no interactive enrollment profile';
    END IF;
END;
$function$;

-- Sets the Device lifetime under network.update. Takes the Network revision
-- lock before the profile row, the order registration uses. Returns the
-- profile before and after; an unchanged choice writes nothing.
CREATE FUNCTION mesh_ops.set_network_device_lifetime_v1(
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
        p_workspace_public_id, p_network_public_id, 'network.update', p_evaluated_at
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

REVOKE ALL ON FUNCTION mesh_ops.read_network_device_lifetime_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_network_device_lifetime_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.set_network_device_lifetime_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT,
    BIGINT, BOOLEAN, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.set_network_device_lifetime_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT,
    BIGINT, BOOLEAN, UUID, TIMESTAMPTZ
) TO mesh_runtime;
