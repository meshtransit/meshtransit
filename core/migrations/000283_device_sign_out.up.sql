-- Schema 283: signing out keeps the Device (docs/device-logout-design.md
-- §3, S1). A signed-out Device keeps its identity, keys, addresses, name,
-- owner, groups, tags and the rules that name it, and is in no map: its
-- expiry is at or before signed_out_at. Only its owner signing in again on
-- the same installation (browser resume) or a handover to a member brings
-- it back; both clear signed_out_at in the same UPDATE.
--
-- A trigger keeps every other path that raises expires_at (transfer to the
-- Workspace, member removal that transfers to the Workspace, any future
-- one) from bringing a signed-out Device back: it keeps the old expiry
-- instead, so those paths still succeed and the Device stays signed out.
-- The CHECK is the backstop. Admin extension refuses (MTL01).
--
-- logout_device_v2 takes p_keep_device. Removing works as logout_device_v1
-- (revoke, addresses quarantined). Keeping: a Kubernetes gateway refuses
-- (MTK11), an ephemeral Device is removed anyway, a Workspace Device is
-- refused (MTL04: nobody can sign it back in), an already signed-out Device
-- answers "unchanged" with nothing written; otherwise expires_at becomes
-- LEAST(expires_at, now), signed_out_at now, the session generation and the
-- Network, inventory and group revisions advance. The caller appends
-- device.signed_out or device.logged_out evidence under the change ID.

ALTER TABLE mesh.device ADD COLUMN signed_out_at TIMESTAMPTZ;
ALTER TABLE mesh.device ADD CONSTRAINT device_signed_out_expiry_check
    CHECK (signed_out_at IS NULL OR expires_at <= signed_out_at);
CREATE INDEX device_signed_out_idx ON mesh.device (signed_out_at)
    WHERE signed_out_at IS NOT NULL AND deleted_at IS NULL;
-- Browser resume and handover run as mesh_runtime and clear it.
GRANT UPDATE (signed_out_at) ON mesh.device TO mesh_runtime;

CREATE FUNCTION mesh_ops.keep_signed_out_expiry_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    -- Only logout_device_v2, running as its owner, starts a sign-out; any
    -- other role (the runtime's, whatever its name) may only end one.
    IF NEW.signed_out_at IS NOT NULL AND NEW.signed_out_at IS DISTINCT FROM OLD.signed_out_at
        AND current_user::TEXT IS DISTINCT FROM (
            SELECT pg_catalog.pg_get_userbyid(proc.proowner)::TEXT FROM pg_catalog.pg_proc AS proc
            WHERE proc.oid = pg_catalog.to_regprocedure(
                'mesh_ops.logout_device_v2(bytea,bytea,boolean,uuid,timestamp with time zone)')) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'only a Device logout signs a Device out';
    END IF;
    IF NEW.signed_out_at IS NOT NULL AND NEW.expires_at > NEW.signed_out_at THEN
        NEW.expires_at := LEAST(OLD.expires_at, NEW.signed_out_at);
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.keep_signed_out_expiry_v1() FROM PUBLIC;
CREATE TRIGGER device_keep_signed_out_expiry
BEFORE UPDATE OF expires_at, signed_out_at ON mesh.device
FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_signed_out_expiry_v1();

CREATE FUNCTION mesh_ops.logout_device_v2(
    p_machine_fingerprint BYTEA, p_node_key BYTEA, p_keep_device BOOLEAN, p_change_public_id UUID,
    p_evaluated_at TIMESTAMPTZ
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
    v_device mesh.device%ROWTYPE;
    v_before JSONB;
    v_actor UUID;
    v_outcome TEXT;
    v_network_revision BIGINT;
    v_inventory_revision BIGINT;
    v_group_revision BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_keep_device IS NULL OR p_change_public_id IS NULL OR p_evaluated_at IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device logout is invalid';
    END IF;
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    -- Serializes with registration, publication and other map inputs.
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
    FOR UPDATE;
    SELECT device.* INTO v_device
    FROM mesh.device AS device
    JOIN mesh.device_machine_key_epoch AS machine
      ON machine.workspace_id = device.workspace_id AND machine.network_id = device.network_id
     AND machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch
     AND machine.state = 'active' AND machine.fingerprint = p_machine_fingerprint
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.workspace_id = device.workspace_id AND node_key.network_id = device.network_id
     AND node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
     AND node_key.state = 'active' AND node_key.public_key = p_node_key
    WHERE device.workspace_id = v_workspace AND device.network_id = v_network
      AND device.state = 'active' AND device.deleted_at IS NULL
    FOR UPDATE OF device;
    IF v_device.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device is unavailable';
    END IF;
    IF v_device.kind = 'kubernetes_gateway' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK11', MESSAGE = 'a Kubernetes gateway cannot log out';
    END IF;
    SELECT principal.public_id INTO STRICT v_actor
    FROM mesh.principal AS principal WHERE principal.id = v_device.owner_principal_id;
    v_before := mesh_ops.device_lifecycle_document_internal_v1(v_device);
    IF p_keep_device AND NOT v_device.is_ephemeral THEN
        -- A repeat first: a Device moved to the Workspace while signed out
        -- is still signed out.
        IF v_device.signed_out_at IS NOT NULL THEN
            RETURN pg_catalog.jsonb_build_object('outcome', 'unchanged', 'before', v_before, 'after', v_before,
                'actor_principal_id', v_actor, 'signed_out_at', v_device.signed_out_at);
        END IF;
        IF v_device.ownership = 'workspace' THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL04',
                MESSAGE = 'a Workspace Device cannot sign out; remove it instead';
        END IF;
        PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
        UPDATE mesh.device AS device
        SET expires_at = LEAST(device.expires_at, v_now), signed_out_at = v_now,
            session_generation = device.session_generation + 1, version = device.version + 1,
            updated_at = v_now
        WHERE device.id = v_device.id;
        v_outcome := 'signed_out';
    ELSE
        PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
        PERFORM mesh_ops.revoke_member_device_internal_v1(v_device.id, 'logged out', v_now);
        v_outcome := 'removed';
    END IF;
    SELECT * INTO STRICT v_device FROM mesh.device AS device WHERE device.id = v_device.id;

    -- Peers lose the Device and groups their member: every projection moves.
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        inventory_revision = revision.inventory_revision + 1,
        group_revision = revision.group_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
    RETURNING revision.network_revision, revision.inventory_revision, revision.group_revision
    INTO v_network_revision, v_inventory_revision, v_group_revision;

    RETURN pg_catalog.jsonb_build_object(
        'outcome', v_outcome,
        'before', v_before,
        'after', mesh_ops.device_lifecycle_document_internal_v1(v_device),
        'actor_principal_id', v_actor,
        'signed_out_at', v_device.signed_out_at,
        'network_revision', v_network_revision,
        'inventory_revision', v_inventory_revision,
        'group_revision', v_group_revision
    );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.logout_device_v2(BYTEA, BYTEA, BOOLEAN, UUID, TIMESTAMPTZ)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.logout_device_v2(BYTEA, BYTEA, BOOLEAN, UUID, TIMESTAMPTZ) TO mesh_runtime;

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
