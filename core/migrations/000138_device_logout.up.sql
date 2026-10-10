-- Device logout over MTCP (mtcp-v1 §6.5): the node itself asks Core to
-- deauthorize its Device. The caller has resolved the Device's scope from
-- its machine key and node key (resolve_map_session_scope), entered it with
-- set_network_scope, and appends the evidence on the Network stream in the
-- same transaction. The Device and its current keys are revoked, exactly as
-- when an administrator removes a member; a logged-out Device must enroll
-- again. Errors: 22023 invalid input, 42501 no scope, P0002 the keys are not
-- the current keys of an active Device in the scope.

CREATE FUNCTION mesh_ops.logout_device_v1(
    p_machine_fingerprint BYTEA, p_node_key BYTEA, p_change_public_id UUID, p_evaluated_at TIMESTAMPTZ
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
    v_network_revision BIGINT;
    v_inventory_revision BIGINT;
    v_group_revision BIGINT;
    v_now TIMESTAMPTZ := GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at);
BEGIN
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_change_public_id IS NULL OR p_evaluated_at IS NULL
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
    SELECT principal.public_id INTO STRICT v_actor
    FROM mesh.principal AS principal WHERE principal.id = v_device.owner_principal_id;
    v_before := mesh_ops.device_lifecycle_document_internal_v1(v_device);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    PERFORM mesh_ops.revoke_member_device_internal_v1(v_device.id, 'logged out', v_now);
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
        'before', v_before,
        'after', mesh_ops.device_lifecycle_document_internal_v1(v_device),
        'actor_principal_id', v_actor,
        'network_revision', v_network_revision,
        'inventory_revision', v_inventory_revision,
        'group_revision', v_group_revision
    );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.logout_device_v1(BYTEA, BYTEA, UUID, TIMESTAMPTZ)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.logout_device_v1(BYTEA, BYTEA, UUID, TIMESTAMPTZ) TO mesh_runtime;
