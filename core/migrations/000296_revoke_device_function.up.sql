-- Schema 296: role isolation step S3 (docs/role-isolation-design.md §4.1, TD-SEC-90).
--
-- Device revocation was three direct UPDATEs from the api's Go store (Device, current machine-key and Node-key
-- epochs) plus the lease quarantine, each guarded only by the store having checked the permission and the owner's
-- ceiling first. mesh_ops.revoke_device_v2 does those writes itself, in the caller's transaction, and only after
-- checking again, inside the database:
--   * the account session holds device.manage on the Network (resolve_network_permission_v2);
--   * the actor may act on this Device given who owns it (device_actor_within_ceiling_v1, schema 295);
--   * the Device and its current epochs are exactly the rows and versions the caller resolved, and still revocable.
-- The decision time must be the transaction's own (transaction_timestamp), as the store's is.
-- It only ever moves a Device to revoked: it never changes an owner, an expiry or a key. The store keeps its locks,
-- idempotency, revision and audit evidence; it no longer writes the three tables directly. Removing the api's direct
-- UPDATE on them waits for step S2 (the api and control still share mesh_runtime, and control needs those rights).
--
-- Expand only: images before 296 keep their direct UPDATEs and do not call the function.

CREATE FUNCTION mesh_ops.revoke_device_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_device_public_id UUID,
    p_expected_device_version BIGINT, p_expected_session_generation BIGINT,
    p_expected_machine_key_epoch BIGINT, p_expected_machine_key_version BIGINT,
    p_expected_node_key_epoch BIGINT, p_expected_node_key_version BIGINT,
    p_reason TEXT, p_change_public_id UUID, p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (
    device_version BIGINT, session_generation BIGINT, machine_key_version BIGINT, node_key_version BIGINT,
    quarantined_leases BIGINT
)
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
    v_machine mesh.device_machine_key_epoch%ROWTYPE;
    v_node mesh.device_node_key_epoch%ROWTYPE;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_device_public_id IS NULL
        OR p_expected_device_version IS NULL OR p_expected_device_version < 1
        OR p_expected_session_generation IS NULL OR p_expected_session_generation < 0
        OR p_expected_machine_key_epoch IS NULL OR p_expected_machine_key_epoch < 1
        OR p_expected_machine_key_version IS NULL OR p_expected_machine_key_version < 1
        OR p_expected_node_key_epoch IS NULL OR p_expected_node_key_epoch < 1
        OR p_expected_node_key_version IS NULL OR p_expected_node_key_version < 1
        OR p_reason IS NULL OR pg_catalog.char_length(p_reason) NOT BETWEEN 1 AND 256
        OR p_reason <> pg_catalog.btrim(p_reason)
        OR p_change_public_id IS NULL OR p_evaluated_at IS NULL
        -- The decision time is the transaction's own: a caller cannot pick a
        -- past time to use a session, membership or role that has expired.
        OR p_evaluated_at <> pg_catalog.transaction_timestamp()
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device revocation is invalid';
    END IF;
    -- The scope arguments must name the transaction's own Network.
    PERFORM 1 FROM mesh.workspace AS workspace
    JOIN mesh.network AS network ON network.workspace_id = workspace.id
    WHERE workspace.id = v_workspace AND network.id = v_network
      AND workspace.public_id = p_workspace_public_id AND network.public_id = p_network_public_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Device revocation names another Network';
    END IF;
    PERFORM 1 FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device.manage', p_evaluated_at
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Device revocation is not authorized';
    END IF;

    SELECT * INTO v_device FROM mesh.device AS device
    WHERE device.workspace_id = v_workspace AND device.network_id = v_network
      AND device.public_id = p_device_public_id
    FOR UPDATE;
    IF v_device.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device is unavailable';
    END IF;
    SELECT * INTO v_machine FROM mesh.device_machine_key_epoch AS key_epoch
    WHERE key_epoch.workspace_id = v_workspace AND key_epoch.network_id = v_network
      AND key_epoch.device_id = v_device.id AND key_epoch.epoch = v_device.current_machine_key_epoch
    FOR UPDATE;
    SELECT * INTO v_node FROM mesh.device_node_key_epoch AS key_epoch
    WHERE key_epoch.workspace_id = v_workspace AND key_epoch.network_id = v_network
      AND key_epoch.device_id = v_device.id AND key_epoch.epoch = v_device.current_node_key_epoch
    FOR UPDATE;
    -- Exactly what the caller resolved: anything else changed under it.
    IF v_machine.id IS NULL OR v_node.id IS NULL
        OR v_device.version <> p_expected_device_version
        OR v_device.session_generation <> p_expected_session_generation
        OR v_machine.epoch <> p_expected_machine_key_epoch OR v_machine.version <> p_expected_machine_key_version
        OR v_node.epoch <> p_expected_node_key_epoch OR v_node.version <> p_expected_node_key_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device changed';
    END IF;
    IF NOT mesh_ops.device_actor_within_ceiling_v1(
        v_workspace, v_network, v_device.id, p_principal_public_id, p_evaluated_at) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Device is beyond the actor''s ceiling';
    END IF;
    IF v_device.state NOT IN ('active', 'suspended', 'expired') OR v_device.deleted_at IS NOT NULL
        OR v_machine.state <> 'active' OR v_machine.valid_until IS NOT NULL OR v_machine.valid_from > p_evaluated_at
        OR v_node.state <> 'active' OR v_node.valid_until IS NOT NULL OR v_node.valid_from > p_evaluated_at THEN
        RAISE EXCEPTION USING ERRCODE = 'MTM03', MESSAGE = 'Device cannot be revoked';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    -- A removed Device keeps no suspension reason or pending handover.
    UPDATE mesh.device AS device
    SET state = 'revoked', suspended_reason = NULL, handover_principal_id = NULL,
        session_generation = device.session_generation + 1, version = device.version + 1,
        updated_at = p_evaluated_at
    WHERE device.id = v_device.id
    RETURNING device.version, device.session_generation INTO device_version, session_generation;
    UPDATE mesh.device_machine_key_epoch AS key_epoch
    SET valid_until = p_evaluated_at, revocation_reason = p_reason, state = 'revoked',
        version = key_epoch.version + 1, updated_at = p_evaluated_at
    WHERE key_epoch.id = v_machine.id
    RETURNING key_epoch.version INTO machine_key_version;
    UPDATE mesh.device_node_key_epoch AS key_epoch
    SET valid_until = p_evaluated_at, revocation_reason = p_reason, state = 'revoked',
        version = key_epoch.version + 1, updated_at = p_evaluated_at
    WHERE key_epoch.id = v_node.id
    RETURNING key_epoch.version INTO node_key_version;
    -- The Device's addresses enter quarantine; registration reuses them after.
    quarantined_leases := mesh_ops.quarantine_device_leases_v1(v_device.id, p_evaluated_at);
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.revoke_device_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TEXT, UUID, TIMESTAMPTZ)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.revoke_device_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TEXT, UUID, TIMESTAMPTZ) TO mesh_runtime;
