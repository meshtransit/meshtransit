-- Schema 227 (K1a1.4b): a Kubernetes gateway moves to a new machine key
-- (mtcp-v1 §6.8), so a copy of its former Secret opens no session. The
-- session must have proved the gateway's current node key (schema 226's
-- mark); the new key was never used by any Device or gateway. The former
-- key's epoch expires and stays in the history; its handshake timestamp is
-- deleted, so the new key starts with none.

-- Rotates the gateway whose current machine key is p_machine_fingerprint and
-- current node key p_node_key, in the transaction's Network, to
-- p_new_machine_key. At most 30 machine keys a Device began within an hour:
-- past that it returns only limited_until, and writes nothing. Lock order:
-- the caller holds the Network revision; then Device and machine key epoch,
-- history, timestamp. Errors: 22023 invalid input, 42501 no scope, P0002 no
-- such gateway session, MTK13 the new key was used before.
CREATE FUNCTION mesh_ops.rotate_kubernetes_gateway_machine_key_v1(
    p_machine_fingerprint BYTEA, p_node_key BYTEA, p_new_machine_key BYTEA, p_new_fingerprint BYTEA,
    p_epoch_public_id UUID, p_change_public_id UUID
)
RETURNS TABLE (
    device_public_id UUID, previous_device_version BIGINT, device_version BIGINT,
    machine_key_epoch BIGINT, session_generation BIGINT, limited_until TIMESTAMPTZ
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
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_device mesh.device%ROWTYPE;
    v_epoch mesh.device_machine_key_epoch%ROWTYPE;
    v_recent BIGINT;
    v_oldest TIMESTAMPTZ;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_new_machine_key IS NULL OR pg_catalog.octet_length(p_new_machine_key) <> 32
        OR p_new_fingerprint IS NULL OR pg_catalog.octet_length(p_new_fingerprint) <> 32
        OR p_new_fingerprint = p_machine_fingerprint
        -- node.MachineKey.Fingerprint: the history and reuse checks rely on it.
        OR p_new_fingerprint <> pg_catalog.sha256('meshtransit/machine-key/v1'::BYTEA || '\x00'::BYTEA
            || p_new_machine_key)
        OR p_epoch_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_epoch_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'gateway machine key rotation is invalid';
    END IF;
    IF NOT mesh_ops.session_proven_node_key_matches_v1(p_machine_fingerprint, p_node_key) THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'no proven gateway session';
    END IF;
    -- The gateway, by its current keys; a rotation that committed since
    -- leaves the old fingerprint without an active epoch, and fails here.
    SELECT device.* INTO v_device
    FROM mesh.device AS device
    JOIN mesh.device_machine_key_epoch AS machine
      ON machine.workspace_id = device.workspace_id AND machine.network_id = device.network_id
     AND machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.workspace_id = device.workspace_id AND node_key.network_id = device.network_id
     AND node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
    WHERE device.workspace_id = v_workspace AND device.network_id = v_network
      AND machine.fingerprint = p_machine_fingerprint AND machine.state = 'active'
      AND node_key.public_key = p_node_key AND node_key.state = 'active'
      AND device.kind = 'kubernetes_gateway' AND device.state = 'active' AND device.deleted_at IS NULL
      AND device.expires_at > v_now
    FOR UPDATE OF device, machine;
    IF v_device.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'no proven gateway session';
    END IF;
    SELECT machine.* INTO STRICT v_epoch FROM mesh.device_machine_key_epoch AS machine
    WHERE machine.workspace_id = v_workspace AND machine.network_id = v_network
      AND machine.device_id = v_device.id AND machine.epoch = v_device.current_machine_key_epoch;
    -- The budget, counted under the Device lock across replicas: machine
    -- keys a rotation began (epoch 1 is the join's) within the hour.
    SELECT pg_catalog.count(*), pg_catalog.min(machine.valid_from) INTO v_recent, v_oldest
    FROM mesh.device_machine_key_epoch AS machine
    WHERE machine.workspace_id = v_workspace AND machine.network_id = v_network
      AND machine.device_id = v_device.id AND machine.epoch >= 2
      AND machine.valid_from > v_now - INTERVAL '1 hour';
    IF v_recent >= 30 THEN
        RETURN QUERY SELECT v_device.public_id, v_device.version, v_device.version,
            v_device.current_machine_key_epoch, v_device.session_generation, v_oldest + INTERVAL '1 hour';
        RETURN;
    END IF;
    -- The fingerprint names the key (indexed); the active key index also
    -- refuses a key another Device holds now.
    IF EXISTS (SELECT 1 FROM mesh.device_machine_key_epoch AS machine
               WHERE machine.fingerprint = p_new_fingerprint)
        OR EXISTS (SELECT 1 FROM mesh_ops.kubernetes_gateway_machine_key_history AS history
                   WHERE history.fingerprint = p_new_fingerprint) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK13', MESSAGE = 'the new machine key was used before';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.device_machine_key_epoch AS machine
    SET state = 'expired', valid_until = GREATEST(v_now, machine.valid_from), version = machine.version + 1,
        updated_at = GREATEST(v_now, machine.updated_at)
    WHERE machine.id = v_epoch.id AND machine.state = 'active';
    INSERT INTO mesh.device_machine_key_epoch (
        public_id, workspace_id, network_id, device_id, epoch, public_key, fingerprint, valid_from, state,
        created_at, updated_at
    ) VALUES (
        p_epoch_public_id, v_workspace, v_network, v_device.id, v_epoch.epoch + 1, p_new_machine_key,
        p_new_fingerprint, v_now, 'active', v_now, v_now
    );
    UPDATE mesh_ops.kubernetes_gateway_machine_key_history AS history
    SET retired_at = GREATEST(v_now, history.created_at)
    WHERE history.fingerprint = p_machine_fingerprint AND history.retired_at IS NULL;
    INSERT INTO mesh_ops.kubernetes_gateway_machine_key_history (fingerprint, device_id, created_at)
    VALUES (p_new_fingerprint, v_device.id, v_now);
    DELETE FROM mesh_ops.mtcp_machine_timestamp AS stored
    WHERE stored.machine_fingerprint = p_machine_fingerprint;
    UPDATE mesh.device AS device
    SET current_machine_key_epoch = v_epoch.epoch + 1, session_generation = device.session_generation + 1,
        version = device.version + 1, updated_at = GREATEST(v_now, device.updated_at)
    WHERE device.id = v_device.id;
    RETURN QUERY SELECT device.public_id, v_device.version, device.version, device.current_machine_key_epoch,
        device.session_generation, NULL::TIMESTAMPTZ
    FROM mesh.device AS device WHERE device.id = v_device.id;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.rotate_kubernetes_gateway_machine_key_v1(BYTEA, BYTEA, BYTEA, BYTEA, UUID, UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.rotate_kubernetes_gateway_machine_key_v1(BYTEA, BYTEA, BYTEA, BYTEA, UUID, UUID)
    TO mesh_runtime;
