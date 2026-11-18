-- Schema 297: role isolation step S2.2 (docs/role-isolation-design.md §3.5, TD-SEC-90).
--
-- Since schema 296 the api revokes a Device only through mesh_ops.revoke_device_v2, but its store still locks the
-- Device and its current machine-key and Node-key epochs FOR UPDATE while it resolves the command, and a row lock
-- needs UPDATE on the table. mesh_ops.lock_device_revocation_target_v1 takes that lock as its owner, for one Device
-- of the transaction's own Network scope only, and returns what the store read. Step S2.3 can then take UPDATE on
-- those tables away from the api's group.
--
-- The scope the caller passes must be the transaction's scope (mesh_ops.current_workspace_id/current_network_id),
-- so the function reaches no row the caller's row-level security would hide. It only reads and locks: it changes
-- nothing. Grants go to the api's group role only; from this schema no migration grants to a login.
--
-- Expand only: images before 297 keep their direct FOR UPDATE and do not call the function.

CREATE FUNCTION mesh_ops.lock_device_revocation_target_v1(
    p_workspace_id BIGINT, p_network_id BIGINT, p_device_public_id UUID
)
RETURNS TABLE (
    device_id BIGINT, device_version BIGINT, session_generation BIGINT, device_state TEXT,
    machine_key_epoch BIGINT, machine_key_id BIGINT, machine_key_version BIGINT, machine_key_state TEXT,
    machine_key_valid_from TIMESTAMPTZ,
    node_key_epoch BIGINT, node_key_id BIGINT, node_key_version BIGINT, node_key_state TEXT,
    node_key_valid_from TIMESTAMPTZ
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
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_workspace_id IS DISTINCT FROM v_workspace OR p_network_id IS DISTINCT FROM v_network
        OR p_device_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Device lock is outside the transaction scope';
    END IF;
    RETURN QUERY
    SELECT
        device.id,
        device.version,
        device.session_generation,
        device.state,
        device.current_machine_key_epoch,
        machine_key.id,
        machine_key.version,
        machine_key.state,
        machine_key.valid_from,
        device.current_node_key_epoch,
        node_key.id,
        node_key.version,
        node_key.state,
        node_key.valid_from
    FROM mesh.device AS device
    JOIN mesh.device_machine_key_epoch AS machine_key
      ON machine_key.workspace_id = device.workspace_id
     AND machine_key.network_id = device.network_id
     AND machine_key.device_id = device.id
     AND machine_key.epoch = device.current_machine_key_epoch
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.workspace_id = device.workspace_id
     AND node_key.network_id = device.network_id
     AND node_key.device_id = device.id
     AND node_key.epoch = device.current_node_key_epoch
    WHERE device.workspace_id = v_workspace
      AND device.network_id = v_network
      AND device.public_id = p_device_public_id
    FOR UPDATE OF device, machine_key, node_key;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.lock_device_revocation_target_v1(BIGINT, BIGINT, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_device_revocation_target_v1(BIGINT, BIGINT, UUID) TO mesh_api_rights;
