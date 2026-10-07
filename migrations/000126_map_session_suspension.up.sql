-- Schema 126: a suspended Device learns it is suspended, not revoked.
--
-- resolve_map_session_scope admits only active Devices, so a suspended
-- Device's map session ends exactly like a revoked one and the client stops
-- for good. This function answers one question for the Device's own current
-- machine and node key: is it suspended and otherwise able to resume? The map
-- adapter then tells the client to wait and retry instead of giving up.
-- It reveals nothing to anyone but the key holder and grants no access. It
-- reads only the Device and its key epochs, like the first step of
-- resolve_map_session_scope: Network and Workspace rows need the map scope,
-- and a Device of an inactive Network merely keeps retrying.

CREATE FUNCTION mesh_ops.map_session_suspended_v1(
    p_machine_key_fingerprint BYTEA,
    p_node_key BYTEA
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
    SELECT EXISTS (
        SELECT 1
        FROM mesh.device_machine_key_epoch AS machine
        JOIN mesh.device AS device
          ON device.workspace_id = machine.workspace_id
         AND device.network_id = machine.network_id
         AND device.id = machine.device_id
        JOIN mesh.device_node_key_epoch AS node_key
          ON node_key.workspace_id = device.workspace_id
         AND node_key.network_id = device.network_id
         AND node_key.device_id = device.id
        WHERE p_machine_key_fingerprint IS NOT NULL
          AND pg_catalog.octet_length(p_machine_key_fingerprint) = 32
          AND p_node_key IS NOT NULL
          AND pg_catalog.octet_length(p_node_key) = 32
          AND machine.fingerprint = p_machine_key_fingerprint
          AND machine.state = 'active'
          AND machine.epoch = device.current_machine_key_epoch
          AND node_key.public_key = p_node_key
          AND node_key.state = 'active'
          AND node_key.epoch = device.current_node_key_epoch
          AND device.state = 'suspended'
          AND device.deleted_at IS NULL
          AND device.expires_at > pg_catalog.transaction_timestamp()
    );
$function$;

REVOKE ALL ON FUNCTION mesh_ops.map_session_suspended_v1(BYTEA, BYTEA) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.map_session_suspended_v1(BYTEA, BYTEA)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.map_session_suspended_v1(BYTEA, BYTEA) TO mesh_runtime;
