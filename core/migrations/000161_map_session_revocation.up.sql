-- Schema 161: a revoked Device learns it is revoked, not expired.
--
-- A map session whose keys have no authority ends with EXPIRED, which asks
-- the node to register again and keeps its keys. A revoked Device's keys can
-- never be used again (revocation keeps them revoked so they cannot come back
-- as a new Device), so mtcp-v1 section 10 has Core send REVOKED and the node
-- erase them. Core must only say so when it is certain: this function answers
-- one question for exactly the presented machine and node key: were they the
-- current keys of a Device that was revoked with them? A key that was rotated
-- away, belongs to another Device, or never existed answers false, and the
-- node keeps getting EXPIRED.
--
-- It reveals nothing to anyone but the key holder and grants no access. Like
-- map_session_suspended_v1 (schema 126) it reads only the Device and its key
-- epochs.

CREATE FUNCTION mesh_ops.map_session_revoked_v1(
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
          AND machine.state = 'revoked'
          AND machine.epoch = device.current_machine_key_epoch
          AND node_key.public_key = p_node_key
          AND node_key.state = 'revoked'
          AND node_key.epoch = device.current_node_key_epoch
          AND device.state = 'revoked'
    );
$function$;

REVOKE ALL ON FUNCTION mesh_ops.map_session_revoked_v1(BYTEA, BYTEA) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.map_session_revoked_v1(BYTEA, BYTEA)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.map_session_revoked_v1(BYTEA, BYTEA) TO mesh_runtime;
