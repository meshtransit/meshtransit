-- Schema 282: an expired Device can log out (TD-CORE-145,
-- docs/device-logout-design.md §2.2). Logout found its Device through
-- resolve_map_session_scope, which admits only Devices that have not
-- expired, so an expired Device's logout was refused and meshd erased keys
-- whose Device stayed, holding its address. resolve_logout_scope_v1 is the
-- same resolution without the expiry: the machine key and node key must
-- still be the Device's current keys, the Device active (not suspended or
-- revoked), its owner, Network, Workspace and deployment active. The
-- logout itself (logout_device_v1) already takes an active Device whatever
-- its expiry. Core asks for it only when the session proved its node key:
-- a map stream that served a map, a proof earlier in the session, or the
-- proof the Logout carries (mtcp-v1 §6.5, §6.7). A key only named in the
-- hello logs out through resolve_map_session_scope, an unexpired Device.

CREATE FUNCTION mesh_ops.resolve_logout_scope_v1(
    p_machine_key_fingerprint BYTEA,
    p_node_key BYTEA
)
RETURNS TABLE (
    workspace_public_id UUID,
    network_public_id UUID,
    recovery_epoch BIGINT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    resolved_workspace_id BIGINT;
    resolved_network_id BIGINT;
    resolved_device_id BIGINT;
    previous_map_workspace_id TEXT;
    previous_map_network_id TEXT;
BEGIN
    previous_map_workspace_id := pg_catalog.current_setting(
        'mesh.map_session_workspace_id',
        TRUE
    );
    previous_map_network_id := pg_catalog.current_setting(
        'mesh.map_session_network_id',
        TRUE
    );

    IF p_machine_key_fingerprint IS NULL
        OR pg_catalog.octet_length(p_machine_key_fingerprint) <> 32
        OR p_node_key IS NULL
        OR pg_catalog.octet_length(p_node_key) <> 32 THEN
        RETURN;
    END IF;

    SELECT device.workspace_id, device.network_id, device.id
    INTO resolved_workspace_id, resolved_network_id, resolved_device_id
    FROM mesh.device_machine_key_epoch AS machine
    JOIN mesh.device AS device
      ON device.workspace_id = machine.workspace_id
     AND device.network_id = machine.network_id
     AND device.id = machine.device_id
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.workspace_id = device.workspace_id
     AND node_key.network_id = device.network_id
     AND node_key.device_id = device.id
    WHERE machine.fingerprint = p_machine_key_fingerprint
      AND machine.state = 'active'
      AND machine.epoch = device.current_machine_key_epoch
      AND node_key.public_key = p_node_key
      AND node_key.state = 'active'
      AND node_key.epoch = device.current_node_key_epoch
      AND device.state = 'active'
      AND device.deleted_at IS NULL
      -- Schema 226: a gateway only for a session that proved its node key.
      AND (device.kind <> 'kubernetes_gateway'
           OR mesh_ops.session_proven_node_key_matches_v1(p_machine_key_fingerprint, p_node_key));

    IF NOT FOUND THEN
        RETURN;
    END IF;

    PERFORM pg_catalog.set_config(
        'mesh.map_session_workspace_id',
        resolved_workspace_id::TEXT,
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.map_session_network_id',
        resolved_network_id::TEXT,
        TRUE
    );

    RETURN QUERY
    SELECT
        workspace.public_id,
        network.public_id,
        deployment.recovery_epoch
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.id = resolved_network_id
    JOIN mesh.deployment AS deployment
      ON deployment.id = workspace.deployment_id
    JOIN mesh.device AS device
      ON device.workspace_id = workspace.id
     AND device.network_id = network.id
     AND device.id = resolved_device_id
    JOIN mesh.principal AS owner
      ON owner.id = device.owner_principal_id
     AND owner.deployment_id = deployment.id
    WHERE workspace.id = resolved_workspace_id
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL
      AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL
      AND network.state = 'active'
      AND network.deleted_at IS NULL
      AND device.state = 'active'
      AND device.deleted_at IS NULL
      AND owner.state = 'active'
      AND owner.deleted_at IS NULL;

    PERFORM pg_catalog.set_config(
        'mesh.map_session_workspace_id',
        COALESCE(previous_map_workspace_id, ''),
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.map_session_network_id',
        COALESCE(previous_map_network_id, ''),
        TRUE
    );
EXCEPTION
    WHEN OTHERS THEN
        PERFORM pg_catalog.set_config(
            'mesh.map_session_workspace_id',
            COALESCE(previous_map_workspace_id, ''),
            TRUE
        );
        PERFORM pg_catalog.set_config(
            'mesh.map_session_network_id',
            COALESCE(previous_map_network_id, ''),
            TRUE
        );
        RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.resolve_logout_scope_v1(BYTEA, BYTEA)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.resolve_logout_scope_v1(BYTEA, BYTEA) TO mesh_runtime;
