-- Schema 287: the names a Device's own map carries for its account
-- (docs/device-logout-s4b-accounts-ux.md §3, MTCP self.identity1): the
-- Workspace's display name, the Device's ownership and, for a member's
-- Device, its owner's account display name. Presentation only.
--
-- mesh.account stays revoked from mesh_runtime (it also holds login digests
-- and profile ciphertext), so the owner's name is read through
-- read_map_self_identity_v1 alone. It takes no Device ID: it is bound to the
-- installed scope and to the session's authenticated keys, under the same
-- conditions as the map's own snapshot read (active, unexpired Device of an
-- active Network), so it answers for the session's own serveable Device
-- and no other. read_scope_workspace_name_v1 gives a shared Network view the
-- Workspace's name under the installed scope, as read_scope_display_codes_v1
-- gives its codes.

CREATE FUNCTION mesh_ops.read_map_self_identity_v1(p_machine_fingerprint BYTEA, p_node_key BYTEA)
RETURNS TABLE (workspace_display_name TEXT, ownership TEXT, owner_display_name TEXT)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
    scoped_network_id BIGINT := mesh_ops.current_network_id();
BEGIN
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map self identity scope is unavailable';
    END IF;
    IF p_machine_fingerprint IS NULL OR p_node_key IS NULL THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT workspace.display_name,
        device.ownership,
        CASE WHEN device.ownership = 'member' THEN account.display_name END
    FROM mesh.device AS device
    JOIN mesh.workspace AS workspace
      ON workspace.id = device.workspace_id
    JOIN mesh.network AS network
      ON network.workspace_id = device.workspace_id
     AND network.id = device.network_id
    JOIN mesh.device_machine_key_epoch AS machine
      ON machine.workspace_id = device.workspace_id
     AND machine.network_id = device.network_id
     AND machine.device_id = device.id
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.workspace_id = device.workspace_id
     AND node_key.network_id = device.network_id
     AND node_key.device_id = device.id
    LEFT JOIN mesh.account AS account
      ON account.deployment_id = workspace.deployment_id
     AND account.principal_id = device.owner_principal_id
    WHERE device.workspace_id = scoped_workspace_id
      AND device.network_id = scoped_network_id
      AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL
      AND machine.fingerprint = p_machine_fingerprint
      AND machine.state = 'active'
      AND machine.epoch = device.current_machine_key_epoch
      AND node_key.public_key = p_node_key
      AND node_key.state = 'active'
      AND node_key.epoch = device.current_node_key_epoch
      AND network.state = 'active'
      AND network.deleted_at IS NULL
      AND device.state = 'active'
      AND device.deleted_at IS NULL
      AND device.expires_at > pg_catalog.transaction_timestamp();
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_map_self_identity_v1(BYTEA, BYTEA)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_map_self_identity_v1(BYTEA, BYTEA) TO mesh_runtime;

CREATE FUNCTION mesh_ops.read_scope_workspace_name_v1()
RETURNS TABLE (workspace_display_name TEXT)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT workspace.display_name
    FROM mesh.workspace AS workspace
    WHERE workspace.id = mesh_ops.current_workspace_id()
      AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_scope_workspace_name_v1()
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_scope_workspace_name_v1() TO mesh_runtime;
