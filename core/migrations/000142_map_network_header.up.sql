-- Schema 142: the header of a shared Network map view (scale-out design
-- S2b): the Network's display name and the deployment recovery epoch, under
-- the same Deployment, Workspace and Network conditions as
-- resolve_map_session_scope (schema 15). No row means the Network cannot
-- serve maps; each Device is then read on its own and refused as before.
CREATE FUNCTION mesh_ops.load_map_network_header_v1()
RETURNS TABLE (network_display_name TEXT, recovery_epoch BIGINT)
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
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network header scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT network.display_name, deployment.recovery_epoch
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.id = scoped_network_id
    JOIN mesh.deployment AS deployment
      ON deployment.id = workspace.deployment_id
    WHERE workspace.id = scoped_workspace_id
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL
      AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL
      AND network.state = 'active'
      AND network.deleted_at IS NULL;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.load_map_network_header_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_header_v1()
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_header_v1() TO mesh_runtime;
