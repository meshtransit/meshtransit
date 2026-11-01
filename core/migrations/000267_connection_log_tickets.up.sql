-- Connection log tickets (connection logs design §16b C27, C31): a map
-- stream reads whether its node's Network logs, in the transaction's exact
-- Network scope (mesh_ops.set_network_scope). Logging counts only while
-- the Workspace has the feature; without settings it is off.
CREATE FUNCTION mesh_ops.read_connection_log_ticket_v1()
RETURNS TABLE (enabled BOOLEAN, forwarded BOOLEAN, window_s INTEGER)
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT settings.enabled AND mesh_ops.workspace_has_feature_internal_v1(settings.workspace_id, 'connection_logs'),
        settings.forwarded, settings.window_s
    FROM mesh.network_connection_log AS settings
    WHERE settings.workspace_id = mesh_ops.current_workspace_id()
      AND settings.network_id = mesh_ops.current_network_id()
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_connection_log_ticket_v1()
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_connection_log_ticket_v1() TO mesh_runtime;
