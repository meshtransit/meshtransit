-- Schema 231: the map names a Kubernetes cluster, not its replicas (K1a2b).
--
-- A map gives a gateway replica of its own Network a placeholder that never
-- resolves and publishes <cluster>.kube.<zone> with the addresses of the
-- cluster's replicas it holds. The runtime role cannot read the clusters, so
-- this function tells it, for the installed scope, which Devices not deleted
-- are gateways and of which cluster (a revoked one too: marking more Devices
-- than the inventory lists hides nothing; at most 64 per cluster hold an
-- ordinal). A gateway's cluster and a cluster's name never change, and a
-- cluster is deleted only without replicas, so the answer only grows or
-- shrinks with the Devices the inventory lists.
CREATE FUNCTION mesh_ops.load_map_network_kubernetes_gateways_v1()
RETURNS TABLE (numeric_node_id BIGINT, cluster_name TEXT)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace_id BIGINT := mesh_ops.current_workspace_id();
    v_network_id BIGINT := mesh_ops.current_network_id();
BEGIN
    IF v_workspace_id IS NULL OR v_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network inventory scope is unavailable';
    END IF;
    RETURN QUERY
    SELECT device.id, cluster.name
    FROM mesh.kubernetes_cluster AS cluster
    JOIN mesh.device AS device
      ON device.kubernetes_cluster_id = cluster.id
     AND device.kubernetes_cluster_id IS NOT NULL
     AND device.deleted_at IS NULL
    WHERE cluster.workspace_id = v_workspace_id
      AND cluster.network_id = v_network_id
      AND cluster.state = 'active'
      AND device.workspace_id = v_workspace_id
      AND device.network_id = v_network_id
      AND device.kind = 'kubernetes_gateway'
    ORDER BY device.id;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_kubernetes_gateways_v1()
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_kubernetes_gateways_v1() TO mesh_runtime;
