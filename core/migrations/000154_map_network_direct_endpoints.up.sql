-- Schema 154: whether a Network still holds a legacy direct share endpoint.
--
-- Every Device map read runs the share readers, which first authenticate the
-- Device by scanning its Workspace's Devices, even when the Device takes part
-- in no share: about 1.7 ms per read at 3,000 Devices, and O(N) per read.
-- The Network inventory already lists the Devices a share binds (schema
-- 146), a superset of the Devices with alias projections or sharing
-- dependencies. Legacy direct endpoints (schema 79, no longer created since
-- schema 92) are the exception: every Device of their consumer Network reads
-- them. This function tells, once per inventory read, whether the Network
-- has any ready one, so Core skips the share readers for a Device the
-- inventory shows takes part in no share. It is a superset of what
-- load_direct_share_map_edges_v1 reads (it ignores the other Workspace and
-- the target Device).

CREATE FUNCTION mesh_ops.map_network_has_direct_endpoints_v1()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
    SELECT EXISTS (
        SELECT 1
        FROM mesh.direct_device_endpoint AS endpoint
        WHERE endpoint.provider_workspace_id = mesh_ops.current_workspace_id()
          AND endpoint.provider_network_id = mesh_ops.current_network_id()
          AND endpoint.state = 'ready'
    ) OR EXISTS (
        SELECT 1
        FROM mesh.direct_device_endpoint AS endpoint
        WHERE endpoint.consumer_workspace_id = mesh_ops.current_workspace_id()
          AND endpoint.consumer_network_id = mesh_ops.current_network_id()
          AND endpoint.state = 'ready'
    )
$function$;

REVOKE ALL ON FUNCTION mesh_ops.map_network_has_direct_endpoints_v1()
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.map_network_has_direct_endpoints_v1() TO mesh_runtime;
