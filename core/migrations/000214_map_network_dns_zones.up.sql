-- Maps read a Network's DNS zones (DNS design D1a.2) with its policy, in the
-- inventory transaction, scoped like the other map readers to the
-- transaction's Workspace and Network.
--
-- Zones come in domain order, each with its failure mode, the internal
-- references of the Device Groups it is sent to (empty: every Device) and
-- its search position (0: none). Resolvers come one row each, in zone and
-- position order: a Device by its internal reference and public ID, with
-- whether it may serve now (active and Workspace-owned), or an Internet
-- address. A resolver Device that no longer exists comes with no internal
-- reference and never serves. Go decides the rest per Device: the
-- distribution, the rule to the resolver, liveness and the peer limit.

CREATE FUNCTION mesh_ops.load_map_network_dns_zones_v1(p_limit INTEGER)
RETURNS TABLE (
    zone_id BIGINT,
    domain TEXT,
    failure_mode TEXT,
    group_ids BIGINT[],
    search_position INTEGER
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
    scoped_network_id BIGINT := mesh_ops.current_network_id();
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1025 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network DNS zone request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network DNS zone scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT zone.id, zone.domain, zone.failure_mode, zone.distribution_group_ids,
           COALESCE(zone.search_position, 0)
    FROM mesh.network_dns_zone AS zone
    WHERE zone.workspace_id = scoped_workspace_id
      AND zone.network_id = scoped_network_id
      AND zone.state = 'active'
    ORDER BY zone.domain COLLATE "C"
    LIMIT p_limit;
END;
$function$;

CREATE FUNCTION mesh_ops.load_map_network_dns_resolvers_v1(p_limit INTEGER)
RETURNS TABLE (
    zone_id BIGINT,
    resolver_position INTEGER,
    device_id BIGINT,
    device_public_id TEXT,
    address TEXT,
    port INTEGER,
    eligible BOOLEAN
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
    scoped_network_id BIGINT := mesh_ops.current_network_id();
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 4101 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network DNS resolver request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network DNS resolver scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT zone.id, resolver.position::INTEGER, COALESCE(device.id, 0),
           COALESCE(resolver.item ->> 'device_id', ''), COALESCE(resolver.item ->> 'address', ''),
           (resolver.item ->> 'port')::INTEGER,
           COALESCE(device.state = 'active' AND device.ownership = 'workspace', FALSE)
    FROM mesh.network_dns_zone AS zone
    CROSS JOIN LATERAL pg_catalog.jsonb_array_elements(zone.resolvers) WITH ORDINALITY AS resolver (item, position)
    LEFT JOIN mesh.device AS device
      ON device.workspace_id = zone.workspace_id AND device.network_id = zone.network_id
     AND device.public_id = (resolver.item ->> 'device_id')::UUID AND device.deleted_at IS NULL
    WHERE zone.workspace_id = scoped_workspace_id
      AND zone.network_id = scoped_network_id
      AND zone.state = 'active'
    ORDER BY zone.id, resolver.position
    LIMIT p_limit;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.load_map_network_dns_zones_v1(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_dns_zones_v1(INTEGER)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_dns_zones_v1(INTEGER) TO mesh_runtime;

REVOKE ALL ON FUNCTION mesh_ops.load_map_network_dns_resolvers_v1(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_dns_resolvers_v1(INTEGER)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_dns_resolvers_v1(INTEGER) TO mesh_runtime;
