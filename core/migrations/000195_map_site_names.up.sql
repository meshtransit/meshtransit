-- Schema 195: maps name each Site (mtcp-v1 §7.6 SiteRoute.name), so clients
-- can show it instead of its reference.

-- The active Sites of the bound scope as v2 reads them, with their names.
CREATE FUNCTION mesh_ops.load_map_network_sites_v3(p_limit INTEGER)
RETURNS TABLE (
    site_id BIGINT,
    site_public_id UUID,
    prefixes CIDR[],
    masquerade BOOLEAN,
    probe_addresses INET[],
    probe_kinds TEXT[],
    probe_ports INTEGER[],
    elected BOOLEAN,
    primary_device_id BIGINT,
    site_name TEXT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    RETURN QUERY
    SELECT sites.site_id, sites.site_public_id, sites.prefixes, sites.masquerade, sites.probe_addresses,
           sites.probe_kinds, sites.probe_ports, sites.elected, sites.primary_device_id, network_site.name
    FROM mesh_ops.load_map_network_sites_v2(p_limit) AS sites
    JOIN mesh.network_site AS network_site ON network_site.id = sites.site_id
    ORDER BY sites.site_public_id;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.load_map_network_sites_v3(INTEGER)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_sites_v3(INTEGER) TO mesh_runtime;
