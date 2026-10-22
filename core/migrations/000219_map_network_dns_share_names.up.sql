-- Maps read the DNS names that point at a share too (DNS design D3b): a
-- name of the consumer Network whose target is a share it imports (schema
-- 217) answers that share's alias in the map of each Device the share is
-- projected to.
--
-- The reader is schema 216's with the share's imported resource public ID
-- added; it returns every active name. Go decides the rest per Device, as
-- for the other names: the zone's distribution, and for a share name the
-- map's projection of that share (a rule to it, a live contract, the peer
-- limit), which also gives the alias it answers. The v1 reader keeps
-- leaving share names out for Core releases that cannot answer them.

CREATE FUNCTION mesh_ops.load_map_network_dns_names_v2(p_limit INTEGER)
RETURNS TABLE (
    zone_id BIGINT,
    fqdn TEXT,
    kind TEXT,
    device_id BIGINT,
    device_public_id TEXT,
    addresses TEXT[],
    cname TEXT,
    share_public_id TEXT
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
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 10001 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network DNS name request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network DNS name scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT name.zone_id, name.fqdn::TEXT, name.kind, COALESCE(device.id, 0),
           COALESCE(name.device_public_id::TEXT, ''),
           COALESCE(ARRAY(SELECT pg_catalog.host(item.address)
                          FROM pg_catalog.unnest(name.addresses) WITH ORDINALITY AS item (address, ordinal)
                          ORDER BY item.ordinal), '{}'::TEXT[]),
           COALESCE(name.cname::TEXT, ''),
           COALESCE(name.share_public_id::TEXT, '')
    FROM mesh.network_dns_name AS name
    LEFT JOIN mesh.device AS device
      ON device.workspace_id = name.workspace_id AND device.network_id = name.network_id
     AND device.public_id = name.device_public_id AND device.deleted_at IS NULL
    WHERE name.workspace_id = scoped_workspace_id
      AND name.network_id = scoped_network_id
      AND name.state = 'active'
    ORDER BY name.fqdn
    LIMIT p_limit;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.load_map_network_dns_names_v2(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_dns_names_v2(INTEGER)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_dns_names_v2(INTEGER) TO mesh_runtime;
