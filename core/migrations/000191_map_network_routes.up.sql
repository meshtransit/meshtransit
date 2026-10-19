-- Schema 191: a Network's subnet routes for maps (R1.4b, mtcp-v1 §7.6), read
-- once per Network revision with the Network's policy (schema 141) and
-- expanded per Device in Go.
--
-- The readers return facts, not decisions: the active Sites with their
-- prefixes, translation and probes; their routers with priority, state,
-- whether the Device is Workspace-owned and what it offers itself; and the
-- active release's rules whose destination is a Site, at selector level.
-- Go decides which routers can serve (Device live, Workspace-owned, offer
-- covering the Site), the primary, statuses and what each Device receives.
-- Every read is bounded by the technical ceilings (1,024 Sites, 32 routers
-- per Site, 10,000 rules per release).

CREATE FUNCTION mesh_ops.load_map_network_sites_v1(p_limit INTEGER)
RETURNS TABLE (
    site_id BIGINT,
    site_public_id UUID,
    prefixes CIDR[],
    masquerade BOOLEAN,
    probe_addresses INET[],
    probe_kinds TEXT[],
    probe_ports INTEGER[]
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
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network site request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network site scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT network_site.id, network_site.public_id, network_site.prefixes, network_site.masquerade,
           ARRAY(SELECT (probe ->> 'address')::INET
                 FROM pg_catalog.jsonb_array_elements(network_site.probes) WITH ORDINALITY AS item(probe, position)
                 ORDER BY item.position),
           ARRAY(SELECT probe ->> 'kind'
                 FROM pg_catalog.jsonb_array_elements(network_site.probes) WITH ORDINALITY AS item(probe, position)
                 ORDER BY item.position),
           ARRAY(SELECT COALESCE((probe ->> 'port')::INTEGER, 0)
                 FROM pg_catalog.jsonb_array_elements(network_site.probes) WITH ORDINALITY AS item(probe, position)
                 ORDER BY item.position)
    FROM mesh.network_site AS network_site
    WHERE network_site.workspace_id = scoped_workspace_id
      AND network_site.network_id = scoped_network_id
      AND network_site.state = 'active'
    ORDER BY network_site.public_id
    LIMIT p_limit;
END;
$function$;

-- The routers of the active Sites, with what Go needs to decide whether
-- each can serve. A Device without an offer offers nothing.
CREATE FUNCTION mesh_ops.load_map_network_site_routers_v1(p_limit INTEGER)
RETURNS TABLE (
    site_id BIGINT,
    device_id BIGINT,
    device_public_id UUID,
    priority INTEGER,
    router_state TEXT,
    workspace_owned BOOLEAN,
    offered CIDR[]
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
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 32769 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network router request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network router scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT router.site_id, router.device_id, device.public_id, router.priority, router.state,
           device.ownership = 'workspace', COALESCE(offer.prefixes, '{}'::CIDR[])
    FROM mesh.network_site_router AS router
    JOIN mesh.network_site AS network_site
      ON network_site.id = router.site_id AND network_site.state = 'active'
    JOIN mesh.device AS device
      ON device.workspace_id = router.workspace_id AND device.network_id = router.network_id
     AND device.id = router.device_id
    LEFT JOIN mesh.device_route_advertisement AS offer ON offer.device_id = router.device_id
    WHERE router.workspace_id = scoped_workspace_id
      AND router.network_id = scoped_network_id
    ORDER BY router.site_id, router.priority, router.device_id
    LIMIT p_limit;
END;
$function$;

-- The active release's rules whose destination is a Site (schema 189), each
-- source named by its selector kind and internal reference.
CREATE FUNCTION mesh_ops.load_map_network_route_rules_v1(p_policy_revision BIGINT, p_limit INTEGER)
RETURNS TABLE (
    access_rule_public_id UUID,
    source_kind TEXT,
    source_ref BIGINT,
    site_id BIGINT,
    prefixes CIDR[],
    protocol TEXT,
    port_first INTEGER[],
    port_last INTEGER[]
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
    IF p_policy_revision IS NULL OR p_policy_revision < 1 OR p_limit IS NULL OR p_limit < 1 OR p_limit > 10001 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network route rule request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network route rule scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT rule.access_rule_public_id,
           CASE WHEN rule.source_device_group_id IS NOT NULL THEN 'device_group'
                WHEN rule.source_identity_group_id IS NOT NULL THEN 'identity_group'
                WHEN rule.source_device_tag_id IS NOT NULL THEN 'device_tag'
                ELSE 'device' END,
           COALESCE(rule.source_device_id, rule.source_device_group_id,
                    rule.source_identity_group_id, rule.source_device_tag_id),
           rule.destination_site_id, rule.prefixes, rule.protocol,
           ARRAY(
               SELECT pg_catalog.lower(port_range)::INTEGER
               FROM pg_catalog.unnest(rule.destination_ports) AS port_range
               ORDER BY pg_catalog.lower(port_range), pg_catalog.upper(port_range)
           ),
           ARRAY(
               SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
               FROM pg_catalog.unnest(rule.destination_ports) AS port_range
               ORDER BY pg_catalog.lower(port_range), pg_catalog.upper(port_range)
           )
    FROM mesh.policy_release AS release
    JOIN mesh.compiled_policy_route_rule AS rule ON rule.policy_release_id = release.id
    WHERE release.workspace_id = scoped_workspace_id
      AND release.network_id = scoped_network_id
      AND release.policy_revision = p_policy_revision
      AND release.state = 'active'
    ORDER BY rule.access_rule_public_id
    LIMIT p_limit;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.load_map_network_sites_v1(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_sites_v1(INTEGER)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_sites_v1(INTEGER) TO mesh_runtime;

REVOKE ALL ON FUNCTION mesh_ops.load_map_network_site_routers_v1(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_site_routers_v1(INTEGER)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_site_routers_v1(INTEGER) TO mesh_runtime;

REVOKE ALL ON FUNCTION mesh_ops.load_map_network_route_rules_v1(BIGINT, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_route_rules_v1(BIGINT, INTEGER)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_route_rules_v1(BIGINT, INTEGER) TO mesh_runtime;
