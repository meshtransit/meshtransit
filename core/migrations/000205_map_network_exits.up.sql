-- Schema 205: a Network's Exit Pools for maps (exit node design §5.3,
-- step E1d; mtcp-v1 §7.7), read once per Network revision with the
-- Network's policy and expanded per Device in Go, as subnet routes are
-- (schema 191).
--
-- The readers return facts, not decisions: the active pools with their
-- settings and elected primary (schema 204); their exit nodes with priority,
-- state, whether the Device is Workspace-owned and whether it offers to be an
-- exit node itself (schema 203); and the active release's rules whose
-- destination is an Exit Pool (schema 202), at selector level. Go decides
-- which exit nodes can serve (Device live, Workspace-owned, offering), the
-- primary, statuses and what each Device receives. Every read is bounded by
-- the technical ceilings (64 pools, 16 exit nodes per pool, 10,000 rules per
-- release).

CREATE FUNCTION mesh_ops.load_map_network_exit_pools_v1(p_limit INTEGER)
RETURNS TABLE (
    pool_id BIGINT,
    pool_public_id UUID,
    pool_name TEXT,
    smtp_allowed BOOLEAN,
    conntrack_per_consumer INTEGER,
    dns_upstreams INET[],
    probe_addresses INET[],
    probe_ports INTEGER[],
    elected BOOLEAN,
    primary_device_id BIGINT
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
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 65 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network exit pool request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network exit pool scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT exit_pool.id, exit_pool.public_id, exit_pool.name, exit_pool.smtp_allowed,
           exit_pool.conntrack_per_consumer, exit_pool.dns_upstreams,
           ARRAY(SELECT (probe ->> 'address')::INET
                 FROM pg_catalog.jsonb_array_elements(exit_pool.probes) WITH ORDINALITY AS item(probe, position)
                 ORDER BY item.position),
           ARRAY(SELECT (probe ->> 'port')::INTEGER
                 FROM pg_catalog.jsonb_array_elements(exit_pool.probes) WITH ORDINALITY AS item(probe, position)
                 ORDER BY item.position),
           elected.pool_id IS NOT NULL, elected.device_id
    FROM mesh.network_exit_pool AS exit_pool
    LEFT JOIN mesh.exit_pool_primary AS elected
      ON elected.pool_id = exit_pool.id AND elected.workspace_id = exit_pool.workspace_id
     AND elected.network_id = exit_pool.network_id
    WHERE exit_pool.workspace_id = scoped_workspace_id
      AND exit_pool.network_id = scoped_network_id
      AND exit_pool.state = 'active'
    ORDER BY exit_pool.public_id
    LIMIT p_limit;
END;
$function$;

-- The exit nodes of the active pools, with what Go needs to decide whether
-- each can serve. A Device without an offer does not offer.
CREATE FUNCTION mesh_ops.load_map_network_exit_nodes_v1(p_limit INTEGER)
RETURNS TABLE (
    pool_id BIGINT,
    device_id BIGINT,
    device_public_id UUID,
    priority INTEGER,
    node_state TEXT,
    workspace_owned BOOLEAN,
    offered BOOLEAN
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
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network exit node request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network exit node scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT exit_node.pool_id, exit_node.device_id, device.public_id, exit_node.priority, exit_node.state,
           device.ownership = 'workspace', COALESCE(offer.offered, FALSE)
    FROM mesh.network_exit_node AS exit_node
    JOIN mesh.network_exit_pool AS exit_pool
      ON exit_pool.id = exit_node.pool_id AND exit_pool.state = 'active'
    JOIN mesh.device AS device
      ON device.workspace_id = exit_node.workspace_id AND device.network_id = exit_node.network_id
     AND device.id = exit_node.device_id
    LEFT JOIN mesh.device_exit_offer AS offer ON offer.device_id = exit_node.device_id
    WHERE exit_node.workspace_id = scoped_workspace_id
      AND exit_node.network_id = scoped_network_id
    ORDER BY exit_node.pool_id, exit_node.priority, exit_node.device_id
    LIMIT p_limit;
END;
$function$;

-- The active release's rules whose destination is an Exit Pool, each source
-- named by its selector kind and internal reference.
CREATE FUNCTION mesh_ops.load_map_network_exit_rules_v1(p_policy_revision BIGINT, p_limit INTEGER)
RETURNS TABLE (
    access_rule_public_id UUID,
    source_kind TEXT,
    source_ref BIGINT,
    pool_id BIGINT,
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
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network exit rule request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network exit rule scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT rule.access_rule_public_id,
           CASE WHEN rule.source_device_group_id IS NOT NULL THEN 'device_group'
                WHEN rule.source_identity_group_id IS NOT NULL THEN 'identity_group'
                WHEN rule.source_device_tag_id IS NOT NULL THEN 'device_tag'
                ELSE 'device' END,
           COALESCE(rule.source_device_id, rule.source_device_group_id,
                    rule.source_identity_group_id, rule.source_device_tag_id),
           rule.destination_exit_pool_id, rule.protocol,
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
    JOIN mesh.compiled_policy_exit_rule AS rule ON rule.policy_release_id = release.id
    WHERE release.workspace_id = scoped_workspace_id
      AND release.network_id = scoped_network_id
      AND release.policy_revision = p_policy_revision
      AND release.state = 'active'
    ORDER BY rule.access_rule_public_id
    LIMIT p_limit;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.load_map_network_exit_pools_v1(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_exit_pools_v1(INTEGER)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_exit_pools_v1(INTEGER) TO mesh_runtime;

REVOKE ALL ON FUNCTION mesh_ops.load_map_network_exit_nodes_v1(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_exit_nodes_v1(INTEGER)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_exit_nodes_v1(INTEGER) TO mesh_runtime;

REVOKE ALL ON FUNCTION mesh_ops.load_map_network_exit_rules_v1(BIGINT, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_exit_rules_v1(BIGINT, INTEGER)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_exit_rules_v1(BIGINT, INTEGER) TO mesh_runtime;
