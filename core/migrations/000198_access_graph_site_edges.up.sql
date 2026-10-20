-- Schema 198: the Access Graph lists the Devices each rule to a Site reaches
-- (TD-CORE-62).
--
-- read_access_graph_v3 is read_access_graph_v2 plus one edge for every
-- Device a route rule of the active release grants a Site to: the rule's
-- Device, or the Devices its group, Identity Group or tag selects now (the
-- rules of selector_devices_internal_v1), but not the Site's own routers,
-- which maps leave out. An edge names the Site, the prefixes the rule grants
-- and the selector it matched through. Its projection identity is derived
-- from the route rule and the Device, so it orders with the other edges and
-- continuation stays bound to the policy and group revisions.
--
-- v2 reads its page after the cursor; this function reads the Site edges
-- after the same cursor and keeps the first page of the two in projection
-- order, with the nodes the kept edges connect. Filtered to one Device it
-- resolves only that Device's memberships; unfiltered, more than 100,000
-- Site edges is refused like group pairs (MTA01). A Site node carries the
-- Site's name only for a caller that may also read routes (route.read).

-- The Devices the route rules of one release grant each Site to. With
-- p_device_id, only that Device, through the memberships given; without, all
-- Devices the rules' selectors hold now.
CREATE FUNCTION mesh_ops.site_graph_edges_internal_v1(
    p_workspace_id BIGINT, p_network_id BIGINT, p_release_id BIGINT, p_device_id BIGINT,
    p_device_groups BIGINT[], p_identity_groups BIGINT[], p_tags BIGINT[]
)
RETURNS TABLE (route_rule_id BIGINT, source_device_id BIGINT, source_selector_kind TEXT)
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT edge.route_rule_id, edge.source_device_id, edge.source_selector_kind
    FROM (
        SELECT rule.id AS route_rule_id, rule.destination_site_id, rule.source_device_id,
               NULL::TEXT AS source_selector_kind
        FROM mesh.compiled_policy_route_rule AS rule
        WHERE rule.policy_release_id = p_release_id AND rule.source_device_id IS NOT NULL
          AND (p_device_id IS NULL OR rule.source_device_id = p_device_id)
        UNION ALL
        SELECT rule.id, rule.destination_site_id, p_device_id,
               CASE WHEN rule.source_device_group_id IS NOT NULL THEN 'device_group'
                    WHEN rule.source_identity_group_id IS NOT NULL THEN 'identity_group'
                    ELSE 'device_tag' END
        FROM mesh.compiled_policy_route_rule AS rule
        WHERE p_device_id IS NOT NULL AND rule.policy_release_id = p_release_id
          AND (rule.source_device_group_id = ANY (p_device_groups)
               OR rule.source_identity_group_id = ANY (p_identity_groups)
               OR rule.source_device_tag_id = ANY (p_tags))
        UNION ALL
        SELECT rule.id, rule.destination_site_id, selected.device_id, selected.selector_kind
        FROM mesh.compiled_policy_route_rule AS rule
        JOIN mesh_ops.selector_devices_internal_v1(p_workspace_id, p_network_id) AS selected
          ON selected.selector_id = COALESCE(rule.source_device_group_id, rule.source_identity_group_id,
                 rule.source_device_tag_id)
         AND selected.selector_kind = CASE WHEN rule.source_device_group_id IS NOT NULL THEN 'device_group'
                 WHEN rule.source_identity_group_id IS NOT NULL THEN 'identity_group'
                 ELSE 'device_tag' END
        WHERE p_device_id IS NULL AND rule.policy_release_id = p_release_id
          AND rule.source_device_id IS NULL
    ) AS edge
    WHERE NOT EXISTS (
        SELECT 1 FROM mesh.network_site_router AS router
        WHERE router.site_id = edge.destination_site_id AND router.device_id = edge.source_device_id
    )
$function$;

REVOKE ALL ON FUNCTION mesh_ops.site_graph_edges_internal_v1(
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT[], BIGINT[], BIGINT[]
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.read_access_graph_v3(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID,
    p_network_public_id UUID,
    p_device_public_id UUID,
    p_protocol TEXT,
    p_after_projection_public_id UUID,
    p_page_size INTEGER,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (
    network_revision BIGINT,
    inventory_revision BIGINT,
    group_revision BIGINT,
    policy_revision BIGINT,
    dns_revision BIGINT,
    route_revision BIGINT,
    sharing_revision BIGINT,
    isolation_generation BIGINT,
    has_active_release BOOLEAN,
    release_public_id UUID,
    compiler_format_version INTEGER,
    release_semantic_hash BYTEA,
    matching_paths INTEGER,
    has_more BOOLEAN,
    paths JSONB,
    nodes JSONB
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    scoped_workspace BIGINT := mesh_ops.current_workspace_id();
    scoped_network BIGINT := mesh_ops.current_network_id();
    base RECORD;
    v_release_id BIGINT;
    v_device_id BIGINT;
    v_owner BIGINT;
    v_device_groups BIGINT[] := '{}';
    v_identity_groups BIGINT[] := '{}';
    v_tags BIGINT[] := '{}';
    v_tagged BOOLEAN := FALSE;
    v_site_edges BIGINT;
    v_site_matching INTEGER := 0;
    v_site_paths JSONB := '[]'::JSONB;
    v_paths JSONB;
    v_nodes JSONB;
    v_names BOOLEAN;
BEGIN
    -- v2 validates the input, the exact Network scope and policy.read and
    -- device.read authority, and raises on any failure.
    SELECT value.* INTO base
    FROM mesh_ops.read_access_graph_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_device_public_id, p_protocol,
        p_after_projection_public_id, p_page_size, p_evaluated_at
    ) AS value;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Access Graph Network scope is unavailable';
    END IF;
    IF NOT base.has_active_release THEN
        RETURN QUERY SELECT base.*;
        RETURN;
    END IF;

    SELECT release.id INTO v_release_id
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = scoped_workspace AND release.network_id = scoped_network
      AND release.public_id = base.release_public_id AND release.state = 'active';
    IF v_release_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Access Graph release changed during the read';
    END IF;

    IF p_device_public_id IS NOT NULL THEN
        SELECT device.id, device.owner_principal_id INTO v_device_id, v_owner
        FROM mesh.device AS device
        WHERE device.workspace_id = scoped_workspace AND device.network_id = scoped_network
          AND device.public_id = p_device_public_id;
        v_device_id := COALESCE(v_device_id, -1);
        SELECT COALESCE(pg_catalog.array_agg(member.device_group_id), '{}') INTO v_device_groups
        FROM mesh.device_group_member AS member
        JOIN mesh.device_group AS device_group
          ON device_group.id = member.device_group_id AND device_group.state = 'active'
        WHERE member.workspace_id = scoped_workspace AND member.network_id = scoped_network
          AND member.device_id = v_device_id;
        SELECT COALESCE(pg_catalog.array_agg(assignment.device_tag_id) FILTER (WHERE tag.state = 'active'), '{}'),
               pg_catalog.count(*) > 0
        INTO v_tags, v_tagged
        FROM mesh.device_tag_assignment AS assignment
        JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id
        WHERE assignment.device_id = v_device_id;
        IF NOT v_tagged AND v_owner IS NOT NULL THEN
            SELECT COALESCE(pg_catalog.array_agg(member.identity_group_id), '{}') INTO v_identity_groups
            FROM mesh.identity_group_member AS member
            JOIN mesh.identity_group AS identity_group
              ON identity_group.id = member.identity_group_id AND identity_group.state = 'active'
            JOIN mesh.principal AS principal
              ON principal.id = member.principal_id AND principal.state = 'active' AND principal.deleted_at IS NULL
            JOIN mesh.workspace_membership AS membership
              ON membership.workspace_id = scoped_workspace AND membership.principal_id = principal.id
             AND membership.state = 'active'
             AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
            WHERE member.workspace_id = scoped_workspace AND member.principal_id = v_owner;
        END IF;
    ELSE
        SELECT pg_catalog.count(*) INTO v_site_edges
        FROM (
            SELECT 1 FROM mesh_ops.site_graph_edges_internal_v1(
                scoped_workspace, scoped_network, v_release_id, NULL, '{}', '{}', '{}')
            LIMIT 100001
        ) AS capped;
        IF v_site_edges > 100000 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MTA01',
                MESSAGE = 'Rules to Sites expand to too many connections to list; choose a Device';
        END IF;
    END IF;

    WITH site_edge AS (
        SELECT (
                SELECT pg_catalog.encode(
                    pg_catalog.set_byte(pg_catalog.set_byte(digest.value,
                        6, (pg_catalog.get_byte(digest.value, 6) & 15) | 112),
                        8, (pg_catalog.get_byte(digest.value, 8) & 63) | 128),
                    'hex')::UUID
                FROM (
                    SELECT pg_catalog.substr(pg_catalog.sha256(pg_catalog.convert_to(
                        'site:' || rule.public_id::TEXT || ':' || source.public_id::TEXT, 'UTF8')), 1, 16) AS value
                ) AS digest
            ) AS projection_id,
            rule.access_rule_public_id AS rule_id,
            source.public_id AS source_id,
            rule.protocol,
            rule.destination_ports,
            rule.prefixes,
            network_site.public_id AS site_id,
            CASE edge.source_selector_kind WHEN 'device_group' THEN device_group.public_id END AS device_group_id,
            CASE edge.source_selector_kind WHEN 'identity_group' THEN identity_group.public_id END
                AS identity_group_id,
            CASE edge.source_selector_kind WHEN 'device_tag' THEN device_tag.public_id END AS tag_id
        FROM mesh_ops.site_graph_edges_internal_v1(
            scoped_workspace, scoped_network, v_release_id, v_device_id,
            v_device_groups, v_identity_groups, v_tags) AS edge
        JOIN mesh.compiled_policy_route_rule AS rule ON rule.id = edge.route_rule_id
        JOIN mesh.network_site AS network_site ON network_site.id = rule.destination_site_id
        JOIN mesh.device AS source
          ON source.workspace_id = scoped_workspace AND source.network_id = scoped_network
         AND source.id = edge.source_device_id
        LEFT JOIN mesh.device_group AS device_group ON device_group.id = rule.source_device_group_id
        LEFT JOIN mesh.identity_group AS identity_group ON identity_group.id = rule.source_identity_group_id
        LEFT JOIN mesh.device_tag AS device_tag ON device_tag.id = rule.source_device_tag_id
    ),
    matching AS (
        SELECT site_edge.* FROM site_edge WHERE p_protocol IS NULL OR site_edge.protocol = p_protocol
    ),
    page AS (
        SELECT matching.* FROM matching
        WHERE p_after_projection_public_id IS NULL OR matching.projection_id > p_after_projection_public_id
        ORDER BY matching.projection_id
        LIMIT p_page_size + 1
    )
    SELECT (SELECT pg_catalog.count(*)::INTEGER FROM matching),
        COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
                'projection_id', page.projection_id,
                'access_rule_id', page.rule_id,
                'source_device_id', page.source_id,
                'protocol', page.protocol,
                'destination_port_range_first', ARRAY(
                    SELECT pg_catalog.lower(port_range)::INTEGER
                    FROM pg_catalog.unnest(page.destination_ports) AS port_range
                    ORDER BY pg_catalog.lower(port_range)),
                'destination_port_range_last', ARRAY(
                    SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
                    FROM pg_catalog.unnest(page.destination_ports) AS port_range
                    ORDER BY pg_catalog.lower(port_range)),
                'selector_kind', 'site',
                'destination_site_id', page.site_id,
                'destination_prefixes', ARRAY(
                    SELECT prefix::TEXT FROM pg_catalog.unnest(page.prefixes) AS prefix ORDER BY prefix),
                'source_device_group_id', page.device_group_id,
                'source_identity_group_id', page.identity_group_id,
                'source_device_tag_id', page.tag_id
            )) ORDER BY page.projection_id)
            FROM page
        ), '[]'::JSONB)
    INTO v_site_matching, v_site_paths;

    -- The first page of both streams, in projection order.
    SELECT COALESCE(pg_catalog.jsonb_agg(kept.value ORDER BY kept.projection_id), '[]'::JSONB)
    INTO v_paths
    FROM (
        SELECT merged.value, (merged.value ->> 'projection_id')::UUID AS projection_id
        FROM (
            SELECT value FROM pg_catalog.jsonb_array_elements(base.paths) AS value
            UNION ALL
            SELECT value FROM pg_catalog.jsonb_array_elements(v_site_paths) AS value
        ) AS merged
        ORDER BY (merged.value ->> 'projection_id')::UUID
        LIMIT p_page_size
    ) AS kept;

    PERFORM permission.role_binding_public_id
    FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'route.read', p_evaluated_at
    ) AS permission;
    v_names := FOUND;

    -- The nodes the kept edges connect: v2's nodes still in use, the source
    -- Devices only Site edges name, and the Sites.
    WITH node_key AS (
        SELECT 'device'::TEXT AS kind, (path.value ->> 'source_device_id')::UUID AS id
        FROM pg_catalog.jsonb_array_elements(v_paths) AS path
        UNION
        SELECT 'device', (path.value ->> 'destination_device_id')::UUID
        FROM pg_catalog.jsonb_array_elements(v_paths) AS path
        WHERE path.value ->> 'selector_kind' = 'device'
        UNION
        SELECT 'resource', (path.value ->> 'destination_resource_id')::UUID
        FROM pg_catalog.jsonb_array_elements(v_paths) AS path
        WHERE path.value ->> 'selector_kind' IN ('resource', 'resource_group')
        UNION
        SELECT 'imported_resource', (path.value ->> 'destination_imported_resource_id')::UUID
        FROM pg_catalog.jsonb_array_elements(v_paths) AS path
        WHERE path.value ->> 'selector_kind' = 'imported_resource'
        UNION
        SELECT 'site', (path.value ->> 'destination_site_id')::UUID
        FROM pg_catalog.jsonb_array_elements(v_paths) AS path
        WHERE path.value ->> 'selector_kind' = 'site'
    ),
    kept_node AS (
        SELECT node.value,
               CASE node.value ->> 'kind' WHEN 'device' THEN 1 WHEN 'resource' THEN 2 ELSE 3 END AS kind_order,
               (node.value ->> 'id')::UUID AS sort_id
        FROM pg_catalog.jsonb_array_elements(base.nodes) AS node
        JOIN node_key ON node_key.kind = node.value ->> 'kind' AND node_key.id = (node.value ->> 'id')::UUID
    ),
    added_device AS (
        SELECT pg_catalog.jsonb_build_object(
                'kind', 'device', 'id', device.public_id, 'name', device.hostname,
                'state', CASE
                    WHEN device.state = 'active' AND device.deleted_at IS NULL
                        AND device.expires_at > p_evaluated_at THEN 'active'
                    ELSE 'inactive'
                END,
                'share', NULL
            ) AS value, 1 AS kind_order, device.public_id AS sort_id
        FROM node_key
        JOIN mesh.device AS device
          ON device.workspace_id = scoped_workspace AND device.network_id = scoped_network
         AND device.public_id = node_key.id
        WHERE node_key.kind = 'device'
          AND NOT EXISTS (SELECT 1 FROM kept_node WHERE kept_node.value ->> 'kind' = 'device'
                          AND kept_node.sort_id = node_key.id)
    ),
    site_node AS (
        SELECT pg_catalog.jsonb_build_object(
                'kind', 'site', 'id', network_site.public_id,
                'name', CASE WHEN v_names THEN network_site.name END,
                'state', CASE WHEN network_site.state = 'active' THEN 'active' ELSE 'inactive' END,
                'share', NULL
            ) AS value, 4 AS kind_order, network_site.public_id AS sort_id
        FROM node_key
        JOIN mesh.network_site AS network_site
          ON network_site.workspace_id = scoped_workspace AND network_site.network_id = scoped_network
         AND network_site.public_id = node_key.id
        WHERE node_key.kind = 'site'
    )
    SELECT COALESCE(pg_catalog.jsonb_agg(node.value ORDER BY node.kind_order, node.sort_id), '[]'::JSONB)
    INTO v_nodes
    FROM (
        SELECT value, kind_order, sort_id FROM kept_node
        UNION ALL SELECT value, kind_order, sort_id FROM added_device
        UNION ALL SELECT value, kind_order, sort_id FROM site_node
    ) AS node;

    RETURN QUERY SELECT base.network_revision, base.inventory_revision, base.group_revision,
        base.policy_revision, base.dns_revision, base.route_revision, base.sharing_revision,
        base.isolation_generation, base.has_active_release, base.release_public_id,
        base.compiler_format_version, base.release_semantic_hash,
        base.matching_paths + v_site_matching,
        pg_catalog.jsonb_array_length(base.paths) + pg_catalog.jsonb_array_length(v_site_paths) > p_page_size
            OR base.has_more,
        v_paths, v_nodes;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_access_graph_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, TEXT, UUID, INTEGER, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_access_graph_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, TEXT, UUID, INTEGER, TIMESTAMPTZ
) TO mesh_runtime;
