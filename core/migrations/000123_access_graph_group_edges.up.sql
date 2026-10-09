-- Schema 123: the Access Graph lists the Device pairs group rules reach.
--
-- read_access_graph_v2 is schema 110's listing plus one edge for every pair
-- of Devices a Device Group, Identity Group or tag rule reaches at the
-- current membership and tags (resolve_group_policy_edges_v2, the resolver
-- maps use). Each such edge names the selectors it matched through. Its
-- projection identity is derived from the rule and the Device pair, so pages
-- keep one total order; callers bind continuation to the group revision as
-- well as the policy revision, because membership and tag changes alter the
-- edges without a new release. Unfiltered, more than 100,000 group pairs is
-- refused (MTA01) and the caller narrows to one Device, whose pairs the edge
-- budget bounds.

CREATE FUNCTION mesh_ops.read_access_graph_v2(
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
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    -- A share created without expiry stores this sentinel; it is reported as null.
    never_expires CONSTANT TIMESTAMPTZ := TIMESTAMPTZ '2200-01-01 00:00:00+00';
    scoped_workspace BIGINT;
    scoped_network BIGINT;
    scoped_workspace_public UUID;
    scoped_network_public UUID;
    revision RECORD;
    v_release_id BIGINT;
    v_release_public_id UUID;
    v_compiler_format INTEGER;
    v_semantic_hash BYTEA;
    v_matching INTEGER := 0;
    v_has_more BOOLEAN := FALSE;
    v_paths JSONB := '[]'::JSONB;
    v_nodes JSONB := '[]'::JSONB;
    v_device_internal BIGINT;
    v_group_edges BIGINT;
BEGIN
    IF p_workspace_public_id IS NULL
        OR p_network_public_id IS NULL
        OR p_evaluated_at IS NULL
        OR p_page_size IS NULL
        OR p_page_size NOT BETWEEN 1 AND 500
        OR (p_protocol IS NOT NULL AND p_protocol NOT IN ('tcp', 'udp', 'icmp'))
        OR (
            p_device_public_id IS NOT NULL
            AND pg_catalog.get_byte(pg_catalog.uuid_send(p_device_public_id), 6) >> 4 <> 7
        )
        OR (
            p_after_projection_public_id IS NOT NULL
            AND pg_catalog.get_byte(pg_catalog.uuid_send(p_after_projection_public_id), 6) >> 4 <> 7
        ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Access Graph listing input is invalid';
    END IF;

    scoped_workspace := mesh_ops.current_workspace_id();
    scoped_network := mesh_ops.current_network_id();
    SELECT workspace.public_id, network.public_id
    INTO scoped_workspace_public, scoped_network_public
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
    WHERE workspace.id = scoped_workspace
      AND network.id = scoped_network;
    IF scoped_workspace_public IS NULL
        OR scoped_workspace_public <> p_workspace_public_id
        OR scoped_network_public <> p_network_public_id THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'Access Graph Network scope is unavailable';
    END IF;

    PERFORM permission.role_binding_public_id
    FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'policy.read', p_evaluated_at
    ) AS permission;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Access Graph listing is not authorized';
    END IF;
    PERFORM permission.role_binding_public_id
    FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device.read', p_evaluated_at
    ) AS permission;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Access Graph listing is not authorized';
    END IF;

    SELECT value.* INTO revision FROM mesh_ops.read_network_revision_v1() AS value;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Access Graph Network scope is unavailable';
    END IF;

    SELECT release.id, release.public_id, release.compiler_format_version, release.semantic_hash
    INTO v_release_id, v_release_public_id, v_compiler_format, v_semantic_hash
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = scoped_workspace
      AND release.network_id = scoped_network
      AND release.policy_revision = revision.policy_revision
      AND release.state = 'active';

    IF v_release_id IS NOT NULL THEN
        -- Group rules resolve over current membership and tags. Filtered to
        -- one Device they stay within its edge budget; unfiltered, a Network
        -- whose group rules expand to more pairs than one listing can count
        -- must be narrowed to a Device first.
        IF p_device_public_id IS NOT NULL THEN
            SELECT device.id INTO v_device_internal
            FROM mesh.device AS device
            WHERE device.workspace_id = scoped_workspace
              AND device.network_id = scoped_network
              AND device.public_id = p_device_public_id;
            v_device_internal := COALESCE(v_device_internal, -1);
        ELSE
            SELECT pg_catalog.count(*) INTO v_group_edges
            FROM (
                SELECT 1 FROM mesh_ops.resolve_group_policy_edges_v2(NULL) LIMIT 100001
            ) AS capped;
            IF v_group_edges > 100000 THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'MTA01',
                    MESSAGE = 'Group rules expand to too many connections to list; choose a Device';
            END IF;
        END IF;

        WITH local_edge AS (
            SELECT rule.public_id AS projection_id,
                rule.access_rule_public_id AS rule_id,
                source.public_id AS source_id,
                destination.public_id AS destination_id,
                rule.protocol,
                rule.destination_ports,
                CASE
                    WHEN group_provenance.id IS NOT NULL THEN 'resource_group'
                    WHEN resource_provenance.id IS NOT NULL THEN 'resource'
                    ELSE 'device'
                END AS selector_kind,
                COALESCE(member.public_id, direct_resource.public_id) AS resource_id,
                resource_group.public_id AS group_id,
                NULL::UUID AS imported_id,
                NULL::UUID AS contract_id,
                NULL::TEXT AS source_selector_kind,
                NULL::UUID AS source_selector_id,
                NULL::TEXT AS destination_selector_kind,
                NULL::UUID AS destination_selector_id
            FROM mesh.compiled_policy_rule AS rule
            JOIN mesh.device AS source
              ON source.workspace_id = rule.workspace_id
             AND source.network_id = rule.network_id
             AND source.id = rule.source_device_id
            JOIN mesh.device AS destination
              ON destination.workspace_id = rule.workspace_id
             AND destination.network_id = rule.network_id
             AND destination.id = rule.destination_device_id
            LEFT JOIN mesh.compiled_policy_resource_destination AS resource_provenance
              ON resource_provenance.workspace_id = rule.workspace_id
             AND resource_provenance.network_id = rule.network_id
             AND resource_provenance.compiled_policy_rule_id = rule.id
            LEFT JOIN mesh.resource AS direct_resource
              ON direct_resource.workspace_id = rule.workspace_id
             AND direct_resource.network_id = rule.network_id
             AND direct_resource.id = resource_provenance.destination_resource_id
            LEFT JOIN mesh.compiled_policy_resource_group_destination AS group_provenance
              ON group_provenance.workspace_id = rule.workspace_id
             AND group_provenance.network_id = rule.network_id
             AND group_provenance.compiled_policy_rule_id = rule.id
            LEFT JOIN mesh.resource AS member
              ON member.workspace_id = rule.workspace_id
             AND member.network_id = rule.network_id
             AND member.id = group_provenance.destination_resource_id
            LEFT JOIN mesh.resource_group AS resource_group
              ON resource_group.workspace_id = rule.workspace_id
             AND resource_group.network_id = rule.network_id
             AND resource_group.id = group_provenance.destination_resource_group_id
            WHERE rule.workspace_id = scoped_workspace
              AND rule.network_id = scoped_network
              AND rule.policy_release_id = v_release_id
              AND rule.policy_revision = revision.policy_revision
        ),
        imported_edge AS (
            SELECT rule.public_id AS projection_id,
                rule.access_rule_public_id AS rule_id,
                source.public_id AS source_id,
                NULL::UUID AS destination_id,
                rule.protocol,
                rule.destination_ports,
                'imported_resource'::TEXT AS selector_kind,
                NULL::UUID AS resource_id,
                NULL::UUID AS group_id,
                imported.public_id AS imported_id,
                contract.public_id AS contract_id,
                NULL::TEXT AS source_selector_kind,
                NULL::UUID AS source_selector_id,
                NULL::TEXT AS destination_selector_kind,
                NULL::UUID AS destination_selector_id
            FROM mesh.compiled_policy_imported_resource_destination AS rule
            JOIN mesh.device AS source
              ON source.workspace_id = rule.workspace_id
             AND source.network_id = rule.network_id
             AND source.id = rule.source_device_id
            JOIN mesh.imported_resource AS imported
              ON imported.workspace_id = rule.workspace_id
             AND imported.network_id = rule.network_id
             AND imported.id = rule.imported_resource_id
            JOIN mesh.trust_contract AS contract
              ON contract.id = rule.trust_contract_id
             AND contract.consumer_workspace_id = scoped_workspace
             AND contract.consumer_network_id = scoped_network
            WHERE rule.workspace_id = scoped_workspace
              AND rule.network_id = scoped_network
              AND rule.policy_release_id = v_release_id
              AND rule.policy_revision = revision.policy_revision
        ),
        -- One edge per Device pair a group rule reaches now. Its projection
        -- identity is derived from the rule and the pair, so it is stable
        -- while the membership holds and orders with compiled projections.
        group_edge AS (
            SELECT (
                    SELECT pg_catalog.encode(
                        pg_catalog.set_byte(pg_catalog.set_byte(digest.value,
                            6, (pg_catalog.get_byte(digest.value, 6) & 15) | 112),
                            8, (pg_catalog.get_byte(digest.value, 8) & 63) | 128),
                        'hex')::UUID
                    FROM (
                        SELECT pg_catalog.substr(pg_catalog.sha256(pg_catalog.convert_to(
                            edge.rule_public_id::TEXT || ':' || source.public_id::TEXT || ':'
                                || destination.public_id::TEXT, 'UTF8')), 1, 16) AS value
                    ) AS digest
                ) AS projection_id,
                edge.access_rule_public_id AS rule_id,
                source.public_id AS source_id,
                destination.public_id AS destination_id,
                edge.protocol,
                edge.destination_ports,
                'device'::TEXT AS selector_kind,
                NULL::UUID AS resource_id,
                NULL::UUID AS group_id,
                NULL::UUID AS imported_id,
                NULL::UUID AS contract_id,
                edge.source_selector_kind,
                edge.source_selector_public_id AS source_selector_id,
                edge.destination_selector_kind,
                edge.destination_selector_public_id AS destination_selector_id
            FROM mesh_ops.resolve_group_policy_edges_v2(v_device_internal) AS edge
            JOIN mesh.device AS source
              ON source.workspace_id = scoped_workspace
             AND source.network_id = scoped_network
             AND source.id = edge.source_device_id
            JOIN mesh.device AS destination
              ON destination.workspace_id = scoped_workspace
             AND destination.network_id = scoped_network
             AND destination.id = edge.destination_device_id
        ),
        matching AS (
            SELECT edge.*
            FROM (
                SELECT * FROM local_edge
                UNION ALL SELECT * FROM imported_edge
                UNION ALL SELECT * FROM group_edge
            ) AS edge
            WHERE (p_protocol IS NULL OR edge.protocol = p_protocol)
              AND (
                p_device_public_id IS NULL
                OR edge.source_id = p_device_public_id
                OR (edge.selector_kind = 'device' AND edge.destination_id = p_device_public_id)
              )
        ),
        page AS (
            SELECT matching.*
            FROM matching
            WHERE p_after_projection_public_id IS NULL
               OR matching.projection_id > p_after_projection_public_id
            ORDER BY matching.projection_id
            LIMIT p_page_size + 1
        ),
        bounded AS (
            SELECT page.* FROM page ORDER BY page.projection_id LIMIT p_page_size
        ),
        node_key AS (
            SELECT 'device'::TEXT AS kind, bounded.source_id AS id FROM bounded
            UNION
            SELECT 'device', bounded.destination_id FROM bounded WHERE bounded.selector_kind = 'device'
            UNION
            SELECT 'resource', bounded.resource_id FROM bounded
            WHERE bounded.selector_kind IN ('resource', 'resource_group')
            UNION
            SELECT 'imported_resource', bounded.imported_id FROM bounded
            WHERE bounded.selector_kind = 'imported_resource'
        ),
        device_node AS (
            SELECT pg_catalog.jsonb_build_object(
                'kind', 'device', 'id', device.public_id, 'name', device.hostname,
                'state', CASE
                    WHEN device.state = 'active' AND device.deleted_at IS NULL
                        AND device.expires_at > p_evaluated_at THEN 'active'
                    ELSE 'inactive'
                END,
                'share', NULL
            ) AS value, device.public_id AS sort_id
            FROM node_key
            JOIN mesh.device AS device
              ON device.workspace_id = scoped_workspace
             AND device.network_id = scoped_network
             AND device.public_id = node_key.id
            WHERE node_key.kind = 'device'
        ),
        resource_node AS (
            SELECT pg_catalog.jsonb_build_object(
                'kind', 'resource', 'id', resource.public_id, 'name', resource.display_name,
                'state', CASE
                    WHEN resource.state = 'active' AND resource.deleted_at IS NULL THEN 'active'
                    ELSE 'inactive'
                END,
                'share', NULL
            ) AS value, resource.public_id AS sort_id
            FROM node_key
            JOIN mesh.resource AS resource
              ON resource.workspace_id = scoped_workspace
             AND resource.network_id = scoped_network
             AND resource.public_id = node_key.id
            WHERE node_key.kind = 'resource'
        ),
        imported_node AS (
            SELECT pg_catalog.jsonb_build_object(
                'kind', 'imported_resource', 'id', imported.public_id, 'name', imported.display_name,
                'state', CASE WHEN imported.state = 'active' THEN 'active' ELSE 'inactive' END,
                'share', pg_catalog.jsonb_build_object(
                    'trust_contract_id', contract.public_id,
                    'state', CASE
                        WHEN contract.state IN ('activating', 'active')
                            AND contract.expires_at <= p_evaluated_at THEN 'expired'
                        ELSE contract.state
                    END,
                    'expires_at', CASE
                        WHEN contract.expires_at >= never_expires THEN NULL
                        ELSE contract.expires_at
                    END,
                    'provider_workspace_code', provider_workspace_code.display_code,
                    'provider_network_code', provider_network_code.display_code,
                    'access_name', (
                        SELECT access_name.access_name
                        FROM mesh.imported_resource_access_name AS access_name
                        WHERE access_name.workspace_id = scoped_workspace
                          AND access_name.network_id = scoped_network
                          AND access_name.imported_resource_id = imported.id
                        ORDER BY (access_name.state = 'reserved') DESC, access_name.id DESC
                        LIMIT 1
                    )
                )
            ) AS value, imported.public_id AS sort_id
            FROM node_key
            JOIN mesh.imported_resource AS imported
              ON imported.workspace_id = scoped_workspace
             AND imported.network_id = scoped_network
             AND imported.public_id = node_key.id
            JOIN mesh.trust_contract AS contract
              ON contract.id = imported.trust_contract_id
             AND contract.consumer_workspace_id = scoped_workspace
             AND contract.consumer_network_id = scoped_network
            -- The consumer's own locator row names the provider; provider
            -- tenant rows stay hidden by their row-level security.
            JOIN mesh.share_offer_locator AS locator
              ON locator.local_workspace_id = scoped_workspace
             AND locator.local_network_id = scoped_network
             AND locator.offer_id = contract.share_offer_id
            LEFT JOIN mesh_ops.tenant_display_identity AS provider_workspace_code
              ON provider_workspace_code.workspace_public_id = locator.provider_workspace_public_id
            LEFT JOIN mesh_ops.tenant_display_identity AS provider_network_code
              ON provider_network_code.network_public_id = locator.provider_network_public_id
            WHERE node_key.kind = 'imported_resource'
        )
        SELECT
            (SELECT pg_catalog.count(*)::INTEGER FROM matching),
            (SELECT pg_catalog.count(*) FROM page) > p_page_size,
            COALESCE((
                SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                    'projection_id', bounded.projection_id,
                    'access_rule_id', bounded.rule_id,
                    'source_device_id', bounded.source_id,
                    'destination_device_id', bounded.destination_id,
                    'protocol', bounded.protocol,
                    'destination_port_range_first', ARRAY(
                        SELECT pg_catalog.lower(port_range)::INTEGER
                        FROM pg_catalog.unnest(bounded.destination_ports) AS port_range
                        ORDER BY pg_catalog.lower(port_range)
                    ),
                    'destination_port_range_last', ARRAY(
                        SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
                        FROM pg_catalog.unnest(bounded.destination_ports) AS port_range
                        ORDER BY pg_catalog.lower(port_range)
                    ),
                    'selector_kind', bounded.selector_kind,
                    'destination_resource_id', bounded.resource_id,
                    'destination_resource_group_id', bounded.group_id,
                    'destination_imported_resource_id', bounded.imported_id,
                    'trust_contract_id', bounded.contract_id,
                    'source_device_group_id', CASE WHEN bounded.source_selector_kind = 'device_group'
                        THEN bounded.source_selector_id END,
                    'source_identity_group_id', CASE WHEN bounded.source_selector_kind = 'identity_group'
                        THEN bounded.source_selector_id END,
                    'source_device_tag_id', CASE WHEN bounded.source_selector_kind = 'device_tag'
                        THEN bounded.source_selector_id END,
                    'destination_device_group_id', CASE WHEN bounded.destination_selector_kind = 'device_group'
                        THEN bounded.destination_selector_id END,
                    'destination_device_tag_id', CASE WHEN bounded.destination_selector_kind = 'device_tag'
                        THEN bounded.destination_selector_id END
                ) ORDER BY bounded.projection_id)
                FROM bounded
            ), '[]'::JSONB),
            COALESCE((
                SELECT pg_catalog.jsonb_agg(node.value ORDER BY node.kind_order, node.sort_id)
                FROM (
                    SELECT device_node.value, 1 AS kind_order, device_node.sort_id FROM device_node
                    UNION ALL
                    SELECT resource_node.value, 2, resource_node.sort_id FROM resource_node
                    UNION ALL
                    SELECT imported_node.value, 3, imported_node.sort_id FROM imported_node
                ) AS node
            ), '[]'::JSONB)
        INTO v_matching, v_has_more, v_paths, v_nodes;
    END IF;

    RETURN QUERY SELECT
        revision.network_revision,
        revision.inventory_revision,
        revision.group_revision,
        revision.policy_revision,
        revision.dns_revision,
        revision.route_revision,
        revision.sharing_revision,
        revision.isolation_generation,
        v_release_id IS NOT NULL,
        v_release_public_id,
        v_compiler_format,
        v_semantic_hash,
        v_matching,
        v_has_more,
        v_paths,
        v_nodes;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_access_graph_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, TEXT, UUID, INTEGER, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_access_graph_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, TEXT, UUID, INTEGER, TIMESTAMPTZ
) TO mesh_runtime;
