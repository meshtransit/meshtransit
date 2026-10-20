-- Schema 206: Explain answers for an address on the Internet through an
-- Exit Pool (exit node design §5.5, step E1e).
--
-- explain_address_access_v1 answers as explain_site_access_v1 (schema 197)
-- while a Site holds the address: Sites take part of the Internet out of
-- the exit path, as maps do. When no Site holds it and it is an Internet
-- address (the set of shared/internet, mesh_ops.internet_address_internal_v1),
-- the target is an Exit Pool: the first active pool by identity whose rules
-- in the active release grant the Internet to the source Device for the
-- protocol and port, and the paths are those rules, with the pool's identity
-- as destination and no prefix. A source that is an exit node of a pool does
-- not use that pool, as in maps. Without such a pool the target is missing,
-- of kind exit_pool: no rule lets the Device reach the Internet. An address
-- that is neither in a Site nor on the Internet is a missing Site, as
-- before. The pool's name, like the Site's, is returned only to a caller
-- that may also read routes (route.read).
--
-- The result keeps the columns of explain_site_access_v1, with the target's
-- identity in target_public_id and its kind in context.

-- The rules of one release to one Exit Pool that grant the Internet to the
-- source Device, given its memberships.
CREATE FUNCTION mesh_ops.explain_exit_rules_internal_v1(
    p_release_id BIGINT, p_pool_id BIGINT, p_source_id BIGINT,
    p_device_groups BIGINT[], p_identity_groups BIGINT[], p_tags BIGINT[],
    p_protocol TEXT, p_port INTEGER
)
RETURNS SETOF mesh.compiled_policy_exit_rule
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT rule.*
    FROM mesh.compiled_policy_exit_rule AS rule
    WHERE rule.policy_release_id = p_release_id
      AND rule.destination_exit_pool_id = p_pool_id
      AND rule.protocol = p_protocol
      AND ((p_protocol = 'icmp' AND pg_catalog.isempty(rule.destination_ports))
           OR (p_protocol <> 'icmp' AND rule.destination_ports @> p_port))
      AND (rule.source_device_id = p_source_id
           OR rule.source_device_group_id = ANY (p_device_groups)
           OR rule.source_identity_group_id = ANY (p_identity_groups)
           OR rule.source_device_tag_id = ANY (p_tags))
      AND NOT EXISTS (
          SELECT 1 FROM mesh.network_exit_node AS exit_node
          WHERE exit_node.pool_id = p_pool_id AND exit_node.device_id = p_source_id
      )
$function$;

REVOKE ALL ON FUNCTION mesh_ops.explain_exit_rules_internal_v1(
    BIGINT, BIGINT, BIGINT, BIGINT[], BIGINT[], BIGINT[], TEXT, INTEGER
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.explain_address_access_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID,
    p_source_device_public_id UUID, p_destination_address INET,
    p_protocol TEXT, p_destination_port INTEGER, p_evaluated_at TIMESTAMPTZ, p_path_limit INTEGER
)
RETURNS TABLE (
    network_revision BIGINT, inventory_revision BIGINT, group_revision BIGINT,
    policy_revision BIGINT, dns_revision BIGINT, route_revision BIGINT,
    sharing_revision BIGINT, isolation_generation BIGINT,
    has_active_release BOOLEAN, release_public_id UUID,
    compiler_format_version INTEGER, release_semantic_hash BYTEA,
    target_public_id UUID, paths JSONB, context JSONB
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
    scoped_workspace_public_id UUID;
    scoped_network_public_id UUID;
    revision RECORD;
    v_release_id BIGINT;
    v_release_public_id UUID;
    v_compiler_format_version INTEGER;
    v_semantic_hash BYTEA;
    v_source_id BIGINT;
    v_source_owner BIGINT;
    source_name TEXT;
    source_state TEXT;
    v_device_groups BIGINT[] := '{}';
    v_identity_groups BIGINT[] := '{}';
    v_tags BIGINT[] := '{}';
    v_tagged BOOLEAN := FALSE;
    v_evaluate BOOLEAN;
    v_site_id BIGINT;
    v_site_public_id UUID;
    site_name TEXT;
    v_target_kind TEXT := 'site';
    v_pool_id BIGINT;
    v_pool_public_id UUID;
    v_paths JSONB := '[]'::JSONB;
BEGIN
    IF p_source_device_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_source_device_public_id), 6) >> 4 <> 7
        OR p_destination_address IS NULL
        OR NOT ((pg_catalog.family(p_destination_address) = 4 AND pg_catalog.masklen(p_destination_address) = 32)
            OR (pg_catalog.family(p_destination_address) = 6 AND pg_catalog.masklen(p_destination_address) = 128))
        OR p_protocol IS NULL OR p_protocol NOT IN ('tcp', 'udp', 'icmp')
        OR (p_protocol = 'icmp' AND p_destination_port IS DISTINCT FROM 0)
        OR (p_protocol IN ('tcp', 'udp')
            AND (p_destination_port IS NULL OR p_destination_port NOT BETWEEN 1 AND 65535))
        OR p_evaluated_at IS NULL
        OR p_path_limit IS NULL OR p_path_limit NOT BETWEEN 1 AND 65 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Access Graph explanation input is invalid';
    END IF;

    SELECT workspace.public_id, network.public_id
    INTO scoped_workspace_public_id, scoped_network_public_id
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network ON network.workspace_id = workspace.id
    WHERE workspace.id = scoped_workspace AND network.id = scoped_network;
    IF scoped_workspace_public_id IS NULL OR scoped_network_public_id IS NULL
        OR scoped_workspace_public_id <> p_workspace_public_id
        OR scoped_network_public_id <> p_network_public_id THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Access Graph Network scope is unavailable';
    END IF;

    PERFORM permission.role_binding_public_id
    FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'policy.explain', p_evaluated_at
    ) AS permission;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Access Graph explanation is not authorized';
    END IF;

    SELECT value.* INTO revision FROM mesh_ops.read_network_revision_v1() AS value;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Access Graph explanation is unavailable';
    END IF;

    SELECT release.id, release.public_id, release.compiler_format_version, release.semantic_hash
    INTO v_release_id, v_release_public_id, v_compiler_format_version, v_semantic_hash
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = scoped_workspace
      AND release.network_id = scoped_network
      AND release.policy_revision = revision.policy_revision
      AND release.state = 'active';

    SELECT device.id, device.owner_principal_id, device.hostname,
        CASE WHEN device.state = 'active' AND device.deleted_at IS NULL
                  AND device.expires_at > p_evaluated_at THEN 'active'
             ELSE 'inactive' END
    INTO v_source_id, v_source_owner, source_name, source_state
    FROM mesh.device AS device
    WHERE device.workspace_id = scoped_workspace
      AND device.network_id = scoped_network
      AND device.public_id = p_source_device_public_id;
    v_evaluate := v_release_id IS NOT NULL AND source_state = 'active';

    IF v_evaluate THEN
        SELECT COALESCE(pg_catalog.array_agg(member.device_group_id), '{}')
        INTO v_device_groups
        FROM mesh.device_group_member AS member
        JOIN mesh.device_group AS device_group
          ON device_group.id = member.device_group_id AND device_group.state = 'active'
        WHERE member.workspace_id = scoped_workspace AND member.network_id = scoped_network
          AND member.device_id = v_source_id;
        SELECT COALESCE(pg_catalog.array_agg(assignment.device_tag_id)
                   FILTER (WHERE tag.state = 'active'), '{}'),
               pg_catalog.count(*) > 0
        INTO v_tags, v_tagged
        FROM mesh.device_tag_assignment AS assignment
        JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id
        WHERE assignment.device_id = v_source_id;
        IF NOT v_tagged AND v_source_owner IS NOT NULL THEN
            SELECT COALESCE(pg_catalog.array_agg(member.identity_group_id), '{}')
            INTO v_identity_groups
            FROM mesh.identity_group_member AS member
            JOIN mesh.identity_group AS identity_group
              ON identity_group.id = member.identity_group_id AND identity_group.state = 'active'
            JOIN mesh.principal AS principal
              ON principal.id = member.principal_id AND principal.state = 'active' AND principal.deleted_at IS NULL
            JOIN mesh.workspace_membership AS membership
              ON membership.workspace_id = scoped_workspace AND membership.principal_id = principal.id
             AND membership.state = 'active'
             AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
            WHERE member.workspace_id = scoped_workspace AND member.principal_id = v_source_owner;
        END IF;
    END IF;

    SELECT holding.id, holding.public_id, holding.name
    INTO v_site_id, v_site_public_id, site_name
    FROM (
        SELECT network_site.id, network_site.public_id, network_site.name,
               pg_catalog.max(pg_catalog.masklen(prefix)) AS bits
        FROM mesh.network_site AS network_site
        CROSS JOIN LATERAL pg_catalog.unnest(network_site.prefixes) AS prefix
        WHERE network_site.workspace_id = scoped_workspace
          AND network_site.network_id = scoped_network
          AND network_site.state = 'active'
          AND prefix >>= p_destination_address
        GROUP BY network_site.id, network_site.public_id, network_site.name
    ) AS holding
    ORDER BY v_evaluate AND EXISTS (
                 SELECT 1 FROM mesh_ops.explain_site_rules_internal_v1(
                     v_release_id, holding.id, v_source_id, v_device_groups, v_identity_groups, v_tags,
                     p_destination_address, p_protocol, p_destination_port)
             ) DESC,
             holding.bits DESC, holding.public_id
    LIMIT 1;

    IF v_evaluate AND v_site_id IS NOT NULL THEN
        SELECT COALESCE(pg_catalog.jsonb_agg(path.value ORDER BY path.rule_id, path.projection_id), '[]'::JSONB)
        INTO v_paths
        FROM (
            SELECT rule.access_rule_public_id::TEXT AS rule_id, rule.public_id::TEXT AS projection_id,
                   pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
                       'projection_id', rule.public_id,
                       'access_rule_id', rule.access_rule_public_id,
                       'source_device_id', p_source_device_public_id,
                       'protocol', rule.protocol,
                       'destination_port_range_first', ARRAY(
                           SELECT pg_catalog.lower(port_range)::INTEGER
                           FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                           ORDER BY pg_catalog.lower(port_range)),
                       'destination_port_range_last', ARRAY(
                           SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
                           FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                           ORDER BY pg_catalog.lower(port_range)),
                       'selector_kind', 'site',
                       'destination_site_id', v_site_public_id,
                       'destination_prefixes', ARRAY(
                           SELECT prefix::TEXT FROM pg_catalog.unnest(rule.prefixes) AS prefix ORDER BY prefix),
                       'source_device_group_id', device_group.public_id,
                       'source_identity_group_id', identity_group.public_id,
                       'source_device_tag_id', device_tag.public_id
                   )) AS value
            FROM mesh_ops.explain_site_rules_internal_v1(
                v_release_id, v_site_id, v_source_id, v_device_groups, v_identity_groups, v_tags,
                p_destination_address, p_protocol, p_destination_port) AS rule
            LEFT JOIN mesh.device_group AS device_group ON device_group.id = rule.source_device_group_id
            LEFT JOIN mesh.identity_group AS identity_group ON identity_group.id = rule.source_identity_group_id
            LEFT JOIN mesh.device_tag AS device_tag ON device_tag.id = rule.source_device_tag_id
            ORDER BY rule.access_rule_public_id, rule.public_id
            LIMIT p_path_limit
        ) AS path;
    END IF;

    -- No Site holds an Internet address: the Exit Pools answer, through
    -- the first pool by identity whose rules grant the Internet to the
    -- source. A source that is an exit node of a pool does not use it.
    IF v_site_id IS NULL AND mesh_ops.internet_address_internal_v1(p_destination_address) THEN
        v_target_kind := 'exit_pool';
        IF v_evaluate THEN
            SELECT exit_pool.id, exit_pool.public_id, exit_pool.name
            INTO v_pool_id, v_pool_public_id, site_name
            FROM mesh.network_exit_pool AS exit_pool
            WHERE exit_pool.workspace_id = scoped_workspace
              AND exit_pool.network_id = scoped_network
              AND exit_pool.state = 'active'
              AND EXISTS (
                  SELECT 1 FROM mesh_ops.explain_exit_rules_internal_v1(
                      v_release_id, exit_pool.id, v_source_id, v_device_groups, v_identity_groups, v_tags,
                      p_protocol, p_destination_port))
            ORDER BY exit_pool.public_id
            LIMIT 1;
        END IF;
        IF v_pool_id IS NOT NULL THEN
            SELECT COALESCE(pg_catalog.jsonb_agg(path.value ORDER BY path.rule_id, path.projection_id), '[]'::JSONB)
            INTO v_paths
            FROM (
                SELECT rule.access_rule_public_id::TEXT AS rule_id, rule.public_id::TEXT AS projection_id,
                       pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
                           'projection_id', rule.public_id,
                           'access_rule_id', rule.access_rule_public_id,
                           'source_device_id', p_source_device_public_id,
                           'protocol', rule.protocol,
                           'destination_port_range_first', ARRAY(
                               SELECT pg_catalog.lower(port_range)::INTEGER
                               FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                               ORDER BY pg_catalog.lower(port_range)),
                           'destination_port_range_last', ARRAY(
                               SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
                               FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                               ORDER BY pg_catalog.lower(port_range)),
                           'selector_kind', 'exit_pool',
                           'destination_exit_pool_id', v_pool_public_id,
                           'source_device_group_id', device_group.public_id,
                           'source_identity_group_id', identity_group.public_id,
                           'source_device_tag_id', device_tag.public_id
                       )) AS value
                FROM mesh_ops.explain_exit_rules_internal_v1(
                    v_release_id, v_pool_id, v_source_id, v_device_groups, v_identity_groups, v_tags,
                    p_protocol, p_destination_port) AS rule
                LEFT JOIN mesh.device_group AS device_group ON device_group.id = rule.source_device_group_id
                LEFT JOIN mesh.identity_group AS identity_group ON identity_group.id = rule.source_identity_group_id
                LEFT JOIN mesh.device_tag AS device_tag ON device_tag.id = rule.source_device_tag_id
                ORDER BY rule.access_rule_public_id, rule.public_id
                LIMIT p_path_limit
            ) AS path;
        END IF;
    END IF;

    IF v_site_id IS NOT NULL OR v_pool_id IS NOT NULL THEN
        PERFORM permission.role_binding_public_id
        FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'route.read', p_evaluated_at
        ) AS permission;
        IF NOT FOUND THEN
            site_name := NULL;
        END IF;
    END IF;

    RETURN QUERY SELECT revision.network_revision, revision.inventory_revision, revision.group_revision,
        revision.policy_revision, revision.dns_revision, revision.route_revision,
        revision.sharing_revision, revision.isolation_generation,
        v_release_id IS NOT NULL, v_release_public_id, v_compiler_format_version, v_semantic_hash,
        COALESCE(v_site_public_id, v_pool_public_id), v_paths,
        pg_catalog.jsonb_build_object(
            'source', pg_catalog.jsonb_build_object(
                'state', COALESCE(source_state, 'missing'), 'name', source_name),
            'target', pg_catalog.jsonb_build_object(
                'kind', v_target_kind,
                'state', CASE WHEN v_site_id IS NULL AND v_pool_id IS NULL THEN 'missing' ELSE 'active' END,
                'name', site_name),
            'share', NULL
        );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.explain_address_access_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, INET, TEXT, INTEGER, TIMESTAMPTZ, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.explain_address_access_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, INET, TEXT, INTEGER, TIMESTAMPTZ, INTEGER
) TO mesh_runtime;
