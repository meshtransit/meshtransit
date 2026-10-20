-- Schema 197: Explain answers for an address inside a Site (TD-CORE-62).
--
-- explain_site_access_v1 asks the same question explain_active_policy_v4
-- asks of a Device or Resource, with an address as the destination: may this
-- Device reach this address with this protocol and port? The target is the
-- active Site whose prefixes hold the address (Sites of a Network never
-- overlap); with none it is missing. Paths are the active release's route
-- rules to that Site whose source holds the Device now (the shared selector
-- resolver maps use), whose granted prefixes hold the address and whose
-- protocol and ports match. Route rules carry no compiled edge: a path names
-- the route rule's own identity as its projection.
--
-- The result keeps the columns of explain_active_policy_v4, with the Site in
-- the place of the target Device, so one reader decodes both.

CREATE FUNCTION mesh_ops.explain_site_access_v1(
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
    target_site_public_id UUID, paths JSONB, context JSONB
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
    source_name TEXT;
    source_state TEXT;
    v_site_id BIGINT;
    v_site_public_id UUID;
    site_name TEXT;
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

    SELECT device.id, device.hostname,
        CASE WHEN device.state = 'active' AND device.deleted_at IS NULL
                  AND device.expires_at > p_evaluated_at THEN 'active'
             ELSE 'inactive' END
    INTO v_source_id, source_name, source_state
    FROM mesh.device AS device
    WHERE device.workspace_id = scoped_workspace
      AND device.network_id = scoped_network
      AND device.public_id = p_source_device_public_id;

    SELECT network_site.id, network_site.public_id, network_site.name
    INTO v_site_id, v_site_public_id, site_name
    FROM mesh.network_site AS network_site
    WHERE network_site.workspace_id = scoped_workspace
      AND network_site.network_id = scoped_network
      AND network_site.state = 'active'
      AND EXISTS (
          SELECT 1 FROM pg_catalog.unnest(network_site.prefixes) AS prefix
          WHERE prefix >>= p_destination_address
      )
    ORDER BY network_site.public_id
    LIMIT 1;

    IF v_release_id IS NOT NULL AND source_state = 'active' AND v_site_id IS NOT NULL THEN
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
                           SELECT prefix::TEXT
                           FROM pg_catalog.unnest(rule.prefixes) AS prefix
                           ORDER BY prefix),
                       'source_device_group_id', device_group.public_id,
                       'source_identity_group_id', identity_group.public_id,
                       'source_device_tag_id', device_tag.public_id
                   )) AS value
            FROM mesh.compiled_policy_route_rule AS rule
            LEFT JOIN mesh.device_group AS device_group ON device_group.id = rule.source_device_group_id
            LEFT JOIN mesh.identity_group AS identity_group ON identity_group.id = rule.source_identity_group_id
            LEFT JOIN mesh.device_tag AS device_tag ON device_tag.id = rule.source_device_tag_id
            WHERE rule.policy_release_id = v_release_id
              AND rule.destination_site_id = v_site_id
              AND rule.protocol = p_protocol
              AND ((p_protocol = 'icmp' AND pg_catalog.isempty(rule.destination_ports))
                   OR rule.destination_ports @> p_destination_port)
              AND EXISTS (
                  SELECT 1 FROM pg_catalog.unnest(rule.prefixes) AS prefix
                  WHERE prefix >>= p_destination_address
              )
              AND (rule.source_device_id = v_source_id OR EXISTS (
                  SELECT 1
                  FROM mesh_ops.selector_devices_internal_v1(scoped_workspace, scoped_network) AS selected
                  WHERE selected.device_id = v_source_id
                    AND selected.selector_id = COALESCE(rule.source_device_group_id,
                        rule.source_identity_group_id, rule.source_device_tag_id)
                    AND selected.selector_kind = CASE
                        WHEN rule.source_device_group_id IS NOT NULL THEN 'device_group'
                        WHEN rule.source_identity_group_id IS NOT NULL THEN 'identity_group'
                        ELSE 'device_tag' END
              ))
            ORDER BY rule.access_rule_public_id, rule.public_id
            LIMIT p_path_limit
        ) AS path;
    END IF;

    RETURN QUERY SELECT revision.network_revision, revision.inventory_revision, revision.group_revision,
        revision.policy_revision, revision.dns_revision, revision.route_revision,
        revision.sharing_revision, revision.isolation_generation,
        v_release_id IS NOT NULL, v_release_public_id, v_compiler_format_version, v_semantic_hash,
        v_site_public_id, v_paths,
        pg_catalog.jsonb_build_object(
            'source', pg_catalog.jsonb_build_object(
                'state', COALESCE(source_state, 'missing'), 'name', source_name),
            'target', pg_catalog.jsonb_build_object(
                'kind', 'site', 'state', CASE WHEN v_site_id IS NULL THEN 'missing' ELSE 'active' END,
                'name', site_name),
            'share', NULL
        );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.explain_site_access_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, INET, TEXT, INTEGER, TIMESTAMPTZ, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.explain_site_access_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, INET, TEXT, INTEGER, TIMESTAMPTZ, INTEGER
) TO mesh_runtime;
