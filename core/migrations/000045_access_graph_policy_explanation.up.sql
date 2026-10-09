CREATE FUNCTION mesh_ops.explain_active_policy_v1(
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
    p_source_device_public_id UUID,
    p_destination_device_public_id UUID,
    p_destination_resource_public_id UUID,
    p_protocol TEXT,
    p_destination_port INTEGER,
    p_evaluated_at TIMESTAMPTZ,
    p_path_limit INTEGER
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
    target_device_public_id UUID,
    paths JSONB
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_public_id UUID;
    scoped_network_public_id UUID;
BEGIN
    IF p_source_device_public_id IS NULL
        OR pg_catalog.get_byte(
            pg_catalog.uuid_send(p_source_device_public_id),
            6
        ) >> 4 <> 7
        OR (p_destination_device_public_id IS NULL)
            = (p_destination_resource_public_id IS NULL)
        OR (
            p_destination_device_public_id IS NOT NULL
            AND pg_catalog.get_byte(
                pg_catalog.uuid_send(p_destination_device_public_id),
                6
            ) >> 4 <> 7
        )
        OR (
            p_destination_resource_public_id IS NOT NULL
            AND pg_catalog.get_byte(
                pg_catalog.uuid_send(p_destination_resource_public_id),
                6
            ) >> 4 <> 7
        )
        OR p_protocol IS NULL
        OR p_protocol NOT IN ('tcp', 'udp', 'icmp')
        OR (
            p_protocol = 'icmp'
            AND p_destination_port <> 0
        )
        OR (
            p_protocol IN ('tcp', 'udp')
            AND (
                p_destination_port IS NULL
                OR p_destination_port NOT BETWEEN 1 AND 65535
            )
        )
        OR p_evaluated_at IS NULL
        OR p_path_limit IS NULL
        OR p_path_limit NOT BETWEEN 1 AND 65 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Access Graph explanation input is invalid';
    END IF;

    SELECT workspace.public_id, network.public_id
    INTO scoped_workspace_public_id, scoped_network_public_id
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
    WHERE workspace.id = mesh_ops.current_workspace_id()
      AND network.id = mesh_ops.current_network_id();
    IF scoped_workspace_public_id IS NULL
        OR scoped_network_public_id IS NULL
        OR scoped_workspace_public_id <> p_workspace_public_id
        OR scoped_network_public_id <> p_network_public_id THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'Access Graph Network scope is unavailable';
    END IF;

    PERFORM permission.role_binding_public_id
    FROM mesh_ops.resolve_network_permission_v1(
        p_session_public_id,
        p_deployment_public_id,
        p_principal_public_id,
        p_identity_subject_public_id,
        p_session_version,
        p_principal_authority_generation,
        p_account_session_generation,
        p_provider_generation,
        p_deployment_recovery_epoch,
        p_workspace_public_id,
        p_network_public_id,
        'policy.explain',
        p_evaluated_at
    ) AS permission;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'Access Graph explanation is not authorized';
    END IF;

    RETURN QUERY
    WITH revision AS (
        SELECT value.*
        FROM mesh_ops.read_network_revision_v1() AS value
    ),
    active_release AS (
        SELECT release.*
        FROM mesh.policy_release AS release
        JOIN revision
          ON revision.policy_revision = release.policy_revision
        WHERE release.workspace_id = mesh_ops.current_workspace_id()
          AND release.network_id = mesh_ops.current_network_id()
          AND release.state = 'active'
    ),
    target AS (
        SELECT device.id, device.public_id
        FROM mesh.device AS device
        WHERE p_destination_device_public_id IS NOT NULL
          AND device.workspace_id = mesh_ops.current_workspace_id()
          AND device.network_id = mesh_ops.current_network_id()
          AND device.public_id = p_destination_device_public_id
          AND device.state = 'active'
        UNION ALL
        SELECT device.id, device.public_id
        FROM mesh.resource AS resource
        JOIN mesh.resource_device_target AS resource_target
          ON resource_target.workspace_id = resource.workspace_id
         AND resource_target.network_id = resource.network_id
         AND resource_target.resource_id = resource.id
         AND resource_target.target_generation = resource.target_generation
         AND resource_target.state = 'active'
        JOIN mesh.device AS device
          ON device.workspace_id = resource_target.workspace_id
         AND device.network_id = resource_target.network_id
         AND device.id = resource_target.device_id
         AND device.state = 'active'
        WHERE p_destination_resource_public_id IS NOT NULL
          AND resource.workspace_id = mesh_ops.current_workspace_id()
          AND resource.network_id = mesh_ops.current_network_id()
          AND resource.public_id = p_destination_resource_public_id
          AND resource.state = 'active'
        LIMIT 1
    ),
    matched_path AS (
        SELECT
            rule.access_rule_public_id,
            rule.destination_device_id,
            rule.public_id AS projection_public_id,
            source.public_id AS source_device_public_id,
            destination.public_id AS destination_device_public_id,
            rule.protocol,
            CASE
                WHEN group_provenance.id IS NOT NULL
                    AND resource_provenance.id IS NOT NULL THEN 'invalid'
                WHEN group_provenance.id IS NOT NULL THEN 'resource_group'
                WHEN resource_provenance.id IS NOT NULL THEN 'resource'
                ELSE 'device'
            END AS selector_kind,
            COALESCE(
                group_member_resource.public_id,
                direct_resource.public_id
            ) AS destination_resource_public_id,
            resource_group.public_id AS destination_resource_group_public_id,
            ARRAY(
                SELECT pg_catalog.lower(port_range)::INTEGER
                FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                ORDER BY pg_catalog.lower(port_range), pg_catalog.upper(port_range)
            ) AS port_range_first,
            ARRAY(
                SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
                FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                ORDER BY pg_catalog.lower(port_range), pg_catalog.upper(port_range)
            ) AS port_range_last
        FROM active_release AS release
        JOIN mesh.compiled_policy_rule AS rule
          ON rule.workspace_id = release.workspace_id
         AND rule.network_id = release.network_id
         AND rule.policy_release_id = release.id
         AND rule.policy_revision = release.policy_revision
        JOIN mesh.device AS source
          ON source.workspace_id = rule.workspace_id
         AND source.network_id = rule.network_id
         AND source.id = rule.source_device_id
         AND source.public_id = p_source_device_public_id
         AND source.state = 'active'
        JOIN target
          ON target.id = rule.destination_device_id
        JOIN mesh.device AS destination
          ON destination.workspace_id = rule.workspace_id
         AND destination.network_id = rule.network_id
         AND destination.id = rule.destination_device_id
         AND destination.state = 'active'
        LEFT JOIN mesh.compiled_policy_resource_destination AS resource_provenance
          ON resource_provenance.workspace_id = rule.workspace_id
         AND resource_provenance.network_id = rule.network_id
         AND resource_provenance.compiled_policy_rule_id = rule.id
        LEFT JOIN mesh.resource AS direct_resource
          ON direct_resource.workspace_id = resource_provenance.workspace_id
         AND direct_resource.network_id = resource_provenance.network_id
         AND direct_resource.id = resource_provenance.destination_resource_id
        LEFT JOIN mesh.compiled_policy_resource_group_destination AS group_provenance
          ON group_provenance.workspace_id = rule.workspace_id
         AND group_provenance.network_id = rule.network_id
         AND group_provenance.compiled_policy_rule_id = rule.id
        LEFT JOIN mesh.resource AS group_member_resource
          ON group_member_resource.workspace_id = group_provenance.workspace_id
         AND group_member_resource.network_id = group_provenance.network_id
         AND group_member_resource.id = group_provenance.destination_resource_id
        LEFT JOIN mesh.resource_group AS resource_group
          ON resource_group.workspace_id = group_provenance.workspace_id
         AND resource_group.network_id = group_provenance.network_id
         AND resource_group.id = group_provenance.destination_resource_group_id
        WHERE rule.protocol = p_protocol
          AND (
            (p_protocol = 'icmp' AND pg_catalog.isempty(rule.destination_ports))
            OR rule.destination_ports @> p_destination_port
          )
        ORDER BY
            rule.access_rule_public_id,
            rule.destination_device_id,
            rule.public_id
        LIMIT p_path_limit
    )
    SELECT
        revision.network_revision,
        revision.inventory_revision,
        revision.group_revision,
        revision.policy_revision,
        revision.dns_revision,
        revision.route_revision,
        revision.sharing_revision,
        revision.isolation_generation,
        release.id IS NOT NULL,
        release.public_id,
        release.compiler_format_version,
        release.semantic_hash,
        target.public_id,
        COALESCE(
            (
                SELECT pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_object(
                        'projection_id', path.projection_public_id,
                        'access_rule_id', path.access_rule_public_id,
                        'source_device_id', path.source_device_public_id,
                        'destination_device_id', path.destination_device_public_id,
                        'protocol', path.protocol,
                        'destination_port_range_first', path.port_range_first,
                        'destination_port_range_last', path.port_range_last,
                        'selector_kind', path.selector_kind,
                        'destination_resource_id', path.destination_resource_public_id,
                        'destination_resource_group_id', path.destination_resource_group_public_id
                    )
                    ORDER BY
                        path.access_rule_public_id,
                        path.destination_device_id,
                        path.projection_public_id
                )
                FROM matched_path AS path
            ),
            '[]'::JSONB
        )
    FROM revision
    LEFT JOIN active_release AS release ON TRUE
    LEFT JOIN target ON TRUE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.explain_active_policy_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, TEXT, INTEGER, TIMESTAMPTZ, INTEGER
) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.explain_active_policy_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, TEXT, INTEGER, TIMESTAMPTZ, INTEGER
) FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.explain_active_policy_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, TEXT, INTEGER, TIMESTAMPTZ, INTEGER
) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
