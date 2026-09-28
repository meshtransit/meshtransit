CREATE FUNCTION mesh_ops.read_policy_simulation_baseline_v1(
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
    p_evaluated_at TIMESTAMPTZ,
    p_rule_limit INTEGER
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
    rules JSONB
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
    IF p_evaluated_at IS NULL
        OR p_rule_limit IS NULL
        OR p_rule_limit NOT BETWEEN 1 AND 10001 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Policy simulation baseline input is invalid';
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
            MESSAGE = 'Policy simulation Network scope is unavailable';
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
        'policy.validate',
        p_evaluated_at
    ) AS permission;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'Policy simulation is not authorized';
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
    compiled_rule AS (
        SELECT
            rule.public_id AS projection_public_id,
            rule.access_rule_public_id,
            source.public_id AS source_node_public_id,
            destination.public_id AS destination_node_public_id,
            rule.protocol,
            ARRAY(
                SELECT pg_catalog.lower(port_range)::INTEGER
                FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                ORDER BY pg_catalog.lower(port_range), pg_catalog.upper(port_range)
            ) AS port_range_first,
            ARRAY(
                SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
                FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                ORDER BY pg_catalog.lower(port_range), pg_catalog.upper(port_range)
            ) AS port_range_last,
            direct_resource.public_id AS destination_resource_public_id,
            resource_provenance.resource_version AS destination_resource_version,
            resource_provenance.target_generation AS destination_target_generation,
            resource_provenance.inventory_revision AS destination_inventory_revision,
            resource_provenance.resource_semantic_hash AS destination_resource_semantic_hash,
            resource_group.public_id AS destination_resource_group_public_id,
            group_provenance.resource_group_version AS destination_resource_group_version,
            group_provenance.definition_version AS destination_group_definition_version,
            group_provenance.group_revision AS destination_group_revision,
            group_provenance.resource_group_semantic_hash AS destination_resource_group_semantic_hash,
            group_member.public_id AS destination_group_member_resource_public_id,
            group_provenance.resource_version AS destination_group_member_resource_version,
            group_provenance.target_generation AS destination_group_member_target_generation,
            group_provenance.inventory_revision AS destination_group_member_inventory_revision,
            group_provenance.resource_semantic_hash AS destination_group_member_resource_semantic_hash
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
        JOIN mesh.device AS destination
          ON destination.workspace_id = rule.workspace_id
         AND destination.network_id = rule.network_id
         AND destination.id = rule.destination_device_id
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
        LEFT JOIN mesh.resource_group AS resource_group
          ON resource_group.workspace_id = group_provenance.workspace_id
         AND resource_group.network_id = group_provenance.network_id
         AND resource_group.id = group_provenance.destination_resource_group_id
        LEFT JOIN mesh.resource AS group_member
          ON group_member.workspace_id = group_provenance.workspace_id
         AND group_member.network_id = group_provenance.network_id
         AND group_member.id = group_provenance.destination_resource_id
        ORDER BY
            rule.access_rule_public_id,
            source.public_id,
            destination.public_id,
            rule.public_id
        LIMIT p_rule_limit
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
        COALESCE(
            (
                SELECT pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_object(
                        'projection_public_id', rule.projection_public_id,
                        'access_rule_public_id', rule.access_rule_public_id,
                        'source_node_public_id', rule.source_node_public_id,
                        'destination_node_public_id', rule.destination_node_public_id,
                        'protocol', rule.protocol,
                        'port_range_first', rule.port_range_first,
                        'port_range_last', rule.port_range_last,
                        'destination_resource_public_id', rule.destination_resource_public_id,
                        'destination_resource_version', rule.destination_resource_version,
                        'destination_target_generation', rule.destination_target_generation,
                        'destination_inventory_revision', rule.destination_inventory_revision,
                        'destination_resource_semantic_hash',
                            pg_catalog.encode(rule.destination_resource_semantic_hash, 'hex'),
                        'destination_resource_group_public_id',
                            rule.destination_resource_group_public_id,
                        'destination_resource_group_version',
                            rule.destination_resource_group_version,
                        'destination_group_definition_version',
                            rule.destination_group_definition_version,
                        'destination_group_revision', rule.destination_group_revision,
                        'destination_resource_group_semantic_hash',
                            pg_catalog.encode(rule.destination_resource_group_semantic_hash, 'hex'),
                        'destination_group_member_resource_public_id',
                            rule.destination_group_member_resource_public_id,
                        'destination_group_member_resource_version',
                            rule.destination_group_member_resource_version,
                        'destination_group_member_target_generation',
                            rule.destination_group_member_target_generation,
                        'destination_group_member_inventory_revision',
                            rule.destination_group_member_inventory_revision,
                        'destination_group_member_resource_semantic_hash',
                            pg_catalog.encode(
                                rule.destination_group_member_resource_semantic_hash,
                                'hex'
                            )
                    )
                    ORDER BY
                        rule.access_rule_public_id,
                        rule.source_node_public_id,
                        rule.destination_node_public_id,
                        rule.projection_public_id
                )
                FROM compiled_rule AS rule
            ),
            '[]'::JSONB
        )
    FROM revision
    LEFT JOIN active_release AS release ON TRUE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_policy_simulation_baseline_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TIMESTAMPTZ, INTEGER
) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.read_policy_simulation_baseline_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TIMESTAMPTZ, INTEGER
) FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_policy_simulation_baseline_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TIMESTAMPTZ, INTEGER
) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
