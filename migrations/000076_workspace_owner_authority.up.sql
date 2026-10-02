-- Workspace ownership is automatic tenant administration authority.
-- It never derives from an email, IdP claim, role expiry or client-provided flag.
-- Ownership, membership and the current authenticated session are locked for
-- the complete operation. Existing member role semantics stay exact-Network.
CREATE FUNCTION mesh_ops.resolve_network_permission_v2(
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
    p_permission_key TEXT,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (
    role_binding_public_id UUID,
    role_definition_public_id UUID,
    scope_authority_generation BIGINT,
    membership_authority_generation BIGINT,
    binding_authority_generation BIGINT,
    role_authority_generation BIGINT,
    binding_expires_at TIMESTAMPTZ,
    workspace_owner_authority_generation BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    IF p_session_public_id IS NULL
        OR p_deployment_public_id IS NULL
        OR p_principal_public_id IS NULL
        OR p_identity_subject_public_id IS NULL
        OR p_workspace_public_id IS NULL
        OR p_network_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_session_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_identity_subject_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_network_public_id), 6) >> 4 <> 7
        OR p_session_version IS NULL OR p_session_version <= 0
        OR p_principal_authority_generation IS NULL
        OR p_principal_authority_generation <= 0
        OR p_account_session_generation IS NULL OR p_account_session_generation <= 0
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0
        OR p_permission_key IS NULL
        OR pg_catalog.char_length(p_permission_key) NOT BETWEEN 3 AND 128
        OR p_permission_key <> pg_catalog.btrim(p_permission_key)
        OR p_permission_key !~ '^[a-z][a-z0-9_]*[.][a-z][a-z0-9_.]*$'
        OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid Network permission resolution input';
    END IF;

    RETURN QUERY
    SELECT
        NULL::UUID,
        NULL::UUID,
        network.authority_generation,
        membership.authority_generation,
        0::BIGINT,
        0::BIGINT,
        NULL::TIMESTAMPTZ,
        workspace.authority_generation
    FROM mesh.account_session AS session
    JOIN mesh.deployment AS deployment
      ON deployment.id = session.deployment_id
    JOIN mesh.principal AS principal
      ON principal.deployment_id = session.deployment_id
     AND principal.id = session.principal_id
    JOIN mesh.account AS account
      ON account.deployment_id = session.deployment_id
     AND account.principal_id = session.principal_id
    JOIN mesh.identity_subject AS subject
      ON subject.deployment_id = session.deployment_id
     AND subject.identity_provider_id = session.identity_provider_id
     AND subject.principal_id = session.principal_id
     AND subject.id = session.identity_subject_id
    JOIN mesh.identity_provider AS provider
      ON provider.deployment_id = session.deployment_id
     AND provider.id = session.identity_provider_id
    JOIN mesh.identity_provider_client AS client
      ON client.deployment_id = session.deployment_id
     AND client.identity_provider_id = session.identity_provider_id
     AND client.id = session.identity_provider_client_id
    JOIN mesh.workspace AS workspace
      ON workspace.deployment_id = session.deployment_id
     AND workspace.public_id = p_workspace_public_id
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.public_id = p_network_public_id
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = session.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = session.principal_id
    JOIN mesh.permission AS permission
      ON permission.permission_key = p_permission_key
     AND 'network' = ANY(permission.allowed_scope_kinds)
    WHERE session.public_id = p_session_public_id
      AND deployment.installation_public_id = p_deployment_public_id
      AND principal.public_id = p_principal_public_id
      AND subject.public_id = p_identity_subject_public_id
      AND session.version = p_session_version
      AND session.principal_authority_generation = p_principal_authority_generation
      AND session.account_session_generation = p_account_session_generation
      AND session.provider_generation = p_provider_generation
      AND session.deployment_recovery_epoch = p_deployment_recovery_epoch
      AND session.state = 'active'
      AND session.authentication_time <= p_evaluated_at
      AND session.idle_expires_at > p_evaluated_at
      AND session.absolute_expires_at > p_evaluated_at
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.recovery_epoch = p_deployment_recovery_epoch
      AND principal.state = 'active'
      AND principal.kind = 'account'
      AND workspace.owner_principal_id = principal.id
      AND principal.authority_generation = p_principal_authority_generation
      AND account.recovery_state = 'verified'
      AND account.session_generation = p_account_session_generation
      AND subject.state = 'active'
      AND provider.state = 'active'
      AND provider.recovery_state = 'verified'
      AND provider.current_generation = p_provider_generation
      AND client.state = 'active'
      AND workspace.state = 'active'
      AND network.state = 'active'
      AND membership.state = 'active'
      AND membership.valid_from <= p_evaluated_at
      AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
    LIMIT 1
    FOR SHARE OF session, deployment, principal, account, subject, provider, client,
        workspace, network, membership, permission;
    IF FOUND THEN RETURN; END IF;

    -- Members retain the existing exact-Network role resolver and its locks.
    RETURN QUERY
    SELECT resolved.role_binding_public_id, resolved.role_definition_public_id,
        resolved.scope_authority_generation, resolved.membership_authority_generation,
        resolved.binding_authority_generation, resolved.role_authority_generation,
        resolved.binding_expires_at, 0::BIGINT
    FROM mesh_ops.resolve_network_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_permission_key, p_evaluated_at
    ) AS resolved;

END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.resolve_network_permission_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TEXT, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.resolve_network_permission_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TEXT, TIMESTAMPTZ
) TO mesh_runtime;


CREATE OR REPLACE FUNCTION mesh_ops.explain_active_policy_v1(
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
    FROM mesh_ops.resolve_network_permission_v2(
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

CREATE OR REPLACE FUNCTION mesh_ops.read_policy_simulation_baseline_v1(
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
    FROM mesh_ops.resolve_network_permission_v2(
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

CREATE OR REPLACE FUNCTION mesh_ops.read_console_devices_v1(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ,
    p_after_device_public_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    resolved_workspace BIGINT;
    resolved_network BIGINT;
    revision BIGINT;
    result JSONB;
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 101 OR
       (p_after_device_public_id IS NOT NULL AND
        pg_catalog.get_byte(pg_catalog.uuid_send(p_after_device_public_id), 6) >> 4 <> 7) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Device inventory input';
    END IF;
    BEGIN
        SELECT workspace_internal_id, network_internal_id
        INTO resolved_workspace, resolved_network
        FROM mesh_ops.set_network_scope(p_workspace_public_id, p_network_public_id);
    EXCEPTION WHEN foreign_key_violation OR insufficient_privilege THEN
        RETURN NULL;
    END;
    IF NOT EXISTS (
        SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version,
            p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'device.read', p_evaluated_at
        )
    ) THEN
        RETURN NULL;
    END IF;
    SELECT inventory_revision INTO revision
    FROM mesh_ops.network_revision
    WHERE workspace_id = resolved_workspace AND network_id = resolved_network
    FOR SHARE;
    IF revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Device inventory unavailable';
    END IF;
    SELECT pg_catalog.jsonb_build_object(
        'workspace_id', p_workspace_public_id, 'network_id', p_network_public_id,
        'inventory_revision', revision,
        'devices', COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'id', device.public_id, 'hostname', device.hostname,
            'state', device.state, 'is_ephemeral', device.is_ephemeral,
            'version', device.version, 'created_at', device.created_at,
            'updated_at', device.updated_at, 'expires_at', device.expires_at
        ) ORDER BY device.public_id), '[]'::JSONB)
    ) INTO result
    FROM (
        SELECT public_id, hostname, state, is_ephemeral, version, created_at, updated_at, expires_at
        FROM mesh.device
        WHERE workspace_id = resolved_workspace AND network_id = resolved_network
          AND (p_after_device_public_id IS NULL OR public_id > p_after_device_public_id)
        ORDER BY public_id LIMIT p_limit
    ) AS device;
    RETURN result;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.read_active_policy_v1(
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
    p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    current_revision BIGINT;
    current_release_id BIGINT;
    current_hash BYTEA;
    row_count BIGINT;
    only_devices BOOLEAN;
    result_rows JSONB;
BEGIN
    IF p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Invalid active policy read';
    END IF;
    PERFORM permission.role_binding_public_id
    FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'policy.read', p_evaluated_at
    ) AS permission;
    IF NOT FOUND THEN RETURN NULL; END IF;

    SELECT revision.policy_revision INTO current_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = mesh_ops.current_workspace_id()
      AND revision.network_id = mesh_ops.current_network_id()
    FOR SHARE;
    IF NOT FOUND THEN RETURN NULL; END IF;

    SELECT release.id, release.semantic_hash
    INTO current_release_id, current_hash
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = mesh_ops.current_workspace_id()
      AND release.network_id = mesh_ops.current_network_id()
      AND release.policy_revision = current_revision AND release.state = 'active';
    IF current_revision > 1 AND current_release_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Active policy is unavailable';
    END IF;

    WITH local_rule AS (
        SELECT rule.access_rule_public_id AS id, rule.public_id AS projection_id,
            source.public_id AS source_id, destination.public_id AS destination_id,
            rule.protocol, rule.destination_ports,
            CASE WHEN group_provenance.id IS NOT NULL THEN 'resource_group'
                 WHEN resource_provenance.id IS NOT NULL THEN 'resource'
                 ELSE 'device' END AS selector_kind,
            COALESCE(resource_group.public_id, resource.public_id, destination.public_id) AS selector_id
        FROM mesh.compiled_policy_rule AS rule
        JOIN mesh.device AS source ON source.workspace_id = rule.workspace_id
            AND source.network_id = rule.network_id AND source.id = rule.source_device_id
        JOIN mesh.device AS destination ON destination.workspace_id = rule.workspace_id
            AND destination.network_id = rule.network_id AND destination.id = rule.destination_device_id
        LEFT JOIN mesh.compiled_policy_resource_destination AS resource_provenance
            ON resource_provenance.workspace_id = rule.workspace_id
            AND resource_provenance.network_id = rule.network_id
            AND resource_provenance.compiled_policy_rule_id = rule.id
        LEFT JOIN mesh.resource AS resource ON resource.workspace_id = rule.workspace_id
            AND resource.network_id = rule.network_id AND resource.id = resource_provenance.destination_resource_id
        LEFT JOIN mesh.compiled_policy_resource_group_destination AS group_provenance
            ON group_provenance.workspace_id = rule.workspace_id
            AND group_provenance.network_id = rule.network_id
            AND group_provenance.compiled_policy_rule_id = rule.id
        LEFT JOIN mesh.resource_group AS resource_group ON resource_group.workspace_id = rule.workspace_id
            AND resource_group.network_id = rule.network_id AND resource_group.id = group_provenance.destination_resource_group_id
        WHERE rule.workspace_id = mesh_ops.current_workspace_id()
            AND rule.network_id = mesh_ops.current_network_id()
            AND rule.policy_release_id = current_release_id AND rule.policy_revision = current_revision
    ), imported_rule AS (
        SELECT rule.access_rule_public_id AS id, rule.public_id AS projection_id,
            source.public_id AS source_id, NULL::UUID AS destination_id,
            rule.protocol, rule.destination_ports, 'imported_resource'::TEXT AS selector_kind,
            imported.public_id AS selector_id
        FROM mesh.compiled_policy_imported_resource_destination AS rule
        JOIN mesh.device AS source ON source.workspace_id = rule.workspace_id
            AND source.network_id = rule.network_id AND source.id = rule.source_device_id
        JOIN mesh.imported_resource AS imported ON imported.workspace_id = rule.workspace_id
            AND imported.network_id = rule.network_id AND imported.id = rule.imported_resource_id
        WHERE rule.workspace_id = mesh_ops.current_workspace_id()
            AND rule.network_id = mesh_ops.current_network_id()
            AND rule.policy_release_id = current_release_id AND rule.policy_revision = current_revision
    ), all_rule AS (SELECT * FROM local_rule UNION ALL SELECT * FROM imported_rule),
    bounded AS (
        SELECT * FROM all_rule ORDER BY id, source_id, destination_id, projection_id LIMIT 1000
    )
    SELECT (SELECT count(*) FROM all_rule),
        NOT EXISTS (SELECT 1 FROM all_rule WHERE selector_kind <> 'device'),
        COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'id', bounded.id, 'source_device_id', bounded.source_id,
            'destination_device_id', COALESCE(bounded.destination_id::TEXT, ''),
            'protocol', bounded.protocol, 'selector_kind', bounded.selector_kind,
            'destination_selector_id', bounded.selector_id,
            'destination_port_ranges', COALESCE((SELECT jsonb_agg(jsonb_build_object(
                'first', lower(port)::INTEGER, 'last', (upper(port)-1)::INTEGER
            ) ORDER BY lower(port)) FROM unnest(bounded.destination_ports) AS port), '[]'::JSONB)
        ) ORDER BY bounded.id, bounded.source_id, bounded.destination_id, bounded.projection_id)
        FROM bounded), '[]'::JSONB)
    INTO row_count, only_devices, result_rows;
    RETURN jsonb_build_object('workspace_id', p_workspace_public_id,
        'network_id', p_network_public_id, 'policy_revision', current_revision,
        'semantic_hash', encode(current_hash, 'hex'), 'rule_count', row_count,
        'device_rules_only', only_devices, 'rules', result_rows);
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.read_console_management_scopes_v1(
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
    p_evaluated_at TIMESTAMPTZ,
    p_after_network_public_id UUID,
    p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
DECLARE
    result JSONB;
    previous_requested_workspace_public_id TEXT;
    previous_projection_workspace_public_id TEXT;
BEGIN
    previous_requested_workspace_public_id := pg_catalog.current_setting(
        'mesh.requested_workspace_public_id',
        TRUE
    );
    previous_projection_workspace_public_id := pg_catalog.current_setting(
        'mesh.console_management_scope_workspace_public_id',
        TRUE
    );
    IF p_session_public_id IS NULL
        OR p_deployment_public_id IS NULL
        OR p_principal_public_id IS NULL
        OR p_identity_subject_public_id IS NULL
        OR p_workspace_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_session_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_identity_subject_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR (
            p_after_network_public_id IS NOT NULL
            AND pg_catalog.get_byte(pg_catalog.uuid_send(p_after_network_public_id), 6) >> 4 <> 7
        )
        OR p_session_version IS NULL OR p_session_version <= 0
        OR p_principal_authority_generation IS NULL OR p_principal_authority_generation <= 0
        OR p_account_session_generation IS NULL OR p_account_session_generation <= 0
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0
        OR p_evaluated_at IS NULL
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 101 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid Console management scope input';
    END IF;

    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id',
        p_workspace_public_id::TEXT,
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.console_management_scope_workspace_public_id',
        p_workspace_public_id::TEXT,
        TRUE
    );

    WITH authority AS MATERIALIZED (
        SELECT
            workspace.id AS workspace_id,
            workspace.public_id AS workspace_public_id,
            workspace.display_name AS workspace_display_name,
            session.deployment_id,
            session.principal_id,
            membership.id AS membership_id,
            workspace.owner_principal_id = session.principal_id AS is_workspace_owner
        FROM mesh.account_session AS session
        JOIN mesh.deployment AS deployment
          ON deployment.id = session.deployment_id
        JOIN mesh.principal AS principal
          ON principal.deployment_id = session.deployment_id
         AND principal.id = session.principal_id
        JOIN mesh.account AS account
          ON account.deployment_id = session.deployment_id
         AND account.principal_id = session.principal_id
        JOIN mesh.identity_subject AS subject
          ON subject.deployment_id = session.deployment_id
         AND subject.identity_provider_id = session.identity_provider_id
         AND subject.principal_id = session.principal_id
         AND subject.id = session.identity_subject_id
        JOIN mesh.identity_provider AS provider
          ON provider.deployment_id = session.deployment_id
         AND provider.id = session.identity_provider_id
        JOIN mesh.identity_provider_client AS client
          ON client.deployment_id = session.deployment_id
         AND client.identity_provider_id = session.identity_provider_id
         AND client.id = session.identity_provider_client_id
        JOIN mesh.workspace AS workspace
          ON workspace.deployment_id = session.deployment_id
         AND workspace.id = session.login_workspace_id
         AND workspace.public_id = p_workspace_public_id
        JOIN mesh.workspace_membership AS membership
          ON membership.deployment_id = session.deployment_id
         AND membership.workspace_id = workspace.id
         AND membership.principal_id = session.principal_id
        WHERE session.public_id = p_session_public_id
          AND deployment.installation_public_id = p_deployment_public_id
          AND principal.public_id = p_principal_public_id
          AND subject.public_id = p_identity_subject_public_id
          AND session.version = p_session_version
          AND session.principal_authority_generation = p_principal_authority_generation
          AND session.account_session_generation = p_account_session_generation
          AND session.provider_generation = p_provider_generation
          AND session.deployment_recovery_epoch = p_deployment_recovery_epoch
          AND session.state = 'active'
          AND session.authentication_time <= p_evaluated_at
          AND session.idle_expires_at > p_evaluated_at
          AND session.absolute_expires_at > p_evaluated_at
          AND deployment.state = 'active'
          AND deployment.recovery_state = 'verified'
          AND deployment.recovery_epoch = p_deployment_recovery_epoch
          AND principal.state = 'active'
          AND principal.authority_generation = p_principal_authority_generation
          AND account.recovery_state = 'verified'
          AND account.session_generation = p_account_session_generation
          AND subject.state = 'active'
          AND provider.state = 'active'
          AND provider.recovery_state = 'verified'
          AND provider.current_generation = p_provider_generation
          AND client.state = 'active'
          AND workspace.state = 'active'
          AND membership.state = 'active'
          AND membership.valid_from <= p_evaluated_at
          AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
        LIMIT 1
    ), scope_permissions AS (
        SELECT
            network.public_id,
            network.display_name,
            CASE WHEN authority.is_workspace_owner THEN ARRAY(
                SELECT permission.permission_key FROM mesh.permission AS permission
                WHERE permission.permission_key = ANY(ARRAY[
                     'device.read', 'network.read', 'policy.approve', 'policy.read', 'policy.publish', 'policy.validate',
                     'share.accept', 'share.offer', 'share.read', 'share.revoke'
                ]::TEXT[])
                  AND 'network' = ANY(permission.allowed_scope_kinds)
                ORDER BY permission.permission_key
            ) ELSE ARRAY(
                SELECT DISTINCT permission.permission_key
                FROM mesh.role_binding AS binding
                JOIN mesh.role_definition AS role_definition
                  ON role_definition.deployment_id = binding.deployment_id
                 AND role_definition.workspace_id = binding.workspace_id
                 AND role_definition.id = binding.role_definition_id
                JOIN mesh.role_permission AS role_permission
                  ON role_permission.deployment_id = role_definition.deployment_id
                 AND role_permission.workspace_id = role_definition.workspace_id
                 AND role_permission.role_definition_id = role_definition.id
                JOIN mesh.permission AS permission
                  ON permission.id = role_permission.permission_id
                 AND permission.permission_key = ANY(ARRAY[
                     'device.read', 'network.read', 'policy.approve', 'policy.read', 'policy.publish', 'policy.validate',
                     'share.accept', 'share.offer', 'share.read', 'share.revoke'
                 ]::TEXT[])
                 AND 'network' = ANY(permission.allowed_scope_kinds)
                WHERE binding.deployment_id = authority.deployment_id
                  AND binding.workspace_id = authority.workspace_id
                  AND binding.network_id = network.id
                  AND binding.principal_id = authority.principal_id
                  AND binding.workspace_membership_id = authority.membership_id
                  AND binding.state = 'active'
                  AND binding.valid_from <= p_evaluated_at
                  AND (binding.expires_at IS NULL OR binding.expires_at > p_evaluated_at)
                  AND role_definition.state = 'active'
                  AND role_permission.state = 'active'
                ORDER BY permission.permission_key
            ) END AS permissions
        FROM authority
        JOIN mesh.network AS network
          ON network.workspace_id = authority.workspace_id
        WHERE network.state = 'active'
          AND (p_after_network_public_id IS NULL OR network.public_id > p_after_network_public_id)
    ), scopes AS (
        SELECT scope_permissions.*
        FROM scope_permissions
        WHERE pg_catalog.cardinality(scope_permissions.permissions) > 0
        ORDER BY scope_permissions.public_id
        LIMIT p_limit
    )
    SELECT pg_catalog.jsonb_build_object(
        'workspace_id', authority.workspace_public_id,
        'workspace_display_name', authority.workspace_display_name,
        'scopes', COALESCE(
            (
                SELECT pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_object(
                        'network_id', scopes.public_id,
                        'network_display_name', scopes.display_name,
                        'permissions', pg_catalog.to_jsonb(scopes.permissions)
                    )
                    ORDER BY scopes.public_id
                )
                FROM scopes
            ),
            '[]'::JSONB
        )
    )
    INTO result
    FROM authority;

    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id',
        COALESCE(previous_requested_workspace_public_id, ''),
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.console_management_scope_workspace_public_id',
        COALESCE(previous_projection_workspace_public_id, ''),
        TRUE
    );
    RETURN result;
EXCEPTION
    WHEN OTHERS THEN
        PERFORM pg_catalog.set_config(
            'mesh.requested_workspace_public_id',
            COALESCE(previous_requested_workspace_public_id, ''),
            TRUE
        );
        PERFORM pg_catalog.set_config(
            'mesh.console_management_scope_workspace_public_id',
            COALESCE(previous_projection_workspace_public_id, ''),
            TRUE
        );
        RAISE;
END;
$function$;
