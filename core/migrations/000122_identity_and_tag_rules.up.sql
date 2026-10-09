-- Schema 122 (G2): Access Rules that select Identity Groups and tags.
--
-- A rule's source may now be an Identity Group (the untagged Devices its
-- active members own in the Network) or a tag (the Network's Devices that
-- carry it); its destination may be a tag. Like Device Group rules, the
-- release stores the selectors and maps resolve them from the membership,
-- ownership and tags current at each Network revision. One resolver feeds
-- maps, Explain and the edge budget, so they always agree.

-- Every Device of the bound Network that a selector stands for right now.
-- Identity Groups count only untagged Devices of active owners with an
-- active Workspace membership; Device liveness is applied by callers.
CREATE FUNCTION mesh_ops.selector_devices_internal_v1(p_workspace_id BIGINT, p_network_id BIGINT)
RETURNS TABLE (selector_kind TEXT, selector_id BIGINT, device_id BIGINT)
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT 'device_group', member.device_group_id, member.device_id
    FROM mesh.device_group_member AS member
    JOIN mesh.device_group AS device_group ON device_group.id = member.device_group_id AND device_group.state = 'active'
    WHERE member.workspace_id = p_workspace_id AND member.network_id = p_network_id
    UNION ALL
    SELECT 'identity_group', member.identity_group_id, device.id
    FROM mesh.identity_group_member AS member
    JOIN mesh.identity_group AS identity_group
      ON identity_group.id = member.identity_group_id AND identity_group.state = 'active'
    JOIN mesh.principal AS principal
      ON principal.id = member.principal_id AND principal.state = 'active' AND principal.deleted_at IS NULL
    JOIN mesh.workspace_membership AS membership
      ON membership.workspace_id = p_workspace_id AND membership.principal_id = principal.id
     AND membership.state = 'active'
     AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
    JOIN mesh.device AS device
      ON device.workspace_id = p_workspace_id AND device.network_id = p_network_id
     AND device.owner_principal_id = principal.id
    WHERE member.workspace_id = p_workspace_id
      AND NOT EXISTS (
          SELECT 1 FROM mesh.device_tag_assignment AS assignment WHERE assignment.device_id = device.id
      )
    UNION ALL
    SELECT 'device_tag', assignment.device_tag_id, assignment.device_id
    FROM mesh.device_tag_assignment AS assignment
    JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id AND tag.state = 'active'
    WHERE assignment.workspace_id = p_workspace_id AND assignment.network_id = p_network_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.selector_devices_internal_v1(BIGINT, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Resolves the group rules of the bound Network's active release into
-- Device pairs, naming the selector each side matched through. With
-- p_device_id, only pairs that touch that Device. Self-pairs are dropped;
-- callers apply Device liveness.
CREATE FUNCTION mesh_ops.resolve_group_policy_edges_v2(p_device_id BIGINT)
RETURNS TABLE (
    rule_public_id UUID,
    access_rule_public_id UUID,
    source_device_id BIGINT,
    destination_device_id BIGINT,
    protocol TEXT,
    destination_ports INT4MULTIRANGE,
    source_selector_kind TEXT,
    source_selector_public_id UUID,
    destination_selector_kind TEXT,
    destination_selector_public_id UUID
)
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    WITH scope AS (
        SELECT revision.workspace_id, revision.network_id, revision.policy_revision
        FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = mesh_ops.current_workspace_id()
          AND revision.network_id = mesh_ops.current_network_id()
    ),
    rule AS (
        SELECT group_rule.*,
               CASE WHEN group_rule.source_device_group_id IS NOT NULL THEN 'device_group'
                    WHEN group_rule.source_identity_group_id IS NOT NULL THEN 'identity_group'
                    WHEN group_rule.source_device_tag_id IS NOT NULL THEN 'device_tag'
                    ELSE 'device' END AS source_kind,
               COALESCE(group_rule.source_device_group_id, group_rule.source_identity_group_id,
                        group_rule.source_device_tag_id) AS source_selector,
               CASE WHEN group_rule.destination_device_group_id IS NOT NULL THEN 'device_group'
                    WHEN group_rule.destination_device_tag_id IS NOT NULL THEN 'device_tag'
                    ELSE 'device' END AS destination_kind,
               COALESCE(group_rule.destination_device_group_id, group_rule.destination_device_tag_id)
                   AS destination_selector
        FROM scope
        JOIN mesh.policy_release AS release
          ON release.workspace_id = scope.workspace_id AND release.network_id = scope.network_id
         AND release.policy_revision = scope.policy_revision AND release.state = 'active'
        JOIN mesh.compiled_policy_group_rule AS group_rule ON group_rule.policy_release_id = release.id
    ),
    member AS (
        SELECT selected.* FROM scope
        CROSS JOIN LATERAL mesh_ops.selector_devices_internal_v1(scope.workspace_id, scope.network_id) AS selected
    ),
    expanded AS (
        SELECT rule.public_id, rule.access_rule_public_id, rule.protocol, rule.destination_ports,
               COALESCE(rule.source_device_id, source_member.device_id) AS source_device_id,
               COALESCE(rule.destination_device_id, destination_member.device_id) AS destination_device_id,
               rule.source_kind, rule.source_selector, rule.destination_kind, rule.destination_selector
        FROM rule
        LEFT JOIN member AS source_member
          ON source_member.selector_kind = rule.source_kind AND source_member.selector_id = rule.source_selector
        LEFT JOIN member AS destination_member
          ON destination_member.selector_kind = rule.destination_kind
         AND destination_member.selector_id = rule.destination_selector
    )
    SELECT expanded.public_id, expanded.access_rule_public_id, expanded.source_device_id,
           expanded.destination_device_id, expanded.protocol, expanded.destination_ports,
           expanded.source_kind,
           CASE expanded.source_kind
               WHEN 'device_group' THEN (SELECT g.public_id FROM mesh.device_group AS g WHERE g.id = expanded.source_selector)
               WHEN 'identity_group' THEN (SELECT g.public_id FROM mesh.identity_group AS g
                                           WHERE g.id = expanded.source_selector)
               WHEN 'device_tag' THEN (SELECT t.public_id FROM mesh.device_tag AS t WHERE t.id = expanded.source_selector)
           END,
           expanded.destination_kind,
           CASE expanded.destination_kind
               WHEN 'device_group' THEN (SELECT g.public_id FROM mesh.device_group AS g
                                         WHERE g.id = expanded.destination_selector)
               WHEN 'device_tag' THEN (SELECT t.public_id FROM mesh.device_tag AS t
                                       WHERE t.id = expanded.destination_selector)
           END
    FROM expanded
    WHERE expanded.source_device_id IS NOT NULL AND expanded.destination_device_id IS NOT NULL
      AND expanded.source_device_id <> expanded.destination_device_id
      AND (p_device_id IS NULL OR expanded.source_device_id = p_device_id
           OR expanded.destination_device_id = p_device_id)
$function$;
REVOKE ALL ON FUNCTION mesh_ops.resolve_group_policy_edges_v2(BIGINT)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.resolve_group_policy_edges_v2(BIGINT) TO mesh_runtime;

-- Schema 120's resolver, now over every selector kind, so maps built by
-- either version agree. Group identities are reported for Device Groups only.
CREATE OR REPLACE FUNCTION mesh_ops.resolve_group_policy_edges_v1(p_device_id BIGINT)
RETURNS TABLE (
    rule_public_id UUID,
    access_rule_public_id UUID,
    source_device_id BIGINT,
    destination_device_id BIGINT,
    protocol TEXT,
    destination_ports INT4MULTIRANGE,
    source_device_group_public_id UUID,
    destination_device_group_public_id UUID
)
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT edge.rule_public_id, edge.access_rule_public_id, edge.source_device_id, edge.destination_device_id,
           edge.protocol, edge.destination_ports,
           CASE WHEN edge.source_selector_kind = 'device_group' THEN edge.source_selector_public_id END,
           CASE WHEN edge.destination_selector_kind = 'device_group' THEN edge.destination_selector_public_id END
    FROM mesh_ops.resolve_group_policy_edges_v2(p_device_id) AS edge
$function$;

-- The most rule edges any one Device would load from the Network's active
-- release, over every selector kind (schema 120 counted Device Groups only).
-- Self-pairs and inactive Devices are counted, so the bound is conservative.
-- The active release is found directly (one per Network), not through the
-- Network revision, so a Workspace change can check every Network it touches.
CREATE OR REPLACE FUNCTION mesh_ops.max_device_policy_edges_internal_v1(p_workspace_id BIGINT, p_network_id BIGINT)
RETURNS BIGINT
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    WITH release AS (
        SELECT release.id
        FROM mesh.policy_release AS release
        WHERE release.workspace_id = p_workspace_id AND release.network_id = p_network_id
          AND release.state = 'active'
    ),
    member AS (
        SELECT * FROM mesh_ops.selector_devices_internal_v1(p_workspace_id, p_network_id)
    ),
    selector_size AS (
        SELECT member.selector_kind, member.selector_id, pg_catalog.count(*) AS size
        FROM member GROUP BY member.selector_kind, member.selector_id
    ),
    rule AS (
        SELECT group_rule.source_device_id, group_rule.destination_device_id,
               CASE WHEN group_rule.source_device_group_id IS NOT NULL THEN 'device_group'
                    WHEN group_rule.source_identity_group_id IS NOT NULL THEN 'identity_group'
                    WHEN group_rule.source_device_tag_id IS NOT NULL THEN 'device_tag' END AS source_kind,
               COALESCE(group_rule.source_device_group_id, group_rule.source_identity_group_id,
                        group_rule.source_device_tag_id) AS source_selector,
               CASE WHEN group_rule.destination_device_group_id IS NOT NULL THEN 'device_group'
                    WHEN group_rule.destination_device_tag_id IS NOT NULL THEN 'device_tag' END AS destination_kind,
               COALESCE(group_rule.destination_device_group_id, group_rule.destination_device_tag_id)
                   AS destination_selector
        FROM release
        JOIN mesh.compiled_policy_group_rule AS group_rule ON group_rule.policy_release_id = release.id
    ),
    sized AS (
        SELECT rule.*,
               CASE WHEN rule.source_device_id IS NOT NULL THEN 1
                    ELSE COALESCE((SELECT size FROM selector_size WHERE selector_size.selector_kind = rule.source_kind
                                     AND selector_size.selector_id = rule.source_selector), 0) END AS source_size,
               CASE WHEN rule.destination_device_id IS NOT NULL THEN 1
                    ELSE COALESCE((SELECT size FROM selector_size
                                   WHERE selector_size.selector_kind = rule.destination_kind
                                     AND selector_size.selector_id = rule.destination_selector), 0) END
                   AS destination_size
        FROM rule
    ),
    per_device AS (
        SELECT COALESCE(sized.destination_device_id, member.device_id) AS device_id, sized.source_size AS edges
        FROM sized
        LEFT JOIN member ON member.selector_kind = sized.destination_kind
                        AND member.selector_id = sized.destination_selector
        UNION ALL
        SELECT COALESCE(sized.source_device_id, member.device_id), sized.destination_size
        FROM sized
        LEFT JOIN member ON member.selector_kind = sized.source_kind AND member.selector_id = sized.source_selector
        UNION ALL
        SELECT device_rule.source_device_id, 1
        FROM release JOIN mesh.compiled_policy_rule AS device_rule ON device_rule.policy_release_id = release.id
        UNION ALL
        SELECT device_rule.destination_device_id, 1
        FROM release JOIN mesh.compiled_policy_rule AS device_rule ON device_rule.policy_release_id = release.id
    )
    SELECT COALESCE(pg_catalog.max(total.edges), 0)::BIGINT
    FROM (
        SELECT per_device.device_id, pg_catalog.sum(per_device.edges) AS edges
        FROM per_device WHERE per_device.device_id IS NOT NULL
        GROUP BY per_device.device_id
    ) AS total
$function$;

-- Attaches the group rules of a release just published in this
-- transaction (schema 120's v1 plus Identity Group sources and tag sides).
-- Each rule: projection_public_id, access_rule_public_id, exactly one source
-- of source_node_public_id / source_device_group_public_id /
-- source_identity_group_public_id / source_device_tag_public_id, exactly one
-- destination of destination_node_public_id /
-- destination_device_group_public_id / destination_device_tag_public_id (not
-- Device to Device), protocol, port_range_first, port_range_last. Devices
-- and Device Groups must be active in this Network, Identity Groups and tags
-- active in its Workspace.
CREATE FUNCTION mesh_ops.attach_policy_group_rules_v2(
    p_release_public_id UUID, p_created_at TIMESTAMPTZ, p_rules JSONB
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_release mesh.policy_release%ROWTYPE;
    v_expected INTEGER;
    v_inserted INTEGER;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_release_public_id IS NULL OR p_created_at IS NULL OR p_rules IS NULL
        OR pg_catalog.jsonb_typeof(p_rules) <> 'array'
        OR pg_catalog.jsonb_array_length(p_rules) NOT BETWEEN 1 AND 10000 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy group rule input is invalid';
    END IF;
    SELECT * INTO v_release FROM mesh.policy_release AS release
    WHERE release.workspace_id = v_workspace AND release.network_id = v_network
      AND release.public_id = p_release_public_id AND release.state = 'active'
      AND EXISTS (
          SELECT 1 FROM mesh_audit.authority_mutation AS mutation
          WHERE mutation.aggregate_kind = 'policy_release' AND mutation.operation = 'insert'
            AND mutation.row_public_id = p_release_public_id
            AND mutation.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
      )
      AND NOT EXISTS (
          SELECT 1 FROM mesh.compiled_policy_group_rule AS attached WHERE attached.policy_release_id = release.id
      );
    IF v_release.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy group rules need the release published now';
    END IF;
    v_expected := pg_catalog.jsonb_array_length(p_rules);

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            projection_public_id UUID, access_rule_public_id UUID,
            source_node_public_id UUID, source_device_group_public_id UUID,
            source_identity_group_public_id UUID, source_device_tag_public_id UUID,
            destination_node_public_id UUID, destination_device_group_public_id UUID,
            destination_device_tag_public_id UUID,
            protocol TEXT, port_range_first INTEGER[], port_range_last INTEGER[]
        )
    ),
    valid_rule AS (
        SELECT rule.* FROM input_rule AS rule
        WHERE rule.projection_public_id IS NOT NULL
          AND pg_catalog.get_byte(pg_catalog.uuid_send(rule.projection_public_id), 6) >> 4 = 7
          AND rule.access_rule_public_id IS NOT NULL
          AND pg_catalog.get_byte(pg_catalog.uuid_send(rule.access_rule_public_id), 6) >> 4 = 7
          AND pg_catalog.num_nonnulls(rule.source_node_public_id, rule.source_device_group_public_id,
                                      rule.source_identity_group_public_id, rule.source_device_tag_public_id) = 1
          AND pg_catalog.num_nonnulls(rule.destination_node_public_id, rule.destination_device_group_public_id,
                                      rule.destination_device_tag_public_id) = 1
          AND (rule.source_node_public_id IS NULL OR rule.destination_node_public_id IS NULL)
          AND rule.protocol IN ('tcp', 'udp', 'icmp')
          AND rule.port_range_first IS NOT NULL AND rule.port_range_last IS NOT NULL
          AND pg_catalog.cardinality(rule.port_range_first) = pg_catalog.cardinality(rule.port_range_last)
          AND pg_catalog.cardinality(rule.port_range_first) <= 64
          AND ((rule.protocol = 'icmp' AND pg_catalog.cardinality(rule.port_range_first) = 0)
               OR (rule.protocol IN ('tcp', 'udp') AND pg_catalog.cardinality(rule.port_range_first) > 0))
          AND NOT EXISTS (
              SELECT 1 FROM ROWS FROM (
                  pg_catalog.unnest(rule.port_range_first), pg_catalog.unnest(rule.port_range_last)
              ) AS port_range(first_port, last_port)
              WHERE port_range.first_port < 1 OR port_range.last_port < port_range.first_port
                 OR port_range.last_port > 65535
          )
          AND NOT EXISTS (
              SELECT 1 FROM mesh.compiled_policy_rule AS device_rule
              WHERE device_rule.policy_release_id = v_release.id
                AND device_rule.access_rule_public_id = rule.access_rule_public_id
          )
    ),
    resolved_rule AS (
        SELECT rule.*, source_device.id AS source_device_id, source_group.id AS source_device_group_id,
               source_identity.id AS source_identity_group_id, source_tag.id AS source_device_tag_id,
               destination_device.id AS destination_device_id,
               destination_group.id AS destination_device_group_id, destination_tag.id AS destination_device_tag_id
        FROM valid_rule AS rule
        LEFT JOIN mesh.device AS source_device
          ON source_device.workspace_id = v_workspace AND source_device.network_id = v_network
         AND source_device.public_id = rule.source_node_public_id AND source_device.state = 'active'
        LEFT JOIN mesh.device_group AS source_group
          ON source_group.workspace_id = v_workspace AND source_group.network_id = v_network
         AND source_group.public_id = rule.source_device_group_public_id AND source_group.state = 'active'
        LEFT JOIN mesh.identity_group AS source_identity
          ON source_identity.workspace_id = v_workspace
         AND source_identity.public_id = rule.source_identity_group_public_id AND source_identity.state = 'active'
        LEFT JOIN mesh.device_tag AS source_tag
          ON source_tag.workspace_id = v_workspace
         AND source_tag.public_id = rule.source_device_tag_public_id AND source_tag.state = 'active'
        LEFT JOIN mesh.device AS destination_device
          ON destination_device.workspace_id = v_workspace AND destination_device.network_id = v_network
         AND destination_device.public_id = rule.destination_node_public_id
         AND destination_device.state = 'active'
        LEFT JOIN mesh.device_group AS destination_group
          ON destination_group.workspace_id = v_workspace AND destination_group.network_id = v_network
         AND destination_group.public_id = rule.destination_device_group_public_id
         AND destination_group.state = 'active'
        LEFT JOIN mesh.device_tag AS destination_tag
          ON destination_tag.workspace_id = v_workspace
         AND destination_tag.public_id = rule.destination_device_tag_public_id AND destination_tag.state = 'active'
        WHERE (rule.source_node_public_id IS NULL OR source_device.id IS NOT NULL)
          AND (rule.source_device_group_public_id IS NULL OR source_group.id IS NOT NULL)
          AND (rule.source_identity_group_public_id IS NULL OR source_identity.id IS NOT NULL)
          AND (rule.source_device_tag_public_id IS NULL OR source_tag.id IS NOT NULL)
          AND (rule.destination_node_public_id IS NULL OR destination_device.id IS NOT NULL)
          AND (rule.destination_device_group_public_id IS NULL OR destination_group.id IS NOT NULL)
          AND (rule.destination_device_tag_public_id IS NULL OR destination_tag.id IS NOT NULL)
    )
    INSERT INTO mesh.compiled_policy_group_rule (
        public_id, access_rule_public_id, workspace_id, network_id, policy_release_id, policy_revision,
        source_device_id, source_device_group_id, source_identity_group_id, source_device_tag_id,
        destination_device_id, destination_device_group_id, destination_device_tag_id,
        protocol, destination_ports, created_at
    )
    SELECT rule.projection_public_id, rule.access_rule_public_id, v_workspace, v_network, v_release.id,
           v_release.policy_revision, rule.source_device_id, rule.source_device_group_id,
           rule.source_identity_group_id, rule.source_device_tag_id, rule.destination_device_id,
           rule.destination_device_group_id, rule.destination_device_tag_id, rule.protocol,
           ports.destination_ports, p_created_at
    FROM resolved_rule AS rule
    CROSS JOIN LATERAL (
        SELECT COALESCE(pg_catalog.range_agg(
            pg_catalog.int4range(port_range.first_port, port_range.last_port + 1, '[)')
        ), '{}'::INT4MULTIRANGE) AS destination_ports
        FROM ROWS FROM (
            pg_catalog.unnest(rule.port_range_first), pg_catalog.unnest(rule.port_range_last)
        ) AS port_range(first_port, last_port)
    ) AS ports
    ORDER BY rule.access_rule_public_id;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted <> v_expected THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'a Device, group or tag changed during publication';
    END IF;
    IF mesh_ops.max_device_policy_edges_internal_v1(v_workspace, v_network) > 10000 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTD06', MESSAGE = 'a Device would load more than 10000 rule edges';
    END IF;
    RETURN v_inserted;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.attach_policy_group_rules_v2(UUID, TIMESTAMPTZ, JSONB)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_group_rules_v2(UUID, TIMESTAMPTZ, JSONB) TO mesh_runtime;

-- The active policy projection (schema 120's v2) over every selector kind:
-- a source may also be an Identity Group or a tag, a destination a tag.
-- device_rules_only means every row selects Devices, Device Groups or tags,
-- so a Console that understands them can rewrite the whole policy.
CREATE OR REPLACE FUNCTION mesh_ops.read_active_policy_v2(
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
            COALESCE(resource_group.public_id, resource.public_id, destination.public_id) AS selector_id,
            'device'::TEXT AS source_kind, source.public_id AS source_selector_id
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
            imported.public_id AS selector_id,
            'device'::TEXT AS source_kind, source.public_id AS source_selector_id
        FROM mesh.compiled_policy_imported_resource_destination AS rule
        JOIN mesh.device AS source ON source.workspace_id = rule.workspace_id
            AND source.network_id = rule.network_id AND source.id = rule.source_device_id
        JOIN mesh.imported_resource AS imported ON imported.workspace_id = rule.workspace_id
            AND imported.network_id = rule.network_id AND imported.id = rule.imported_resource_id
        WHERE rule.workspace_id = mesh_ops.current_workspace_id()
            AND rule.network_id = mesh_ops.current_network_id()
            AND rule.policy_release_id = current_release_id AND rule.policy_revision = current_revision
    ), group_rule AS (
        SELECT rule.access_rule_public_id AS id, rule.public_id AS projection_id,
            source_device.public_id AS source_id, destination_device.public_id AS destination_id,
            rule.protocol, rule.destination_ports,
            CASE WHEN rule.destination_device_group_id IS NOT NULL THEN 'device_group'
                 WHEN rule.destination_device_tag_id IS NOT NULL THEN 'device_tag'
                 ELSE 'device' END AS selector_kind,
            COALESCE(destination_group.public_id, destination_tag.public_id, destination_device.public_id)
                AS selector_id,
            CASE WHEN rule.source_device_group_id IS NOT NULL THEN 'device_group'
                 WHEN rule.source_identity_group_id IS NOT NULL THEN 'identity_group'
                 WHEN rule.source_device_tag_id IS NOT NULL THEN 'device_tag'
                 ELSE 'device' END AS source_kind,
            COALESCE(source_group.public_id, source_identity.public_id, source_tag.public_id,
                     source_device.public_id) AS source_selector_id
        FROM mesh.compiled_policy_group_rule AS rule
        LEFT JOIN mesh.device AS source_device ON source_device.id = rule.source_device_id
        LEFT JOIN mesh.device_group AS source_group ON source_group.id = rule.source_device_group_id
        LEFT JOIN mesh.identity_group AS source_identity ON source_identity.id = rule.source_identity_group_id
        LEFT JOIN mesh.device_tag AS source_tag ON source_tag.id = rule.source_device_tag_id
        LEFT JOIN mesh.device AS destination_device ON destination_device.id = rule.destination_device_id
        LEFT JOIN mesh.device_group AS destination_group ON destination_group.id = rule.destination_device_group_id
        LEFT JOIN mesh.device_tag AS destination_tag ON destination_tag.id = rule.destination_device_tag_id
        WHERE rule.workspace_id = mesh_ops.current_workspace_id()
            AND rule.network_id = mesh_ops.current_network_id()
            AND rule.policy_release_id = current_release_id AND rule.policy_revision = current_revision
    ), all_rule AS (
        SELECT * FROM local_rule UNION ALL SELECT * FROM imported_rule UNION ALL SELECT * FROM group_rule
    ),
    bounded AS (
        SELECT * FROM all_rule ORDER BY id, source_id, destination_id, projection_id LIMIT 1000
    )
    SELECT (SELECT count(*) FROM all_rule),
        NOT EXISTS (SELECT 1 FROM all_rule WHERE selector_kind NOT IN ('device', 'device_group', 'device_tag')),
        COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'id', bounded.id, 'source_device_id', COALESCE(bounded.source_id::TEXT, ''),
            'source_kind', bounded.source_kind, 'source_selector_id', bounded.source_selector_id,
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

-- The simulation baseline (schema 120's v3) over every selector kind: the
-- group rules carry Identity Group and tag sides, and selector_members lists
-- the live Devices of every selector with one or more Devices, by kind.
-- More than 100,000 selector memberships is too large to simulate (MTD07).
CREATE FUNCTION mesh_ops.read_policy_simulation_baseline_v4(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ, p_rule_limit INTEGER
)
RETURNS TABLE (
    network_revision BIGINT, inventory_revision BIGINT, group_revision BIGINT,
    policy_revision BIGINT, dns_revision BIGINT, route_revision BIGINT,
    sharing_revision BIGINT, isolation_generation BIGINT,
    has_active_release BOOLEAN, release_public_id UUID,
    compiler_format_version INTEGER, release_semantic_hash BYTEA, rules JSONB,
    group_rules JSONB, selector_members JSONB
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    baseline RECORD;
    v_rules JSONB;
    v_members JSONB;
    v_member_count BIGINT;
BEGIN
    SELECT value.* INTO baseline
    FROM mesh_ops.read_policy_simulation_baseline_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_evaluated_at, p_rule_limit
    ) AS value;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Policy simulation baseline is unavailable';
    END IF;

    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
               'projection_public_id', rule.public_id,
               'access_rule_public_id', rule.access_rule_public_id,
               'source_node_public_id', source_device.public_id,
               'source_device_group_public_id', source_group.public_id,
               'source_identity_group_public_id', source_identity.public_id,
               'source_device_tag_public_id', source_tag.public_id,
               'destination_node_public_id', destination_device.public_id,
               'destination_device_group_public_id', destination_group.public_id,
               'destination_device_tag_public_id', destination_tag.public_id,
               'protocol', rule.protocol,
               'port_range_first', ARRAY(
                   SELECT pg_catalog.lower(port_range)::INTEGER
                   FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                   ORDER BY pg_catalog.lower(port_range)),
               'port_range_last', ARRAY(
                   SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
                   FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                   ORDER BY pg_catalog.lower(port_range))
           )) ORDER BY rule.access_rule_public_id), '[]'::JSONB)
    INTO v_rules
    FROM mesh.policy_release AS release
    JOIN mesh.compiled_policy_group_rule AS rule ON rule.policy_release_id = release.id
    LEFT JOIN mesh.device AS source_device ON source_device.id = rule.source_device_id
    LEFT JOIN mesh.device_group AS source_group ON source_group.id = rule.source_device_group_id
    LEFT JOIN mesh.identity_group AS source_identity ON source_identity.id = rule.source_identity_group_id
    LEFT JOIN mesh.device_tag AS source_tag ON source_tag.id = rule.source_device_tag_id
    LEFT JOIN mesh.device AS destination_device ON destination_device.id = rule.destination_device_id
    LEFT JOIN mesh.device_group AS destination_group ON destination_group.id = rule.destination_device_group_id
    LEFT JOIN mesh.device_tag AS destination_tag ON destination_tag.id = rule.destination_device_tag_id
    WHERE release.workspace_id = mesh_ops.current_workspace_id()
      AND release.network_id = mesh_ops.current_network_id()
      AND release.public_id = baseline.release_public_id
      AND release.state = 'active';

    -- Every selector the release can name, with its live Devices.
    SELECT pg_catalog.count(*) INTO v_member_count
    FROM mesh_ops.selector_devices_internal_v1(mesh_ops.current_workspace_id(), mesh_ops.current_network_id());
    IF v_member_count > 100000 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTD07', MESSAGE = 'groups and tags are too large to simulate';
    END IF;
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'kind', grouped.selector_kind, 'selector_id', grouped.public_id, 'device_ids', grouped.device_ids
           ) ORDER BY grouped.selector_kind, grouped.public_id::TEXT), '[]'::JSONB)
    INTO v_members
    FROM (
        SELECT selected.selector_kind,
               COALESCE(device_group.public_id, identity_group.public_id, tag.public_id) AS public_id,
               COALESCE(pg_catalog.jsonb_agg(device.public_id ORDER BY device.public_id::TEXT)
                   FILTER (WHERE device.id IS NOT NULL), '[]'::JSONB) AS device_ids
        FROM mesh_ops.selector_devices_internal_v1(mesh_ops.current_workspace_id(), mesh_ops.current_network_id())
            AS selected
        LEFT JOIN mesh.device_group AS device_group
          ON selected.selector_kind = 'device_group' AND device_group.id = selected.selector_id
        LEFT JOIN mesh.identity_group AS identity_group
          ON selected.selector_kind = 'identity_group' AND identity_group.id = selected.selector_id
        LEFT JOIN mesh.device_tag AS tag ON selected.selector_kind = 'device_tag' AND tag.id = selected.selector_id
        LEFT JOIN mesh.device AS device
          ON device.id = selected.device_id AND device.state = 'active' AND device.deleted_at IS NULL
         AND device.expires_at > p_evaluated_at
        GROUP BY selected.selector_kind, COALESCE(device_group.public_id, identity_group.public_id, tag.public_id)
    ) AS grouped;

    RETURN QUERY SELECT baseline.network_revision, baseline.inventory_revision, baseline.group_revision,
        baseline.policy_revision, baseline.dns_revision, baseline.route_revision, baseline.sharing_revision,
        baseline.isolation_generation, baseline.has_active_release, baseline.release_public_id,
        baseline.compiler_format_version, baseline.release_semantic_hash, baseline.rules,
        v_rules, v_members;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_policy_simulation_baseline_v4(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_policy_simulation_baseline_v4(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, INTEGER
) TO mesh_runtime;

-- Policy Explain (schema 120's v4) over every selector kind: a group path
-- names the Device Group, Identity Group or tag each side matched through.
CREATE OR REPLACE FUNCTION mesh_ops.explain_active_policy_v4(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID,
    p_source_device_public_id UUID, p_destination_device_public_id UUID,
    p_destination_resource_public_id UUID, p_destination_imported_resource_public_id UUID,
    p_protocol TEXT, p_destination_port INTEGER, p_evaluated_at TIMESTAMPTZ, p_path_limit INTEGER
)
RETURNS TABLE (
    network_revision BIGINT, inventory_revision BIGINT, group_revision BIGINT,
    policy_revision BIGINT, dns_revision BIGINT, route_revision BIGINT,
    sharing_revision BIGINT, isolation_generation BIGINT,
    has_active_release BOOLEAN, release_public_id UUID,
    compiler_format_version INTEGER, release_semantic_hash BYTEA,
    target_device_public_id UUID, paths JSONB, context JSONB
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    base RECORD;
    v_source BIGINT;
    v_target BIGINT;
    v_group_paths JSONB := '[]'::JSONB;
BEGIN
    SELECT value.* INTO base
    FROM mesh_ops.explain_active_policy_v3(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_source_device_public_id,
        p_destination_device_public_id, p_destination_resource_public_id,
        p_destination_imported_resource_public_id, p_protocol, p_destination_port,
        p_evaluated_at, p_path_limit
    ) AS value;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Access Graph explanation is unavailable';
    END IF;

    IF p_destination_device_public_id IS NOT NULL AND base.target_device_public_id IS NOT NULL
        AND base.context #>> '{source,state}' = 'active'
        AND base.context #>> '{target,state}' = 'active'
        AND pg_catalog.jsonb_array_length(base.paths) < p_path_limit THEN
        SELECT device.id INTO v_source FROM mesh.device AS device
        WHERE device.workspace_id = mesh_ops.current_workspace_id()
          AND device.network_id = mesh_ops.current_network_id()
          AND device.public_id = p_source_device_public_id;
        SELECT device.id INTO v_target FROM mesh.device AS device
        WHERE device.workspace_id = mesh_ops.current_workspace_id()
          AND device.network_id = mesh_ops.current_network_id()
          AND device.public_id = base.target_device_public_id;
        SELECT COALESCE(pg_catalog.jsonb_agg(path.value ORDER BY path.rule_id), '[]'::JSONB)
        INTO v_group_paths
        FROM (
            SELECT edge.access_rule_public_id::TEXT AS rule_id,
                   pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
                       'projection_id', edge.rule_public_id,
                       'access_rule_id', edge.access_rule_public_id,
                       'source_device_id', p_source_device_public_id,
                       'destination_device_id', base.target_device_public_id,
                       'protocol', edge.protocol,
                       'destination_port_range_first', ARRAY(
                           SELECT pg_catalog.lower(port_range)::INTEGER
                           FROM pg_catalog.unnest(edge.destination_ports) AS port_range
                           ORDER BY pg_catalog.lower(port_range)),
                       'destination_port_range_last', ARRAY(
                           SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
                           FROM pg_catalog.unnest(edge.destination_ports) AS port_range
                           ORDER BY pg_catalog.lower(port_range)),
                       'selector_kind', 'device',
                       'source_device_group_id', CASE WHEN edge.source_selector_kind = 'device_group'
                           THEN edge.source_selector_public_id END,
                       'source_identity_group_id', CASE WHEN edge.source_selector_kind = 'identity_group'
                           THEN edge.source_selector_public_id END,
                       'source_device_tag_id', CASE WHEN edge.source_selector_kind = 'device_tag'
                           THEN edge.source_selector_public_id END,
                       'destination_device_group_id', CASE WHEN edge.destination_selector_kind = 'device_group'
                           THEN edge.destination_selector_public_id END,
                       'destination_device_tag_id', CASE WHEN edge.destination_selector_kind = 'device_tag'
                           THEN edge.destination_selector_public_id END
                   )) AS value
            FROM mesh_ops.resolve_group_policy_edges_v2(v_source) AS edge
            WHERE edge.source_device_id = v_source
              AND edge.destination_device_id = v_target
              AND edge.protocol = p_protocol
              AND ((p_protocol = 'icmp' AND pg_catalog.isempty(edge.destination_ports))
                   OR edge.destination_ports @> p_destination_port)
            ORDER BY edge.access_rule_public_id
            LIMIT p_path_limit - pg_catalog.jsonb_array_length(base.paths)
        ) AS path;
    END IF;

    RETURN QUERY SELECT base.network_revision, base.inventory_revision, base.group_revision,
        base.policy_revision, base.dns_revision, base.route_revision, base.sharing_revision,
        base.isolation_generation, base.has_active_release, base.release_public_id,
        base.compiler_format_version, base.release_semantic_hash, base.target_device_public_id,
        base.paths || v_group_paths, base.context;
END;
$function$;
