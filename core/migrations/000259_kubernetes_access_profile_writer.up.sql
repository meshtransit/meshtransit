-- K2d d2: a Core that hashes access profiles writes them (K2 design §24).
--
-- attach_policy_kubernetes_profiles_v1 attaches the profiles of a release
-- just published, before its rules; attach_policy_group_rules_v4 attaches
-- rules with their profiles as a writer that hashes both groups and
-- profiles; read_policy_kubernetes_access_v1 reads both back for compile,
-- catalog and simulation. Schema 258's functions stay for a Core before K2.

-- A profile ID names one profile within its Network, as a rule ID does: the
-- same ID in another Network is another profile (review d2 L1).

CREATE FUNCTION mesh_ops.attach_policy_kubernetes_profiles_v1(
    p_release_public_id UUID, p_created_at TIMESTAMPTZ, p_profiles JSONB
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
    v_deployment BIGINT;
    v_release mesh.policy_release%ROWTYPE;
    v_expected INTEGER;
    v_inserted INTEGER;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_release_public_id IS NULL OR p_created_at IS NULL OR p_profiles IS NULL
        OR pg_catalog.jsonb_typeof(p_profiles) <> 'array'
        OR pg_catalog.jsonb_array_length(p_profiles) NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy Kubernetes profile input is invalid';
    END IF;
    -- The release published in this transaction, before any of its rules
    -- or profiles.
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
      )
      AND NOT EXISTS (
          SELECT 1 FROM mesh.policy_release_kubernetes_profile AS held WHERE held.policy_release_id = release.id
      );
    IF v_release.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'policy Kubernetes profiles need the release published now, before its rules';
    END IF;
    SELECT workspace.deployment_id INTO v_deployment FROM mesh.workspace AS workspace
    WHERE workspace.id = v_workspace;
    v_expected := pg_catalog.jsonb_array_length(p_profiles);
    -- Core checks profiles in full (owner: compute in Go); here only their
    -- shape, and IDs and names once each.
    IF EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_profiles) AS profile(
            profile_public_id UUID, content_hash TEXT, name TEXT, rules JSONB, description TEXT
        )
        WHERE profile.profile_public_id IS NULL
           OR pg_catalog.get_byte(pg_catalog.uuid_send(profile.profile_public_id), 6) >> 4 <> 7
           OR profile.content_hash IS NULL OR profile.content_hash !~ '^[0-9a-f]{64}$'
           OR profile.name IS NULL OR profile.rules IS NULL OR profile.description IS NULL
    ) OR (
        SELECT pg_catalog.count(DISTINCT profile.profile_public_id) <> v_expected
            OR pg_catalog.count(DISTINCT profile.name) <> v_expected
        FROM pg_catalog.jsonb_to_recordset(p_profiles) AS profile(profile_public_id UUID, name TEXT)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy Kubernetes profile input is invalid';
    END IF;
    INSERT INTO mesh.kubernetes_access_profile_content (
        deployment_id, workspace_id, network_id, content_hash, name, rules, created_at
    )
    SELECT v_deployment, v_workspace, v_network, pg_catalog.decode(profile.content_hash, 'hex'), profile.name,
           profile.rules, p_created_at
    FROM pg_catalog.jsonb_to_recordset(p_profiles) AS profile(content_hash TEXT, name TEXT, rules JSONB)
    ORDER BY profile.content_hash
    ON CONFLICT (workspace_id, network_id, content_hash) DO NOTHING;
    -- A content hash names one content forever.
    IF EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_profiles) AS profile(content_hash TEXT, name TEXT, rules JSONB)
        JOIN mesh.kubernetes_access_profile_content AS content
          ON content.workspace_id = v_workspace AND content.network_id = v_network
         AND content.content_hash = pg_catalog.decode(profile.content_hash, 'hex')
        WHERE content.name <> profile.name OR content.rules <> profile.rules
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTP08',
            MESSAGE = 'a Kubernetes access profile hash names other content';
    END IF;
    INSERT INTO mesh.policy_release_kubernetes_profile (
        workspace_id, network_id, policy_release_id, policy_revision, profile_public_id, content_hash,
        description, created_at
    )
    SELECT v_workspace, v_network, v_release.id, v_release.policy_revision, profile.profile_public_id,
           pg_catalog.decode(profile.content_hash, 'hex'), profile.description, p_created_at
    FROM pg_catalog.jsonb_to_recordset(p_profiles) AS profile(
        profile_public_id UUID, content_hash TEXT, description TEXT
    )
    ORDER BY profile.profile_public_id;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted <> v_expected THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy Kubernetes profile input is invalid';
    END IF;
    RETURN v_inserted;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.attach_policy_kubernetes_profiles_v1(UUID, TIMESTAMPTZ, JSONB)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_kubernetes_profiles_v1(UUID, TIMESTAMPTZ, JSONB) TO mesh_runtime;

-- attach_policy_group_rules_v3 of schema 258 as a writer that hashes
-- profiles too: it sends each cluster rule's profile, or none for full
-- groups, and the trigger never carries one.
CREATE FUNCTION mesh_ops.attach_policy_group_rules_v4(
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
    v_previous_release BIGINT;
    v_expected INTEGER;
    v_inserted INTEGER;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    -- The caller hashed the release with each cluster rule's Kubernetes
    -- groups and access profile: the trigger refuses a rule that would lose
    -- either instead of carrying it. Transaction-local, and turned off again
    -- before returning, so it never leaks to a later writer.
    PERFORM pg_catalog.set_config('mesh.kubernetes_groups_aware', 'on', TRUE);
    PERFORM pg_catalog.set_config('mesh.kubernetes_profiles_aware', 'on', TRUE);
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
    SELECT previous.id INTO v_previous_release FROM mesh.policy_release AS previous
    WHERE previous.workspace_id = v_workspace AND previous.network_id = v_network
      AND previous.policy_revision = v_release.policy_revision - 1
      AND previous.state = 'superseded';
    v_expected := pg_catalog.jsonb_array_length(p_rules);
    -- A profile hash is 32 bytes in hex, refused as input when not.
    IF EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(kubernetes_profile_hash TEXT)
        WHERE rule.kubernetes_profile_hash IS NOT NULL AND rule.kubernetes_profile_hash !~ '^[0-9a-f]{64}$'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy group rule input is invalid';
    END IF;

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            projection_public_id UUID, access_rule_public_id UUID,
            source_node_public_id UUID, source_device_group_public_id UUID,
            source_identity_group_public_id UUID, source_device_tag_public_id UUID,
            destination_node_public_id UUID, destination_device_group_public_id UUID,
            destination_device_tag_public_id UUID,
            protocol TEXT, port_range_first INTEGER[], port_range_last INTEGER[],
            kubernetes_groups TEXT[], kubernetes_profile_public_id UUID, kubernetes_profile_hash TEXT,
            kubernetes_namespaces TEXT[], kubernetes_cluster_part BOOLEAN, kubernetes_mode TEXT,
            kubernetes_report_until TIMESTAMPTZ
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
               destination_group.id AS destination_device_group_id, destination_tag.id AS destination_device_tag_id,
               ports.destination_ports
        FROM valid_rule AS rule
        LEFT JOIN mesh.device AS source_device
          ON source_device.workspace_id = v_workspace AND source_device.network_id = v_network
         AND source_device.public_id = rule.source_node_public_id
        LEFT JOIN mesh.device_group AS source_group
          ON source_group.workspace_id = v_workspace AND source_group.network_id = v_network
         AND source_group.public_id = rule.source_device_group_public_id AND source_group.state = 'active'
        LEFT JOIN mesh.identity_group AS source_identity
          ON source_identity.workspace_id = v_workspace AND source_identity.network_id = v_network
         AND source_identity.public_id = rule.source_identity_group_public_id AND source_identity.state = 'active'
        LEFT JOIN mesh.device_tag AS source_tag
          ON source_tag.workspace_id = v_workspace AND source_tag.network_id = v_network
         AND source_tag.public_id = rule.source_device_tag_public_id AND source_tag.state = 'active'
        LEFT JOIN mesh.device AS destination_device
          ON destination_device.workspace_id = v_workspace AND destination_device.network_id = v_network
         AND destination_device.public_id = rule.destination_node_public_id
        LEFT JOIN mesh.device_group AS destination_group
          ON destination_group.workspace_id = v_workspace AND destination_group.network_id = v_network
         AND destination_group.public_id = rule.destination_device_group_public_id
         AND destination_group.state = 'active'
        LEFT JOIN mesh.device_tag AS destination_tag
          ON destination_tag.workspace_id = v_workspace AND destination_tag.network_id = v_network
         AND destination_tag.public_id = rule.destination_device_tag_public_id AND destination_tag.state = 'active'
        CROSS JOIN LATERAL (
            SELECT COALESCE(pg_catalog.range_agg(
                pg_catalog.int4range(port_range.first_port, port_range.last_port + 1, '[)')
            ), '{}'::INT4MULTIRANGE) AS destination_ports
            FROM ROWS FROM (
                pg_catalog.unnest(rule.port_range_first), pg_catalog.unnest(rule.port_range_last)
            ) AS port_range(first_port, last_port)
        ) AS ports
        WHERE (rule.source_node_public_id IS NULL OR source_device.id IS NOT NULL)
          AND (rule.source_device_group_public_id IS NULL OR source_group.id IS NOT NULL)
          AND (rule.source_identity_group_public_id IS NULL OR source_identity.id IS NOT NULL)
          AND (rule.source_device_tag_public_id IS NULL OR source_tag.id IS NOT NULL)
          AND (rule.destination_node_public_id IS NULL OR destination_device.id IS NOT NULL)
          AND (rule.destination_device_group_public_id IS NULL OR destination_group.id IS NOT NULL)
          AND (rule.destination_device_tag_public_id IS NULL OR destination_tag.id IS NOT NULL)
          -- A revoked or deleted Device side only for a rule the replaced
          -- release held unchanged: same sides, protocol and ports.
          AND ((source_device.id IS NULL OR source_device.state IN ('active', 'expired', 'suspended'))
               AND (destination_device.id IS NULL OR destination_device.state IN ('active', 'expired', 'suspended'))
               OR EXISTS (
                   SELECT 1 FROM mesh.compiled_policy_group_rule AS carried
                   WHERE carried.policy_release_id = v_previous_release
                     AND carried.access_rule_public_id = rule.access_rule_public_id
                     AND carried.source_device_id IS NOT DISTINCT FROM source_device.id
                     AND carried.source_device_group_id IS NOT DISTINCT FROM source_group.id
                     AND carried.source_identity_group_id IS NOT DISTINCT FROM source_identity.id
                     AND carried.source_device_tag_id IS NOT DISTINCT FROM source_tag.id
                     AND carried.destination_device_id IS NOT DISTINCT FROM destination_device.id
                     AND carried.destination_device_group_id IS NOT DISTINCT FROM destination_group.id
                     AND carried.destination_device_tag_id IS NOT DISTINCT FROM destination_tag.id
                     AND carried.protocol = rule.protocol
                     AND carried.destination_ports = ports.destination_ports))
    )
    INSERT INTO mesh.compiled_policy_group_rule (
        public_id, access_rule_public_id, workspace_id, network_id, policy_release_id, policy_revision,
        source_device_id, source_device_group_id, source_identity_group_id, source_device_tag_id,
        destination_device_id, destination_device_group_id, destination_device_tag_id,
        protocol, destination_ports, kubernetes_groups, kubernetes_profile_public_id, kubernetes_profile_hash,
        kubernetes_namespaces, kubernetes_cluster_part, kubernetes_mode, kubernetes_report_until, created_at
    )
    SELECT rule.projection_public_id, rule.access_rule_public_id, v_workspace, v_network, v_release.id,
           v_release.policy_revision, rule.source_device_id, rule.source_device_group_id,
           rule.source_identity_group_id, rule.source_device_tag_id, rule.destination_device_id,
           rule.destination_device_group_id, rule.destination_device_tag_id, rule.protocol,
           rule.destination_ports, rule.kubernetes_groups, rule.kubernetes_profile_public_id,
           pg_catalog.decode(rule.kubernetes_profile_hash, 'hex'), rule.kubernetes_namespaces,
           rule.kubernetes_cluster_part, rule.kubernetes_mode, rule.kubernetes_report_until, p_created_at
    FROM resolved_rule AS rule
    ORDER BY rule.access_rule_public_id;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted <> v_expected THEN
        -- A rule left out that names a Device not in this Network, or one
        -- that is gone, is new or changed: refuse it as such.
        IF EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
                projection_public_id UUID, source_node_public_id UUID, destination_node_public_id UUID
            )
            CROSS JOIN LATERAL (VALUES
                (rule.source_node_public_id), (rule.destination_node_public_id)
            ) AS side(node_public_id)
            WHERE side.node_public_id IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1 FROM mesh.compiled_policy_group_rule AS attached
                  WHERE attached.public_id = rule.projection_public_id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM mesh.device AS device
                  WHERE device.workspace_id = v_workspace AND device.network_id = v_network
                    AND device.public_id = side.node_public_id AND device.state IN ('active', 'expired', 'suspended')
              )
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTP05',
                MESSAGE = 'a new policy rule names a Device that is not in this Network or was removed';
        END IF;
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'a Device, group or tag changed during publication';
    END IF;
    IF mesh_ops.max_device_policy_edges_internal_v1(v_workspace, v_network) > 10000 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTD06', MESSAGE = 'a Device would load more than 10000 rule edges';
    END IF;
    -- A gateway reports at most 64 groups: the rules of one cluster grant no
    -- more.
    IF EXISTS (
        SELECT 1 FROM mesh.compiled_policy_group_rule AS attached
        CROSS JOIN LATERAL pg_catalog.unnest(attached.kubernetes_groups) AS kubernetes_group(name)
        WHERE attached.policy_release_id = v_release.id
        GROUP BY attached.destination_device_group_id
        HAVING pg_catalog.count(DISTINCT kubernetes_group.name) > 64
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTP07',
            MESSAGE = 'the rules of a Kubernetes cluster grant more than 64 Kubernetes groups';
    END IF;
    PERFORM pg_catalog.set_config('mesh.kubernetes_groups_aware', 'off', TRUE);
    PERFORM pg_catalog.set_config('mesh.kubernetes_profiles_aware', 'off', TRUE);
    RETURN v_inserted;
END;
$function$;REVOKE ALL ON FUNCTION mesh_ops.attach_policy_group_rules_v4(UUID, TIMESTAMPTZ, JSONB)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_group_rules_v4(UUID, TIMESTAMPTZ, JSONB) TO mesh_runtime;

-- read_policy_kubernetes_groups_v1 of schema 236 with each rule's profile,
-- which flags the release hash covers, and the release's profiles.
CREATE FUNCTION mesh_ops.read_policy_kubernetes_access_v1(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_policy_revision BIGINT, p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_release BIGINT;
    v_result JSONB;
    v_permission TEXT;
    v_allowed BOOLEAN := FALSE;
BEGIN
    IF p_policy_revision IS NULL OR p_policy_revision < 1 OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Invalid Kubernetes access read';
    END IF;
    IF v_workspace IS NULL OR v_network IS NULL OR NOT EXISTS (
        SELECT 1 FROM mesh.network AS network
        JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
        WHERE network.id = v_network AND network.workspace_id = v_workspace
          AND network.public_id = p_network_public_id AND workspace.public_id = p_workspace_public_id
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    -- Whoever reads, validates or publishes the Network's policy compiles
    -- or shows its rules, groups and profiles included.
    FOREACH v_permission IN ARRAY ARRAY['policy.read', 'policy.validate', 'policy.publish'] LOOP
        PERFORM 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version,
            p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, v_permission, p_evaluated_at
        );
        IF FOUND THEN
            v_allowed := TRUE;
            EXIT;
        END IF;
    END LOOP;
    IF NOT v_allowed THEN RETURN NULL; END IF;
    SELECT release.id INTO v_release FROM mesh.policy_release AS release
    WHERE release.workspace_id = v_workspace AND release.network_id = v_network
      AND release.policy_revision = p_policy_revision;
    -- No release at the revision holds nothing: a publish on it fails its
    -- revision check, not this read (review d2 L3).
    IF v_release IS NULL THEN
        RETURN pg_catalog.jsonb_build_object('policy_revision', p_policy_revision, 'groups_hashed', FALSE,
            'profiles_hashed', FALSE, 'rules', '[]'::JSONB, 'profiles', '[]'::JSONB);
    END IF;
    SELECT pg_catalog.jsonb_build_object(
        'policy_revision', p_policy_revision,
        'groups_hashed', COALESCE(pg_catalog.bool_or(rule.kubernetes_groups_hashed), FALSE),
        'profiles_hashed', COALESCE(pg_catalog.bool_or(rule.kubernetes_profile_hashed), FALSE),
        'rules', COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'id', rule.access_rule_public_id, 'cluster_id', cluster.public_id,
            'source_kind', CASE WHEN rule.source_device_group_id IS NOT NULL THEN 'device_group'
                                WHEN rule.source_identity_group_id IS NOT NULL THEN 'identity_group'
                                WHEN rule.source_device_tag_id IS NOT NULL THEN 'device_tag'
                                ELSE 'device' END,
            'source_id', COALESCE(source_group.public_id, source_identity.public_id, source_tag.public_id,
                                  source_device.public_id),
            'groups', pg_catalog.to_jsonb(rule.kubernetes_groups),
            'profile', CASE WHEN rule.kubernetes_profile_public_id IS NULL THEN NULL ELSE pg_catalog.jsonb_build_object(
                'id', rule.kubernetes_profile_public_id,
                'hash', pg_catalog.encode(rule.kubernetes_profile_hash, 'hex'),
                'namespaces', pg_catalog.to_jsonb(rule.kubernetes_namespaces),
                'cluster_part', rule.kubernetes_cluster_part,
                'mode', rule.kubernetes_mode,
                'report_until_ms', pg_catalog.floor(
                    EXTRACT(EPOCH FROM rule.kubernetes_report_until) * 1000)::BIGINT
            ) END
        ) ORDER BY rule.access_rule_public_id), '[]'::JSONB),
        -- Every profile of the release, used or not, with its content.
        'profiles', (
            SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'id', held.profile_public_id, 'hash', pg_catalog.encode(held.content_hash, 'hex'),
                'name', content.name, 'rules', content.rules, 'description', held.description
            ) ORDER BY held.profile_public_id), '[]'::JSONB)
            FROM mesh.policy_release_kubernetes_profile AS held
            JOIN mesh.kubernetes_access_profile_content AS content
              ON content.workspace_id = held.workspace_id AND content.network_id = held.network_id
             AND content.content_hash = held.content_hash
            WHERE held.policy_release_id = v_release
        ))
    INTO v_result
    FROM mesh.compiled_policy_group_rule AS rule
    JOIN mesh.device_group AS cluster_group
      ON cluster_group.id = rule.destination_device_group_id AND cluster_group.kind = 'kubernetes_cluster'
    JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = cluster_group.kubernetes_cluster_id
    LEFT JOIN mesh.device AS source_device ON source_device.id = rule.source_device_id
    LEFT JOIN mesh.device_group AS source_group ON source_group.id = rule.source_device_group_id
    LEFT JOIN mesh.identity_group AS source_identity ON source_identity.id = rule.source_identity_group_id
    LEFT JOIN mesh.device_tag AS source_tag ON source_tag.id = rule.source_device_tag_id
    WHERE rule.policy_release_id = v_release;
    RETURN v_result;
END;
$function$;REVOKE ALL ON FUNCTION mesh_ops.read_policy_kubernetes_access_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_policy_kubernetes_access_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT, TIMESTAMPTZ
) TO mesh_runtime;
