-- Policy rules that name a Device keep publishing after that Device leaves
-- the active state.
--
-- Before this schema, publish_compiled_policy_local_v1 (schema 21) and
-- attach_policy_group_rules_v2 (schema 122) resolved a rule's fixed Device
-- only while it was active. A Network whose policy still named a suspended,
-- expired or removed Device could then publish nothing at all: every edit
-- resent that rule and the publication failed, even an edit that removed the
-- rule's twin.
--
-- Map delivery already admits only live Devices (active, not deleted, not
-- expired) on both ends of every edge, so compiling a rule for a Device that
-- is not live grants nothing. Now:
--
--   active, expired or suspended Device  the rule compiles as before, so the
--                                        Device's access comes back when it
--                                        is renewed or resumed;
--   revoked or deleted Device            the rule compiles only when the
--                                        release being replaced already held
--                                        the same rule for the same Device.
--                                        Administrators may keep or remove
--                                        such rules; a new rule for a removed
--                                        Device is refused with MTP05.
--
-- Group and tag membership is unchanged: it is resolved when maps are built.

CREATE OR REPLACE FUNCTION mesh_ops.publish_compiled_policy_local_v1(
    p_release_public_id UUID,
    p_expected_policy_revision BIGINT,
    p_semantic_hash BYTEA,
    p_compiler_format_version INTEGER,
    p_activated_at TIMESTAMPTZ,
    p_rules JSONB
)
RETURNS TABLE (
    network_revision BIGINT,
    policy_revision BIGINT,
    release_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    current_network_revision BIGINT;
    current_policy_revision BIGINT;
    active_release_id BIGINT;
    active_release_revision BIGINT;
    new_release_id BIGINT;
    new_release_version BIGINT;
    advanced_network_revision BIGINT;
    advanced_policy_revision BIGINT;
    expected_rule_count INTEGER;
    inserted_rule_count INTEGER;
BEGIN
    BEGIN
        scoped_workspace_id := NULLIF(
            pg_catalog.current_setting('mesh.workspace_id', TRUE),
            ''
        )::BIGINT;
        scoped_network_id := NULLIF(
            pg_catalog.current_setting('mesh.network_id', TRUE),
            ''
        )::BIGINT;
    EXCEPTION
        WHEN invalid_text_representation OR numeric_value_out_of_range THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                MESSAGE = 'transaction Network scope is unavailable';
    END;

    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_release_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_release_public_id), 6) >> 4 <> 7
        OR p_expected_policy_revision <= 0
        OR p_expected_policy_revision = 9223372036854775807
        OR p_semantic_hash IS NULL
        OR pg_catalog.octet_length(p_semantic_hash) <> 32
        OR p_semantic_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_compiler_format_version <= 0
        OR p_compiler_format_version > 65535
        OR p_activated_at IS NULL
        OR p_rules IS NULL
        OR pg_catalog.jsonb_typeof(p_rules) <> 'array'
        OR pg_catalog.jsonb_array_length(p_rules) > 10000 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'compiled policy publication input is invalid';
    END IF;

    SELECT revision.network_revision, revision.policy_revision
    INTO current_network_revision, current_policy_revision
    FROM mesh_ops.lock_network_revision() AS revision;

    IF current_network_revision IS NULL OR current_policy_revision IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'Network revision is unavailable';
    END IF;
    IF current_policy_revision <> p_expected_policy_revision THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT001',
            MESSAGE = 'compiled policy base revision changed';
    END IF;

    SELECT release.id, release.policy_revision
    INTO active_release_id, active_release_revision
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = scoped_workspace_id
      AND release.network_id = scoped_network_id
      AND release.state = 'active'
    FOR UPDATE;

    IF active_release_id IS NULL AND current_policy_revision <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'active compiled policy release is unavailable';
    END IF;
    IF active_release_id IS NOT NULL
        AND active_release_revision <> current_policy_revision THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'active compiled policy release revision is inconsistent';
    END IF;

    IF active_release_id IS NOT NULL THEN
        UPDATE mesh.policy_release AS release
        SET state = 'superseded',
            superseded_at = p_activated_at,
            version = release.version + 1
        WHERE release.id = active_release_id
          AND release.workspace_id = scoped_workspace_id
          AND release.network_id = scoped_network_id
          AND release.state = 'active';
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT001',
                MESSAGE = 'active compiled policy release changed';
        END IF;
    END IF;

    SELECT advanced.network_revision, advanced.policy_revision
    INTO advanced_network_revision, advanced_policy_revision
    FROM mesh_ops.advance_network_policy_revision() AS advanced;
    IF advanced_network_revision <> current_network_revision + 1
        OR advanced_policy_revision <> current_policy_revision + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'compiled policy revision advance is inconsistent';
    END IF;

    INSERT INTO mesh.policy_release (
        public_id,
        workspace_id,
        network_id,
        policy_revision,
        activated_network_revision,
        semantic_hash,
        compiler_format_version,
        state,
        created_at,
        activated_at
    ) VALUES (
        p_release_public_id,
        scoped_workspace_id,
        scoped_network_id,
        advanced_policy_revision,
        advanced_network_revision,
        p_semantic_hash,
        p_compiler_format_version,
        'active',
        p_activated_at,
        p_activated_at
    )
    RETURNING id, version INTO new_release_id, new_release_version;

    expected_rule_count := pg_catalog.jsonb_array_length(p_rules);
    IF expected_rule_count > 0 THEN
        WITH input_rule AS (
            SELECT rule.*
            FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
                projection_public_id UUID,
                access_rule_public_id UUID,
                source_node_public_id UUID,
                destination_node_public_id UUID,
                protocol TEXT,
                port_range_first INTEGER[],
                port_range_last INTEGER[]
            )
        ),
        valid_rule AS (
            SELECT rule.*
            FROM input_rule AS rule
            WHERE rule.projection_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.projection_public_id),
                    6
                  ) >> 4 = 7
              AND rule.access_rule_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.access_rule_public_id),
                    6
                  ) >> 4 = 7
              AND rule.source_node_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.source_node_public_id),
                    6
                  ) >> 4 = 7
              AND rule.destination_node_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.destination_node_public_id),
                    6
                  ) >> 4 = 7
              AND rule.source_node_public_id <> rule.destination_node_public_id
              AND rule.protocol IN ('tcp', 'udp', 'icmp')
              AND rule.port_range_first IS NOT NULL
              AND rule.port_range_last IS NOT NULL
              AND pg_catalog.cardinality(rule.port_range_first)
                    = pg_catalog.cardinality(rule.port_range_last)
              AND pg_catalog.cardinality(rule.port_range_first) <= 64
              AND (
                    (
                        rule.protocol = 'icmp'
                        AND pg_catalog.cardinality(rule.port_range_first) = 0
                    )
                    OR (
                        rule.protocol IN ('tcp', 'udp')
                        AND pg_catalog.cardinality(rule.port_range_first) > 0
                    )
                  )
              AND NOT EXISTS (
                    SELECT 1
                    FROM ROWS FROM (
                        pg_catalog.unnest(rule.port_range_first),
                        pg_catalog.unnest(rule.port_range_last)
                    ) AS port_range(first_port, last_port)
                    WHERE port_range.first_port < 1
                       OR port_range.last_port < port_range.first_port
                       OR port_range.last_port > 65535
                  )
        ),
        resolved_rule AS (
            SELECT
                rule.*,
                source.id AS source_device_id,
                destination.id AS destination_device_id
            FROM valid_rule AS rule
            JOIN mesh.device AS source
              ON source.workspace_id = scoped_workspace_id
             AND source.network_id = scoped_network_id
             AND source.public_id = rule.source_node_public_id
            JOIN mesh.device AS destination
              ON destination.workspace_id = scoped_workspace_id
             AND destination.network_id = scoped_network_id
             AND destination.public_id = rule.destination_node_public_id
            WHERE (
                    source.state IN ('active', 'expired', 'suspended')
                    AND destination.state IN ('active', 'expired', 'suspended')
                  )
               OR EXISTS (
                    SELECT 1
                    FROM mesh.compiled_policy_rule AS carried
                    WHERE carried.policy_release_id = active_release_id
                      AND carried.workspace_id = scoped_workspace_id
                      AND carried.network_id = scoped_network_id
                      AND carried.access_rule_public_id = rule.access_rule_public_id
                      AND carried.source_device_id = source.id
                      AND carried.destination_device_id = destination.id
                  )
        )
        INSERT INTO mesh.compiled_policy_rule (
            public_id,
            access_rule_public_id,
            workspace_id,
            network_id,
            policy_release_id,
            policy_revision,
            source_device_id,
            destination_device_id,
            protocol,
            destination_ports,
            created_at
        )
        SELECT
            rule.projection_public_id,
            rule.access_rule_public_id,
            scoped_workspace_id,
            scoped_network_id,
            new_release_id,
            advanced_policy_revision,
            rule.source_device_id,
            rule.destination_device_id,
            rule.protocol,
            ports.destination_ports,
            p_activated_at
        FROM resolved_rule AS rule
        CROSS JOIN LATERAL (
            SELECT COALESCE(
                pg_catalog.range_agg(
                    pg_catalog.int4range(
                        port_range.first_port,
                        port_range.last_port + 1,
                        '[)'
                    )
                ),
                '{}'::INT4MULTIRANGE
            ) AS destination_ports
            FROM ROWS FROM (
                pg_catalog.unnest(rule.port_range_first),
                pg_catalog.unnest(rule.port_range_last)
            ) AS port_range(first_port, last_port)
        ) AS ports
        ORDER BY
            rule.access_rule_public_id,
            rule.source_node_public_id,
            rule.destination_node_public_id,
            rule.protocol,
            rule.projection_public_id;

        GET DIAGNOSTICS inserted_rule_count = ROW_COUNT;
        IF inserted_rule_count <> expected_rule_count THEN
            IF EXISTS (
                SELECT 1
                FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
                    access_rule_public_id UUID,
                    source_node_public_id UUID,
                    destination_node_public_id UUID
                )
                WHERE rule.source_node_public_id IS NOT NULL
                  AND rule.destination_node_public_id IS NOT NULL
                  AND rule.source_node_public_id <> rule.destination_node_public_id
                  AND NOT EXISTS (
                    SELECT 1
                    FROM mesh.device AS source
                    JOIN mesh.device AS destination
                      ON destination.workspace_id = scoped_workspace_id
                     AND destination.network_id = scoped_network_id
                     AND destination.public_id = rule.destination_node_public_id
                    WHERE source.workspace_id = scoped_workspace_id
                      AND source.network_id = scoped_network_id
                      AND source.public_id = rule.source_node_public_id
                      AND (
                            (
                                source.state IN ('active', 'expired', 'suspended')
                                AND destination.state IN ('active', 'expired', 'suspended')
                            )
                            OR EXISTS (
                                SELECT 1
                                FROM mesh.compiled_policy_rule AS carried
                                WHERE carried.policy_release_id = active_release_id
                                  AND carried.workspace_id = scoped_workspace_id
                                  AND carried.network_id = scoped_network_id
                                  AND carried.access_rule_public_id = rule.access_rule_public_id
                                  AND carried.source_device_id = source.id
                                  AND carried.destination_device_id = destination.id
                            )
                          )
                )
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'MTP05',
                    MESSAGE = 'a new policy rule names a Device that is not in this Network or was removed';
            END IF;
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'compiled policy rule count mismatch';
        END IF;
    END IF;

    network_revision := advanced_network_revision;
    policy_revision := advanced_policy_revision;
    release_version := new_release_version;
    RETURN NEXT;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.attach_policy_group_rules_v2(
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
         AND source_device.public_id = rule.source_node_public_id
         AND (source_device.state IN ('active', 'expired', 'suspended') OR EXISTS (
              SELECT 1 FROM mesh.compiled_policy_group_rule AS carried
              WHERE carried.policy_release_id = v_previous_release
                AND carried.access_rule_public_id = rule.access_rule_public_id
                AND carried.source_device_id = source_device.id))
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
         AND (destination_device.state IN ('active', 'expired', 'suspended') OR EXISTS (
              SELECT 1 FROM mesh.compiled_policy_group_rule AS carried
              WHERE carried.policy_release_id = v_previous_release
                AND carried.access_rule_public_id = rule.access_rule_public_id
                AND carried.destination_device_id = destination_device.id))
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
        IF EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
                access_rule_public_id UUID, source_node_public_id UUID, destination_node_public_id UUID
            )
            CROSS JOIN LATERAL (VALUES
                (rule.source_node_public_id, TRUE), (rule.destination_node_public_id, FALSE)
            ) AS side(node_public_id, is_source)
            WHERE side.node_public_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM mesh.device AS device
                WHERE device.workspace_id = v_workspace AND device.network_id = v_network
                  AND device.public_id = side.node_public_id
                  AND (device.state IN ('active', 'expired', 'suspended') OR EXISTS (
                       SELECT 1 FROM mesh.compiled_policy_group_rule AS carried
                       WHERE carried.policy_release_id = v_previous_release
                         AND carried.access_rule_public_id = rule.access_rule_public_id
                         AND device.id = CASE WHEN side.is_source
                             THEN carried.source_device_id ELSE carried.destination_device_id END))
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
    RETURN v_inserted;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.publish_compiled_policy_local_v1(
    UUID, BIGINT, BYTEA, INTEGER, TIMESTAMPTZ, JSONB
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.attach_policy_group_rules_v2(UUID, TIMESTAMPTZ, JSONB)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_group_rules_v2(UUID, TIMESTAMPTZ, JSONB) TO mesh_runtime;
