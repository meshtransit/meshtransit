-- Schema 165: rules to a Resource, a Resource Group member or an Imported
-- Resource keep publishing after their Device leaves the active state, as
-- Device rules and group rules do since schema 144.
--
-- Before this schema the destination attach functions resolved the
-- Resource's Device (attach_policy_resource_destinations, schema 43;
-- attach_policy_resource_group_destinations, schema 44) or the Imported
-- Resource rule's source Device (attach_policy_imported_resource_
-- destinations_internal_v1/_v2, schemas 52 and 148) only while it was
-- active, and the Imported ones only before its expires_at. A Network whose
-- policy still held such a rule failed every publication with MT001 (a stale
-- revision to the Console, so retrying never helped). Now, in every attach
-- function, as schema 144 decided:
--
--   active, expired or suspended Device  the rule compiles; expires_at is not
--                                        checked, so an expired Device's
--                                        access comes back when it is renewed;
--   revoked or deleted Device            the rule compiles only when the
--                                        release being replaced held it
--                                        unchanged;
--   a new or changed rule for a revoked
--   or deleted Device                    MTP05, never MT001.
--
-- Maps admit only live Devices (active, not deleted, not expired) on both
-- ends of every edge, so compiling a rule for a Device that is not live
-- grants nothing.
--
-- "Unchanged" now means the whole rule: schema 144 compared only the rule ID
-- and the Device side, so a kept rule resubmitted with another protocol,
-- other ports or another group or tag side passed. publish_compiled_policy_
-- local_v1 and attach_policy_group_rules_v2 are replaced to compare every
-- side, the protocol and the ports, and the attach functions also compare the
-- destination (Resource, Resource Group member or Imported Resource).
--
-- Signatures, owners and grants stay as they were; the Imported attach
-- functions keep the fixed join order of schema 150.

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
        -- The ports as stored, so a kept rule is compared in full.
        ported_rule AS (
            SELECT rule.*, ports.destination_ports
            FROM valid_rule AS rule
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
        ),
        resolved_rule AS (
            SELECT
                rule.*,
                source.id AS source_device_id,
                destination.id AS destination_device_id
            FROM ported_rule AS rule
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
                      AND carried.protocol = rule.protocol
                      AND carried.destination_ports = rule.destination_ports
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
            rule.destination_ports,
            p_activated_at
        FROM resolved_rule AS rule
        ORDER BY
            rule.access_rule_public_id,
            rule.source_node_public_id,
            rule.destination_node_public_id,
            rule.protocol,
            rule.projection_public_id;

        GET DIAGNOSTICS inserted_rule_count = ROW_COUNT;
        IF inserted_rule_count <> expected_rule_count THEN
            -- A rule left out that names a Device not in this Network, or
            -- one that is gone, is new or changed: refuse it as such.
            IF EXISTS (
                SELECT 1
                FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
                    projection_public_id UUID,
                    source_node_public_id UUID,
                    destination_node_public_id UUID
                )
                CROSS JOIN LATERAL (VALUES
                    (rule.source_node_public_id), (rule.destination_node_public_id)
                ) AS side(node_public_id)
                WHERE side.node_public_id IS NOT NULL
                  AND NOT EXISTS (
                    SELECT 1
                    FROM mesh.compiled_policy_rule AS attached
                    WHERE attached.public_id = rule.projection_public_id
                  )
                  AND NOT EXISTS (
                    SELECT 1
                    FROM mesh.device AS device
                    WHERE device.workspace_id = scoped_workspace_id
                      AND device.network_id = scoped_network_id
                      AND device.public_id = side.node_public_id
                      AND device.state IN ('active', 'expired', 'suspended')
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
          ON source_identity.workspace_id = v_workspace
         AND source_identity.public_id = rule.source_identity_group_public_id AND source_identity.state = 'active'
        LEFT JOIN mesh.device_tag AS source_tag
          ON source_tag.workspace_id = v_workspace
         AND source_tag.public_id = rule.source_device_tag_public_id AND source_tag.state = 'active'
        LEFT JOIN mesh.device AS destination_device
          ON destination_device.workspace_id = v_workspace AND destination_device.network_id = v_network
         AND destination_device.public_id = rule.destination_node_public_id
        LEFT JOIN mesh.device_group AS destination_group
          ON destination_group.workspace_id = v_workspace AND destination_group.network_id = v_network
         AND destination_group.public_id = rule.destination_device_group_public_id
         AND destination_group.state = 'active'
        LEFT JOIN mesh.device_tag AS destination_tag
          ON destination_tag.workspace_id = v_workspace
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
        protocol, destination_ports, created_at
    )
    SELECT rule.projection_public_id, rule.access_rule_public_id, v_workspace, v_network, v_release.id,
           v_release.policy_revision, rule.source_device_id, rule.source_device_group_id,
           rule.source_identity_group_id, rule.source_device_tag_id, rule.destination_device_id,
           rule.destination_device_group_id, rule.destination_device_tag_id, rule.protocol,
           rule.destination_ports, p_created_at
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
    RETURN v_inserted;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.attach_policy_resource_destinations(
    p_release_public_id UUID,
    p_created_at TIMESTAMPTZ,
    p_rules JSONB
)
RETURNS TABLE (attached_count INTEGER)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    release_internal_id BIGINT;
    release_policy_revision BIGINT;
    previous_release_id BIGINT;
    expected_count INTEGER;
    valid_count INTEGER;
    inserted_count INTEGER;
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
        OR pg_catalog.get_byte(
            pg_catalog.uuid_send(p_release_public_id),
            6
        ) >> 4 <> 7
        OR p_created_at IS NULL
        OR p_rules IS NULL
        OR pg_catalog.jsonb_typeof(p_rules) <> 'array'
        OR pg_catalog.jsonb_array_length(p_rules) > 10000 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'policy Resource destination input is invalid';
    END IF;

    SELECT release.id, release.policy_revision
    INTO release_internal_id, release_policy_revision
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = scoped_workspace_id
      AND release.network_id = scoped_network_id
      AND release.public_id = p_release_public_id
      AND release.state = 'active'
    FOR KEY SHARE;
    IF release_internal_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'active Policy Release is unavailable';
    END IF;

    -- The release this publication replaced: only its rules may keep naming
    -- a Device that is gone.
    SELECT previous.id
    INTO previous_release_id
    FROM mesh.policy_release AS previous
    WHERE previous.workspace_id = scoped_workspace_id
      AND previous.network_id = scoped_network_id
      AND previous.policy_revision = release_policy_revision - 1
      AND previous.state = 'superseded';

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            projection_public_id UUID,
            access_rule_public_id UUID,
            destination_node_public_id UUID,
            destination_resource_public_id UUID,
            destination_resource_version BIGINT,
            destination_target_generation BIGINT,
            destination_inventory_revision BIGINT,
            destination_resource_semantic_hash TEXT
        )
    )
    SELECT
        pg_catalog.count(*) FILTER (
            WHERE rule.destination_resource_public_id IS NOT NULL
               OR rule.destination_resource_version IS NOT NULL
               OR rule.destination_target_generation IS NOT NULL
               OR rule.destination_inventory_revision IS NOT NULL
               OR rule.destination_resource_semantic_hash IS NOT NULL
        )::INTEGER,
        pg_catalog.count(*) FILTER (
            WHERE rule.destination_resource_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.destination_resource_public_id),
                    6
                  ) >> 4 = 7
              AND rule.projection_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.projection_public_id),
                    6
                  ) >> 4 = 7
              AND rule.access_rule_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.access_rule_public_id),
                    6
                  ) >> 4 = 7
              AND rule.destination_node_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.destination_node_public_id),
                    6
                  ) >> 4 = 7
              AND rule.destination_resource_version > 0
              AND rule.destination_target_generation > 0
              AND rule.destination_inventory_revision > 0
              AND rule.destination_resource_semantic_hash
                    ~ '^[0-9a-f]{64}$'
        )::INTEGER
    INTO expected_count, valid_count
    FROM input_rule AS rule;

    IF expected_count IS NULL OR valid_count IS NULL
        OR expected_count = 0
        OR expected_count <> valid_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'policy Resource destination shape is invalid';
    END IF;

    PERFORM resource.id
    FROM mesh.resource AS resource
    JOIN (
        SELECT DISTINCT
            rule.destination_resource_public_id,
            rule.destination_resource_version,
            rule.destination_target_generation,
            rule.destination_inventory_revision,
            rule.destination_resource_semantic_hash
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            destination_resource_public_id UUID,
            destination_resource_version BIGINT,
            destination_target_generation BIGINT,
            destination_inventory_revision BIGINT,
            destination_resource_semantic_hash TEXT
        )
        WHERE rule.destination_resource_public_id IS NOT NULL
    ) AS input_resource
      ON resource.workspace_id = scoped_workspace_id
     AND resource.network_id = scoped_network_id
     AND resource.public_id = input_resource.destination_resource_public_id
     AND resource.version = input_resource.destination_resource_version
     AND resource.target_generation = input_resource.destination_target_generation
     AND resource.inventory_revision = input_resource.destination_inventory_revision
     AND resource.semantic_hash = pg_catalog.decode(
            input_resource.destination_resource_semantic_hash,
            'hex'
         )
     AND resource.state = 'active'
    ORDER BY resource.id
    FOR KEY SHARE OF resource;

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            projection_public_id UUID,
            access_rule_public_id UUID,
            destination_node_public_id UUID,
            destination_resource_public_id UUID,
            destination_resource_version BIGINT,
            destination_target_generation BIGINT,
            destination_inventory_revision BIGINT,
            destination_resource_semantic_hash TEXT
        )
        WHERE rule.destination_resource_public_id IS NOT NULL
    ),
    resolved AS (
        SELECT
            compiled.id AS compiled_policy_rule_id,
            compiled.public_id AS compiled_policy_rule_public_id,
            resource.id AS resource_id,
            input_rule.destination_resource_version AS resource_version,
            input_rule.destination_target_generation AS target_generation,
            input_rule.destination_inventory_revision AS inventory_revision,
            resource.semantic_hash AS resource_semantic_hash
        FROM input_rule
        JOIN mesh.compiled_policy_rule AS compiled
          ON compiled.workspace_id = scoped_workspace_id
         AND compiled.network_id = scoped_network_id
         AND compiled.policy_release_id = release_internal_id
         AND compiled.public_id = input_rule.projection_public_id
         AND compiled.access_rule_public_id = input_rule.access_rule_public_id
        JOIN mesh.device AS destination
          ON destination.workspace_id = scoped_workspace_id
         AND destination.network_id = scoped_network_id
         AND destination.id = compiled.destination_device_id
         AND destination.public_id = input_rule.destination_node_public_id
        JOIN mesh.resource AS resource
          ON resource.workspace_id = scoped_workspace_id
         AND resource.network_id = scoped_network_id
         AND resource.public_id = input_rule.destination_resource_public_id
         AND resource.version = input_rule.destination_resource_version
         AND resource.target_generation = input_rule.destination_target_generation
         AND resource.inventory_revision = input_rule.destination_inventory_revision
         AND resource.semantic_hash = pg_catalog.decode(
                input_rule.destination_resource_semantic_hash,
                'hex'
             )
         AND resource.state = 'active'
        JOIN mesh.resource_device_target AS target
          ON target.workspace_id = scoped_workspace_id
         AND target.network_id = scoped_network_id
         AND target.resource_id = resource.id
         AND target.target_generation = resource.target_generation
         AND target.device_id = compiled.destination_device_id
         AND target.state = 'active'
        -- A revoked or deleted Device only for a rule the replaced release
        -- held unchanged: same Devices, protocol, ports and destination.
        WHERE destination.state IN ('active', 'expired', 'suspended')
           OR EXISTS (
                SELECT 1
                FROM mesh.compiled_policy_resource_destination AS carried_destination
                JOIN mesh.compiled_policy_rule AS carried
                  ON carried.id = carried_destination.compiled_policy_rule_id
                WHERE carried.workspace_id = scoped_workspace_id
                  AND carried.network_id = scoped_network_id
                  AND carried.policy_release_id = previous_release_id
                  AND carried.access_rule_public_id = compiled.access_rule_public_id
                  AND carried.source_device_id = compiled.source_device_id
                  AND carried.destination_device_id = compiled.destination_device_id
                  AND carried.protocol = compiled.protocol
                  AND carried.destination_ports = compiled.destination_ports
                  AND carried_destination.destination_resource_id = resource.id
              )
    )
    INSERT INTO mesh.compiled_policy_resource_destination (
        public_id,
        workspace_id,
        network_id,
        compiled_policy_rule_id,
        destination_resource_id,
        resource_version,
        target_generation,
        inventory_revision,
        resource_semantic_hash,
        created_at
    )
    SELECT
        resolved.compiled_policy_rule_public_id,
        scoped_workspace_id,
        scoped_network_id,
        resolved.compiled_policy_rule_id,
        resolved.resource_id,
        resolved.resource_version,
        resolved.target_generation,
        resolved.inventory_revision,
        resolved.resource_semantic_hash,
        p_created_at
    FROM resolved
    ORDER BY resolved.compiled_policy_rule_id;

    GET DIAGNOSTICS inserted_count = ROW_COUNT;
    IF inserted_count <> expected_count THEN
        -- A rule left out to a Device that is gone is new or changed.
        IF EXISTS (
            SELECT 1
            FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
                projection_public_id UUID,
                access_rule_public_id UUID,
                destination_node_public_id UUID,
                destination_resource_public_id UUID
            )
            WHERE rule.destination_resource_public_id IS NOT NULL
              AND NOT EXISTS (
                    SELECT 1
                    FROM mesh.compiled_policy_resource_destination AS attached
                    WHERE attached.public_id = rule.projection_public_id
                  )
              AND NOT EXISTS (
                    SELECT 1
                    FROM mesh.device AS device
                    WHERE device.workspace_id = scoped_workspace_id
                      AND device.network_id = scoped_network_id
                      AND device.public_id = rule.destination_node_public_id
                      AND device.state IN ('active', 'expired', 'suspended')
                  )
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MTP05',
                MESSAGE = 'a new policy rule names a Device that is not in this Network or was removed';
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = 'MT001',
            MESSAGE = 'policy Resource destination changed';
    END IF;

    attached_count := inserted_count;
    RETURN NEXT;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.attach_policy_resource_group_destinations(
    p_release_public_id UUID,
    p_created_at TIMESTAMPTZ,
    p_rules JSONB
)
RETURNS TABLE (attached_count INTEGER)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    release_internal_id BIGINT;
    release_policy_revision BIGINT;
    previous_release_id BIGINT;
    expected_count INTEGER;
    valid_count INTEGER;
    expected_group_count INTEGER;
    valid_group_count INTEGER;
    inserted_count INTEGER;
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
        OR pg_catalog.get_byte(
            pg_catalog.uuid_send(p_release_public_id),
            6
        ) >> 4 <> 7
        OR p_created_at IS NULL
        OR p_rules IS NULL
        OR pg_catalog.jsonb_typeof(p_rules) <> 'array'
        OR pg_catalog.jsonb_array_length(p_rules) > 10000 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'policy Resource Group destination input is invalid';
    END IF;

    SELECT release.id, release.policy_revision
    INTO release_internal_id, release_policy_revision
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = scoped_workspace_id
      AND release.network_id = scoped_network_id
      AND release.public_id = p_release_public_id
      AND release.state = 'active'
    FOR KEY SHARE;
    IF release_internal_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'active Policy Release is unavailable';
    END IF;

    -- The release this publication replaced: only its rules may keep naming
    -- a Device that is gone.
    SELECT previous.id
    INTO previous_release_id
    FROM mesh.policy_release AS previous
    WHERE previous.workspace_id = scoped_workspace_id
      AND previous.network_id = scoped_network_id
      AND previous.policy_revision = release_policy_revision - 1
      AND previous.state = 'superseded';

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            projection_public_id UUID,
            access_rule_public_id UUID,
            destination_node_public_id UUID,
            destination_resource_group_public_id UUID,
            destination_resource_group_version BIGINT,
            destination_group_definition_version BIGINT,
            destination_group_revision BIGINT,
            destination_resource_group_semantic_hash TEXT,
            destination_group_member_resource_public_id UUID,
            destination_group_member_resource_version BIGINT,
            destination_group_member_target_generation BIGINT,
            destination_group_member_inventory_revision BIGINT,
            destination_group_member_resource_semantic_hash TEXT
        )
    )
    SELECT
        pg_catalog.count(*) FILTER (
            WHERE rule.destination_resource_group_public_id IS NOT NULL
               OR rule.destination_resource_group_version IS NOT NULL
               OR rule.destination_group_definition_version IS NOT NULL
               OR rule.destination_group_revision IS NOT NULL
               OR rule.destination_resource_group_semantic_hash IS NOT NULL
               OR rule.destination_group_member_resource_public_id IS NOT NULL
               OR rule.destination_group_member_resource_version IS NOT NULL
               OR rule.destination_group_member_target_generation IS NOT NULL
               OR rule.destination_group_member_inventory_revision IS NOT NULL
               OR rule.destination_group_member_resource_semantic_hash IS NOT NULL
        )::INTEGER,
        pg_catalog.count(*) FILTER (
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
              AND rule.destination_node_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.destination_node_public_id),
                    6
                  ) >> 4 = 7
              AND rule.destination_resource_group_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.destination_resource_group_public_id),
                    6
                  ) >> 4 = 7
              AND rule.destination_resource_group_version > 0
              AND rule.destination_group_definition_version > 0
              AND rule.destination_group_revision > 0
              AND rule.destination_resource_group_semantic_hash ~ '^[0-9a-f]{64}$'
              AND rule.destination_group_member_resource_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.destination_group_member_resource_public_id),
                    6
                  ) >> 4 = 7
              AND rule.destination_group_member_resource_version > 0
              AND rule.destination_group_member_target_generation > 0
              AND rule.destination_group_member_inventory_revision > 0
              AND rule.destination_group_member_resource_semantic_hash ~ '^[0-9a-f]{64}$'
        )::INTEGER
    INTO expected_count, valid_count
    FROM input_rule AS rule;

    IF expected_count IS NULL OR valid_count IS NULL
        OR expected_count = 0
        OR expected_count <> valid_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'policy Resource Group destination shape is invalid';
    END IF;

    PERFORM resource_group.id
    FROM mesh.resource_group AS resource_group
    JOIN (
        SELECT DISTINCT
            rule.destination_resource_group_public_id,
            rule.destination_resource_group_version,
            rule.destination_group_definition_version,
            rule.destination_group_revision,
            rule.destination_resource_group_semantic_hash
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            destination_resource_group_public_id UUID,
            destination_resource_group_version BIGINT,
            destination_group_definition_version BIGINT,
            destination_group_revision BIGINT,
            destination_resource_group_semantic_hash TEXT
        )
        WHERE rule.destination_resource_group_public_id IS NOT NULL
    ) AS input_group
      ON resource_group.workspace_id = scoped_workspace_id
     AND resource_group.network_id = scoped_network_id
     AND resource_group.public_id = input_group.destination_resource_group_public_id
     AND resource_group.version = input_group.destination_resource_group_version
     AND resource_group.active_definition_version = input_group.destination_group_definition_version
     AND resource_group.group_revision = input_group.destination_group_revision
     AND resource_group.semantic_hash = pg_catalog.decode(
            input_group.destination_resource_group_semantic_hash,
            'hex'
         )
     AND resource_group.state = 'active'
    ORDER BY resource_group.id
    FOR KEY SHARE OF resource_group;

    PERFORM resource.id
    FROM mesh.resource AS resource
    JOIN (
        SELECT DISTINCT
            rule.destination_group_member_resource_public_id,
            rule.destination_group_member_resource_version,
            rule.destination_group_member_target_generation,
            rule.destination_group_member_inventory_revision,
            rule.destination_group_member_resource_semantic_hash
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            destination_group_member_resource_public_id UUID,
            destination_group_member_resource_version BIGINT,
            destination_group_member_target_generation BIGINT,
            destination_group_member_inventory_revision BIGINT,
            destination_group_member_resource_semantic_hash TEXT
        )
        WHERE rule.destination_group_member_resource_public_id IS NOT NULL
    ) AS input_resource
      ON resource.workspace_id = scoped_workspace_id
     AND resource.network_id = scoped_network_id
     AND resource.public_id = input_resource.destination_group_member_resource_public_id
     AND resource.version = input_resource.destination_group_member_resource_version
     AND resource.target_generation = input_resource.destination_group_member_target_generation
     AND resource.inventory_revision = input_resource.destination_group_member_inventory_revision
     AND resource.semantic_hash = pg_catalog.decode(
            input_resource.destination_group_member_resource_semantic_hash,
            'hex'
         )
     AND resource.state = 'active'
    ORDER BY resource.id
    FOR KEY SHARE OF resource;

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            access_rule_public_id UUID,
            destination_resource_group_public_id UUID,
            destination_resource_group_version BIGINT,
            destination_group_definition_version BIGINT,
            destination_group_revision BIGINT,
            destination_resource_group_semantic_hash TEXT,
            destination_group_member_resource_public_id UUID
        )
        WHERE rule.destination_resource_group_public_id IS NOT NULL
    ),
    input_group AS (
        SELECT
            rule.access_rule_public_id,
            rule.destination_resource_group_public_id,
            rule.destination_resource_group_version,
            rule.destination_group_definition_version,
            rule.destination_group_revision,
            rule.destination_resource_group_semantic_hash,
            pg_catalog.count(*)::INTEGER AS member_count,
            pg_catalog.count(DISTINCT rule.destination_group_member_resource_public_id)::INTEGER
                AS distinct_member_count
        FROM input_rule AS rule
        GROUP BY
            rule.access_rule_public_id,
            rule.destination_resource_group_public_id,
            rule.destination_resource_group_version,
            rule.destination_group_definition_version,
            rule.destination_group_revision,
            rule.destination_resource_group_semantic_hash
    )
    SELECT
        (SELECT pg_catalog.count(DISTINCT rule.access_rule_public_id)::INTEGER FROM input_rule AS rule),
        pg_catalog.count(*)::INTEGER
    INTO expected_group_count, valid_group_count
    FROM input_group
    JOIN mesh.resource_group AS resource_group
      ON resource_group.workspace_id = scoped_workspace_id
     AND resource_group.network_id = scoped_network_id
     AND resource_group.public_id = input_group.destination_resource_group_public_id
     AND resource_group.version = input_group.destination_resource_group_version
     AND resource_group.active_definition_version = input_group.destination_group_definition_version
     AND resource_group.group_revision = input_group.destination_group_revision
     AND resource_group.semantic_hash = pg_catalog.decode(
            input_group.destination_resource_group_semantic_hash,
            'hex'
         )
     AND resource_group.state = 'active'
    JOIN mesh.resource_group_version AS version
      ON version.workspace_id = resource_group.workspace_id
     AND version.network_id = resource_group.network_id
     AND version.resource_group_id = resource_group.id
     AND version.definition_version = resource_group.active_definition_version
     AND version.semantic_hash = resource_group.semantic_hash
     AND version.member_count = input_group.member_count
     AND input_group.distinct_member_count = input_group.member_count;

    IF expected_group_count IS NULL OR valid_group_count IS NULL
        OR expected_group_count = 0
        OR expected_group_count <> valid_group_count THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT001',
            MESSAGE = 'policy Resource Group definition changed';
    END IF;

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            projection_public_id UUID,
            access_rule_public_id UUID,
            destination_node_public_id UUID,
            destination_resource_group_public_id UUID,
            destination_resource_group_version BIGINT,
            destination_group_definition_version BIGINT,
            destination_group_revision BIGINT,
            destination_resource_group_semantic_hash TEXT,
            destination_group_member_resource_public_id UUID,
            destination_group_member_resource_version BIGINT,
            destination_group_member_target_generation BIGINT,
            destination_group_member_inventory_revision BIGINT,
            destination_group_member_resource_semantic_hash TEXT
        )
        WHERE rule.destination_resource_group_public_id IS NOT NULL
    ),
    resolved AS (
        SELECT
            compiled.id AS compiled_policy_rule_id,
            compiled.public_id AS compiled_policy_rule_public_id,
            resource_group.id AS resource_group_id,
            input_rule.destination_resource_group_version AS resource_group_version,
            input_rule.destination_group_definition_version AS definition_version,
            input_rule.destination_group_revision AS group_revision,
            resource_group.semantic_hash AS resource_group_semantic_hash,
            resource.id AS resource_id,
            input_rule.destination_group_member_resource_version AS resource_version,
            input_rule.destination_group_member_target_generation AS target_generation,
            input_rule.destination_group_member_inventory_revision AS inventory_revision,
            resource.semantic_hash AS resource_semantic_hash
        FROM input_rule
        JOIN mesh.compiled_policy_rule AS compiled
          ON compiled.workspace_id = scoped_workspace_id
         AND compiled.network_id = scoped_network_id
         AND compiled.policy_release_id = release_internal_id
         AND compiled.public_id = input_rule.projection_public_id
         AND compiled.access_rule_public_id = input_rule.access_rule_public_id
        JOIN mesh.device AS destination
          ON destination.workspace_id = scoped_workspace_id
         AND destination.network_id = scoped_network_id
         AND destination.id = compiled.destination_device_id
         AND destination.public_id = input_rule.destination_node_public_id
        JOIN mesh.resource_group AS resource_group
          ON resource_group.workspace_id = scoped_workspace_id
         AND resource_group.network_id = scoped_network_id
         AND resource_group.public_id = input_rule.destination_resource_group_public_id
         AND resource_group.version = input_rule.destination_resource_group_version
         AND resource_group.active_definition_version = input_rule.destination_group_definition_version
         AND resource_group.group_revision = input_rule.destination_group_revision
         AND resource_group.semantic_hash = pg_catalog.decode(
                input_rule.destination_resource_group_semantic_hash,
                'hex'
             )
         AND resource_group.state = 'active'
        JOIN mesh.resource_group_version AS version
          ON version.workspace_id = resource_group.workspace_id
         AND version.network_id = resource_group.network_id
         AND version.resource_group_id = resource_group.id
         AND version.definition_version = resource_group.active_definition_version
         AND version.semantic_hash = resource_group.semantic_hash
        JOIN mesh.resource AS resource
          ON resource.workspace_id = scoped_workspace_id
         AND resource.network_id = scoped_network_id
         AND resource.public_id = input_rule.destination_group_member_resource_public_id
         AND resource.version = input_rule.destination_group_member_resource_version
         AND resource.target_generation = input_rule.destination_group_member_target_generation
         AND resource.inventory_revision = input_rule.destination_group_member_inventory_revision
         AND resource.semantic_hash = pg_catalog.decode(
                input_rule.destination_group_member_resource_semantic_hash,
                'hex'
             )
         AND resource.state = 'active'
        JOIN mesh.resource_group_version_member AS member
          ON member.workspace_id = version.workspace_id
         AND member.network_id = version.network_id
         AND member.resource_group_id = version.resource_group_id
         AND member.resource_group_version_id = version.id
         AND member.resource_id = resource.id
         AND member.resource_version = input_rule.destination_group_member_resource_version
         AND member.target_generation = input_rule.destination_group_member_target_generation
        JOIN mesh.resource_device_target AS target
          ON target.workspace_id = scoped_workspace_id
         AND target.network_id = scoped_network_id
         AND target.resource_id = resource.id
         AND target.target_generation = resource.target_generation
         AND target.device_id = compiled.destination_device_id
         AND target.state = 'active'
        -- A revoked or deleted Device only for a rule the replaced release
        -- held unchanged: same Devices, protocol, ports and destination.
        WHERE destination.state IN ('active', 'expired', 'suspended')
           OR EXISTS (
                SELECT 1
                FROM mesh.compiled_policy_resource_group_destination AS carried_destination
                JOIN mesh.compiled_policy_rule AS carried
                  ON carried.id = carried_destination.compiled_policy_rule_id
                WHERE carried.workspace_id = scoped_workspace_id
                  AND carried.network_id = scoped_network_id
                  AND carried.policy_release_id = previous_release_id
                  AND carried.access_rule_public_id = compiled.access_rule_public_id
                  AND carried.source_device_id = compiled.source_device_id
                  AND carried.destination_device_id = compiled.destination_device_id
                  AND carried.protocol = compiled.protocol
                  AND carried.destination_ports = compiled.destination_ports
                  AND carried_destination.destination_resource_group_id = resource_group.id
                  AND carried_destination.destination_resource_id = resource.id
              )
    )
    INSERT INTO mesh.compiled_policy_resource_group_destination (
        public_id,
        workspace_id,
        network_id,
        compiled_policy_rule_id,
        destination_resource_group_id,
        resource_group_version,
        definition_version,
        group_revision,
        resource_group_semantic_hash,
        destination_resource_id,
        resource_version,
        target_generation,
        inventory_revision,
        resource_semantic_hash,
        created_at
    )
    SELECT
        resolved.compiled_policy_rule_public_id,
        scoped_workspace_id,
        scoped_network_id,
        resolved.compiled_policy_rule_id,
        resolved.resource_group_id,
        resolved.resource_group_version,
        resolved.definition_version,
        resolved.group_revision,
        resolved.resource_group_semantic_hash,
        resolved.resource_id,
        resolved.resource_version,
        resolved.target_generation,
        resolved.inventory_revision,
        resolved.resource_semantic_hash,
        p_created_at
    FROM resolved
    ORDER BY resolved.compiled_policy_rule_id;

    GET DIAGNOSTICS inserted_count = ROW_COUNT;
    IF inserted_count <> expected_count THEN
        -- A rule left out to a Device that is gone is new or changed.
        IF EXISTS (
            SELECT 1
            FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
                projection_public_id UUID,
                access_rule_public_id UUID,
                destination_node_public_id UUID,
                destination_resource_group_public_id UUID
            )
            WHERE rule.destination_resource_group_public_id IS NOT NULL
              AND NOT EXISTS (
                    SELECT 1
                    FROM mesh.compiled_policy_resource_group_destination AS attached
                    WHERE attached.public_id = rule.projection_public_id
                  )
              AND NOT EXISTS (
                    SELECT 1
                    FROM mesh.device AS device
                    WHERE device.workspace_id = scoped_workspace_id
                      AND device.network_id = scoped_network_id
                      AND device.public_id = rule.destination_node_public_id
                      AND device.state IN ('active', 'expired', 'suspended')
                  )
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MTP05',
                MESSAGE = 'a new policy rule names a Device that is not in this Network or was removed';
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = 'MT001',
            MESSAGE = 'policy Resource Group destination changed';
    END IF;

    attached_count := inserted_count;
    RETURN NEXT;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.attach_policy_imported_resource_destinations_internal_v1(
    p_release_public_id UUID,
    p_created_at TIMESTAMPTZ,
    p_rules JSONB,
    p_authority JSONB
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, mesh, mesh_ops
SET join_collapse_limit = 1
SET from_collapse_limit = 1
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    release_internal_id BIGINT;
    release_policy_revision BIGINT;
    previous_release_id BIGINT;
    expected_count INTEGER;
    valid_count INTEGER;
    orphan_count INTEGER;
    inserted_count INTEGER;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_release_public_id IS NULL OR p_created_at IS NULL OR p_rules IS NULL
        OR pg_catalog.jsonb_typeof(p_rules) <> 'array'
        OR pg_catalog.jsonb_array_length(p_rules) > 10000
        OR p_authority IS NULL
        OR pg_catalog.jsonb_typeof(p_authority) <> 'array'
        OR pg_catalog.jsonb_array_length(p_authority) > 256 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Imported Resource provenance input is invalid';
    END IF;

    SELECT release.id, release.policy_revision
    INTO release_internal_id, release_policy_revision
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = scoped_workspace_id
      AND release.network_id = scoped_network_id
      AND release.public_id = p_release_public_id
      AND release.state = 'active'
      AND release.compiler_format_version = 4
    FOR KEY SHARE;

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            projection_public_id UUID,
            access_rule_public_id UUID,
            source_node_public_id UUID,
            destination_node_public_id UUID,
            destination_resource_public_id UUID,
            destination_resource_group_public_id UUID,
            protocol TEXT,
            port_range_first INTEGER[],
            port_range_last INTEGER[],
            destination_imported_resource_public_id UUID,
            destination_imported_resource_version BIGINT,
            destination_trust_contract_public_id UUID,
            destination_trust_contract_version BIGINT,
            destination_resource_export_public_id UUID,
            destination_resource_export_version BIGINT,
            destination_provider_workspace_public_id UUID,
            destination_provider_network_public_id UUID,
            destination_provider_resource_public_id UUID,
            destination_provider_resource_version BIGINT,
            destination_provider_target_generation BIGINT,
            destination_provider_resource_semantic_hash TEXT,
            destination_provider_inventory_revision BIGINT,
            destination_provider_sharing_revision BIGINT,
            destination_consumer_sharing_revision BIGINT,
            destination_provider_authority_generation BIGINT,
            destination_consumer_authority_generation BIGINT,
            destination_recovery_epoch BIGINT,
            destination_contract_expires_at TIMESTAMPTZ,
            destination_constraint_hash TEXT
        )
    )
    SELECT
        pg_catalog.count(*) FILTER (
            WHERE rule.destination_imported_resource_public_id IS NOT NULL
        )::INTEGER,
        pg_catalog.count(*) FILTER (
            WHERE rule.destination_imported_resource_public_id IS NOT NULL
              AND rule.projection_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.projection_public_id), 6
                  ) >> 4 = 7
              AND rule.access_rule_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.access_rule_public_id), 6
                  ) >> 4 = 7
              AND rule.source_node_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.source_node_public_id), 6
                  ) >> 4 = 7
              AND rule.destination_node_public_id IS NULL
              AND rule.destination_resource_public_id IS NULL
              AND rule.destination_resource_group_public_id IS NULL
              AND rule.destination_imported_resource_version > 0
              AND rule.destination_trust_contract_public_id IS NOT NULL
              AND rule.destination_trust_contract_version > 0
              AND rule.destination_resource_export_public_id IS NOT NULL
              AND rule.destination_resource_export_version > 0
              AND rule.destination_provider_workspace_public_id IS NOT NULL
              AND rule.destination_provider_network_public_id IS NOT NULL
              AND rule.destination_provider_resource_public_id IS NOT NULL
              AND rule.destination_provider_resource_version > 0
              AND rule.destination_provider_target_generation > 0
              AND rule.destination_provider_resource_semantic_hash ~ '^[0-9a-f]{64}$'
              AND rule.destination_provider_inventory_revision > 0
              AND rule.destination_provider_sharing_revision > 0
              AND rule.destination_consumer_sharing_revision > 0
              AND rule.destination_provider_authority_generation > 0
              AND rule.destination_consumer_authority_generation > 0
              AND rule.destination_recovery_epoch > 0
              AND rule.destination_contract_expires_at > p_created_at
              AND rule.destination_constraint_hash ~ '^[0-9a-f]{64}$'
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
        )::INTEGER,
        pg_catalog.count(*) FILTER (
            WHERE rule.destination_imported_resource_public_id IS NULL
              AND (
                    rule.destination_imported_resource_version IS NOT NULL
                    OR rule.destination_trust_contract_public_id IS NOT NULL
                    OR rule.destination_trust_contract_version IS NOT NULL
                    OR rule.destination_resource_export_public_id IS NOT NULL
                    OR rule.destination_resource_export_version IS NOT NULL
                    OR rule.destination_provider_workspace_public_id IS NOT NULL
                    OR rule.destination_provider_network_public_id IS NOT NULL
                    OR rule.destination_provider_resource_public_id IS NOT NULL
                    OR rule.destination_provider_resource_version IS NOT NULL
                    OR rule.destination_provider_target_generation IS NOT NULL
                    OR rule.destination_provider_resource_semantic_hash IS NOT NULL
                    OR rule.destination_provider_inventory_revision IS NOT NULL
                    OR rule.destination_provider_sharing_revision IS NOT NULL
                    OR rule.destination_consumer_sharing_revision IS NOT NULL
                    OR rule.destination_provider_authority_generation IS NOT NULL
                    OR rule.destination_consumer_authority_generation IS NOT NULL
                    OR rule.destination_recovery_epoch IS NOT NULL
                    OR rule.destination_contract_expires_at IS NOT NULL
                    OR rule.destination_constraint_hash IS NOT NULL
              )
        )::INTEGER
    INTO expected_count, valid_count, orphan_count
    FROM input_rule AS rule;

    IF orphan_count <> 0 OR expected_count <> valid_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Imported Resource provenance shape is invalid';
    END IF;
    IF (expected_count = 0 AND pg_catalog.jsonb_array_length(p_authority) <> 0)
        OR (expected_count > 0 AND pg_catalog.jsonb_array_length(p_authority) = 0)
        OR EXISTS (
            SELECT 1
            FROM pg_catalog.jsonb_to_recordset(p_authority) AS authority(
                imported_resource_id UUID
            )
            GROUP BY authority.imported_resource_id
            HAVING authority.imported_resource_id IS NULL
                OR pg_catalog.count(*) > 1
        ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Imported Resource authority snapshot is invalid';
    END IF;
    IF expected_count = 0 THEN
        RETURN 0;
    END IF;
    IF release_internal_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'active format-v4 Policy Release is unavailable';
    END IF;

    -- The release this publication replaced: only its rules may keep naming
    -- a Device that is gone.
    SELECT previous.id
    INTO previous_release_id
    FROM mesh.policy_release AS previous
    WHERE previous.workspace_id = scoped_workspace_id
      AND previous.network_id = scoped_network_id
      AND previous.policy_revision = release_policy_revision - 1
      AND previous.state = 'superseded';

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            projection_public_id UUID,
            access_rule_public_id UUID,
            source_node_public_id UUID,
            protocol TEXT,
            port_range_first INTEGER[],
            port_range_last INTEGER[],
            destination_imported_resource_public_id UUID,
            destination_imported_resource_version BIGINT,
            destination_trust_contract_public_id UUID,
            destination_trust_contract_version BIGINT,
            destination_resource_export_public_id UUID,
            destination_resource_export_version BIGINT,
            destination_provider_workspace_public_id UUID,
            destination_provider_network_public_id UUID,
            destination_provider_resource_public_id UUID,
            destination_provider_resource_version BIGINT,
            destination_provider_target_generation BIGINT,
            destination_provider_resource_semantic_hash TEXT,
            destination_provider_inventory_revision BIGINT,
            destination_provider_sharing_revision BIGINT,
            destination_consumer_sharing_revision BIGINT,
            destination_provider_authority_generation BIGINT,
            destination_consumer_authority_generation BIGINT,
            destination_recovery_epoch BIGINT,
            destination_contract_expires_at TIMESTAMPTZ,
            destination_constraint_hash TEXT
        )
        WHERE rule.destination_imported_resource_public_id IS NOT NULL
    ),
    authority AS (
        SELECT authority.*
        FROM pg_catalog.jsonb_to_recordset(p_authority) AS authority(
            imported_resource_id UUID,
            imported_resource_version BIGINT,
            contract_id UUID,
            contract_version BIGINT,
            offer_id UUID,
            export_id UUID,
            export_version BIGINT,
            provider_workspace_id UUID,
            provider_network_id UUID,
            consumer_workspace_id UUID,
            consumer_network_id UUID,
            resource_id UUID,
            resource_version BIGINT,
            target_generation BIGINT,
            resource_semantic_hash TEXT,
            provider_inventory_revision BIGINT,
            provider_sharing_revision BIGINT,
            consumer_sharing_revision BIGINT,
            provider_authority_generation BIGINT,
            consumer_authority_generation BIGINT,
            recovery_epoch BIGINT,
            expires_at TIMESTAMPTZ,
            constraint_hash TEXT
        )
    ),
    resolved AS (
        SELECT
            rule.*,
            source.id AS source_device_id,
            imported.id AS imported_resource_id,
            contract.id AS trust_contract_id,
            export.id AS resource_export_id,
            contract.provider_workspace_id,
            contract.provider_network_id,
            resource.id AS destination_resource_id,
            ports.destination_ports
        FROM input_rule AS rule
        JOIN authority
          ON authority.imported_resource_id
                = rule.destination_imported_resource_public_id
         AND authority.imported_resource_version
                = rule.destination_imported_resource_version
         AND authority.contract_id = rule.destination_trust_contract_public_id
         AND authority.contract_version = rule.destination_trust_contract_version
         AND authority.export_id = rule.destination_resource_export_public_id
         AND authority.export_version = rule.destination_resource_export_version
         AND authority.provider_workspace_id
                = rule.destination_provider_workspace_public_id
         AND authority.provider_network_id
                = rule.destination_provider_network_public_id
         AND authority.resource_id = rule.destination_provider_resource_public_id
         AND authority.resource_version = rule.destination_provider_resource_version
         AND authority.target_generation
                = rule.destination_provider_target_generation
         AND authority.resource_semantic_hash
                = rule.destination_provider_resource_semantic_hash
         AND authority.provider_inventory_revision
                = rule.destination_provider_inventory_revision
         AND authority.provider_sharing_revision
                = rule.destination_provider_sharing_revision
         AND authority.consumer_sharing_revision
                = rule.destination_consumer_sharing_revision
         AND authority.provider_authority_generation
                = rule.destination_provider_authority_generation
         AND authority.consumer_authority_generation
                = rule.destination_consumer_authority_generation
         AND authority.recovery_epoch = rule.destination_recovery_epoch
         AND authority.expires_at = rule.destination_contract_expires_at
         AND authority.constraint_hash = rule.destination_constraint_hash
        JOIN mesh.device AS source
          ON source.workspace_id = scoped_workspace_id
         AND source.network_id = scoped_network_id
         AND source.public_id = rule.source_node_public_id
        JOIN mesh.imported_resource AS imported
          ON imported.workspace_id = scoped_workspace_id
         AND imported.network_id = scoped_network_id
         AND imported.public_id = rule.destination_imported_resource_public_id
         AND imported.version = rule.destination_imported_resource_version
         AND imported.state = 'active'
        JOIN mesh.trust_contract AS contract
          ON contract.id = imported.trust_contract_id
         AND contract.consumer_workspace_id = scoped_workspace_id
         AND contract.consumer_network_id = scoped_network_id
         AND contract.public_id = rule.destination_trust_contract_public_id
         AND contract.version = rule.destination_trust_contract_version
         AND contract.imported_resource_public_id = imported.public_id
         AND contract.provider_authority_generation
                = rule.destination_provider_authority_generation
         AND contract.consumer_authority_generation
                = rule.destination_consumer_authority_generation
         AND contract.recovery_epoch = rule.destination_recovery_epoch
         AND contract.expires_at = rule.destination_contract_expires_at
         AND contract.constraint_hash = pg_catalog.decode(
                rule.destination_constraint_hash, 'hex'
             )
         AND contract.state = 'active'
         AND p_created_at < contract.expires_at
        JOIN mesh.share_offer AS offer
          ON offer.id = contract.share_offer_id
         AND offer.public_id = authority.offer_id
         AND offer.state = 'accepted'
         AND offer.accepted_contract_public_id = contract.public_id
        JOIN mesh.resource_export AS export
          ON export.id = contract.resource_export_id
         AND export.public_id = rule.destination_resource_export_public_id
         AND export.version = rule.destination_resource_export_version
         AND export.provider_workspace_id = contract.provider_workspace_id
         AND export.provider_network_id = contract.provider_network_id
         AND export.consumer_workspace_id = scoped_workspace_id
         AND export.consumer_network_id = scoped_network_id
         AND export.resource_id = contract.resource_id
         AND export.resource_version = contract.resource_version
         AND export.target_generation = contract.target_generation
         AND export.resource_semantic_hash = contract.resource_semantic_hash
         AND export.constraint_hash = contract.constraint_hash
         AND export.provider_authority_generation = contract.provider_authority_generation
         AND export.state = 'active'
         AND p_created_at < export.expires_at
        JOIN mesh.resource AS resource
          ON resource.workspace_id = contract.provider_workspace_id
         AND resource.network_id = contract.provider_network_id
         AND resource.id = contract.resource_id
         AND resource.public_id = rule.destination_provider_resource_public_id
         AND resource.version = rule.destination_provider_resource_version
         AND resource.version = contract.resource_version
         AND resource.target_generation = rule.destination_provider_target_generation
         AND resource.target_generation = contract.target_generation
         AND resource.semantic_hash = pg_catalog.decode(
                rule.destination_provider_resource_semantic_hash, 'hex'
             )
         AND resource.semantic_hash = contract.resource_semantic_hash
         AND resource.state = 'active'
         AND resource.deleted_at IS NULL
        JOIN mesh.resource_device_target AS target
          ON target.workspace_id = resource.workspace_id
         AND target.network_id = resource.network_id
         AND target.resource_id = resource.id
         AND target.target_generation = resource.target_generation
         AND target.state = 'active'
        JOIN mesh.resource_export_constraint AS constraint_row
          ON constraint_row.resource_export_id = export.id
         AND constraint_row.protocol = rule.protocol
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
        WHERE ports.destination_ports <@ constraint_row.destination_ports
          -- A revoked or deleted source Device only for a rule the replaced
          -- release held unchanged: same source, share, protocol and ports.
          AND (
                source.state IN ('active', 'expired', 'suspended')
                OR EXISTS (
                    SELECT 1
                    FROM mesh.compiled_policy_imported_resource_destination AS carried
                    WHERE carried.workspace_id = scoped_workspace_id
                      AND carried.network_id = scoped_network_id
                      AND carried.policy_release_id = previous_release_id
                      AND carried.access_rule_public_id = rule.access_rule_public_id
                      AND carried.source_device_id = source.id
                      AND carried.imported_resource_id = imported.id
                      AND carried.protocol = rule.protocol
                      AND carried.destination_ports = ports.destination_ports
                )
          )
    )
    INSERT INTO mesh.compiled_policy_imported_resource_destination (
        public_id, access_rule_public_id, workspace_id, network_id,
        policy_release_id, policy_revision, source_device_id,
        imported_resource_id, imported_resource_version,
        trust_contract_id, trust_contract_version,
        resource_export_id, resource_export_version,
        provider_workspace_id, provider_network_id, destination_resource_id,
        resource_version, target_generation, resource_semantic_hash,
        provider_inventory_revision, provider_sharing_revision,
        consumer_sharing_revision, provider_authority_generation,
        consumer_authority_generation, recovery_epoch, contract_expires_at,
        constraint_hash, protocol, destination_ports, created_at
    )
    SELECT
        resolved.projection_public_id,
        resolved.access_rule_public_id,
        scoped_workspace_id,
        scoped_network_id,
        release_internal_id,
        release_policy_revision,
        resolved.source_device_id,
        resolved.imported_resource_id,
        resolved.destination_imported_resource_version,
        resolved.trust_contract_id,
        resolved.destination_trust_contract_version,
        resolved.resource_export_id,
        resolved.destination_resource_export_version,
        resolved.provider_workspace_id,
        resolved.provider_network_id,
        resolved.destination_resource_id,
        resolved.destination_provider_resource_version,
        resolved.destination_provider_target_generation,
        pg_catalog.decode(resolved.destination_provider_resource_semantic_hash, 'hex'),
        resolved.destination_provider_inventory_revision,
        resolved.destination_provider_sharing_revision,
        resolved.destination_consumer_sharing_revision,
        resolved.destination_provider_authority_generation,
        resolved.destination_consumer_authority_generation,
        resolved.destination_recovery_epoch,
        resolved.destination_contract_expires_at,
        pg_catalog.decode(resolved.destination_constraint_hash, 'hex'),
        resolved.protocol,
        resolved.destination_ports,
        p_created_at
    FROM resolved
    ORDER BY resolved.access_rule_public_id, resolved.projection_public_id;

    GET DIAGNOSTICS inserted_count = ROW_COUNT;
    IF inserted_count <> expected_count THEN
        -- A rule left out from a source Device that is gone is new or
        -- changed.
        IF EXISTS (
            SELECT 1
            FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
                projection_public_id UUID,
                access_rule_public_id UUID,
                source_node_public_id UUID,
                destination_imported_resource_public_id UUID
            )
            WHERE rule.destination_imported_resource_public_id IS NOT NULL
              AND NOT EXISTS (
                    SELECT 1
                    FROM mesh.compiled_policy_imported_resource_destination AS attached
                    WHERE attached.public_id = rule.projection_public_id
                  )
              AND NOT EXISTS (
                    SELECT 1
                    FROM mesh.device AS device
                    WHERE device.workspace_id = scoped_workspace_id
                      AND device.network_id = scoped_network_id
                      AND device.public_id = rule.source_node_public_id
                      AND device.state IN ('active', 'expired', 'suspended')
                  )
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MTP05',
                MESSAGE = 'a new policy rule names a Device that is not in this Network or was removed';
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = 'MT001',
            MESSAGE = 'Imported Resource authority changed during publication';
    END IF;
    RETURN inserted_count;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.attach_policy_imported_resource_destinations_internal_v2(
    p_release_public_id UUID,
    p_created_at TIMESTAMPTZ,
    p_rules JSONB,
    p_authority JSONB
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, mesh, mesh_ops
SET join_collapse_limit = 1
SET from_collapse_limit = 1
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    release_internal_id BIGINT;
    release_policy_revision BIGINT;
    previous_release_id BIGINT;
    expected_count INTEGER;
    valid_count INTEGER;
    orphan_count INTEGER;
    inserted_count INTEGER;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_release_public_id IS NULL OR p_created_at IS NULL OR p_rules IS NULL
        OR pg_catalog.jsonb_typeof(p_rules) <> 'array'
        OR pg_catalog.jsonb_array_length(p_rules) > 10000
        OR p_authority IS NULL
        OR pg_catalog.jsonb_typeof(p_authority) <> 'array'
        OR pg_catalog.jsonb_array_length(p_authority) > 10000 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Imported Resource provenance input is invalid';
    END IF;

    SELECT release.id, release.policy_revision
    INTO release_internal_id, release_policy_revision
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = scoped_workspace_id
      AND release.network_id = scoped_network_id
      AND release.public_id = p_release_public_id
      AND release.state = 'active'
      AND release.compiler_format_version = 4
    FOR KEY SHARE;

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            projection_public_id UUID,
            access_rule_public_id UUID,
            source_node_public_id UUID,
            destination_node_public_id UUID,
            destination_resource_public_id UUID,
            destination_resource_group_public_id UUID,
            protocol TEXT,
            port_range_first INTEGER[],
            port_range_last INTEGER[],
            destination_imported_resource_public_id UUID,
            destination_imported_resource_version BIGINT,
            destination_trust_contract_public_id UUID,
            destination_trust_contract_version BIGINT,
            destination_resource_export_public_id UUID,
            destination_resource_export_version BIGINT,
            destination_provider_workspace_public_id UUID,
            destination_provider_network_public_id UUID,
            destination_provider_resource_public_id UUID,
            destination_provider_resource_version BIGINT,
            destination_provider_target_generation BIGINT,
            destination_provider_resource_semantic_hash TEXT,
            destination_provider_inventory_revision BIGINT,
            destination_provider_sharing_revision BIGINT,
            destination_consumer_sharing_revision BIGINT,
            destination_provider_authority_generation BIGINT,
            destination_consumer_authority_generation BIGINT,
            destination_recovery_epoch BIGINT,
            destination_contract_expires_at TIMESTAMPTZ,
            destination_constraint_hash TEXT
        )
    )
    SELECT
        pg_catalog.count(*) FILTER (
            WHERE rule.destination_imported_resource_public_id IS NOT NULL
        )::INTEGER,
        pg_catalog.count(*) FILTER (
            WHERE rule.destination_imported_resource_public_id IS NOT NULL
              AND rule.projection_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.projection_public_id), 6
                  ) >> 4 = 7
              AND rule.access_rule_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.access_rule_public_id), 6
                  ) >> 4 = 7
              AND rule.source_node_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.source_node_public_id), 6
                  ) >> 4 = 7
              AND rule.destination_node_public_id IS NULL
              AND rule.destination_resource_public_id IS NULL
              AND rule.destination_resource_group_public_id IS NULL
              AND rule.destination_imported_resource_version > 0
              AND rule.destination_trust_contract_public_id IS NOT NULL
              AND rule.destination_trust_contract_version > 0
              AND rule.destination_resource_export_public_id IS NOT NULL
              AND rule.destination_resource_export_version > 0
              AND rule.destination_provider_workspace_public_id IS NOT NULL
              AND rule.destination_provider_network_public_id IS NOT NULL
              AND rule.destination_provider_resource_public_id IS NOT NULL
              AND rule.destination_provider_resource_version > 0
              AND rule.destination_provider_target_generation > 0
              AND rule.destination_provider_resource_semantic_hash ~ '^[0-9a-f]{64}$'
              AND rule.destination_provider_inventory_revision > 0
              AND rule.destination_provider_sharing_revision > 0
              AND rule.destination_consumer_sharing_revision > 0
              AND rule.destination_provider_authority_generation > 0
              AND rule.destination_consumer_authority_generation > 0
              AND rule.destination_recovery_epoch > 0
              AND rule.destination_contract_expires_at > p_created_at
              AND rule.destination_constraint_hash ~ '^[0-9a-f]{64}$'
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
        )::INTEGER,
        pg_catalog.count(*) FILTER (
            WHERE rule.destination_imported_resource_public_id IS NULL
              AND (
                    rule.destination_imported_resource_version IS NOT NULL
                    OR rule.destination_trust_contract_public_id IS NOT NULL
                    OR rule.destination_trust_contract_version IS NOT NULL
                    OR rule.destination_resource_export_public_id IS NOT NULL
                    OR rule.destination_resource_export_version IS NOT NULL
                    OR rule.destination_provider_workspace_public_id IS NOT NULL
                    OR rule.destination_provider_network_public_id IS NOT NULL
                    OR rule.destination_provider_resource_public_id IS NOT NULL
                    OR rule.destination_provider_resource_version IS NOT NULL
                    OR rule.destination_provider_target_generation IS NOT NULL
                    OR rule.destination_provider_resource_semantic_hash IS NOT NULL
                    OR rule.destination_provider_inventory_revision IS NOT NULL
                    OR rule.destination_provider_sharing_revision IS NOT NULL
                    OR rule.destination_consumer_sharing_revision IS NOT NULL
                    OR rule.destination_provider_authority_generation IS NOT NULL
                    OR rule.destination_consumer_authority_generation IS NOT NULL
                    OR rule.destination_recovery_epoch IS NOT NULL
                    OR rule.destination_contract_expires_at IS NOT NULL
                    OR rule.destination_constraint_hash IS NOT NULL
              )
        )::INTEGER
    INTO expected_count, valid_count, orphan_count
    FROM input_rule AS rule;

    IF orphan_count <> 0 OR expected_count <> valid_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Imported Resource provenance shape is invalid';
    END IF;
    IF (expected_count = 0 AND pg_catalog.jsonb_array_length(p_authority) <> 0)
        OR (expected_count > 0 AND pg_catalog.jsonb_array_length(p_authority) = 0)
        OR EXISTS (
            SELECT 1
            FROM pg_catalog.jsonb_to_recordset(p_authority) AS authority(
                imported_resource_id UUID
            )
            GROUP BY authority.imported_resource_id
            HAVING authority.imported_resource_id IS NULL
                OR pg_catalog.count(*) > 1
        ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Imported Resource authority snapshot is invalid';
    END IF;
    IF expected_count = 0 THEN
        RETURN 0;
    END IF;
    IF release_internal_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'active format-v4 Policy Release is unavailable';
    END IF;

    -- The release this publication replaced: only its rules may keep naming
    -- a Device that is gone.
    SELECT previous.id
    INTO previous_release_id
    FROM mesh.policy_release AS previous
    WHERE previous.workspace_id = scoped_workspace_id
      AND previous.network_id = scoped_network_id
      AND previous.policy_revision = release_policy_revision - 1
      AND previous.state = 'superseded';

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            projection_public_id UUID,
            access_rule_public_id UUID,
            source_node_public_id UUID,
            protocol TEXT,
            port_range_first INTEGER[],
            port_range_last INTEGER[],
            destination_imported_resource_public_id UUID,
            destination_imported_resource_version BIGINT,
            destination_trust_contract_public_id UUID,
            destination_trust_contract_version BIGINT,
            destination_resource_export_public_id UUID,
            destination_resource_export_version BIGINT,
            destination_provider_workspace_public_id UUID,
            destination_provider_network_public_id UUID,
            destination_provider_resource_public_id UUID,
            destination_provider_resource_version BIGINT,
            destination_provider_target_generation BIGINT,
            destination_provider_resource_semantic_hash TEXT,
            destination_provider_inventory_revision BIGINT,
            destination_provider_sharing_revision BIGINT,
            destination_consumer_sharing_revision BIGINT,
            destination_provider_authority_generation BIGINT,
            destination_consumer_authority_generation BIGINT,
            destination_recovery_epoch BIGINT,
            destination_contract_expires_at TIMESTAMPTZ,
            destination_constraint_hash TEXT
        )
        WHERE rule.destination_imported_resource_public_id IS NOT NULL
    ),
    authority AS (
        SELECT authority.*
        FROM pg_catalog.jsonb_to_recordset(p_authority) AS authority(
            imported_resource_id UUID,
            imported_resource_version BIGINT,
            contract_id UUID,
            contract_version BIGINT,
            offer_id UUID,
            export_id UUID,
            export_version BIGINT,
            provider_workspace_id UUID,
            provider_network_id UUID,
            consumer_workspace_id UUID,
            consumer_network_id UUID,
            resource_id UUID,
            resource_version BIGINT,
            target_generation BIGINT,
            resource_semantic_hash TEXT,
            provider_inventory_revision BIGINT,
            provider_sharing_revision BIGINT,
            consumer_sharing_revision BIGINT,
            provider_authority_generation BIGINT,
            consumer_authority_generation BIGINT,
            recovery_epoch BIGINT,
            expires_at TIMESTAMPTZ,
            constraint_hash TEXT
        )
    ),
    resolved AS (
        SELECT
            rule.*,
            source.id AS source_device_id,
            imported.id AS imported_resource_id,
            contract.id AS trust_contract_id,
            export.id AS resource_export_id,
            contract.provider_workspace_id,
            contract.provider_network_id,
            resource.id AS destination_resource_id,
            ports.destination_ports
        FROM input_rule AS rule
        JOIN authority
          ON authority.imported_resource_id
                = rule.destination_imported_resource_public_id
         AND authority.imported_resource_version
                = rule.destination_imported_resource_version
         AND authority.contract_id = rule.destination_trust_contract_public_id
         AND authority.contract_version = rule.destination_trust_contract_version
         AND authority.export_id = rule.destination_resource_export_public_id
         AND authority.export_version = rule.destination_resource_export_version
         AND authority.provider_workspace_id
                = rule.destination_provider_workspace_public_id
         AND authority.provider_network_id
                = rule.destination_provider_network_public_id
         AND authority.resource_id = rule.destination_provider_resource_public_id
         AND authority.resource_version = rule.destination_provider_resource_version
         AND authority.target_generation
                = rule.destination_provider_target_generation
         AND authority.resource_semantic_hash
                = rule.destination_provider_resource_semantic_hash
         AND authority.provider_inventory_revision
                = rule.destination_provider_inventory_revision
         AND authority.provider_sharing_revision
                = rule.destination_provider_sharing_revision
         AND authority.consumer_sharing_revision
                = rule.destination_consumer_sharing_revision
         AND authority.provider_authority_generation
                = rule.destination_provider_authority_generation
         AND authority.consumer_authority_generation
                = rule.destination_consumer_authority_generation
         AND authority.recovery_epoch = rule.destination_recovery_epoch
         AND authority.expires_at = rule.destination_contract_expires_at
         AND authority.constraint_hash = rule.destination_constraint_hash
        JOIN mesh.device AS source
          ON source.workspace_id = scoped_workspace_id
         AND source.network_id = scoped_network_id
         AND source.public_id = rule.source_node_public_id
        JOIN mesh.imported_resource AS imported
          ON imported.workspace_id = scoped_workspace_id
         AND imported.network_id = scoped_network_id
         AND imported.public_id = rule.destination_imported_resource_public_id
         AND imported.version = rule.destination_imported_resource_version
         AND imported.state = 'active'
        JOIN mesh.trust_contract AS contract
          ON contract.id = imported.trust_contract_id
         AND contract.consumer_workspace_id = scoped_workspace_id
         AND contract.consumer_network_id = scoped_network_id
         AND contract.public_id = rule.destination_trust_contract_public_id
         AND contract.version = rule.destination_trust_contract_version
         AND contract.imported_resource_public_id = imported.public_id
         AND contract.provider_authority_generation
                = rule.destination_provider_authority_generation
         AND contract.consumer_authority_generation
                = rule.destination_consumer_authority_generation
         AND contract.recovery_epoch = rule.destination_recovery_epoch
         AND contract.expires_at = rule.destination_contract_expires_at
         AND contract.constraint_hash = pg_catalog.decode(
                rule.destination_constraint_hash, 'hex'
             )
         AND contract.state = 'active'
         AND p_created_at < contract.expires_at
        JOIN mesh.share_offer AS offer
          ON offer.id = contract.share_offer_id
         AND offer.public_id = authority.offer_id
         AND offer.state = 'accepted'
         AND offer.accepted_contract_public_id = contract.public_id
        JOIN mesh.resource_export AS export
          ON export.id = contract.resource_export_id
         AND export.public_id = rule.destination_resource_export_public_id
         AND export.version = rule.destination_resource_export_version
         AND export.provider_workspace_id = contract.provider_workspace_id
         AND export.provider_network_id = contract.provider_network_id
         AND export.consumer_workspace_id = scoped_workspace_id
         AND export.consumer_network_id = scoped_network_id
         AND export.resource_id = contract.resource_id
         AND export.resource_version = contract.resource_version
         AND export.target_generation = contract.target_generation
         AND export.resource_semantic_hash = contract.resource_semantic_hash
         AND export.constraint_hash = contract.constraint_hash
         AND export.provider_authority_generation = contract.provider_authority_generation
         AND export.state = 'active'
         AND p_created_at < export.expires_at
        JOIN mesh.resource AS resource
          ON resource.workspace_id = contract.provider_workspace_id
         AND resource.network_id = contract.provider_network_id
         AND resource.id = contract.resource_id
         AND resource.public_id = rule.destination_provider_resource_public_id
         AND resource.version = rule.destination_provider_resource_version
         AND resource.version = contract.resource_version
         AND resource.target_generation = rule.destination_provider_target_generation
         AND resource.target_generation = contract.target_generation
         AND resource.semantic_hash = pg_catalog.decode(
                rule.destination_provider_resource_semantic_hash, 'hex'
             )
         AND resource.semantic_hash = contract.resource_semantic_hash
         AND resource.state = 'active'
         AND resource.deleted_at IS NULL
        JOIN mesh.resource_device_target AS target
          ON target.workspace_id = resource.workspace_id
         AND target.network_id = resource.network_id
         AND target.resource_id = resource.id
         AND target.target_generation = resource.target_generation
         AND target.state = 'active'
        JOIN mesh.resource_export_constraint AS constraint_row
          ON constraint_row.resource_export_id = export.id
         AND constraint_row.protocol = rule.protocol
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
        WHERE ports.destination_ports <@ constraint_row.destination_ports
          -- A revoked or deleted source Device only for a rule the replaced
          -- release held unchanged: same source, share, protocol and ports.
          AND (
                source.state IN ('active', 'expired', 'suspended')
                OR EXISTS (
                    SELECT 1
                    FROM mesh.compiled_policy_imported_resource_destination AS carried
                    WHERE carried.workspace_id = scoped_workspace_id
                      AND carried.network_id = scoped_network_id
                      AND carried.policy_release_id = previous_release_id
                      AND carried.access_rule_public_id = rule.access_rule_public_id
                      AND carried.source_device_id = source.id
                      AND carried.imported_resource_id = imported.id
                      AND carried.protocol = rule.protocol
                      AND carried.destination_ports = ports.destination_ports
                )
          )
    )
    INSERT INTO mesh.compiled_policy_imported_resource_destination (
        public_id, access_rule_public_id, workspace_id, network_id,
        policy_release_id, policy_revision, source_device_id,
        imported_resource_id, imported_resource_version,
        trust_contract_id, trust_contract_version,
        resource_export_id, resource_export_version,
        provider_workspace_id, provider_network_id, destination_resource_id,
        resource_version, target_generation, resource_semantic_hash,
        provider_inventory_revision, provider_sharing_revision,
        consumer_sharing_revision, provider_authority_generation,
        consumer_authority_generation, recovery_epoch, contract_expires_at,
        constraint_hash, protocol, destination_ports, created_at
    )
    SELECT
        resolved.projection_public_id,
        resolved.access_rule_public_id,
        scoped_workspace_id,
        scoped_network_id,
        release_internal_id,
        release_policy_revision,
        resolved.source_device_id,
        resolved.imported_resource_id,
        resolved.destination_imported_resource_version,
        resolved.trust_contract_id,
        resolved.destination_trust_contract_version,
        resolved.resource_export_id,
        resolved.destination_resource_export_version,
        resolved.provider_workspace_id,
        resolved.provider_network_id,
        resolved.destination_resource_id,
        resolved.destination_provider_resource_version,
        resolved.destination_provider_target_generation,
        pg_catalog.decode(resolved.destination_provider_resource_semantic_hash, 'hex'),
        resolved.destination_provider_inventory_revision,
        resolved.destination_provider_sharing_revision,
        resolved.destination_consumer_sharing_revision,
        resolved.destination_provider_authority_generation,
        resolved.destination_consumer_authority_generation,
        resolved.destination_recovery_epoch,
        resolved.destination_contract_expires_at,
        pg_catalog.decode(resolved.destination_constraint_hash, 'hex'),
        resolved.protocol,
        resolved.destination_ports,
        p_created_at
    FROM resolved
    ORDER BY resolved.access_rule_public_id, resolved.projection_public_id;

    GET DIAGNOSTICS inserted_count = ROW_COUNT;
    IF inserted_count <> expected_count THEN
        -- A rule left out from a source Device that is gone is new or
        -- changed.
        IF EXISTS (
            SELECT 1
            FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
                projection_public_id UUID,
                access_rule_public_id UUID,
                source_node_public_id UUID,
                destination_imported_resource_public_id UUID
            )
            WHERE rule.destination_imported_resource_public_id IS NOT NULL
              AND NOT EXISTS (
                    SELECT 1
                    FROM mesh.compiled_policy_imported_resource_destination AS attached
                    WHERE attached.public_id = rule.projection_public_id
                  )
              AND NOT EXISTS (
                    SELECT 1
                    FROM mesh.device AS device
                    WHERE device.workspace_id = scoped_workspace_id
                      AND device.network_id = scoped_network_id
                      AND device.public_id = rule.source_node_public_id
                      AND device.state IN ('active', 'expired', 'suspended')
                  )
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MTP05',
                MESSAGE = 'a new policy rule names a Device that is not in this Network or was removed';
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = 'MT001',
            MESSAGE = 'Imported Resource authority changed during publication';
    END IF;
    RETURN inserted_count;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.publish_compiled_policy_local_v1(
    UUID, BIGINT, BYTEA, INTEGER, TIMESTAMPTZ, JSONB
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.attach_policy_group_rules_v2(UUID, TIMESTAMPTZ, JSONB)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_group_rules_v2(UUID, TIMESTAMPTZ, JSONB) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.attach_policy_resource_destinations(UUID, TIMESTAMPTZ, JSONB)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_resource_destinations(UUID, TIMESTAMPTZ, JSONB) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.attach_policy_resource_group_destinations(UUID, TIMESTAMPTZ, JSONB)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_resource_group_destinations(UUID, TIMESTAMPTZ, JSONB)
    TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.attach_policy_imported_resource_destinations_internal_v1(
    UUID, TIMESTAMPTZ, JSONB, JSONB
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.attach_policy_imported_resource_destinations_internal_v2(
    UUID, TIMESTAMPTZ, JSONB, JSONB
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
