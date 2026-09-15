ALTER TABLE mesh.policy_release
ADD CONSTRAINT policy_release_semantic_hash_nonzero_check CHECK (
    semantic_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
);

ALTER TABLE mesh.policy_release
ADD CONSTRAINT policy_release_compiler_format_version_upper_check CHECK (
    compiler_format_version <= 65535
);

ALTER TABLE mesh.policy_release
ADD COLUMN activated_network_revision BIGINT;

ALTER TABLE mesh.policy_release
ADD CONSTRAINT policy_release_activated_network_revision_check CHECK (
    activated_network_revision IS NULL
    OR activated_network_revision >= policy_revision
);

CREATE FUNCTION mesh_ops.lock_active_policy_release()
RETURNS TABLE (
    release_public_id TEXT,
    policy_revision BIGINT,
    semantic_hash BYTEA
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

    RETURN QUERY
    SELECT
        release.public_id::TEXT,
        release.policy_revision,
        release.semantic_hash
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = scoped_workspace_id
      AND release.network_id = scoped_network_id
      AND release.state = 'active'
    FOR UPDATE;
END;
$function$;

CREATE FUNCTION mesh_ops.publish_compiled_policy(
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
             AND source.state = 'active'
            JOIN mesh.device AS destination
              ON destination.workspace_id = scoped_workspace_id
             AND destination.network_id = scoped_network_id
             AND destination.public_id = rule.destination_node_public_id
             AND destination.state = 'active'
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

REVOKE ALL ON FUNCTION mesh_ops.publish_compiled_policy(
    UUID, BIGINT, BYTEA, INTEGER, TIMESTAMPTZ, JSONB
) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.publish_compiled_policy(
    UUID, BIGINT, BYTEA, INTEGER, TIMESTAMPTZ, JSONB
) FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.lock_active_policy_release() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.lock_active_policy_release()
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_active_policy_release() TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.publish_compiled_policy(
    UUID, BIGINT, BYTEA, INTEGER, TIMESTAMPTZ, JSONB
) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
