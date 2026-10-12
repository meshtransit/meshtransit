-- Schema 148: one policy publication may name up to 10000 Imported
-- Resources (share scale plan step 3, C7). The publication chain accepted at
-- most 256 (resolve, lock-and-resolve, attach), so a Network could use at
-- most 256 of the shares it receives in rules. These are verbatim copies with
-- that bound at 10000, the most rules one policy holds:
--   * resolve_imported_policy_destinations_v2, lock_and_resolve_..._internal_v2,
--     attach_policy_imported_resource_destinations_internal_v2;
--   * publish_compiled_policy_v2, calling the v2 helpers.
-- The operator gives the two resolvers to the share writer as for v1; runtime
-- keeps v1 until it may run v2.

CREATE FUNCTION mesh_ops.attach_policy_imported_resource_destinations_internal_v2(
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
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    release_internal_id BIGINT;
    release_policy_revision BIGINT;
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
         AND source.state = 'active'
         AND p_created_at < source.expires_at
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
        RAISE EXCEPTION USING
            ERRCODE = 'MT001',
            MESSAGE = 'Imported Resource authority changed during publication';
    END IF;
    RETURN inserted_count;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.attach_policy_imported_resource_destinations_internal_v2(
    UUID, TIMESTAMPTZ, JSONB, JSONB
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.publish_compiled_policy_v2(
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
    local_rules JSONB;
    expected_imported_count INTEGER;
    matched_imported_count INTEGER;
    attached_imported_count INTEGER;
    duplicate_projection_count INTEGER;
    imported_rule_conflict_count INTEGER;
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    sharing_groups JSONB;
    imported_authority JSONB;
BEGIN
    IF p_rules IS NULL OR pg_catalog.jsonb_typeof(p_rules) <> 'array'
        OR pg_catalog.jsonb_array_length(p_rules) > 10000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'compiled policy rules are invalid';
    END IF;
    SELECT
        COALESCE(
            pg_catalog.jsonb_agg(rule.value ORDER BY rule.ordinal) FILTER (
                WHERE rule.value->>'destination_imported_resource_public_id' IS NULL
            ),
            '[]'::JSONB
        ),
        pg_catalog.count(*) FILTER (
            WHERE rule.value->>'destination_imported_resource_public_id' IS NOT NULL
        )::INTEGER
    INTO local_rules, expected_imported_count
    FROM pg_catalog.jsonb_array_elements(p_rules) WITH ORDINALITY AS rule(value, ordinal);

    SELECT pg_catalog.count(*)::INTEGER
    INTO duplicate_projection_count
    FROM (
        SELECT rule.value->>'projection_public_id'
        FROM pg_catalog.jsonb_array_elements(p_rules) AS rule(value)
        GROUP BY rule.value->>'projection_public_id'
        HAVING rule.value->>'projection_public_id' IS NULL
            OR pg_catalog.count(*) > 1
    ) AS invalid_projection;

    WITH parsed_rule AS (
        SELECT
            rule.value->>'access_rule_public_id' AS access_rule_public_id,
            rule.value->>'destination_imported_resource_public_id' IS NOT NULL
                AS is_imported
        FROM pg_catalog.jsonb_array_elements(p_rules) AS rule(value)
    )
    SELECT pg_catalog.count(*)::INTEGER
    INTO imported_rule_conflict_count
    FROM (
        SELECT imported.access_rule_public_id
        FROM parsed_rule AS imported
        WHERE imported.is_imported
        GROUP BY imported.access_rule_public_id
        HAVING imported.access_rule_public_id IS NULL
            OR pg_catalog.count(*) > 1
            OR EXISTS (
                SELECT 1
                FROM parsed_rule AS local_rule
                WHERE NOT local_rule.is_imported
                  AND local_rule.access_rule_public_id = imported.access_rule_public_id
            )
    ) AS invalid_imported_rule;

    IF (expected_imported_count > 0 AND p_compiler_format_version <> 4)
        OR (expected_imported_count = 0 AND p_compiler_format_version = 4)
        OR duplicate_projection_count <> 0
        OR imported_rule_conflict_count <> 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'compiled policy format is inconsistent';
    END IF;

    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'transaction Network scope is unavailable';
    END IF;

    IF expected_imported_count > 0 THEN
        WITH requested_rule AS (
            SELECT rule.destination_imported_resource_public_id
            FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
                destination_imported_resource_public_id UUID
            )
            WHERE rule.destination_imported_resource_public_id IS NOT NULL
        ),
        authority_group AS (
            SELECT
                contract.provider_workspace_id,
                contract.provider_network_id,
                contract.consumer_workspace_id,
                contract.consumer_network_id,
                locator.provider_workspace_public_id,
                locator.provider_network_public_id,
                locator.consumer_workspace_public_id,
                locator.consumer_network_public_id,
                pg_catalog.array_agg(
                    DISTINCT imported.public_id ORDER BY imported.public_id
                ) AS imported_resource_public_ids,
                pg_catalog.count(*)::INTEGER AS matched_rule_count
            FROM requested_rule AS rule
            JOIN mesh.imported_resource AS imported
              ON imported.workspace_id = scoped_workspace_id
             AND imported.network_id = scoped_network_id
             AND imported.public_id = rule.destination_imported_resource_public_id
            JOIN mesh.trust_contract AS contract
              ON contract.id = imported.trust_contract_id
             AND contract.consumer_workspace_id = scoped_workspace_id
             AND contract.consumer_network_id = scoped_network_id
            JOIN mesh.share_offer_locator AS locator
              ON locator.local_workspace_id = scoped_workspace_id
             AND locator.local_network_id = scoped_network_id
             AND locator.offer_id = contract.share_offer_id
             AND locator.provider_workspace_id = contract.provider_workspace_id
             AND locator.provider_network_id = contract.provider_network_id
             AND locator.consumer_workspace_id = contract.consumer_workspace_id
             AND locator.consumer_network_id = contract.consumer_network_id
             AND locator.direction = 'incoming'
             AND locator.state = 'accepted'
            GROUP BY
                contract.provider_workspace_id,
                contract.provider_network_id,
                contract.consumer_workspace_id,
                contract.consumer_network_id,
                locator.provider_workspace_public_id,
                locator.provider_network_public_id,
                locator.consumer_workspace_public_id,
                locator.consumer_network_public_id
        )
        SELECT
            COALESCE(
                pg_catalog.jsonb_agg(
                    pg_catalog.to_jsonb(authority_group)
                        - 'matched_rule_count'
                    ORDER BY
                        authority_group.provider_workspace_id,
                        authority_group.provider_network_id
                ),
                '[]'::JSONB
            ),
            COALESCE(pg_catalog.sum(authority_group.matched_rule_count), 0)::INTEGER
        INTO sharing_groups, matched_imported_count
        FROM authority_group;

        IF matched_imported_count <> expected_imported_count THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT001',
                MESSAGE = 'Imported Resource authority changed during publication';
        END IF;

        imported_authority :=
            mesh_ops.lock_and_resolve_policy_imported_resources_internal_v2(
                sharing_groups,
                p_activated_at
            );
    ELSE
        imported_authority := '[]'::JSONB;
    END IF;

    SELECT published.network_revision, published.policy_revision, published.release_version
    INTO network_revision, policy_revision, release_version
    FROM mesh_ops.publish_compiled_policy_local_v1(
        p_release_public_id,
        p_expected_policy_revision,
        p_semantic_hash,
        p_compiler_format_version,
        p_activated_at,
        local_rules
    ) AS published;

    attached_imported_count :=
        mesh_ops.attach_policy_imported_resource_destinations_internal_v2(
            p_release_public_id,
            p_activated_at,
            p_rules,
            imported_authority
        );
    IF attached_imported_count <> expected_imported_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'compiled Imported Resource destination count mismatch';
    END IF;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.publish_compiled_policy_v2(
    UUID, BIGINT, BYTEA, INTEGER, TIMESTAMPTZ, JSONB
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.publish_compiled_policy_v2(
    UUID, BIGINT, BYTEA, INTEGER, TIMESTAMPTZ, JSONB
) TO mesh_runtime;

CREATE FUNCTION mesh_ops.resolve_imported_policy_destinations_v2(
    p_provider_workspace_id BIGINT,
    p_provider_network_id BIGINT,
    p_consumer_workspace_id BIGINT,
    p_consumer_network_id BIGINT,
    p_provider_workspace_public_id UUID,
    p_provider_network_public_id UUID,
    p_consumer_workspace_public_id UUID,
    p_consumer_network_public_id UUID,
    p_imported_resource_public_ids UUID[],
    p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    resolved JSONB;
    requested_count INTEGER;
BEGIN
    requested_count := pg_catalog.cardinality(p_imported_resource_public_ids);
    IF p_provider_workspace_id <= 0 OR p_provider_network_id <= 0
        OR p_consumer_workspace_id <= 0 OR p_consumer_network_id <= 0
        OR p_consumer_workspace_id <> mesh_ops.current_workspace_id()
        OR p_consumer_network_id <> mesh_ops.current_network_id()
        OR p_provider_workspace_public_id IS NULL
        OR p_provider_network_public_id IS NULL
        OR p_consumer_workspace_public_id IS NULL
        OR p_consumer_network_public_id IS NULL
        OR p_evaluated_at IS NULL
        OR requested_count NOT BETWEEN 1 AND 10000
        OR EXISTS (
            SELECT 1
            FROM pg_catalog.unnest(p_imported_resource_public_ids) AS requested(public_id)
            WHERE requested.public_id IS NULL
               OR pg_catalog.get_byte(pg_catalog.uuid_send(requested.public_id), 6) >> 4 <> 7
        )
        OR (
            SELECT pg_catalog.count(DISTINCT requested.public_id)
            FROM pg_catalog.unnest(p_imported_resource_public_ids) AS requested(public_id)
        ) <> requested_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Imported Resource policy resolution input is invalid';
    END IF;

    PERFORM mesh_ops.set_share_scope_v1(
        p_provider_workspace_id,
        p_provider_network_id,
        p_consumer_workspace_id,
        p_consumer_network_id
    );

    WITH requested AS (
        SELECT requested.public_id
        FROM pg_catalog.unnest(p_imported_resource_public_ids) AS requested(public_id)
    ),
    current_authority AS (
        SELECT
            imported.public_id AS imported_resource_public_id,
            imported.version AS imported_resource_version,
            contract.public_id AS trust_contract_public_id,
            contract.version AS trust_contract_version,
            offer.public_id AS share_offer_public_id,
            export.public_id AS resource_export_public_id,
            export.version AS resource_export_version,
            provider_workspace.public_id AS provider_workspace_public_id,
            provider_network.public_id AS provider_network_public_id,
            consumer_workspace.public_id AS consumer_workspace_public_id,
            consumer_network.public_id AS consumer_network_public_id,
            resource.public_id AS provider_resource_public_id,
            resource.version AS provider_resource_version,
            resource.target_generation AS provider_target_generation,
            resource.semantic_hash AS provider_resource_semantic_hash,
            provider_revision.inventory_revision AS provider_inventory_revision,
            provider_revision.sharing_revision AS provider_sharing_revision,
            consumer_revision.sharing_revision AS consumer_sharing_revision,
            contract.provider_authority_generation,
            contract.consumer_authority_generation,
            contract.recovery_epoch,
            contract.expires_at AS contract_expires_at,
            contract.constraint_hash,
            COALESCE((
                SELECT pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_object(
                        'protocol', constraint_row.protocol,
                        'ranges', COALESCE((
                            SELECT pg_catalog.jsonb_agg(
                                pg_catalog.jsonb_build_array(
                                    pg_catalog.lower(port_range),
                                    pg_catalog.upper(port_range) - 1
                                )
                                ORDER BY pg_catalog.lower(port_range), pg_catalog.upper(port_range)
                            )
                            FROM pg_catalog.unnest(
                                constraint_row.destination_ports
                            ) AS port_range
                        ), '[]'::JSONB)
                    )
                    ORDER BY constraint_row.protocol
                )
                FROM mesh.resource_export_constraint AS constraint_row
                WHERE constraint_row.resource_export_id = export.id
            ), '[]'::JSONB) AS constraints
        FROM requested
        JOIN mesh.imported_resource AS imported
          ON imported.workspace_id = p_consumer_workspace_id
         AND imported.network_id = p_consumer_network_id
         AND imported.public_id = requested.public_id
         AND imported.state = 'active'
        JOIN mesh.trust_contract AS contract
          ON contract.id = imported.trust_contract_id
         AND contract.consumer_workspace_id = p_consumer_workspace_id
         AND contract.consumer_network_id = p_consumer_network_id
         AND contract.provider_workspace_id = p_provider_workspace_id
         AND contract.provider_network_id = p_provider_network_id
         AND contract.imported_resource_public_id = imported.public_id
         AND contract.state = 'active'
         AND p_evaluated_at < contract.expires_at
        JOIN mesh.share_offer AS offer
          ON offer.id = contract.share_offer_id
         AND offer.state = 'accepted'
         AND offer.accepted_contract_public_id = contract.public_id
        JOIN mesh.resource_export AS export
          ON export.id = contract.resource_export_id
         AND export.provider_workspace_id = p_provider_workspace_id
         AND export.provider_network_id = p_provider_network_id
         AND export.consumer_workspace_id = p_consumer_workspace_id
         AND export.consumer_network_id = p_consumer_network_id
         AND export.resource_id = contract.resource_id
         AND export.resource_version = contract.resource_version
         AND export.target_generation = contract.target_generation
         AND export.resource_semantic_hash = contract.resource_semantic_hash
         AND export.constraint_hash = contract.constraint_hash
         AND export.provider_authority_generation = contract.provider_authority_generation
         AND export.state = 'active'
         AND p_evaluated_at < export.expires_at
        JOIN mesh.resource AS resource
          ON resource.workspace_id = p_provider_workspace_id
         AND resource.network_id = p_provider_network_id
         AND resource.id = contract.resource_id
         AND resource.version = contract.resource_version
         AND resource.target_generation = contract.target_generation
         AND resource.semantic_hash = contract.resource_semantic_hash
         AND resource.state = 'active'
         AND resource.deleted_at IS NULL
        JOIN mesh.resource_device_target AS target
          ON target.workspace_id = resource.workspace_id
         AND target.network_id = resource.network_id
         AND target.resource_id = resource.id
         AND target.target_generation = resource.target_generation
         AND target.state = 'active'
        JOIN mesh.workspace AS provider_workspace
          ON provider_workspace.id = p_provider_workspace_id
         AND provider_workspace.public_id = p_provider_workspace_public_id
         AND provider_workspace.state = 'active'
        JOIN mesh.network AS provider_network
          ON provider_network.workspace_id = provider_workspace.id
         AND provider_network.id = p_provider_network_id
         AND provider_network.public_id = p_provider_network_public_id
         AND provider_network.state = 'active'
         AND provider_network.authority_generation = contract.provider_authority_generation
        JOIN mesh.workspace AS consumer_workspace
          ON consumer_workspace.id = p_consumer_workspace_id
         AND consumer_workspace.public_id = p_consumer_workspace_public_id
         AND consumer_workspace.deployment_id = provider_workspace.deployment_id
         AND consumer_workspace.state = 'active'
        JOIN mesh.network AS consumer_network
          ON consumer_network.workspace_id = consumer_workspace.id
         AND consumer_network.id = p_consumer_network_id
         AND consumer_network.public_id = p_consumer_network_public_id
         AND consumer_network.state = 'active'
         AND consumer_network.authority_generation = contract.consumer_authority_generation
        JOIN mesh.deployment AS deployment
          ON deployment.id = contract.deployment_id
         AND deployment.id = provider_workspace.deployment_id
         AND deployment.state = 'active'
         AND deployment.recovery_state = 'verified'
         AND deployment.recovery_epoch = contract.recovery_epoch
         AND deployment.deleted_at IS NULL
        JOIN mesh_ops.network_revision AS provider_revision
          ON provider_revision.workspace_id = p_provider_workspace_id
         AND provider_revision.network_id = p_provider_network_id
        JOIN mesh_ops.network_revision AS consumer_revision
          ON consumer_revision.workspace_id = p_consumer_workspace_id
         AND consumer_revision.network_id = p_consumer_network_id
    )
    SELECT COALESCE(
        pg_catalog.jsonb_agg(
            pg_catalog.jsonb_build_object(
                'imported_resource_id', authority.imported_resource_public_id,
                'imported_resource_version', authority.imported_resource_version,
                'contract_id', authority.trust_contract_public_id,
                'contract_version', authority.trust_contract_version,
                'offer_id', authority.share_offer_public_id,
                'export_id', authority.resource_export_public_id,
                'export_version', authority.resource_export_version,
                'provider_workspace_id', authority.provider_workspace_public_id,
                'provider_network_id', authority.provider_network_public_id,
                'consumer_workspace_id', authority.consumer_workspace_public_id,
                'consumer_network_id', authority.consumer_network_public_id,
                'resource_id', authority.provider_resource_public_id,
                'resource_version', authority.provider_resource_version,
                'target_generation', authority.provider_target_generation,
                'resource_semantic_hash',
                    pg_catalog.encode(authority.provider_resource_semantic_hash, 'hex'),
                'provider_inventory_revision', authority.provider_inventory_revision,
                'provider_sharing_revision', authority.provider_sharing_revision,
                'consumer_sharing_revision', authority.consumer_sharing_revision,
                'provider_authority_generation', authority.provider_authority_generation,
                'consumer_authority_generation', authority.consumer_authority_generation,
                'recovery_epoch', authority.recovery_epoch,
                'expires_at', authority.contract_expires_at,
                'constraint_hash', pg_catalog.encode(authority.constraint_hash, 'hex'),
                'constraints', authority.constraints
            )
            ORDER BY authority.imported_resource_public_id
        ),
        '[]'::JSONB
    )
    INTO resolved
    FROM current_authority AS authority;

    IF pg_catalog.jsonb_array_length(resolved) <> requested_count THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT001',
            MESSAGE = 'Imported Resource authority changed or is unavailable';
    END IF;
    RETURN resolved;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.resolve_imported_policy_destinations_v2(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID[], TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;

CREATE FUNCTION mesh_ops.lock_and_resolve_policy_imported_resources_internal_v2(
    p_groups JSONB,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    authority_group RECORD;
    authority_scope RECORD;
    group_count INTEGER;
    invalid_group_count INTEGER;
    provider_scope_count INTEGER;
    consumer_scope_count INTEGER;
    requested_count INTEGER;
    distinct_requested_count INTEGER;
    locked_network_id BIGINT;
    group_authority JSONB;
    resolved_authority JSONB := '[]'::JSONB;
BEGIN
    IF p_groups IS NULL
        OR pg_catalog.jsonb_typeof(p_groups) <> 'array'
        OR pg_catalog.jsonb_array_length(p_groups) NOT BETWEEN 1 AND 10000
        OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Imported Resource authority group input is invalid';
    END IF;

    WITH group_input AS (
        SELECT group_row.*
        FROM pg_catalog.jsonb_to_recordset(p_groups) AS group_row(
            provider_workspace_id BIGINT,
            provider_network_id BIGINT,
            consumer_workspace_id BIGINT,
            consumer_network_id BIGINT,
            provider_workspace_public_id UUID,
            provider_network_public_id UUID,
            consumer_workspace_public_id UUID,
            consumer_network_public_id UUID,
            imported_resource_public_ids UUID[]
        )
    )
    SELECT
        pg_catalog.count(*)::INTEGER,
        pg_catalog.count(*) FILTER (
            WHERE group_row.provider_workspace_id IS NULL
               OR group_row.provider_workspace_id <= 0
               OR group_row.provider_network_id IS NULL
               OR group_row.provider_network_id <= 0
               OR group_row.consumer_workspace_id IS NULL
               OR group_row.consumer_workspace_id <= 0
               OR group_row.consumer_network_id IS NULL
               OR group_row.consumer_network_id <= 0
               OR (
                    group_row.provider_workspace_id = group_row.consumer_workspace_id
                    AND group_row.provider_network_id = group_row.consumer_network_id
               )
               OR group_row.provider_workspace_public_id IS NULL
               OR pg_catalog.get_byte(
                    pg_catalog.uuid_send(group_row.provider_workspace_public_id), 6
                  ) >> 4 <> 7
               OR group_row.provider_network_public_id IS NULL
               OR pg_catalog.get_byte(
                    pg_catalog.uuid_send(group_row.provider_network_public_id), 6
                  ) >> 4 <> 7
               OR group_row.consumer_workspace_public_id IS NULL
               OR pg_catalog.get_byte(
                    pg_catalog.uuid_send(group_row.consumer_workspace_public_id), 6
                  ) >> 4 <> 7
               OR group_row.consumer_network_public_id IS NULL
               OR pg_catalog.get_byte(
                    pg_catalog.uuid_send(group_row.consumer_network_public_id), 6
                  ) >> 4 <> 7
               OR group_row.imported_resource_public_ids IS NULL
               OR pg_catalog.cardinality(group_row.imported_resource_public_ids)
                    NOT BETWEEN 1 AND 10000
               OR EXISTS (
                    SELECT 1
                    FROM pg_catalog.unnest(
                        group_row.imported_resource_public_ids
                    ) AS requested(public_id)
                    WHERE requested.public_id IS NULL
                       OR pg_catalog.get_byte(
                            pg_catalog.uuid_send(requested.public_id), 6
                          ) >> 4 <> 7
               )
        )::INTEGER,
        pg_catalog.count(DISTINCT (
            group_row.provider_workspace_id,
            group_row.provider_network_id
        ))::INTEGER,
        pg_catalog.count(DISTINCT (
            group_row.consumer_workspace_id,
            group_row.consumer_network_id,
            group_row.consumer_workspace_public_id,
            group_row.consumer_network_public_id
        ))::INTEGER,
        COALESCE(
            pg_catalog.sum(
                pg_catalog.cardinality(group_row.imported_resource_public_ids)
            ),
            0
        )::INTEGER
    INTO
        group_count,
        invalid_group_count,
        provider_scope_count,
        consumer_scope_count,
        requested_count
    FROM group_input AS group_row;

    SELECT pg_catalog.count(DISTINCT requested.public_id)::INTEGER
    INTO distinct_requested_count
    FROM pg_catalog.jsonb_to_recordset(p_groups) AS group_row(
        imported_resource_public_ids UUID[]
    )
    CROSS JOIN LATERAL pg_catalog.unnest(
        group_row.imported_resource_public_ids
    ) AS requested(public_id);

    IF invalid_group_count <> 0
        OR provider_scope_count <> group_count
        OR consumer_scope_count <> 1
        OR requested_count NOT BETWEEN 1 AND 10000
        OR distinct_requested_count <> requested_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Imported Resource authority group input is invalid';
    END IF;

    -- Resource/sharing mutations acquire the same revision rows. Every policy
    -- publication locks provider and consumer scopes in one deterministic order.
    FOR authority_scope IN
        WITH group_input AS (
            SELECT group_row.*
            FROM pg_catalog.jsonb_to_recordset(p_groups) AS group_row(
                provider_workspace_id BIGINT,
                provider_network_id BIGINT,
                consumer_workspace_id BIGINT,
                consumer_network_id BIGINT
            )
        ),
        first_group AS (
            SELECT group_row.*
            FROM group_input AS group_row
            ORDER BY group_row.provider_workspace_id, group_row.provider_network_id
            LIMIT 1
        ),
        scope_to_lock AS (
            SELECT
                group_row.provider_workspace_id AS workspace_id,
                group_row.provider_network_id AS network_id,
                group_row.provider_workspace_id AS context_provider_workspace_id,
                group_row.provider_network_id AS context_provider_network_id,
                group_row.consumer_workspace_id,
                group_row.consumer_network_id
            FROM group_input AS group_row
            UNION
            SELECT
                group_row.consumer_workspace_id,
                group_row.consumer_network_id,
                group_row.provider_workspace_id,
                group_row.provider_network_id,
                group_row.consumer_workspace_id,
                group_row.consumer_network_id
            FROM first_group AS group_row
        )
        SELECT scope_to_lock.*
        FROM scope_to_lock
        ORDER BY scope_to_lock.workspace_id, scope_to_lock.network_id
    LOOP
        PERFORM mesh_ops.set_share_scope_v1(
            authority_scope.context_provider_workspace_id,
            authority_scope.context_provider_network_id,
            authority_scope.consumer_workspace_id,
            authority_scope.consumer_network_id
        );
        SELECT revision.network_id
        INTO locked_network_id
        FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = authority_scope.workspace_id
          AND revision.network_id = authority_scope.network_id
        FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT001',
                MESSAGE = 'Imported Resource authority changed or is unavailable';
        END IF;
    END LOOP;

    FOR authority_group IN
        SELECT group_row.*
        FROM pg_catalog.jsonb_to_recordset(p_groups) AS group_row(
            provider_workspace_id BIGINT,
            provider_network_id BIGINT,
            consumer_workspace_id BIGINT,
            consumer_network_id BIGINT,
            provider_workspace_public_id UUID,
            provider_network_public_id UUID,
            consumer_workspace_public_id UUID,
            consumer_network_public_id UUID,
            imported_resource_public_ids UUID[]
        )
        ORDER BY group_row.provider_workspace_id, group_row.provider_network_id
    LOOP
        PERFORM mesh_ops.set_share_scope_v1(
            authority_group.provider_workspace_id,
            authority_group.provider_network_id,
            authority_group.consumer_workspace_id,
            authority_group.consumer_network_id
        );
        group_authority := mesh_ops.resolve_imported_policy_destinations_v2(
            authority_group.provider_workspace_id,
            authority_group.provider_network_id,
            authority_group.consumer_workspace_id,
            authority_group.consumer_network_id,
            authority_group.provider_workspace_public_id,
            authority_group.provider_network_public_id,
            authority_group.consumer_workspace_public_id,
            authority_group.consumer_network_public_id,
            authority_group.imported_resource_public_ids,
            p_evaluated_at
        );
        IF pg_catalog.jsonb_typeof(group_authority) <> 'array'
            OR pg_catalog.jsonb_array_length(group_authority)
                <> pg_catalog.cardinality(authority_group.imported_resource_public_ids) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT001',
                MESSAGE = 'Imported Resource authority changed or is unavailable';
        END IF;
        resolved_authority := resolved_authority || group_authority;
    END LOOP;

    IF pg_catalog.jsonb_array_length(resolved_authority) <> requested_count THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT001',
            MESSAGE = 'Imported Resource authority changed or is unavailable';
    END IF;
    RETURN resolved_authority;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.lock_and_resolve_policy_imported_resources_internal_v2(
    JSONB, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
