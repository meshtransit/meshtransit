-- Schema 318 (TD-SEC-105): Policy publication activates at the transaction's
-- own time. publish_compiled_policy_v2 (and publish_compiled_policy, still
-- granted to the api) passed the caller's p_activated_at on to the
-- Imported Resource lock and attach functions, which decide whether a
-- share's Trust Contract and export are still live at that time, and to
-- publish_compiled_policy_local_v1, which stamps the release with it: a
-- compromised api could backdate it and bind rules to an expired share. Core
-- always passes the transaction's time. As schemas 181 and 314-316 did,
-- p_activated_at stays in the signatures and is now ignored: a NULL, which
-- publish_compiled_policy_local_v1 refused before, is accepted (Core never
-- sends one). The bodies are schemas 052's and 148's otherwise.

-- From schema 000052.
CREATE OR REPLACE FUNCTION mesh_ops.publish_compiled_policy(
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
            mesh_ops.lock_and_resolve_policy_imported_resources_internal_v1(
                sharing_groups,
                pg_catalog.transaction_timestamp()
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
        pg_catalog.transaction_timestamp(),
        local_rules
    ) AS published;

    attached_imported_count :=
        mesh_ops.attach_policy_imported_resource_destinations_internal_v1(
            p_release_public_id,
            pg_catalog.transaction_timestamp(),
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

-- From schema 000148.
CREATE OR REPLACE FUNCTION mesh_ops.publish_compiled_policy_v2(
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
                pg_catalog.transaction_timestamp()
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
        pg_catalog.transaction_timestamp(),
        local_rules
    ) AS published;

    attached_imported_count :=
        mesh_ops.attach_policy_imported_resource_destinations_internal_v2(
            p_release_public_id,
            pg_catalog.transaction_timestamp(),
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
