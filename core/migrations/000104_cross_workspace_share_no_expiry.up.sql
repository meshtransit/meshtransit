-- Owner decision (2026-10-06): a cross-Workspace share may also have no
-- scheduled expiry, like a same-Workspace share. Any other deadline stays
-- within 30 days. Only the deadline check of create_resource_share_offer_v3
-- changes; the pending offer itself still expires within 168 hours.

CREATE OR REPLACE FUNCTION mesh_ops.create_resource_share_offer_v3(
    p_provider_workspace_id BIGINT,
    p_provider_network_id BIGINT,
    p_consumer_workspace_id BIGINT,
    p_consumer_network_id BIGINT,
    p_provider_workspace_public_id UUID,
    p_provider_network_public_id UUID,
    p_consumer_workspace_public_id UUID,
    p_consumer_network_public_id UUID,
    p_resource_public_id UUID,
    p_resource_version BIGINT,
    p_target_generation BIGINT,
    p_resource_semantic_hash BYTEA,
    p_export_public_id UUID,
    p_offer_public_id UUID,
    p_constraint_public_ids JSONB,
    p_constraints JSONB,
    p_constraint_hash BYTEA,
    p_nonce_digest BYTEA,
    p_provider_authority_generation BIGINT,
    p_consumer_authority_generation BIGINT,
    p_expected_provider_sharing_revision BIGINT,
    p_expected_consumer_sharing_revision BIGINT,
    p_expires_at TIMESTAMPTZ,
    p_occurred_at TIMESTAMPTZ,
    p_access_label TEXT
)
RETURNS TABLE (
    provider_network_revision BIGINT,
    provider_sharing_revision BIGINT,
    consumer_network_revision BIGINT,
    consumer_sharing_revision BIGINT,
    export_version BIGINT,
    offer_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_deployment_id BIGINT;
    resource_internal_id BIGINT;
    export_internal_id BIGINT;
    offer_internal_id BIGINT;
    constraint_count INTEGER;
BEGIN
    PERFORM mesh_ops.set_share_scope_v1(
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id
    );
    IF p_occurred_at IS NULL OR p_expires_at IS NULL
        OR p_expires_at <= p_occurred_at
        OR NOT pg_catalog.isfinite(p_occurred_at)
        OR NOT pg_catalog.isfinite(p_expires_at)
        OR (
            p_expires_at > p_occurred_at + INTERVAL '30 days'
            AND p_expires_at <> TIMESTAMPTZ '2200-01-01 00:00:00+00'
        )
        OR p_resource_version <= 0 OR p_target_generation <= 0
        OR p_provider_authority_generation <= 0 OR p_consumer_authority_generation <= 0
        OR p_expected_provider_sharing_revision <= 0
        OR p_expected_consumer_sharing_revision <= 0
        OR pg_catalog.octet_length(p_resource_semantic_hash) <> 32
        OR pg_catalog.octet_length(p_constraint_hash) <> 32
        OR pg_catalog.octet_length(p_nonce_digest) <> 32
        OR p_constraints IS NULL OR pg_catalog.jsonb_typeof(p_constraints) <> 'array'
        OR p_constraint_public_ids IS NULL
        OR pg_catalog.jsonb_typeof(p_constraint_public_ids) <> 'array'
        OR pg_catalog.jsonb_array_length(p_constraints) NOT BETWEEN 1 AND 3
        OR pg_catalog.jsonb_array_length(p_constraint_public_ids)
            <> pg_catalog.jsonb_array_length(p_constraints) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource share offer input';
    END IF;
    IF p_access_label IS NULL
        OR pg_catalog.char_length(p_access_label) NOT BETWEEN 1 AND 63
        OR pg_catalog.octet_length(p_access_label) <> pg_catalog.char_length(p_access_label)
        OR p_access_label !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
        OR p_access_label ~ '^[0-9]+$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid share access label';
    END IF;
    constraint_count := pg_catalog.jsonb_array_length(p_constraints);
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements(p_constraints) AS item(value)
        WHERE item.value->>'protocol' NOT IN ('tcp', 'udp', 'icmp')
           OR pg_catalog.jsonb_typeof(item.value->'ranges') <> 'array'
           OR (
                item.value->>'protocol' IN ('tcp', 'udp')
                AND pg_catalog.jsonb_array_length(item.value->'ranges') NOT BETWEEN 1 AND 64
           )
           OR (
                item.value->>'protocol' = 'icmp'
                AND pg_catalog.jsonb_array_length(item.value->'ranges') <> 0
           )
    ) OR (
        SELECT pg_catalog.count(DISTINCT item.value->>'protocol') <> constraint_count
        FROM pg_catalog.jsonb_array_elements(p_constraints) AS item(value)
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements(p_constraints) AS item(value)
        CROSS JOIN LATERAL pg_catalog.jsonb_array_elements(item.value->'ranges') AS range_row(value)
        WHERE pg_catalog.jsonb_typeof(range_row.value) <> 'object'
           OR (range_row.value->>'first') !~ '^[0-9]{1,5}$'
           OR (range_row.value->>'last') !~ '^[0-9]{1,5}$'
           OR (range_row.value->>'first')::BIGINT NOT BETWEEN 1 AND 65535
           OR (range_row.value->>'last')::BIGINT NOT BETWEEN 1 AND 65535
           OR (range_row.value->>'last')::BIGINT < (range_row.value->>'first')::BIGINT
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource share traffic constraints';
    END IF;

    -- This pair is the serialization lock used by every Network authority
    -- mutation. Hold it before reading Workspace, Network, or Resource
    -- authority so their snapshots cannot change before the sharing write.
    PERFORM revision.network_id
    FROM mesh_ops.network_revision AS revision
    WHERE (
        revision.workspace_id = p_provider_workspace_id
        AND revision.network_id = p_provider_network_id
    ) OR (
        revision.workspace_id = p_consumer_workspace_id
        AND revision.network_id = p_consumer_network_id
    )
    ORDER BY revision.workspace_id, revision.network_id
    FOR UPDATE;
    IF NOT EXISTS (
        SELECT 1 FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = p_provider_workspace_id
          AND revision.network_id = p_provider_network_id
          AND revision.sharing_revision = p_expected_provider_sharing_revision
    ) OR NOT EXISTS (
        SELECT 1 FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = p_consumer_workspace_id
          AND revision.network_id = p_consumer_network_id
          AND revision.sharing_revision = p_expected_consumer_sharing_revision
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'sharing revision changed';
    END IF;

    PERFORM workspace.id
    FROM mesh.workspace AS workspace
    WHERE workspace.id IN (p_provider_workspace_id, p_consumer_workspace_id)
      AND workspace.public_id IN (p_provider_workspace_public_id, p_consumer_workspace_public_id)
      AND workspace.state = 'active';
    SELECT provider_workspace.deployment_id
    INTO scoped_deployment_id
    FROM mesh.workspace AS provider_workspace
    JOIN mesh.workspace AS consumer_workspace
      ON consumer_workspace.id = p_consumer_workspace_id
     AND consumer_workspace.public_id = p_consumer_workspace_public_id
     AND consumer_workspace.deployment_id = provider_workspace.deployment_id
     AND consumer_workspace.state = 'active'
    WHERE provider_workspace.id = p_provider_workspace_id
      AND provider_workspace.public_id = p_provider_workspace_public_id
      AND provider_workspace.state = 'active';
    IF scoped_deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'sharing scope is unavailable';
    END IF;
    PERFORM network.id
    FROM mesh.network AS network
    WHERE (
        network.workspace_id = p_provider_workspace_id
        AND network.id = p_provider_network_id
        AND network.public_id = p_provider_network_public_id
    ) OR (
        network.workspace_id = p_consumer_workspace_id
        AND network.id = p_consumer_network_id
        AND network.public_id = p_consumer_network_public_id
    );
    IF (
        SELECT pg_catalog.count(*) FROM mesh.network AS network
        WHERE network.state = 'active' AND (
            (
                network.workspace_id = p_provider_workspace_id
                AND network.id = p_provider_network_id
                AND network.public_id = p_provider_network_public_id
                AND network.authority_generation = p_provider_authority_generation
            ) OR (
                network.workspace_id = p_consumer_workspace_id
                AND network.id = p_consumer_network_id
                AND network.public_id = p_consumer_network_public_id
                AND network.authority_generation = p_consumer_authority_generation
            )
        )
    ) <> 2 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'sharing authority changed';
    END IF;
    SELECT resource.id INTO resource_internal_id
    FROM mesh.resource AS resource
    JOIN mesh.resource_device_target AS target
      ON target.workspace_id = resource.workspace_id
     AND target.network_id = resource.network_id
     AND target.resource_id = resource.id
     AND target.target_generation = resource.target_generation
     AND target.state = 'active'
    WHERE resource.workspace_id = p_provider_workspace_id
      AND resource.network_id = p_provider_network_id
      AND resource.public_id = p_resource_public_id
      AND resource.version = p_resource_version
      AND resource.target_generation = p_target_generation
      AND resource.semantic_hash = p_resource_semantic_hash
      AND resource.state = 'active'
      AND resource.deleted_at IS NULL;
    IF resource_internal_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource export authority changed';
    END IF;
    IF mesh_ops.share_access_label_conflicts_v1(
        p_provider_workspace_id, p_provider_network_id,
        p_access_label, resource_internal_id, p_occurred_at
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'share access label names another Resource';
    END IF;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        sharing_revision = revision.sharing_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE (
        revision.workspace_id = p_provider_workspace_id
        AND revision.network_id = p_provider_network_id
    ) OR (
        revision.workspace_id = p_consumer_workspace_id
        AND revision.network_id = p_consumer_network_id
    );

    INSERT INTO mesh.resource_export (
        public_id, deployment_id,
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id,
        resource_id, resource_public_id, resource_version, target_generation,
        resource_semantic_hash, constraint_hash,
        provider_authority_generation, expires_at, state, created_at, updated_at
    ) VALUES (
        p_export_public_id, scoped_deployment_id,
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id,
        resource_internal_id, p_resource_public_id, p_resource_version, p_target_generation,
        p_resource_semantic_hash, p_constraint_hash,
        p_provider_authority_generation, p_expires_at, 'active', p_occurred_at, p_occurred_at
    ) RETURNING id, version INTO export_internal_id, export_version;

    INSERT INTO mesh.resource_export_constraint (
        public_id,
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id,
        resource_export_id, protocol, destination_ports, created_at
    )
    SELECT
        (p_constraint_public_ids->>((item.ordinality - 1)::INTEGER))::UUID,
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id,
        export_internal_id,
        item.value->>'protocol',
        CASE
            WHEN item.value->>'protocol' = 'icmp' THEN '{}'::INT4MULTIRANGE
            ELSE (
                SELECT pg_catalog.range_agg(INT4RANGE(
                    (range_row.value->>'first')::INTEGER,
                    (range_row.value->>'last')::INTEGER + 1,
                    '[)'
                ))
                FROM pg_catalog.jsonb_array_elements(item.value->'ranges') AS range_row(value)
            )
        END,
        p_occurred_at
    FROM pg_catalog.jsonb_array_elements(p_constraints) WITH ORDINALITY AS item(value, ordinality);

    INSERT INTO mesh.share_offer (
        public_id, deployment_id,
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id,
        resource_export_id, nonce_digest, constraint_hash,
        expires_at, state, created_at, updated_at, access_label
    ) VALUES (
        p_offer_public_id, scoped_deployment_id,
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id,
        export_internal_id, p_nonce_digest, p_constraint_hash,
        CASE
            WHEN p_expires_at = TIMESTAMPTZ '2200-01-01 00:00:00+00'
                THEN LEAST(p_expires_at, p_occurred_at + INTERVAL '168 hours')
            ELSE p_expires_at
        END,
        'offered', p_occurred_at, p_occurred_at, p_access_label
    ) RETURNING id, version INTO offer_internal_id, offer_version;

    INSERT INTO mesh.share_offer_locator (
        local_workspace_id, local_network_id, offer_id, offer_public_id,
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id,
        provider_workspace_public_id, provider_network_public_id,
        consumer_workspace_public_id, consumer_network_public_id,
        direction, state, created_at
    ) VALUES
    (
        p_provider_workspace_id, p_provider_network_id, offer_internal_id, p_offer_public_id,
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id,
        p_provider_workspace_public_id, p_provider_network_public_id,
        p_consumer_workspace_public_id, p_consumer_network_public_id,
        'outgoing', 'offered', p_occurred_at
    ),
    (
        p_consumer_workspace_id, p_consumer_network_id, offer_internal_id, p_offer_public_id,
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id,
        p_provider_workspace_public_id, p_provider_network_public_id,
        p_consumer_workspace_public_id, p_consumer_network_public_id,
        'incoming', 'offered', p_occurred_at
    );

    SELECT revision.network_revision, revision.sharing_revision
    INTO provider_network_revision, provider_sharing_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = p_provider_workspace_id
      AND revision.network_id = p_provider_network_id;
    SELECT revision.network_revision, revision.sharing_revision
    INTO consumer_network_revision, consumer_sharing_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = p_consumer_workspace_id
      AND revision.network_id = p_consumer_network_id;
    RETURN NEXT;
END;
$function$;
