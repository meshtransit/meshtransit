-- Schema 94 lets the share creator choose the consumer DNS label. The label is
-- one canonical DNS label stored on the immutable Share Offer. Acceptance
-- derives the access name <label>.<provider Workspace code>.<provider Network
-- code>.shared.mesh, so the consumer no longer types a name. Within one
-- provider Network a live label names exactly one Resource; the same Resource
-- may reuse its label for other consumer Networks. Offers created by v2 keep a
-- NULL label and still require a consumer-typed name.

ALTER TABLE mesh.share_offer ADD COLUMN access_label TEXT;
ALTER TABLE mesh.share_offer ADD CONSTRAINT share_offer_access_label_check CHECK (
    access_label IS NULL OR (
        pg_catalog.char_length(access_label) BETWEEN 1 AND 63
        AND pg_catalog.octet_length(access_label) = pg_catalog.char_length(access_label)
        AND access_label ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
        AND access_label !~ '^[0-9]+$'
    )
);
CREATE INDEX share_offer_provider_access_label_idx
    ON mesh.share_offer (provider_workspace_id, provider_network_id, access_label)
    WHERE access_label IS NOT NULL;

CREATE FUNCTION mesh_ops.enforce_share_offer_access_label_frozen_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF OLD.access_label IS DISTINCT FROM NEW.access_label THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Share Offer access label is frozen';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enforce_share_offer_access_label_frozen_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER share_offer_access_label_frozen
BEFORE UPDATE ON mesh.share_offer
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_share_offer_access_label_frozen_v1();

-- Display codes are readable only by the migration owner. This helper is the
-- single derivation of a share access name; callers pass only public IDs the
-- caller has already authorized.
CREATE FUNCTION mesh_ops.derive_share_access_name_v1(
    p_access_label TEXT,
    p_provider_workspace_public_id UUID,
    p_provider_network_public_id UUID
)
RETURNS TEXT
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
DECLARE
    workspace_code TEXT;
    network_code TEXT;
BEGIN
    IF p_access_label IS NULL
        OR pg_catalog.char_length(p_access_label) NOT BETWEEN 1 AND 63
        OR pg_catalog.octet_length(p_access_label) <> pg_catalog.char_length(p_access_label)
        OR p_access_label !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
        OR p_access_label ~ '^[0-9]+$'
        OR p_provider_workspace_public_id IS NULL
        OR p_provider_network_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid share access label';
    END IF;
    SELECT identity.display_code INTO workspace_code
    FROM mesh_ops.tenant_display_identity AS identity
    WHERE identity.workspace_public_id = p_provider_workspace_public_id;
    SELECT identity.display_code INTO network_code
    FROM mesh_ops.tenant_display_identity AS identity
    WHERE identity.network_public_id = p_provider_network_public_id;
    IF workspace_code IS NULL OR network_code IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'provider display identity is unavailable';
    END IF;
    RETURN p_access_label || '.' || workspace_code || '.' || network_code || '.shared.mesh';
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.derive_share_access_name_v1(TEXT, UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.derive_share_access_name_v1(TEXT, UUID, UUID)
    TO mesh_share_writer;

-- The share writer sees only the exact provider/consumer pair, so the
-- provider-Network label binding is checked across every consumer here. The
-- caller holds the provider Network revision lock, which serializes creators.
CREATE FUNCTION mesh_ops.share_access_label_conflicts_v1(
    p_provider_workspace_id BIGINT,
    p_provider_network_id BIGINT,
    p_access_label TEXT,
    p_resource_id BIGINT,
    p_at TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
    SELECT EXISTS (
        SELECT 1
        FROM mesh.share_offer AS offer
        JOIN mesh.resource_export AS export ON export.id = offer.resource_export_id
        LEFT JOIN mesh.trust_contract AS contract
          ON contract.share_offer_id = offer.id
        WHERE offer.provider_workspace_id = p_provider_workspace_id
          AND offer.provider_network_id = p_provider_network_id
          AND offer.access_label = p_access_label
          AND export.resource_id <> p_resource_id
          AND (
              (offer.state = 'offered' AND p_at < offer.expires_at)
              OR (
                  offer.state = 'accepted'
                  AND contract.state IN ('activating', 'active')
                  AND p_at < contract.expires_at
              )
          )
    );
$function$;
REVOKE ALL ON FUNCTION mesh_ops.share_access_label_conflicts_v1(BIGINT, BIGINT, TEXT, BIGINT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.share_access_label_conflicts_v1(BIGINT, BIGINT, TEXT, BIGINT, TIMESTAMPTZ)
    TO mesh_share_writer;

-- Runtime reads the derived name only for an offer located in its exact
-- current Network scope; any other offer yields NULL.
CREATE FUNCTION mesh_ops.read_share_offer_access_name_v1(p_offer_public_id UUID)
RETURNS TEXT
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    selected RECORD;
BEGIN
    SELECT offer.access_label, locator.provider_workspace_public_id, locator.provider_network_public_id
    INTO selected
    FROM mesh.share_offer AS offer
    JOIN mesh.share_offer_locator AS locator
      ON locator.offer_id = offer.id
     AND locator.local_workspace_id = mesh_ops.current_workspace_id()
     AND locator.local_network_id = mesh_ops.current_network_id()
    WHERE offer.public_id = p_offer_public_id;
    IF selected.access_label IS NULL THEN
        RETURN NULL;
    END IF;
    RETURN mesh_ops.derive_share_access_name_v1(
        selected.access_label,
        selected.provider_workspace_public_id,
        selected.provider_network_public_id
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_share_offer_access_name_v1(UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_share_offer_access_name_v1(UUID) TO mesh_runtime;

-- v3 is v2 plus the frozen provider label and its provider-Network binding.
CREATE FUNCTION mesh_ops.create_resource_share_offer_v3(
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
            AND NOT (
                p_provider_workspace_id = p_consumer_workspace_id
                AND p_expires_at = TIMESTAMPTZ '2200-01-01 00:00:00+00'
            )
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

-- v4 derives the access name from a labeled offer. A consumer-supplied name
-- must be absent or equal to the derived one; unlabeled v2 offers keep the
-- consumer-typed name. v3 then performs the complete locked decision.
CREATE FUNCTION mesh_ops.decide_resource_share_offer_v4(
    p_provider_workspace_id BIGINT,
    p_provider_network_id BIGINT,
    p_consumer_workspace_id BIGINT,
    p_consumer_network_id BIGINT,
    p_provider_workspace_public_id UUID,
    p_provider_network_public_id UUID,
    p_consumer_workspace_public_id UUID,
    p_consumer_network_public_id UUID,
    p_offer_public_id UUID,
    p_expected_offer_version BIGINT,
    p_nonce_digest BYTEA,
    p_action TEXT,
    p_contract_public_id UUID,
    p_imported_resource_public_id UUID,
    p_imported_display_name TEXT,
    p_access_name_public_id UUID,
    p_access_name TEXT,
    p_provider_authority_generation BIGINT,
    p_consumer_authority_generation BIGINT,
    p_recovery_epoch BIGINT,
    p_expected_provider_sharing_revision BIGINT,
    p_expected_consumer_sharing_revision BIGINT,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    provider_network_revision BIGINT,
    provider_sharing_revision BIGINT,
    consumer_network_revision BIGINT,
    consumer_sharing_revision BIGINT,
    offer_version BIGINT,
    contract_version BIGINT,
    imported_resource_version BIGINT,
    contract_state TEXT,
    access_name_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    offer_found BOOLEAN;
    offer_label TEXT;
    effective_access_name TEXT := p_access_name;
BEGIN
    IF p_action = 'accept' THEN
        PERFORM mesh_ops.set_share_scope_v1(
            p_provider_workspace_id, p_provider_network_id,
            p_consumer_workspace_id, p_consumer_network_id
        );
        -- The label is frozen, so reading it before v3 takes its locks cannot
        -- race with a label change; v3 rechecks the offer state and version.
        SELECT TRUE, offer.access_label INTO offer_found, offer_label
        FROM mesh.share_offer AS offer
        WHERE offer.provider_workspace_id = p_provider_workspace_id
          AND offer.provider_network_id = p_provider_network_id
          AND offer.consumer_workspace_id = p_consumer_workspace_id
          AND offer.consumer_network_id = p_consumer_network_id
          AND offer.public_id = p_offer_public_id;
        IF offer_found IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Share Offer changed or is unavailable';
        END IF;
        IF offer_label IS NOT NULL THEN
            effective_access_name := mesh_ops.derive_share_access_name_v1(
                offer_label, p_provider_workspace_public_id, p_provider_network_public_id
            );
            IF p_access_name IS NOT NULL AND p_access_name <> effective_access_name THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'consumer access name differs from the provider label';
            END IF;
        END IF;
    END IF;

    RETURN QUERY
    SELECT
        decision.provider_network_revision,
        decision.provider_sharing_revision,
        decision.consumer_network_revision,
        decision.consumer_sharing_revision,
        decision.offer_version,
        decision.contract_version,
        decision.imported_resource_version,
        decision.contract_state,
        decision.access_name_version
    FROM mesh_ops.decide_resource_share_offer_v3(
        p_provider_workspace_id,
        p_provider_network_id,
        p_consumer_workspace_id,
        p_consumer_network_id,
        p_provider_workspace_public_id,
        p_provider_network_public_id,
        p_consumer_workspace_public_id,
        p_consumer_network_public_id,
        p_offer_public_id,
        p_expected_offer_version,
        p_nonce_digest,
        p_action,
        p_contract_public_id,
        p_imported_resource_public_id,
        p_imported_display_name,
        p_access_name_public_id,
        effective_access_name,
        p_provider_authority_generation,
        p_consumer_authority_generation,
        p_recovery_epoch,
        p_expected_provider_sharing_revision,
        p_expected_consumer_sharing_revision,
        p_occurred_at
    ) AS decision;
END;
$function$;

-- Only the application entry points are exposed to mesh_runtime by the
-- operator ownership step.
REVOKE ALL ON FUNCTION mesh_ops.create_resource_share_offer_v3(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID,
    BIGINT, BIGINT, BYTEA, UUID, UUID, JSONB, JSONB,
    BYTEA, BYTEA, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.decide_resource_share_offer_v4(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, BIGINT, BYTEA, TEXT,
    UUID, UUID, TEXT, UUID, TEXT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
