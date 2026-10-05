-- One alias technique for every Device share (design decision 2026-10-05).
--
-- Same-Workspace Device shares now use the client alias path instead of
-- canonical addresses. Alias uniqueness moves from the Deployment to the
-- Networks a lease touches: a retained alias must be unique among retained
-- aliases whose provider or consumer Network is either Network of the new
-- lease. That is exactly the client per-map rule (a local alias cannot collide
-- with a mapped address or have incompatible owners), and it scales capacity
-- per Network.
--
-- Derived functions are verbatim copies of their previous versions except for
-- these deltas:
--   * Workspace inequality guards become Network inequality guards.
--   * The Deployment-wide address cursor is replaced by the Network-scoped
--     allocator; uniqueness is re-checked by a trigger on every lease insert.
--   * The work scan no longer requires the cloud Deployment profile.
--   * The map reader selects local/remote aliases by Network, not Workspace
--     (a Workspace comparison cannot distinguish two Networks of one Workspace).
--   * Activation always takes the alias endpoint and first requires the
--     exported Device to be active on current keys (the check the
--     same-Workspace direct branch already made).
--   * The lease transition trigger drops its Deployment-wide comparison with
--     every legacy Resource Alias ever issued; retained ownership is checked
--     per Network instead.
-- Previous versions remain for the supported rollback writer; the operator
-- script for this schema closes their runtime and worker entry points.

-- Network, not Workspace, separation is the invariant for every alias row.
DO $constraints$
DECLARE
    found_name TEXT;
BEGIN
    SELECT constraint_row.conname INTO STRICT found_name
    FROM pg_catalog.pg_constraint AS constraint_row
    WHERE constraint_row.conrelid = 'mesh.device_alias_lease'::REGCLASS
      AND constraint_row.contype = 'c'
      AND pg_catalog.pg_get_constraintdef(constraint_row.oid)
          = 'CHECK ((provider_workspace_id <> consumer_workspace_id))';
    EXECUTE pg_catalog.format('ALTER TABLE mesh.device_alias_lease DROP CONSTRAINT %I', found_name);
    SELECT constraint_row.conname INTO STRICT found_name
    FROM pg_catalog.pg_constraint AS constraint_row
    WHERE constraint_row.conrelid = 'mesh.device_alias_client_readiness'::REGCLASS
      AND constraint_row.contype = 'c'
      AND pg_catalog.pg_get_constraintdef(constraint_row.oid)
          = 'CHECK (((provider_workspace_id <> consumer_workspace_id) AND (expires_at > created_at)))';
    EXECUTE pg_catalog.format('ALTER TABLE mesh.device_alias_client_readiness DROP CONSTRAINT %I', found_name);
END;
$constraints$;
ALTER TABLE mesh.device_alias_lease
    ADD CONSTRAINT device_alias_lease_network_scope_check
    CHECK (provider_network_id <> consumer_network_id);
ALTER TABLE mesh.device_alias_client_readiness
    ADD CONSTRAINT device_alias_client_readiness_network_scope_check
    CHECK (provider_network_id <> consumer_network_id AND expires_at > created_at);

-- Deployment-wide address uniqueness is replaced by Network-scoped checks.
DROP INDEX mesh.device_alias_address_retained_uidx;
DROP INDEX mesh.federation_alias_lease_current_address_uidx;
CREATE INDEX device_alias_lease_retained_address_idx
    ON mesh.device_alias_lease (deployment_id, address)
    WHERE state IN ('reserved', 'quarantined');
CREATE INDEX federation_alias_lease_retained_address_idx
    ON mesh.federation_alias_lease (deployment_id, resource_alias)
    WHERE state IN ('reserved', 'active');
CREATE INDEX private_endpoint_alias_work_v2_idx
    ON mesh.private_endpoint (deployment_id, public_id)
    WHERE state <> 'ready';

-- True when the address is retained by another alias in either Network. The
-- legacy Resource Alias of the same endpoint carries the same address by
-- design and is excluded only for its own Resource lease. Every writer holds
-- both Network revision row locks before calling this, so concurrent writers
-- that share a Network serialize on that lock.
CREATE FUNCTION mesh_ops.device_alias_address_retained_v1(
    p_deployment_id BIGINT, p_address INET, p_provider_network_id BIGINT,
    p_consumer_network_id BIGINT, p_ignored_lease_id BIGINT, p_ignored_legacy_lease_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE sql STABLE PARALLEL UNSAFE SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (
        SELECT 1 FROM mesh.device_alias_lease AS lease
        WHERE lease.deployment_id = p_deployment_id AND lease.address = p_address
          AND lease.state IN ('reserved', 'quarantined')
          AND lease.id IS DISTINCT FROM p_ignored_lease_id
          AND (lease.provider_network_id IN (p_provider_network_id, p_consumer_network_id)
            OR lease.consumer_network_id IN (p_provider_network_id, p_consumer_network_id))
    ) OR EXISTS (
        SELECT 1 FROM mesh.federation_alias_lease AS lease
        WHERE lease.deployment_id = p_deployment_id AND lease.resource_alias = p_address
          AND lease.state IN ('reserved', 'active')
          AND lease.id IS DISTINCT FROM p_ignored_legacy_lease_id
          AND (lease.provider_network_id IN (p_provider_network_id, p_consumer_network_id)
            OR lease.consumer_network_id IN (p_provider_network_id, p_consumer_network_id))
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.device_alias_address_retained_v1(BIGINT, INET, BIGINT, BIGINT, BIGINT, BIGINT)
    FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;

-- Same lifecycle rules as v1, without its Deployment-wide comparison against
-- every legacy Resource Alias ever issued (including withdrawn ones). A
-- withdrawn legacy lease never entered a map; retained ownership is enforced
-- per Network by device_alias_network_uniqueness below.
CREATE FUNCTION mesh_ops.enforce_device_alias_transition_v2()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Device alias history is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'reserved' OR NEW.version <> 1 OR NEW.created_at <> NEW.updated_at THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Device alias reservation';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM mesh.address_pool AS pool
            JOIN mesh.address_realm AS realm ON realm.id = pool.address_realm_id
            WHERE pool.id = NEW.address_pool_id AND realm.id = NEW.address_realm_id
              AND pool.deployment_id = NEW.deployment_id AND realm.deployment_id = NEW.deployment_id
              AND realm.kind = 'federation_alias' AND realm.state = 'active'
              AND pool.state = 'active' AND pool.workspace_id IS NULL
              AND pool.family = NEW.family AND NEW.address << pool.prefix
              AND pool.purpose = CASE NEW.alias_role WHEN 'resource' THEN 'federation_resource_alias'
                  ELSE 'federation_consumer_alias' END) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Device alias pool ownership mismatch';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM mesh.private_endpoint AS endpoint
            JOIN mesh.trust_contract AS contract ON contract.id = endpoint.trust_contract_id
            JOIN mesh.device AS device ON device.id = NEW.owner_device_id
                AND device.workspace_id = NEW.owner_workspace_id AND device.network_id = NEW.owner_network_id
            JOIN mesh.device_node_key_epoch AS node_key ON node_key.device_id = device.id
                AND node_key.epoch = NEW.node_key_epoch AND node_key.public_key = NEW.node_public_key
                AND node_key.state = 'active'
            JOIN mesh.device_machine_key_epoch AS machine ON machine.device_id = device.id
                AND machine.epoch = NEW.machine_key_epoch AND machine.state = 'active'
            WHERE endpoint.id = NEW.private_endpoint_id AND endpoint.deployment_id = NEW.deployment_id
              AND endpoint.generation = NEW.endpoint_generation AND endpoint.recovery_epoch = NEW.recovery_epoch
              AND endpoint.provider_workspace_id = NEW.provider_workspace_id
              AND endpoint.provider_network_id = NEW.provider_network_id
              AND endpoint.consumer_workspace_id = NEW.consumer_workspace_id
              AND endpoint.consumer_network_id = NEW.consumer_network_id
              AND endpoint.state IN ('provisioning', 'ready') AND contract.state = 'active'
              AND contract.version = endpoint.contract_version
              AND contract.resource_version = NEW.resource_version AND contract.target_generation = NEW.target_generation
              AND device.session_generation = NEW.session_generation
              AND device.current_machine_key_epoch = NEW.machine_key_epoch
              AND device.current_node_key_epoch = NEW.node_key_epoch AND device.state = 'active'
              AND device.deleted_at IS NULL AND NEW.expires_at <= LEAST(endpoint.expires_at, device.expires_at)
              AND NEW.expires_at > pg_catalog.clock_timestamp()
              AND (NEW.alias_role = 'consumer_source' OR EXISTS (
                  SELECT 1 FROM mesh.resource_device_target AS target
                  WHERE target.resource_id = contract.resource_id AND target.target_generation = contract.target_generation
                    AND target.workspace_id = NEW.provider_workspace_id AND target.network_id = NEW.provider_network_id
                    AND target.device_id = NEW.owner_device_id AND target.state = 'active'))) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Device alias endpoint or Node pin mismatch';
        END IF;
        RETURN NEW;
    END IF;
    IF (pg_catalog.to_jsonb(OLD) - ARRAY['state', 'quarantine_until', 'version', 'updated_at',
            'provider_network_revision', 'provider_sharing_revision',
            'consumer_network_revision', 'consumer_sharing_revision'])
        IS DISTINCT FROM
        (pg_catalog.to_jsonb(NEW) - ARRAY['state', 'quarantine_until', 'version', 'updated_at',
            'provider_network_revision', 'provider_sharing_revision',
            'consumer_network_revision', 'consumer_sharing_revision'])
        OR NEW.version <> OLD.version + 1 OR NEW.updated_at < OLD.updated_at
        OR NEW.provider_network_revision <= OLD.provider_network_revision
        OR NEW.provider_sharing_revision <= OLD.provider_sharing_revision
        OR NEW.consumer_network_revision <= OLD.consumer_network_revision
        OR NEW.consumer_sharing_revision <= OLD.consumer_sharing_revision THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Device alias owner is immutable';
    END IF;
    IF OLD.state = 'reserved' AND NEW.state = 'quarantined'
        AND NEW.quarantine_until >= GREATEST(NEW.updated_at, NEW.expires_at) + INTERVAL '24 hours' THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'quarantined' AND NEW.state = 'released'
        AND NEW.quarantine_until = OLD.quarantine_until
        AND pg_catalog.clock_timestamp() >= OLD.quarantine_until
        AND EXISTS (SELECT 1 FROM mesh.private_endpoint AS endpoint
            WHERE endpoint.id = NEW.private_endpoint_id
              AND endpoint.state IN ('revoked', 'expired', 'invalidated')) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Device alias lifecycle';
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enforce_device_alias_transition_v2() FROM PUBLIC;
DROP TRIGGER device_alias_transition ON mesh.device_alias_lease;
CREATE TRIGGER device_alias_transition BEFORE INSERT OR UPDATE OR DELETE ON mesh.device_alias_lease
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_device_alias_transition_v2();

CREATE FUNCTION mesh_ops.enforce_device_alias_network_uniqueness_v1()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
DECLARE
    legacy_lease_id BIGINT;
BEGIN
    IF TG_TABLE_NAME = 'federation_alias_lease' THEN
        IF mesh_ops.device_alias_address_retained_v1(NEW.deployment_id, NEW.resource_alias,
            NEW.provider_network_id, NEW.consumer_network_id, NULL, NEW.id) THEN
            RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'alias address is retained in a participating Network';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.alias_role = 'resource' THEN
        SELECT endpoint.alias_lease_id INTO legacy_lease_id FROM mesh.private_endpoint AS endpoint
        WHERE endpoint.id = NEW.private_endpoint_id AND endpoint.resource_alias = NEW.address;
    END IF;
    IF mesh_ops.device_alias_address_retained_v1(NEW.deployment_id, NEW.address,
        NEW.provider_network_id, NEW.consumer_network_id, NEW.id, legacy_lease_id) THEN
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'alias address is retained in a participating Network';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enforce_device_alias_network_uniqueness_v1() FROM PUBLIC;
CREATE TRIGGER device_alias_network_uniqueness BEFORE INSERT ON mesh.device_alias_lease
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_device_alias_network_uniqueness_v1();
CREATE TRIGGER federation_alias_network_uniqueness BEFORE INSERT ON mesh.federation_alias_lease
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_device_alias_network_uniqueness_v1();

-- Selects the lowest host of an explicit alias pool that no retained alias in
-- either Network holds, inspecting at most 65,536 candidates. Callers must
-- already hold both Network revision row locks.
CREATE FUNCTION mesh_ops.allocate_network_scoped_alias_v1(
    p_deployment_id BIGINT, p_pool_id BIGINT, p_provider_network_id BIGINT, p_consumer_network_id BIGINT
)
RETURNS INET
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    pool_row mesh.address_pool%ROWTYPE;
    prior_deployment TEXT := pg_catalog.current_setting('mesh.device_alias_deployment_id', TRUE);
    maximum_offset BIGINT;
    attempt_limit BIGINT;
    candidate INET;
BEGIN
    IF p_deployment_id IS NULL OR p_pool_id IS NULL OR p_provider_network_id IS NULL
        OR p_consumer_network_id IS NULL OR p_provider_network_id = p_consumer_network_id THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid alias allocation request';
    END IF;
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', p_deployment_id::TEXT, TRUE);
    SELECT pool.* INTO pool_row FROM mesh.address_pool AS pool
    JOIN mesh.address_realm AS realm ON realm.id = pool.address_realm_id
        AND realm.deployment_id = pool.deployment_id AND realm.kind = 'federation_alias'
        AND realm.state = 'active' AND realm.deleted_at IS NULL
    WHERE pool.id = p_pool_id AND pool.deployment_id = p_deployment_id AND pool.workspace_id IS NULL
      AND pool.purpose IN ('federation_resource_alias', 'federation_consumer_alias')
      AND pool.state = 'active' AND pool.deleted_at IS NULL
    FOR SHARE OF pool;
    IF pool_row.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'explicit Device alias pool is unavailable';
    END IF;
    IF (pool_row.family = 4 AND pg_catalog.masklen(pool_row.prefix) NOT BETWEEN 8 AND 30)
        OR (pool_row.family = 6 AND pg_catalog.masklen(pool_row.prefix) NOT BETWEEN 67 AND 126)
        OR EXISTS (SELECT 1 FROM (VALUES ('0.0.0.0/8'::CIDR), ('127.0.0.0/8'),
            ('169.254.0.0/16'), ('224.0.0.0/4'), ('240.0.0.0/4'), ('::/128'),
            ('::1/128'), ('::ffff:0:0/96'), ('fe80::/10'), ('ff00::/8')) AS unsafe(prefix)
            WHERE pool_row.prefix && unsafe.prefix)
        OR EXISTS (SELECT 1 FROM mesh.address_pool AS other
            WHERE other.deployment_id = pool_row.deployment_id
              AND other.purpose IN ('node_overlay', 'workspace_service')
              AND other.state IN ('reserved', 'active', 'quarantined')
              AND pool_row.prefix && other.prefix) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Device alias pool overlaps an excluded prefix';
    END IF;
    maximum_offset := (1::BIGINT << (CASE pool_row.family WHEN 4 THEN 32 ELSE 128 END
        - pg_catalog.masklen(pool_row.prefix))) - CASE pool_row.family WHEN 4 THEN 2 ELSE 1 END;
    attempt_limit := LEAST(maximum_offset, 65536);
    candidate := NULL;
    FOR candidate_offset IN 1..attempt_limit LOOP
        candidate := pg_catalog.set_masklen(pg_catalog.network(pool_row.prefix) + candidate_offset,
            CASE pool_row.family WHEN 4 THEN 32 ELSE 128 END);
        EXIT WHEN NOT mesh_ops.device_alias_address_retained_v1(pool_row.deployment_id, candidate,
            p_provider_network_id, p_consumer_network_id, NULL, NULL);
        candidate := NULL;
    END LOOP;
    IF candidate IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Device alias candidate window is exhausted';
    END IF;
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', COALESCE(prior_deployment, ''), TRUE);
    RETURN candidate;
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', COALESCE(prior_deployment, ''), TRUE);
    RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.allocate_network_scoped_alias_v1(BIGINT, BIGINT, BIGINT, BIGINT)
    FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;
GRANT EXECUTE ON FUNCTION mesh_ops.allocate_network_scoped_alias_v1(BIGINT, BIGINT, BIGINT, BIGINT)
    TO mesh_share_writer, mesh_device_alias_writer;

-- Every Device share activates the alias endpoint; no direct readiness row.
CREATE FUNCTION mesh_ops.activate_resource_share_v4(
    p_provider_workspace_id BIGINT,
    p_provider_network_id BIGINT,
    p_consumer_workspace_id BIGINT,
    p_consumer_network_id BIGINT,
    p_contract_public_id UUID,
    p_expected_contract_version BIGINT,
    p_expected_provider_sharing_revision BIGINT,
    p_expected_consumer_sharing_revision BIGINT,
    p_alias_lease_public_id UUID,
    p_private_endpoint_public_id UUID,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    provider_network_revision BIGINT,
    provider_sharing_revision BIGINT,
    consumer_network_revision BIGINT,
    consumer_sharing_revision BIGINT,
    contract_version BIGINT,
    imported_resource_version BIGINT,
    alias_lease_version BIGINT,
    private_endpoint_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    contract_row mesh.trust_contract%ROWTYPE;
    imported_row mesh.imported_resource%ROWTYPE;
    access_name_row mesh.imported_resource_access_name%ROWTYPE;
    pool_row mesh.address_pool%ROWTYPE;
    allocated_alias INET;
    alias_lease_internal_id BIGINT;
BEGIN
    IF p_alias_lease_public_id IS NULL OR p_private_endpoint_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Private Endpoint identity';
    END IF;

    SELECT
        activated.provider_network_revision,
        activated.provider_sharing_revision,
        activated.consumer_network_revision,
        activated.consumer_sharing_revision,
        activated.contract_version,
        activated.imported_resource_version
    INTO
        provider_network_revision,
        provider_sharing_revision,
        consumer_network_revision,
        consumer_sharing_revision,
        contract_version,
        imported_resource_version
    FROM mesh_ops.activate_resource_share_v1(
        p_provider_workspace_id,
        p_provider_network_id,
        p_consumer_workspace_id,
        p_consumer_network_id,
        p_contract_public_id,
        p_expected_contract_version,
        p_expected_provider_sharing_revision,
        p_expected_consumer_sharing_revision,
        p_occurred_at
    ) AS activated;

    SELECT contract.* INTO contract_row
    FROM mesh.trust_contract AS contract
    WHERE contract.public_id = p_contract_public_id
      AND contract.provider_workspace_id = p_provider_workspace_id
      AND contract.provider_network_id = p_provider_network_id
      AND contract.consumer_workspace_id = p_consumer_workspace_id
      AND contract.consumer_network_id = p_consumer_network_id
      AND contract.version = contract_version
      AND contract.state = 'active'
    FOR UPDATE;
    SELECT imported.* INTO imported_row
    FROM mesh.imported_resource AS imported
    WHERE imported.trust_contract_id = contract_row.id
      AND imported.workspace_id = p_consumer_workspace_id
      AND imported.network_id = p_consumer_network_id
      AND imported.version = imported_resource_version
      AND imported.state = 'active'
    FOR UPDATE;
    SELECT access_name.* INTO access_name_row
    FROM mesh.imported_resource_access_name AS access_name
    WHERE access_name.imported_resource_id = imported_row.id
      AND access_name.workspace_id = p_consumer_workspace_id
      AND access_name.network_id = p_consumer_network_id
      AND access_name.state = 'reserved'
    FOR UPDATE;
    IF contract_row.id IS NULL OR imported_row.id IS NULL OR access_name_row.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Private Endpoint authority is unavailable';
    END IF;
    -- Fail closed before allocation when the exported Device cannot hold an
    -- alias: it must be active, unexpired and on current machine/Node keys.
    IF NOT EXISTS (
        SELECT 1 FROM mesh.resource AS resource
        JOIN mesh.resource_device_target AS target
          ON target.workspace_id = resource.workspace_id AND target.network_id = resource.network_id
         AND target.resource_id = resource.id AND target.target_generation = resource.target_generation
         AND target.state = 'active'
        JOIN mesh.device AS device
          ON device.workspace_id = target.workspace_id AND device.network_id = target.network_id
         AND device.id = target.device_id
        JOIN mesh.device_machine_key_epoch AS machine
          ON machine.workspace_id = device.workspace_id AND machine.network_id = device.network_id
         AND machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch
         AND machine.state = 'active' AND machine.valid_from <= p_occurred_at
        JOIN mesh.device_node_key_epoch AS node_key
          ON node_key.workspace_id = device.workspace_id AND node_key.network_id = device.network_id
         AND node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
         AND node_key.state = 'active' AND node_key.valid_from <= p_occurred_at
        WHERE resource.id = contract_row.resource_id AND resource.kind = 'device'
          AND resource.workspace_id = p_provider_workspace_id AND resource.network_id = p_provider_network_id
          AND resource.version = contract_row.resource_version
          AND resource.target_generation = contract_row.target_generation
          AND resource.semantic_hash = contract_row.resource_semantic_hash
          AND resource.state = 'active' AND resource.deleted_at IS NULL
          AND device.state = 'active' AND device.deleted_at IS NULL
          AND device.created_at <= p_occurred_at AND device.expires_at > p_occurred_at
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Device share target is unavailable';
    END IF;

    SELECT pool.* INTO pool_row
    FROM mesh.address_pool AS pool
    JOIN mesh.address_realm AS realm
      ON realm.deployment_id = pool.deployment_id
     AND realm.id = pool.address_realm_id
     AND realm.kind = 'federation_alias'
     AND realm.state = 'active'
     AND realm.deleted_at IS NULL
    WHERE pool.deployment_id = contract_row.deployment_id
      AND pool.workspace_id IS NULL
      AND pool.purpose = 'federation_resource_alias'
      AND pool.state = 'active'
      AND pool.deleted_at IS NULL
      AND (
          (pool.family = 4 AND pg_catalog.masklen(pool.prefix) BETWEEN 8 AND 30)
          OR (pool.family = 6 AND pg_catalog.masklen(pool.prefix) BETWEEN 67 AND 126)
      )
    ORDER BY pool.family DESC, pool.id
    LIMIT 1;
    IF pool_row.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Federation Alias pool is unavailable';
    END IF;

    -- activate_resource_share_v1 already holds both Network revision locks.
    allocated_alias := mesh_ops.allocate_network_scoped_alias_v1(
        contract_row.deployment_id, pool_row.id, p_provider_network_id, p_consumer_network_id
    );

    INSERT INTO mesh.federation_alias_lease (
        public_id, deployment_id, address_realm_id, address_pool_id,
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id,
        imported_resource_id, resource_alias, family, generation,
        state, created_at, updated_at
    ) VALUES (
        p_alias_lease_public_id, contract_row.deployment_id,
        pool_row.address_realm_id, pool_row.id,
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id,
        imported_row.id, allocated_alias, pool_row.family, 1,
        'reserved', p_occurred_at, p_occurred_at
    ) RETURNING id, version INTO alias_lease_internal_id, alias_lease_version;

    INSERT INTO mesh.private_endpoint (
        public_id, deployment_id,
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id,
        trust_contract_id, imported_resource_id, access_name_id, alias_lease_id,
        mode, resource_alias, generation,
        contract_version, imported_resource_version,
        provider_authority_generation, consumer_authority_generation,
        recovery_epoch, constraint_hash, expires_at,
        state, created_at, updated_at
    ) VALUES (
        p_private_endpoint_public_id, contract_row.deployment_id,
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id,
        contract_row.id, imported_row.id, access_name_row.id,
        alias_lease_internal_id,
        'federation_alias', allocated_alias, 1,
        contract_row.version, imported_row.version,
        contract_row.provider_authority_generation,
        contract_row.consumer_authority_generation,
        contract_row.recovery_epoch, contract_row.constraint_hash,
        contract_row.expires_at,
        'provisioning', p_occurred_at, p_occurred_at
    ) RETURNING version INTO private_endpoint_version;
    RETURN NEXT;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.activate_resource_share_v4(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;

-- Network-scoped Consumer Source and second-family Resource allocation.
CREATE FUNCTION mesh_ops.reserve_device_aliases_internal_v2(
    p_endpoint_public_id UUID, p_consumer_device_public_id UUID,
    p_expected_generation BIGINT, p_expected_provider_node_epoch BIGINT,
    p_expected_consumer_node_epoch BIGINT, p_lease_public_ids UUID[]
)
RETURNS SETOF mesh.device_alias_lease
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
    endpoint_row mesh.private_endpoint%ROWTYPE;
    contract_row mesh.trust_contract%ROWTYPE;
    provider_device mesh.device%ROWTYPE;
    consumer_device mesh.device%ROWTYPE;
    owner_device mesh.device%ROWTYPE;
    realm_row mesh.address_realm%ROWTYPE;
    pool_row mesh.address_pool%ROWTYPE;
    existing_row mesh.device_alias_lease%ROWTYPE;
    lease_row mesh.federation_alias_lease%ROWTYPE;
    node_key BYTEA;
    role_value TEXT; family_value INTEGER; pool_ids BIGINT[] := '{}';
    allocation_offset BIGINT; maximum_offset BIGINT; candidate INET;
    decision_at TIMESTAMPTZ; count_value INTEGER; index_value INTEGER := 0;
    provider_revision BIGINT; provider_sharing BIGINT;
    consumer_revision BIGINT; consumer_sharing BIGINT;
    changed BOOLEAN := FALSE;
    authority_stage TEXT := 'endpoint';
    revision_scope RECORD;
    prior_workspace TEXT := pg_catalog.current_setting('mesh.workspace_id', TRUE);
    prior_network TEXT := pg_catalog.current_setting('mesh.network_id', TRUE);
    prior_deployment TEXT := pg_catalog.current_setting('mesh.device_alias_deployment_id', TRUE);
    prior_share_provider_workspace_id TEXT := pg_catalog.current_setting('mesh.share_provider_workspace_id', TRUE);
    prior_share_provider_network_id TEXT := pg_catalog.current_setting('mesh.share_provider_network_id', TRUE);
    prior_share_consumer_workspace_id TEXT := pg_catalog.current_setting('mesh.share_consumer_workspace_id', TRUE);
    prior_share_consumer_network_id TEXT := pg_catalog.current_setting('mesh.share_consumer_network_id', TRUE);
BEGIN
    IF p_endpoint_public_id IS NULL OR p_consumer_device_public_id IS NULL
        OR p_expected_generation IS NULL OR p_expected_generation <= 0
        OR p_expected_provider_node_epoch IS NULL OR p_expected_provider_node_epoch <= 0
        OR p_expected_consumer_node_epoch IS NULL OR p_expected_consumer_node_epoch <= 0
        OR p_lease_public_ids IS NULL OR pg_catalog.array_ndims(p_lease_public_ids) <> 1
        OR pg_catalog.array_lower(p_lease_public_ids, 1) <> 1
        OR pg_catalog.cardinality(p_lease_public_ids) <> 4
        OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p_lease_public_ids) AS value
            WHERE value IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(value), 6) >> 4 <> 7)
        OR (SELECT count(DISTINCT value) FROM pg_catalog.unnest(p_lease_public_ids) AS value) <> 4 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Device alias request';
    END IF;
    SELECT endpoint.* INTO STRICT endpoint_row FROM mesh.private_endpoint AS endpoint
    WHERE endpoint.public_id = p_endpoint_public_id;
    PERFORM pg_catalog.set_config('mesh.share_provider_workspace_id', endpoint_row.provider_workspace_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_network_id', endpoint_row.provider_network_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_workspace_id', endpoint_row.consumer_workspace_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_network_id', endpoint_row.consumer_network_id::TEXT, TRUE);
    -- Same order as ordinary authority writers. No external I/O under these locks.
    FOR revision_scope IN SELECT * FROM (VALUES
        (endpoint_row.provider_workspace_id, endpoint_row.provider_network_id),
        (endpoint_row.consumer_workspace_id, endpoint_row.consumer_network_id)
    ) AS scopes(workspace_id, network_id) ORDER BY workspace_id, network_id LOOP
        PERFORM pg_catalog.set_config('mesh.workspace_id', revision_scope.workspace_id::TEXT, TRUE);
        PERFORM pg_catalog.set_config('mesh.network_id', revision_scope.network_id::TEXT, TRUE);
        PERFORM revision.network_id FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = revision_scope.workspace_id AND revision.network_id = revision_scope.network_id
        FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device alias Network revision is unavailable';
        END IF;
    END LOOP;
    SELECT endpoint.* INTO STRICT endpoint_row FROM mesh.private_endpoint AS endpoint
    WHERE endpoint.public_id = p_endpoint_public_id FOR UPDATE;
    authority_stage := 'contract';
    SELECT contract.* INTO STRICT contract_row FROM mesh.trust_contract AS contract
    WHERE contract.id = endpoint_row.trust_contract_id FOR UPDATE;
    PERFORM imported.id FROM mesh.imported_resource AS imported
    WHERE imported.id = endpoint_row.imported_resource_id AND imported.state = 'active'
      AND imported.version = endpoint_row.imported_resource_version FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device alias import changed';
    END IF;
    authority_stage := 'provider_target';
    SELECT device.* INTO STRICT provider_device FROM mesh.resource AS resource
    JOIN mesh.resource_device_target AS target ON target.resource_id = resource.id
        AND target.workspace_id = resource.workspace_id AND target.network_id = resource.network_id
        AND target.target_generation = resource.target_generation AND target.state = 'active'
    JOIN mesh.device AS device ON device.id = target.device_id
        AND device.workspace_id = target.workspace_id AND device.network_id = target.network_id
    WHERE resource.id = contract_row.resource_id AND resource.kind = 'device' AND resource.state = 'active'
      AND resource.deleted_at IS NULL AND resource.version = contract_row.resource_version
      AND resource.target_generation = contract_row.target_generation
      AND resource.semantic_hash = contract_row.resource_semantic_hash
      AND resource.workspace_id = endpoint_row.provider_workspace_id
      AND resource.network_id = endpoint_row.provider_network_id
    FOR SHARE OF resource, target;
    SELECT device.* INTO STRICT consumer_device FROM mesh.device AS device
    WHERE device.public_id = p_consumer_device_public_id
      AND device.workspace_id = endpoint_row.consumer_workspace_id
      AND device.network_id = endpoint_row.consumer_network_id;
    PERFORM device.id FROM mesh.device AS device
    WHERE device.id IN (provider_device.id, consumer_device.id) ORDER BY device.id FOR SHARE;
    -- Read after locking, so a waited-on key rotation cannot use the old snapshot.
    SELECT device.* INTO STRICT provider_device FROM mesh.device AS device WHERE device.id = provider_device.id;
    SELECT device.* INTO STRICT consumer_device FROM mesh.device AS device WHERE device.id = consumer_device.id;
    PERFORM machine.id FROM mesh.device_machine_key_epoch AS machine
    WHERE (machine.device_id, machine.epoch) IN (
        (provider_device.id, provider_device.current_machine_key_epoch),
        (consumer_device.id, consumer_device.current_machine_key_epoch)) ORDER BY machine.id FOR SHARE;
    PERFORM node_key_row.id FROM mesh.device_node_key_epoch AS node_key_row
    WHERE (node_key_row.device_id, node_key_row.epoch) IN (
        (provider_device.id, provider_device.current_node_key_epoch),
        (consumer_device.id, consumer_device.current_node_key_epoch)) ORDER BY node_key_row.id FOR SHARE;
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', endpoint_row.deployment_id::TEXT, TRUE);
    authority_stage := 'alias_realm';
    SELECT realm.* INTO STRICT realm_row FROM mesh.address_realm AS realm
    WHERE realm.deployment_id = endpoint_row.deployment_id AND realm.kind = 'federation_alias'
      AND realm.state = 'active' AND realm.deleted_at IS NULL FOR UPDATE;
    decision_at := pg_catalog.clock_timestamp();
    IF endpoint_row.state NOT IN ('provisioning', 'ready')
        OR endpoint_row.provider_network_id = endpoint_row.consumer_network_id
        OR endpoint_row.generation <> p_expected_generation
        OR endpoint_row.contract_version <> contract_row.version OR contract_row.state <> 'active'
        OR endpoint_row.constraint_hash <> contract_row.constraint_hash
        OR endpoint_row.expires_at <= decision_at OR contract_row.expires_at <= decision_at
        OR provider_device.current_node_key_epoch <> p_expected_provider_node_epoch
        OR consumer_device.current_node_key_epoch <> p_expected_consumer_node_epoch
        OR NOT EXISTS (SELECT 1 FROM mesh.deployment AS deployment
            JOIN mesh.workspace AS provider_workspace ON provider_workspace.deployment_id = deployment.id
            JOIN mesh.workspace AS consumer_workspace ON consumer_workspace.deployment_id = deployment.id
            JOIN mesh.network AS provider_network ON provider_network.workspace_id = provider_workspace.id
            JOIN mesh.network AS consumer_network ON consumer_network.workspace_id = consumer_workspace.id
            WHERE deployment.id = endpoint_row.deployment_id AND deployment.state = 'active'
              AND deployment.recovery_epoch = endpoint_row.recovery_epoch
              AND deployment.recovery_state = 'verified'
              AND provider_workspace.id = endpoint_row.provider_workspace_id AND provider_workspace.state = 'active'
              AND consumer_workspace.id = endpoint_row.consumer_workspace_id AND consumer_workspace.state = 'active'
              AND provider_network.id = endpoint_row.provider_network_id AND provider_network.state = 'active'
              AND consumer_network.id = endpoint_row.consumer_network_id AND consumer_network.state = 'active'
              AND provider_network.authority_generation = endpoint_row.provider_authority_generation
              AND consumer_network.authority_generation = endpoint_row.consumer_authority_generation) THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device alias authority changed';
    END IF;
    FOREACH owner_device IN ARRAY ARRAY[provider_device, consumer_device] LOOP
        IF owner_device.state <> 'active' OR owner_device.deleted_at IS NOT NULL
            OR owner_device.created_at > decision_at OR owner_device.expires_at <= decision_at
            OR NOT EXISTS (SELECT 1 FROM mesh.device_machine_key_epoch AS machine
                WHERE machine.device_id = owner_device.id AND machine.epoch = owner_device.current_machine_key_epoch
                  AND machine.state = 'active' AND machine.valid_from <= decision_at)
            OR NOT EXISTS (SELECT 1 FROM mesh.device_node_key_epoch AS node_key_row
                WHERE node_key_row.device_id = owner_device.id AND node_key_row.epoch = owner_device.current_node_key_epoch
                  AND node_key_row.state = 'active' AND node_key_row.valid_from <= decision_at) THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device alias Node authority changed';
        END IF;
    END LOOP;
    -- Require exactly one active pool for each enabled family and role. Never
    -- infer a missing pool or put a source alias into a Resource Alias pool.
    FOREACH role_value IN ARRAY ARRAY['resource', 'consumer_source'] LOOP
        FOREACH family_value IN ARRAY ARRAY[4, 6] LOOP
            IF (family_value = 4 AND NOT realm_row.ipv4_enabled)
                OR (family_value = 6 AND NOT realm_row.ipv6_enabled) THEN CONTINUE; END IF;
            SELECT count(*), min(pool.id) INTO count_value, allocation_offset FROM mesh.address_pool AS pool
            WHERE pool.address_realm_id = realm_row.id AND pool.family = family_value
              AND pool.state = 'active' AND pool.deleted_at IS NULL AND pool.workspace_id IS NULL
              AND pool.purpose = CASE role_value WHEN 'resource' THEN 'federation_resource_alias'
                  ELSE 'federation_consumer_alias' END;
            IF count_value <> 1 THEN
                RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'explicit Device alias pool is unavailable';
            END IF;
            pool_ids := pg_catalog.array_append(pool_ids, allocation_offset);
        END LOOP;
    END LOOP;
    PERFORM pool.id FROM mesh.address_pool AS pool WHERE pool.id = ANY(pool_ids) ORDER BY pool.id FOR SHARE;
    INSERT INTO mesh_ops.federation_alias_pool_cursor (address_pool_id, deployment_id, next_offset, updated_at)
    SELECT pool.id, pool.deployment_id, 1, decision_at FROM mesh.address_pool AS pool
    WHERE pool.id = ANY(pool_ids) ORDER BY pool.id ON CONFLICT (address_pool_id) DO NOTHING;
    PERFORM cursor.address_pool_id FROM mesh_ops.federation_alias_pool_cursor AS cursor
    WHERE cursor.address_pool_id = ANY(pool_ids) ORDER BY cursor.address_pool_id FOR UPDATE;
    IF EXISTS (SELECT 1 FROM mesh.device_alias_lease AS lease
        WHERE lease.private_endpoint_id = endpoint_row.id AND lease.alias_role = 'resource')
        AND (SELECT count(*) FROM mesh.device_alias_lease AS lease
            WHERE lease.private_endpoint_id = endpoint_row.id AND lease.alias_role = 'resource')
            <> (realm_row.ipv4_enabled::INTEGER + realm_row.ipv6_enabled::INTEGER) THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device alias address families changed';
    END IF;
    decision_at := pg_catalog.clock_timestamp();
    IF endpoint_row.expires_at <= decision_at OR contract_row.expires_at <= decision_at
        OR provider_device.expires_at <= decision_at OR consumer_device.expires_at <= decision_at THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device alias authority expired after locking';
    END IF;
    authority_stage := 'legacy_alias';
    SELECT lease.* INTO STRICT lease_row FROM mesh.federation_alias_lease AS lease
    WHERE lease.id = endpoint_row.alias_lease_id AND lease.state IN ('reserved', 'active') FOR SHARE;
    IF (lease_row.family = 4 AND NOT realm_row.ipv4_enabled)
        OR (lease_row.family = 6 AND NOT realm_row.ipv6_enabled) THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'legacy Resource Alias family is disabled';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM mesh.device_alias_lease AS lease
        WHERE lease.private_endpoint_id = endpoint_row.id AND lease.alias_role = 'consumer_source'
          AND lease.owner_device_id = consumer_device.id)
        AND (SELECT count(DISTINCT lease.owner_device_id) FROM mesh.device_alias_lease AS lease
            WHERE lease.private_endpoint_id = endpoint_row.id AND lease.alias_role = 'consumer_source') >= 256 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Device alias consumer budget is exhausted';
    END IF;
    FOREACH role_value IN ARRAY ARRAY['resource', 'consumer_source'] LOOP
        owner_device := CASE role_value WHEN 'resource' THEN provider_device ELSE consumer_device END;
    authority_stage := 'node_key';
        SELECT node_key_row.public_key INTO STRICT node_key FROM mesh.device_node_key_epoch AS node_key_row
        WHERE node_key_row.device_id = owner_device.id AND node_key_row.epoch = owner_device.current_node_key_epoch;
        FOREACH family_value IN ARRAY ARRAY[4, 6] LOOP
            index_value := index_value + 1;
            IF (family_value = 4 AND NOT realm_row.ipv4_enabled)
                OR (family_value = 6 AND NOT realm_row.ipv6_enabled) THEN CONTINUE; END IF;
    authority_stage := 'role_pool';
            SELECT pool.* INTO STRICT pool_row FROM mesh.address_pool AS pool
            WHERE pool.id = ANY(pool_ids) AND pool.family = family_value
              AND pool.state = 'active' AND pool.deleted_at IS NULL
              AND pool.purpose = CASE role_value WHEN 'resource' THEN 'federation_resource_alias'
                  ELSE 'federation_consumer_alias' END;
            IF (pool_row.family = 4 AND pg_catalog.masklen(pool_row.prefix) NOT BETWEEN 8 AND 30)
                OR (pool_row.family = 6 AND pg_catalog.masklen(pool_row.prefix) NOT BETWEEN 67 AND 126)
                OR EXISTS (SELECT 1 FROM (VALUES ('0.0.0.0/8'::CIDR), ('127.0.0.0/8'),
                    ('169.254.0.0/16'), ('224.0.0.0/4'), ('240.0.0.0/4'), ('::/128'),
                    ('::1/128'), ('::ffff:0:0/96'), ('fe80::/10'), ('ff00::/8')) AS unsafe(prefix)
                    WHERE pool_row.prefix && unsafe.prefix)
                OR EXISTS (SELECT 1 FROM mesh.address_pool AS other
                    WHERE other.deployment_id = pool_row.deployment_id
                      AND other.purpose IN ('node_overlay', 'workspace_service')
                      AND other.state IN ('reserved', 'active', 'quarantined')
                      AND pool_row.prefix && other.prefix) THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Device alias pool overlaps an excluded prefix';
            END IF;
            SELECT lease.* INTO existing_row FROM mesh.device_alias_lease AS lease
            WHERE lease.private_endpoint_id = endpoint_row.id AND lease.alias_role = role_value
              AND lease.family = family_value AND lease.owner_device_id = owner_device.id;
            IF FOUND THEN
                IF existing_row.state <> 'reserved' OR existing_row.endpoint_generation <> endpoint_row.generation
                    OR existing_row.recovery_epoch <> endpoint_row.recovery_epoch
                    OR existing_row.resource_version <> contract_row.resource_version
                    OR existing_row.target_generation <> contract_row.target_generation
                    OR existing_row.session_generation <> owner_device.session_generation
                    OR existing_row.machine_key_epoch <> owner_device.current_machine_key_epoch
                    OR existing_row.node_key_epoch <> owner_device.current_node_key_epoch
                    OR existing_row.node_public_key <> node_key OR existing_row.address_pool_id <> pool_row.id
                    OR existing_row.expires_at <= decision_at
                    OR existing_row.expires_at > LEAST(endpoint_row.expires_at, owner_device.expires_at) THEN
                    RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device alias retry owner changed';
                END IF;
                CONTINUE;
            END IF;
            IF role_value = 'resource' AND family_value = lease_row.family THEN
                IF pool_row.id <> lease_row.address_pool_id OR realm_row.id <> lease_row.address_realm_id
                    OR lease_row.resource_alias <> endpoint_row.resource_alias
                    OR lease_row.generation <> endpoint_row.generation THEN
                    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'legacy Resource Alias owner mismatch';
                END IF;
                candidate := lease_row.resource_alias;
            ELSE
                candidate := mesh_ops.allocate_network_scoped_alias_v1(endpoint_row.deployment_id,
                    pool_row.id, endpoint_row.provider_network_id, endpoint_row.consumer_network_id);
            END IF;
            IF NOT changed THEN
                PERFORM pg_catalog.set_config('mesh.workspace_id', endpoint_row.provider_workspace_id::TEXT, TRUE);
                PERFORM pg_catalog.set_config('mesh.network_id', endpoint_row.provider_network_id::TEXT, TRUE);
                UPDATE mesh_ops.network_revision AS revision SET network_revision = revision.network_revision + 1,
                    sharing_revision = revision.sharing_revision + 1, updated_at = decision_at
                WHERE revision.workspace_id = endpoint_row.provider_workspace_id
                  AND revision.network_id = endpoint_row.provider_network_id
                RETURNING revision.network_revision, revision.sharing_revision INTO provider_revision, provider_sharing;
                PERFORM pg_catalog.set_config('mesh.workspace_id', endpoint_row.consumer_workspace_id::TEXT, TRUE);
                PERFORM pg_catalog.set_config('mesh.network_id', endpoint_row.consumer_network_id::TEXT, TRUE);
                UPDATE mesh_ops.network_revision AS revision SET network_revision = revision.network_revision + 1,
                    sharing_revision = revision.sharing_revision + 1, updated_at = decision_at
                WHERE revision.workspace_id = endpoint_row.consumer_workspace_id
                  AND revision.network_id = endpoint_row.consumer_network_id
                RETURNING revision.network_revision, revision.sharing_revision INTO consumer_revision, consumer_sharing;
                changed := TRUE;
            END IF;
            INSERT INTO mesh.device_alias_lease (
                public_id, deployment_id, address_realm_id, address_pool_id,
                provider_workspace_id, provider_network_id, consumer_workspace_id, consumer_network_id,
                private_endpoint_id, endpoint_generation, recovery_epoch, resource_version, target_generation,
                owner_workspace_id, owner_network_id, owner_device_id, session_generation,
                machine_key_epoch, node_key_epoch, node_public_key, alias_role, family, address, expires_at,
                provider_network_revision, provider_sharing_revision, consumer_network_revision, consumer_sharing_revision,
                state, created_at, updated_at
            ) VALUES (p_lease_public_ids[index_value], endpoint_row.deployment_id, realm_row.id, pool_row.id,
                endpoint_row.provider_workspace_id, endpoint_row.provider_network_id,
                endpoint_row.consumer_workspace_id, endpoint_row.consumer_network_id,
                endpoint_row.id, endpoint_row.generation, endpoint_row.recovery_epoch,
                contract_row.resource_version, contract_row.target_generation,
                owner_device.workspace_id, owner_device.network_id, owner_device.id, owner_device.session_generation,
                owner_device.current_machine_key_epoch, owner_device.current_node_key_epoch, node_key,
                role_value, family_value, candidate, LEAST(endpoint_row.expires_at, owner_device.expires_at),
                provider_revision, provider_sharing, consumer_revision, consumer_sharing,
                'reserved', decision_at, decision_at);
        END LOOP;
    END LOOP;
    IF LEAST(endpoint_row.expires_at, contract_row.expires_at,
        provider_device.expires_at, consumer_device.expires_at) <= pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device alias authority expired during reservation';
    END IF;
    RETURN QUERY SELECT lease.* FROM mesh.device_alias_lease AS lease
    WHERE lease.private_endpoint_id = endpoint_row.id
      AND ((lease.alias_role = 'resource' AND lease.owner_device_id = provider_device.id)
        OR (lease.alias_role = 'consumer_source' AND lease.owner_device_id = consumer_device.id))
    ORDER BY lease.alias_role, lease.family;
    PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(prior_workspace, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(prior_network, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', COALESCE(prior_deployment, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_workspace_id', COALESCE(prior_share_provider_workspace_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_network_id', COALESCE(prior_share_provider_network_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_workspace_id', COALESCE(prior_share_consumer_workspace_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_network_id', COALESCE(prior_share_consumer_network_id, ''), TRUE);
EXCEPTION WHEN no_data_found THEN
    PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(prior_workspace, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(prior_network, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', COALESCE(prior_deployment, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_workspace_id', COALESCE(prior_share_provider_workspace_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_network_id', COALESCE(prior_share_provider_network_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_workspace_id', COALESCE(prior_share_consumer_workspace_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_network_id', COALESCE(prior_share_consumer_network_id, ''), TRUE);

    RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device alias authority is unavailable',
        DETAIL = authority_stage;
WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(prior_workspace, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(prior_network, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', COALESCE(prior_deployment, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_workspace_id', COALESCE(prior_share_provider_workspace_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_network_id', COALESCE(prior_share_provider_network_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_workspace_id', COALESCE(prior_share_consumer_workspace_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_network_id', COALESCE(prior_share_consumer_network_id, ''), TRUE);
    RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.reserve_device_aliases_internal_v2(UUID, UUID, BIGINT, BIGINT, BIGINT, UUID[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_share_writer, mesh_audit_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.reserve_device_aliases_internal_v2(UUID, UUID, BIGINT, BIGINT, BIGINT, UUID[])
    TO mesh_device_alias_writer;

-- Local and remote aliases are selected by Network.
CREATE FUNCTION mesh_ops.load_device_alias_map_edges_v2(
    p_machine_key_fingerprint BYTEA, p_node_key BYTEA, p_limit INTEGER
)
RETURNS SETOF JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    self_id BIGINT;
    self_workspace BIGINT;
    self_network BIGINT;
    previous_remote TEXT;
    previous_alias_provider_workspace TEXT;
    previous_alias_provider_network TEXT;
    previous_alias_consumer_workspace TEXT;
    previous_alias_consumer_network TEXT;
    previous_alias_endpoint TEXT;

    endpoint_row mesh.private_endpoint%ROWTYPE;
    endpoint_count INTEGER := 0;
    edge_count INTEGER := 0;
    edge JSONB;
BEGIN
    previous_remote := pg_catalog.current_setting('mesh.direct_map_remote_network_id', TRUE);
    -- Discard caller-controlled remote scope before authenticating self.
    PERFORM pg_catalog.set_config('mesh.direct_map_remote_network_id', '', TRUE);
    previous_alias_provider_workspace := current_setting('mesh.alias_map_provider_workspace_id',TRUE);
    PERFORM set_config('mesh.alias_map_provider_workspace_id','',TRUE);
    previous_alias_provider_network := current_setting('mesh.alias_map_provider_network_id',TRUE);
    PERFORM set_config('mesh.alias_map_provider_network_id','',TRUE);
    previous_alias_consumer_workspace := current_setting('mesh.alias_map_consumer_workspace_id',TRUE);
    PERFORM set_config('mesh.alias_map_consumer_workspace_id','',TRUE);
    previous_alias_consumer_network := current_setting('mesh.alias_map_consumer_network_id',TRUE);
    PERFORM set_config('mesh.alias_map_consumer_network_id','',TRUE);
    previous_alias_endpoint := current_setting('mesh.alias_map_endpoint_id',TRUE);
    PERFORM set_config('mesh.alias_map_endpoint_id','',TRUE);
    self_workspace := mesh_ops.current_workspace_id();
    self_network := mesh_ops.current_network_id();
    IF self_workspace IS NULL OR self_network IS NULL
        OR p_machine_key_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_key_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 257 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid alias map request';
    END IF;
    SELECT device.id INTO self_id
    FROM mesh.device AS device
    JOIN mesh.device_machine_key_epoch AS machine
      ON machine.workspace_id = device.workspace_id AND machine.network_id = device.network_id
     AND machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch
     AND machine.state = 'active' AND machine.valid_from <= pg_catalog.transaction_timestamp()
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.workspace_id = device.workspace_id AND node_key.network_id = device.network_id
     AND node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
     AND node_key.state = 'active' AND node_key.valid_from <= pg_catalog.transaction_timestamp()
    JOIN mesh.workspace AS workspace ON workspace.id = device.workspace_id
    JOIN mesh.network AS network ON network.workspace_id = workspace.id AND network.id = device.network_id
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    JOIN mesh.principal AS owner ON owner.id = device.owner_principal_id AND owner.deployment_id = deployment.id
    WHERE device.workspace_id = self_workspace AND device.network_id = self_network
      AND machine.fingerprint = p_machine_key_fingerprint AND node_key.public_key = p_node_key
      AND device.state = 'active' AND device.deleted_at IS NULL
      AND device.created_at <= pg_catalog.transaction_timestamp()
      AND device.expires_at > pg_catalog.transaction_timestamp()
      AND workspace.state = 'active' AND workspace.deleted_at IS NULL
      AND network.state = 'active' AND network.deleted_at IS NULL
      AND deployment.state = 'active' AND deployment.recovery_state = 'verified' AND deployment.deleted_at IS NULL
      AND owner.state = 'active' AND owner.deleted_at IS NULL;
    IF self_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'alias map authority unavailable';
    END IF;

    -- Bound endpoints as well as output rules, including endpoints with no rule.
    FOR endpoint_row IN
        SELECT endpoint.* FROM mesh.private_endpoint AS endpoint
        WHERE endpoint.provider_network_id <> endpoint.consumer_network_id
          AND endpoint.state='provisioning'
          AND ((endpoint.provider_workspace_id=self_workspace AND endpoint.provider_network_id=self_network
            AND EXISTS (SELECT 1 FROM mesh.resource_device_target AS target JOIN mesh.trust_contract AS contract ON contract.id=endpoint.trust_contract_id
              WHERE target.workspace_id=self_workspace AND target.network_id=self_network AND target.resource_id=contract.resource_id
                AND target.device_id=self_id AND target.target_generation=contract.target_generation AND target.state='active'))
            OR (endpoint.consumer_workspace_id=self_workspace AND endpoint.consumer_network_id=self_network))
        ORDER BY endpoint.id LIMIT 257
    LOOP
        endpoint_count := endpoint_count + 1;
        IF endpoint_count > 256 THEN
            RAISE EXCEPTION USING ERRCODE = '54000', MESSAGE = 'alias map endpoint limit exceeded';
        END IF;
        PERFORM pg_catalog.set_config('mesh.direct_map_remote_network_id',
            CASE WHEN endpoint_row.provider_network_id = self_network
                THEN endpoint_row.consumer_network_id ELSE endpoint_row.provider_network_id END::TEXT, TRUE);
        PERFORM set_config('mesh.alias_map_provider_workspace_id',endpoint_row.provider_workspace_id::TEXT,TRUE);
        PERFORM set_config('mesh.alias_map_provider_network_id',endpoint_row.provider_network_id::TEXT,TRUE);
        PERFORM set_config('mesh.alias_map_consumer_workspace_id',endpoint_row.consumer_workspace_id::TEXT,TRUE);
        PERFORM set_config('mesh.alias_map_consumer_network_id',endpoint_row.consumer_network_id::TEXT,TRUE);
        PERFORM set_config('mesh.alias_map_endpoint_id',endpoint_row.id::TEXT,TRUE);
        FOR edge IN
            SELECT pg_catalog.jsonb_build_object(
                'evaluated_at', pg_catalog.transaction_timestamp(),
                'ceiling_profile', deployment.direct_sharing_ceiling_profile,
                'provider_workspace_id', provider_workspace.public_id,
                'consumer_workspace_id', consumer_workspace.public_id,
                'provider_network_id', provider_network.public_id,
                'consumer_network_id', consumer_network.public_id,
                'provider_network_revision', provider_revision.network_revision,
                'consumer_network_revision', consumer_revision.network_revision,
                'consumer_policy_revision', consumer_revision.policy_revision,
                'provider_inventory_revision', provider_revision.inventory_revision,
                'provider_sharing_revision', provider_revision.sharing_revision,
                'consumer_sharing_revision', consumer_revision.sharing_revision,
                'provider_authority_generation', provider_network.authority_generation,
                'consumer_authority_generation', consumer_network.authority_generation,
                'recovery_epoch', deployment.recovery_epoch,
                'contract', pg_catalog.jsonb_build_object(
                    'id', contract.public_id, 'version', contract.version,
                    'imported_resource_id', imported.public_id, 'imported_resource_version', imported.version,
                    'offer_id', offer.public_id, 'export_id', export.public_id,
                    'expires_at', contract.expires_at, 'constraint_hash', pg_catalog.encode(contract.constraint_hash, 'hex')),
                'export', pg_catalog.jsonb_build_object(
                    'version', export.version, 'expires_at', export.expires_at,
                    'constraints', COALESCE((
                        SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                            'protocol', ceiling.protocol, 'ranges', COALESCE((
                                SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
                                    pg_catalog.lower(port_range), pg_catalog.upper(port_range) - 1)
                                    ORDER BY pg_catalog.lower(port_range))
                                FROM pg_catalog.unnest(ceiling.destination_ports) AS port_range
                            ), '[]'::JSONB)) ORDER BY ceiling.protocol)
                        FROM mesh.resource_export_constraint AS ceiling
                        WHERE ceiling.resource_export_id = export.id
                          AND ceiling.provider_workspace_id = endpoint_row.provider_workspace_id
                          AND ceiling.provider_network_id = endpoint_row.provider_network_id
                          AND ceiling.consumer_workspace_id = endpoint_row.consumer_workspace_id
                          AND ceiling.consumer_network_id = endpoint_row.consumer_network_id
                    ), '[]'::JSONB)),
                'endpoint', pg_catalog.jsonb_build_object(
                    'id', endpoint_row.public_id, 'access_name', access_name.access_name,
                    'generation', endpoint_row.generation, 'expires_at', endpoint_row.expires_at,
                    'resource_address', pg_catalog.host(endpoint_row.resource_alias)),
                'aliases', jsonb_build_object('expires_at',LEAST(readiness.expires_at,provider_aliases.expires_at,consumer_aliases.expires_at),
                  'local_addresses', CASE WHEN self_network=endpoint_row.provider_network_id THEN provider_aliases.addresses ELSE consumer_aliases.addresses END,
                  'remote_addresses', CASE WHEN self_network=endpoint_row.provider_network_id THEN consumer_aliases.addresses ELSE provider_aliases.addresses END),
                'target', pg_catalog.jsonb_build_object(
                    'id', resource.public_id, 'version', resource.version,
                    'target_generation', resource.target_generation,
                    'semantic_hash', pg_catalog.encode(resource.semantic_hash, 'hex'),
                    'display_name', resource.display_name, 'device_id', provider.public_id,
                    'owner_id', resource_owner.public_id, 'custodian_id', custodian.public_id,
                    'activated_network_revision', resource.activated_network_revision,
                    'inventory_revision', resource.inventory_revision,
                    'created_at', resource.created_at, 'updated_at', resource.updated_at),
                'rule', pg_catalog.jsonb_build_object(
                    'id', rule.access_rule_public_id, 'source_id', consumer.public_id,
                    'protocol', rule.protocol, 'ranges', COALESCE((
                        SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
                            pg_catalog.lower(port_range), pg_catalog.upper(port_range) - 1)
                            ORDER BY pg_catalog.lower(port_range))
                        FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                    ), '[]'::JSONB)),
                'peer', CASE WHEN self_network = endpoint_row.provider_network_id THEN
                    pg_catalog.jsonb_build_object(
                        'numeric_node_id', consumer.id, 'numeric_owner_id', consumer.owner_principal_id,
                        'id', consumer.public_id, 'owner_id', consumer_owner.public_id,
                        'hostname', consumer.hostname, 'machine_key', pg_catalog.encode(consumer_machine.public_key, 'hex'),
                        'node_key', pg_catalog.encode(consumer_node.public_key, 'hex'),
                        'session_generation', consumer.session_generation,
                        'created_at', consumer.created_at, 'key_expiry', consumer.expires_at,
                        'addresses', consumer_aliases.addresses)
                ELSE pg_catalog.jsonb_build_object(
                        'numeric_node_id', provider.id, 'numeric_owner_id', provider.owner_principal_id,
                        'id', provider.public_id, 'owner_id', provider_owner.public_id,
                        'hostname', provider.hostname, 'machine_key', pg_catalog.encode(provider_machine.public_key, 'hex'),
                        'node_key', pg_catalog.encode(provider_node.public_key, 'hex'),
                        'session_generation', provider.session_generation,
                        'created_at', provider.created_at, 'key_expiry', provider.expires_at,
                        'addresses', provider_aliases.addresses) END)
            FROM mesh.trust_contract AS contract
            JOIN mesh.imported_resource AS imported
              ON imported.workspace_id = endpoint_row.consumer_workspace_id
             AND imported.network_id = endpoint_row.consumer_network_id
             AND imported.id = endpoint_row.imported_resource_id
             AND imported.trust_contract_id = contract.id AND imported.public_id = contract.imported_resource_public_id
             AND imported.state = 'active' AND imported.version = endpoint_row.imported_resource_version
            JOIN mesh.share_offer AS offer ON offer.id = contract.share_offer_id
             AND offer.state = 'accepted' AND offer.accepted_contract_public_id = contract.public_id
            JOIN mesh.resource_export AS export ON export.id = contract.resource_export_id
             AND export.provider_workspace_id = endpoint_row.provider_workspace_id
             AND export.provider_network_id = endpoint_row.provider_network_id
             AND export.consumer_workspace_id = endpoint_row.consumer_workspace_id
             AND export.consumer_network_id = endpoint_row.consumer_network_id
             AND export.resource_id = contract.resource_id AND export.resource_version = contract.resource_version
             AND export.target_generation = contract.target_generation AND export.resource_semantic_hash = contract.resource_semantic_hash
             AND export.constraint_hash = contract.constraint_hash AND export.state = 'active'
             AND export.provider_authority_generation = contract.provider_authority_generation
             AND export.expires_at >= contract.expires_at AND export.expires_at > pg_catalog.transaction_timestamp()
            JOIN mesh.resource AS resource ON resource.workspace_id = endpoint_row.provider_workspace_id
             AND resource.network_id = endpoint_row.provider_network_id AND resource.id = contract.resource_id
             AND resource.id = contract.resource_id AND resource.version = contract.resource_version
             AND resource.target_generation = contract.target_generation AND resource.semantic_hash = contract.resource_semantic_hash
             AND resource.kind = 'device' AND resource.provenance_kind = 'manual'
             AND resource.state = 'active' AND resource.deleted_at IS NULL
            JOIN mesh.resource_device_target AS target ON target.workspace_id = resource.workspace_id
             AND target.network_id = resource.network_id AND target.resource_id = resource.id
             AND target.target_generation = resource.target_generation AND target.state = 'active'
            JOIN mesh.device AS provider ON provider.workspace_id = target.workspace_id
             AND provider.network_id = target.network_id AND provider.id = target.device_id
             AND provider.state = 'active' AND provider.deleted_at IS NULL
             AND provider.created_at <= pg_catalog.transaction_timestamp() AND provider.expires_at > pg_catalog.transaction_timestamp()
            JOIN mesh.device_machine_key_epoch AS provider_machine ON provider_machine.workspace_id = provider.workspace_id
             AND provider_machine.network_id = provider.network_id AND provider_machine.device_id = provider.id
             AND provider_machine.epoch = provider.current_machine_key_epoch AND provider_machine.state = 'active'
             AND provider_machine.valid_from <= pg_catalog.transaction_timestamp()
            JOIN mesh.device_node_key_epoch AS provider_node ON provider_node.workspace_id = provider.workspace_id
             AND provider_node.network_id = provider.network_id AND provider_node.device_id = provider.id
             AND provider_node.epoch = provider.current_node_key_epoch AND provider_node.state = 'active'
             AND provider_node.valid_from <= pg_catalog.transaction_timestamp()
            JOIN mesh.workspace AS provider_workspace ON provider_workspace.id=contract.provider_workspace_id
             AND provider_workspace.state='active' AND provider_workspace.deleted_at IS NULL
            JOIN mesh.workspace AS consumer_workspace ON consumer_workspace.id=contract.consumer_workspace_id
             AND consumer_workspace.state='active' AND consumer_workspace.deleted_at IS NULL
            JOIN mesh.deployment AS deployment ON deployment.id=provider_workspace.deployment_id AND deployment.id=consumer_workspace.deployment_id
             AND deployment.id=contract.deployment_id AND deployment.id=endpoint_row.deployment_id
             AND deployment.state='active' AND deployment.recovery_state='verified' AND deployment.deleted_at IS NULL
             AND deployment.recovery_epoch=contract.recovery_epoch AND deployment.recovery_epoch=endpoint_row.recovery_epoch
             AND deployment.direct_sharing_ceiling_profile='no-additional-traffic-ceilings-v1'
            JOIN mesh.network AS provider_network ON provider_network.workspace_id = provider_workspace.id
             AND provider_network.id = endpoint_row.provider_network_id
             AND provider_network.state = 'active' AND provider_network.deleted_at IS NULL
             AND provider_network.authority_generation = contract.provider_authority_generation
             AND provider_network.authority_generation = endpoint_row.provider_authority_generation
            JOIN mesh.network AS consumer_network ON consumer_network.workspace_id = consumer_workspace.id
             AND consumer_network.id = endpoint_row.consumer_network_id
             AND consumer_network.state = 'active' AND consumer_network.deleted_at IS NULL
             AND consumer_network.authority_generation = contract.consumer_authority_generation
             AND consumer_network.authority_generation = endpoint_row.consumer_authority_generation
            JOIN mesh_ops.network_revision AS provider_revision ON provider_revision.workspace_id = provider_workspace.id
             AND provider_revision.network_id = provider_network.id
            JOIN mesh_ops.network_revision AS consumer_revision ON consumer_revision.workspace_id = consumer_workspace.id
             AND consumer_revision.network_id = consumer_network.id
            JOIN mesh.policy_release AS release ON release.workspace_id = consumer_workspace.id
             AND release.network_id = consumer_network.id AND release.policy_revision = consumer_revision.policy_revision
             AND release.state = 'active'
            JOIN mesh.compiled_policy_imported_resource_destination AS rule ON rule.workspace_id = consumer_workspace.id
             AND rule.network_id = consumer_network.id AND rule.policy_release_id = release.id
             AND rule.policy_revision = release.policy_revision
             AND rule.imported_resource_id = imported.id AND rule.imported_resource_version = imported.version
             AND rule.trust_contract_id = contract.id AND rule.trust_contract_version = contract.version
             AND rule.resource_export_id = export.id AND rule.resource_export_version = export.version
             AND rule.provider_workspace_id = provider_workspace.id AND rule.provider_network_id = provider_network.id
             AND rule.destination_resource_id = resource.id AND rule.resource_version = resource.version
             AND rule.target_generation = resource.target_generation AND rule.resource_semantic_hash = resource.semantic_hash
             AND rule.provider_authority_generation = provider_network.authority_generation
             AND rule.consumer_authority_generation = consumer_network.authority_generation
             AND rule.recovery_epoch = deployment.recovery_epoch AND rule.contract_expires_at = contract.expires_at
             AND rule.constraint_hash = contract.constraint_hash
             AND rule.provider_inventory_revision <= provider_revision.inventory_revision
             AND rule.provider_sharing_revision <= provider_revision.sharing_revision
             AND rule.consumer_sharing_revision <= consumer_revision.sharing_revision
            JOIN mesh.device AS consumer ON consumer.workspace_id = consumer_workspace.id AND consumer.network_id = consumer_network.id
             AND consumer.id = rule.source_device_id AND consumer.state = 'active' AND consumer.deleted_at IS NULL
             AND consumer.created_at <= pg_catalog.transaction_timestamp() AND consumer.expires_at > pg_catalog.transaction_timestamp()
            JOIN mesh.device_machine_key_epoch AS consumer_machine ON consumer_machine.workspace_id = consumer.workspace_id
             AND consumer_machine.network_id = consumer.network_id AND consumer_machine.device_id = consumer.id
             AND consumer_machine.epoch = consumer.current_machine_key_epoch AND consumer_machine.state = 'active'
             AND consumer_machine.valid_from <= pg_catalog.transaction_timestamp()
            JOIN mesh.device_node_key_epoch AS consumer_node ON consumer_node.workspace_id = consumer.workspace_id
             AND consumer_node.network_id = consumer.network_id AND consumer_node.device_id = consumer.id
             AND consumer_node.epoch = consumer.current_node_key_epoch AND consumer_node.state = 'active'
             AND consumer_node.valid_from <= pg_catalog.transaction_timestamp()
            JOIN mesh.principal AS provider_owner ON provider_owner.id = provider.owner_principal_id
             AND provider_owner.deployment_id = deployment.id AND provider_owner.state = 'active' AND provider_owner.deleted_at IS NULL
            JOIN mesh.principal AS consumer_owner ON consumer_owner.id = consumer.owner_principal_id
             AND consumer_owner.deployment_id = deployment.id AND consumer_owner.state = 'active' AND consumer_owner.deleted_at IS NULL
            JOIN mesh.principal AS resource_owner ON resource_owner.id = resource.owner_principal_id
             AND resource_owner.deployment_id = deployment.id AND resource_owner.state = 'active' AND resource_owner.deleted_at IS NULL
            JOIN mesh.principal AS custodian ON custodian.id = resource.custodian_principal_id
             AND custodian.deployment_id = deployment.id AND custodian.state = 'active' AND custodian.deleted_at IS NULL
            JOIN mesh.imported_resource_access_name AS access_name ON access_name.id = endpoint_row.access_name_id
             AND access_name.workspace_id = imported.workspace_id AND access_name.network_id = imported.network_id
             AND access_name.imported_resource_id = imported.id AND access_name.state = 'reserved'
            JOIN mesh.federation_alias_lease AS legacy ON legacy.id=endpoint_row.alias_lease_id
             AND legacy.deployment_id=deployment.id AND legacy.provider_workspace_id=provider_workspace.id
             AND legacy.provider_network_id=provider_network.id AND legacy.consumer_workspace_id=consumer_workspace.id
             AND legacy.consumer_network_id=consumer_network.id AND legacy.imported_resource_id=imported.id
             AND legacy.generation=endpoint_row.generation AND legacy.resource_alias=endpoint_row.resource_alias
             AND legacy.family=family(endpoint_row.resource_alias) AND legacy.state='reserved'
            JOIN mesh.device_alias_client_readiness AS readiness ON readiness.private_endpoint_id=endpoint_row.id
             AND readiness.deployment_id=deployment.id AND readiness.state='ready'
             AND readiness.provider_workspace_id=provider_workspace.id AND readiness.provider_network_id=provider_network.id
             AND readiness.consumer_workspace_id=consumer_workspace.id AND readiness.consumer_network_id=consumer_network.id
             AND readiness.endpoint_generation=endpoint_row.generation AND readiness.provider_device_id=provider.id
             AND readiness.consumer_device_id=consumer.id AND readiness.contract_version=contract.version
             AND readiness.imported_resource_version=imported.version AND readiness.resource_version=resource.version
             AND readiness.target_generation=resource.target_generation AND readiness.recovery_epoch=deployment.recovery_epoch
             AND readiness.created_at<=transaction_timestamp() AND readiness.expires_at>transaction_timestamp()
             AND readiness.expires_at<=LEAST(endpoint_row.expires_at,provider.expires_at,consumer.expires_at)
             AND readiness.provider_network_revision<=provider_revision.network_revision
             AND readiness.provider_sharing_revision<=provider_revision.sharing_revision
             AND readiness.consumer_network_revision<=consumer_revision.network_revision
             AND readiness.consumer_sharing_revision<=consumer_revision.sharing_revision
            JOIN mesh.device_alias_client_version AS provider_compat ON provider_compat.workspace_id=provider.workspace_id
             AND provider_compat.network_id=provider.network_id AND provider_compat.device_id=provider.id
             AND provider_compat.alias_version=1 AND provider_compat.session_generation=provider.session_generation
             AND provider_compat.machine_key_epoch=provider.current_machine_key_epoch AND provider_compat.node_key_epoch=provider.current_node_key_epoch
             AND provider_compat.node_public_key=provider_node.public_key
            CROSS JOIN LATERAL (SELECT array_agg(host(lease.address)||CASE lease.family WHEN 4 THEN '/32' ELSE '/128' END ORDER BY lease.family) AS addresses,
                array_agg(lease.public_id ORDER BY lease.public_id) AS lease_ids,min(lease.expires_at) AS expires_at,count(*) AS family_count,bool_or(lease.family=4) AS ipv4,bool_or(lease.family=6) AS ipv6
                FROM mesh.device_alias_lease AS lease
                JOIN mesh.address_realm AS realm ON realm.id=lease.address_realm_id AND realm.deployment_id=deployment.id
                 AND realm.kind='federation_alias' AND realm.state='active' AND realm.deleted_at IS NULL
                JOIN mesh.address_pool AS pool ON pool.id=lease.address_pool_id AND pool.deployment_id=deployment.id
                 AND pool.address_realm_id=realm.id AND pool.family=lease.family AND pool.workspace_id IS NULL
                 AND pool.purpose='federation_resource_alias' AND pool.state='active' AND pool.deleted_at IS NULL AND lease.address << pool.prefix
                WHERE lease.private_endpoint_id=endpoint_row.id AND lease.alias_role='resource'
                  AND lease.deployment_id=deployment.id AND lease.endpoint_generation=endpoint_row.generation
                  AND lease.recovery_epoch=deployment.recovery_epoch AND lease.state='reserved'
                  AND lease.provider_workspace_id=provider_workspace.id AND lease.provider_network_id=provider_network.id
                  AND lease.consumer_workspace_id=consumer_workspace.id AND lease.consumer_network_id=consumer_network.id
                  AND lease.owner_workspace_id=provider.workspace_id AND lease.owner_network_id=provider.network_id AND lease.owner_device_id=provider.id
                  AND lease.session_generation=provider.session_generation AND lease.machine_key_epoch=provider.current_machine_key_epoch
                  AND lease.node_key_epoch=provider.current_node_key_epoch AND lease.node_public_key=provider_node.public_key
                  AND lease.resource_version=resource.version AND lease.target_generation=resource.target_generation
                  AND lease.created_at<=transaction_timestamp() AND lease.expires_at>transaction_timestamp()
                  AND lease.expires_at<=LEAST(endpoint_row.expires_at,provider.expires_at)
                  AND (lease.family=4 AND realm.ipv4_enabled OR lease.family=6 AND realm.ipv6_enabled)) AS provider_aliases
            JOIN mesh.device_alias_client_version AS consumer_compat ON consumer_compat.workspace_id=consumer.workspace_id
             AND consumer_compat.network_id=consumer.network_id AND consumer_compat.device_id=consumer.id
             AND consumer_compat.alias_version=1 AND consumer_compat.session_generation=consumer.session_generation
             AND consumer_compat.machine_key_epoch=consumer.current_machine_key_epoch AND consumer_compat.node_key_epoch=consumer.current_node_key_epoch
             AND consumer_compat.node_public_key=consumer_node.public_key
            CROSS JOIN LATERAL (SELECT array_agg(host(lease.address)||CASE lease.family WHEN 4 THEN '/32' ELSE '/128' END ORDER BY lease.family) AS addresses,
                array_agg(lease.public_id ORDER BY lease.public_id) AS lease_ids,min(lease.expires_at) AS expires_at,count(*) AS family_count,bool_or(lease.family=4) AS ipv4,bool_or(lease.family=6) AS ipv6
                FROM mesh.device_alias_lease AS lease
                JOIN mesh.address_realm AS realm ON realm.id=lease.address_realm_id AND realm.deployment_id=deployment.id
                 AND realm.kind='federation_alias' AND realm.state='active' AND realm.deleted_at IS NULL
                JOIN mesh.address_pool AS pool ON pool.id=lease.address_pool_id AND pool.deployment_id=deployment.id
                 AND pool.address_realm_id=realm.id AND pool.family=lease.family AND pool.workspace_id IS NULL
                 AND pool.purpose='federation_consumer_alias' AND pool.state='active' AND pool.deleted_at IS NULL AND lease.address << pool.prefix
                WHERE lease.private_endpoint_id=endpoint_row.id AND lease.alias_role='consumer_source'
                  AND lease.deployment_id=deployment.id AND lease.endpoint_generation=endpoint_row.generation
                  AND lease.recovery_epoch=deployment.recovery_epoch AND lease.state='reserved'
                  AND lease.provider_workspace_id=provider_workspace.id AND lease.provider_network_id=provider_network.id
                  AND lease.consumer_workspace_id=consumer_workspace.id AND lease.consumer_network_id=consumer_network.id
                  AND lease.owner_workspace_id=consumer.workspace_id AND lease.owner_network_id=consumer.network_id AND lease.owner_device_id=consumer.id
                  AND lease.session_generation=consumer.session_generation AND lease.machine_key_epoch=consumer.current_machine_key_epoch
                  AND lease.node_key_epoch=consumer.current_node_key_epoch AND lease.node_public_key=consumer_node.public_key
                  AND lease.resource_version=resource.version AND lease.target_generation=resource.target_generation
                  AND lease.created_at<=transaction_timestamp() AND lease.expires_at>transaction_timestamp()
                  AND lease.expires_at<=LEAST(endpoint_row.expires_at,consumer.expires_at)
                  AND (lease.family=4 AND realm.ipv4_enabled OR lease.family=6 AND realm.ipv6_enabled)) AS consumer_aliases
            WHERE contract.id = endpoint_row.trust_contract_id AND contract.state = 'active'
              AND contract.provider_workspace_id = endpoint_row.provider_workspace_id
              AND contract.provider_network_id = endpoint_row.provider_network_id
              AND contract.consumer_workspace_id = endpoint_row.consumer_workspace_id
              AND contract.consumer_network_id = endpoint_row.consumer_network_id
              AND endpoint_row.state='provisioning' AND contract.version = endpoint_row.contract_version AND contract.constraint_hash = endpoint_row.constraint_hash
              AND contract.expires_at > pg_catalog.transaction_timestamp() AND endpoint_row.expires_at > pg_catalog.transaction_timestamp()
              AND ((self_network = provider.network_id AND self_id = provider.id)
                OR (self_network = consumer.network_id AND self_id = consumer.id))
              AND EXISTS (SELECT 1 FROM mesh.device_alias_lease AS resource_lease
                WHERE resource_lease.private_endpoint_id=endpoint_row.id AND resource_lease.alias_role='resource'
                  AND resource_lease.family=legacy.family AND resource_lease.address=legacy.resource_alias
                  AND resource_lease.address_pool_id=legacy.address_pool_id AND resource_lease.address_realm_id=legacy.address_realm_id
                  AND resource_lease.state='reserved')
              AND provider_aliases.family_count BETWEEN 1 AND 2
              AND consumer_aliases.family_count=provider_aliases.family_count
              AND readiness.lease_public_ids=ARRAY(SELECT lease_id FROM unnest(provider_aliases.lease_ids || consumer_aliases.lease_ids) AS lease_id ORDER BY lease_id)
              AND consumer_aliases.ipv4 IS NOT DISTINCT FROM provider_aliases.ipv4
              AND consumer_aliases.ipv6 IS NOT DISTINCT FROM provider_aliases.ipv6
              AND EXISTS (SELECT 1 FROM mesh.address_realm AS realm WHERE realm.deployment_id=deployment.id
                AND realm.kind='federation_alias' AND realm.state='active' AND realm.deleted_at IS NULL
                AND realm.ipv4_enabled=COALESCE(provider_aliases.ipv4,FALSE) AND realm.ipv6_enabled=COALESCE(provider_aliases.ipv6,FALSE))
            ORDER BY rule.access_rule_public_id LIMIT p_limit - edge_count
        LOOP
            RETURN NEXT edge;
            edge_count := edge_count + 1;
            IF edge_count >= p_limit THEN
                    PERFORM set_config('mesh.alias_map_provider_workspace_id',COALESCE(previous_alias_provider_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_provider_network_id',COALESCE(previous_alias_provider_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_workspace_id',COALESCE(previous_alias_consumer_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_network_id',COALESCE(previous_alias_consumer_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_endpoint_id',COALESCE(previous_alias_endpoint,''),TRUE);
    PERFORM pg_catalog.set_config('mesh.direct_map_remote_network_id', COALESCE(previous_remote, ''), TRUE);
                RETURN;
            END IF;
        END LOOP;
    END LOOP;
        PERFORM set_config('mesh.alias_map_provider_workspace_id',COALESCE(previous_alias_provider_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_provider_network_id',COALESCE(previous_alias_provider_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_workspace_id',COALESCE(previous_alias_consumer_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_network_id',COALESCE(previous_alias_consumer_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_endpoint_id',COALESCE(previous_alias_endpoint,''),TRUE);
    PERFORM pg_catalog.set_config('mesh.direct_map_remote_network_id', COALESCE(previous_remote, ''), TRUE);
EXCEPTION WHEN OTHERS THEN
        PERFORM set_config('mesh.alias_map_provider_workspace_id',COALESCE(previous_alias_provider_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_provider_network_id',COALESCE(previous_alias_provider_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_workspace_id',COALESCE(previous_alias_consumer_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_network_id',COALESCE(previous_alias_consumer_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_endpoint_id',COALESCE(previous_alias_endpoint,''),TRUE);
    PERFORM pg_catalog.set_config('mesh.direct_map_remote_network_id', COALESCE(previous_remote, ''), TRUE);
    RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.load_device_alias_map_edges_v2(BYTEA,BYTEA,INTEGER) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer,mesh_direct_map_reader;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v2(BYTEA,BYTEA,INTEGER) TO mesh_device_alias_writer;

CREATE FUNCTION mesh_ops.prepare_device_alias_change_v2(p_deployment UUID,p_endpoint UUID,p_consumer UUID,p_generation BIGINT,
 p_provider_node_epoch BIGINT,p_consumer_node_epoch BIGINT,p_leases UUID[],p_readiness UUID,p_change UUID,p_mode TEXT) RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE saved JSONB:=mesh_ops.save_device_alias_worker_context_v1(); endpoint mesh.private_endpoint%ROWTYPE;
 provider mesh.device%ROWTYPE; consumer mesh.device%ROWTYPE; contract mesh.trust_contract%ROWTYPE; imported mesh.imported_resource%ROWTYPE;
 lease_ids UUID[]; deadline TIMESTAMPTZ; provider_revision BIGINT; provider_sharing BIGINT; consumer_revision BIGINT; consumer_sharing BIGINT;
 fingerprint BYTEA; node_key BYTEA; proof JSONB; kind TEXT; scope RECORD;
BEGIN
 IF p_mode IS NULL OR p_mode NOT IN ('reserve','ready') OR p_change IS NULL OR get_byte(uuid_send(p_change),6)>>4<>7
  OR p_readiness IS NULL OR get_byte(uuid_send(p_readiness),6)>>4<>7 THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid Device alias worker change';
 END IF;
 endpoint:=mesh_ops.derive_device_alias_worker_scope_v1(p_deployment,p_endpoint);
 PERFORM set_config('mesh.change_public_id',p_change::TEXT,TRUE);
 IF endpoint.state<>'provisioning' OR endpoint.provider_network_id=endpoint.consumer_network_id THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias endpoint not client-only';
 END IF;
 PERFORM mesh_ops.reserve_device_aliases_internal_v2(p_endpoint,p_consumer,p_generation,p_provider_node_epoch,p_consumer_node_epoch,p_leases);
 -- The allocator holds both Network revisions and exact Device/key locks.
 -- Recheck bilateral consent and client claims before any allocation can commit.
 IF NOT EXISTS(SELECT 1 FROM mesh.trust_contract AS accepted
  JOIN mesh.share_offer AS offer ON offer.id=accepted.share_offer_id AND offer.state='accepted' AND offer.accepted_contract_public_id=accepted.public_id
  JOIN mesh.resource_export AS export ON export.id=accepted.resource_export_id AND export.state='active'
   AND export.resource_id=accepted.resource_id AND export.resource_version=accepted.resource_version AND export.target_generation=accepted.target_generation
   AND export.resource_semantic_hash=accepted.resource_semantic_hash AND export.constraint_hash=accepted.constraint_hash
   AND export.expires_at>=accepted.expires_at AND export.provider_authority_generation=accepted.provider_authority_generation
   AND (export.provider_workspace_id,export.provider_network_id,export.consumer_workspace_id,export.consumer_network_id)=
       (accepted.provider_workspace_id,accepted.provider_network_id,accepted.consumer_workspace_id,accepted.consumer_network_id)
  WHERE accepted.id=endpoint.trust_contract_id AND accepted.state='active' AND accepted.version=endpoint.contract_version
   AND accepted.expires_at>clock_timestamp()) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias acceptance changed';
 END IF;
 IF (SELECT count(DISTINCT device.id) FROM mesh.device_alias_lease AS lease
  JOIN mesh.device AS device ON device.id=lease.owner_device_id
  JOIN mesh.device_alias_client_version AS compatibility ON compatibility.device_id=device.id AND compatibility.workspace_id=device.workspace_id AND compatibility.network_id=device.network_id
   AND compatibility.alias_version=1 AND compatibility.session_generation=device.session_generation AND compatibility.machine_key_epoch=device.current_machine_key_epoch
   AND compatibility.node_key_epoch=device.current_node_key_epoch AND compatibility.node_public_key=lease.node_public_key
  WHERE lease.private_endpoint_id=endpoint.id AND lease.state='reserved'
   AND (lease.alias_role='resource' OR lease.alias_role='consumer_source' AND device.public_id=p_consumer))<>2 THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias client claims unavailable';
 END IF;
 kind:='device_alias_lease';
 IF p_mode='ready' THEN
  IF EXISTS(SELECT 1 FROM mesh_audit.authority_mutation WHERE transaction_id=(pg_current_xact_id()::TEXT)::BIGINT AND change_public_id=p_change AND aggregate_kind='device_alias_lease') THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device aliases must be reserved before readiness';
  END IF;
  SELECT * INTO STRICT contract FROM mesh.trust_contract WHERE id=endpoint.trust_contract_id;
  SELECT * INTO STRICT imported FROM mesh.imported_resource WHERE id=endpoint.imported_resource_id;
  SELECT device.* INTO STRICT provider FROM mesh.device AS device JOIN mesh.resource_device_target AS target ON target.device_id=device.id
   WHERE target.resource_id=contract.resource_id AND target.target_generation=contract.target_generation AND target.state='active';
  SELECT * INTO STRICT consumer FROM mesh.device WHERE public_id=p_consumer AND workspace_id=endpoint.consumer_workspace_id AND network_id=endpoint.consumer_network_id;
  IF NOT EXISTS(SELECT 1 FROM mesh.device_alias_client_readiness WHERE private_endpoint_id=endpoint.id AND consumer_device_id=consumer.id) THEN
   FOR scope IN SELECT * FROM (VALUES (endpoint.provider_workspace_id,endpoint.provider_network_id),(endpoint.consumer_workspace_id,endpoint.consumer_network_id)) AS scopes(workspace_id,network_id)
    ORDER BY workspace_id,network_id LOOP
    UPDATE mesh_ops.network_revision SET network_revision=network_revision+1,sharing_revision=sharing_revision+1,updated_at=clock_timestamp()
     WHERE workspace_id=scope.workspace_id AND network_id=scope.network_id;
   END LOOP;
   SELECT network_revision,sharing_revision INTO STRICT provider_revision,provider_sharing FROM mesh_ops.network_revision WHERE workspace_id=endpoint.provider_workspace_id AND network_id=endpoint.provider_network_id;
   SELECT network_revision,sharing_revision INTO STRICT consumer_revision,consumer_sharing FROM mesh_ops.network_revision WHERE workspace_id=endpoint.consumer_workspace_id AND network_id=endpoint.consumer_network_id;
   SELECT array_agg(public_id ORDER BY public_id),min(expires_at) INTO lease_ids,deadline FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND state='reserved'
    AND (alias_role='resource' AND owner_device_id=provider.id OR alias_role='consumer_source' AND owner_device_id=consumer.id);
   INSERT INTO mesh.device_alias_client_readiness(public_id,deployment_id,provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id,private_endpoint_id,endpoint_generation,
    consumer_device_id,provider_device_id,contract_version,imported_resource_version,resource_version,target_generation,recovery_epoch,lease_public_ids,expires_at,state,created_at,updated_at,
    provider_network_revision,provider_sharing_revision,consumer_network_revision,consumer_sharing_revision)
   VALUES(p_readiness,endpoint.deployment_id,endpoint.provider_workspace_id,endpoint.provider_network_id,endpoint.consumer_workspace_id,endpoint.consumer_network_id,endpoint.id,endpoint.generation,
    consumer.id,provider.id,contract.version,imported.version,contract.resource_version,contract.target_generation,endpoint.recovery_epoch,lease_ids,
    LEAST(deadline,endpoint.expires_at,contract.expires_at,provider.expires_at,consumer.expires_at),'ready',transaction_timestamp(),transaction_timestamp(),provider_revision,provider_sharing,consumer_revision,consumer_sharing);
  END IF;
  -- Reuse the complete authenticated projection predicate, never the trigger's
  -- smaller insertion subset, before marking this pair ready.
  PERFORM set_config('mesh.workspace_id',endpoint.consumer_workspace_id::TEXT,TRUE);
  PERFORM set_config('mesh.network_id',endpoint.consumer_network_id::TEXT,TRUE);
  SELECT machine.fingerprint,key.public_key INTO STRICT fingerprint,node_key FROM mesh.device_machine_key_epoch AS machine JOIN mesh.device_node_key_epoch AS key ON key.device_id=machine.device_id
   WHERE machine.device_id=consumer.id AND machine.epoch=consumer.current_machine_key_epoch AND key.epoch=consumer.current_node_key_epoch;
  IF NOT EXISTS(SELECT 1 FROM mesh_ops.load_device_alias_map_edges_v2(fingerprint,node_key,257) AS edge
    WHERE edge->'endpoint'->>'id'=p_endpoint::TEXT AND edge->'peer'->>'id'=provider.public_id::TEXT) THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias complete map authority unavailable';
  END IF;
  kind:='device_alias_client_readiness';
 END IF;
 proof:=mesh_ops.device_alias_change_proof_internal_v1(p_endpoint,p_change,kind);
 PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);
 RETURN proof;
EXCEPTION WHEN OTHERS THEN PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved); RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.prepare_device_alias_change_v2(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;

CREATE FUNCTION mesh_ops.prepare_device_alias_withdrawal_v2(p_deployment UUID,p_endpoint UUID,p_consumer UUID,p_generation BIGINT,p_change UUID,p_mode TEXT) RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE saved JSONB:=mesh_ops.save_device_alias_worker_context_v1(); endpoint mesh.private_endpoint%ROWTYPE;
 consumer_id BIGINT; scope RECORD; changed BOOLEAN; proof JSONB; decision_at TIMESTAMPTZ;
 provider_revision BIGINT; provider_sharing BIGINT; consumer_revision BIGINT; consumer_sharing BIGINT;
BEGIN
 IF p_mode IS NULL OR p_mode NOT IN ('withdraw','quarantine_consumer','quarantine_resource') OR p_generation IS NULL OR p_generation<=0
  OR p_consumer IS NULL OR p_change IS NULL OR get_byte(uuid_send(p_change),6)>>4<>7 THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid Device alias withdrawal';
 END IF;
 endpoint:=mesh_ops.derive_device_alias_worker_scope_v1(p_deployment,p_endpoint);
 PERFORM set_config('mesh.change_public_id',p_change::TEXT,TRUE);
 FOR scope IN SELECT * FROM (VALUES (endpoint.provider_workspace_id,endpoint.provider_network_id),(endpoint.consumer_workspace_id,endpoint.consumer_network_id)) AS scopes(workspace_id,network_id)
  ORDER BY workspace_id,network_id LOOP
  PERFORM network_id FROM mesh_ops.network_revision WHERE workspace_id=scope.workspace_id AND network_id=scope.network_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias withdrawal Network unavailable'; END IF;
 END LOOP;
 SELECT * INTO STRICT endpoint FROM mesh.private_endpoint WHERE public_id=p_endpoint FOR UPDATE;
 IF endpoint.generation<>p_generation OR endpoint.provider_network_id=endpoint.consumer_network_id OR endpoint.state='ready' THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias withdrawal endpoint changed';
 END IF;
 SELECT id INTO consumer_id FROM mesh.device WHERE public_id=p_consumer AND workspace_id=endpoint.consumer_workspace_id AND network_id=endpoint.consumer_network_id;
 IF consumer_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Device alias consumer scope unavailable'; END IF;
 IF p_mode='withdraw' THEN
  PERFORM id FROM mesh.device_alias_client_readiness WHERE private_endpoint_id=endpoint.id AND consumer_device_id=consumer_id ORDER BY id FOR UPDATE;
  SELECT EXISTS(SELECT 1 FROM mesh.device_alias_client_readiness WHERE private_endpoint_id=endpoint.id AND consumer_device_id=consumer_id AND state='ready') INTO changed;
 ELSE
  PERFORM id FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND
   (p_mode='quarantine_resource' AND alias_role='resource' OR p_mode='quarantine_consumer' AND alias_role='consumer_source' AND owner_device_id=consumer_id) ORDER BY id FOR UPDATE;
  SELECT EXISTS(SELECT 1 FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND state='reserved' AND
   (p_mode='quarantine_resource' AND alias_role='resource' OR p_mode='quarantine_consumer' AND alias_role='consumer_source' AND owner_device_id=consumer_id)) INTO changed;
 END IF;
 IF NOT changed THEN
  PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);
  RETURN jsonb_build_object('changed',FALSE,'events','[]'::JSONB);
 END IF;
 decision_at:=clock_timestamp();
 FOR scope IN SELECT * FROM (VALUES (endpoint.provider_workspace_id,endpoint.provider_network_id),(endpoint.consumer_workspace_id,endpoint.consumer_network_id)) AS scopes(workspace_id,network_id)
  ORDER BY workspace_id,network_id LOOP
  UPDATE mesh_ops.network_revision SET network_revision=network_revision+1,sharing_revision=sharing_revision+1,updated_at=decision_at
   WHERE workspace_id=scope.workspace_id AND network_id=scope.network_id;
 END LOOP;
 SELECT network_revision,sharing_revision INTO STRICT provider_revision,provider_sharing FROM mesh_ops.network_revision WHERE workspace_id=endpoint.provider_workspace_id AND network_id=endpoint.provider_network_id;
 SELECT network_revision,sharing_revision INTO STRICT consumer_revision,consumer_sharing FROM mesh_ops.network_revision WHERE workspace_id=endpoint.consumer_workspace_id AND network_id=endpoint.consumer_network_id;
 IF p_mode='withdraw' THEN
  UPDATE mesh.device_alias_client_readiness SET state='withdrawn',version=version+1,updated_at=decision_at,
   provider_network_revision=provider_revision,provider_sharing_revision=provider_sharing,consumer_network_revision=consumer_revision,consumer_sharing_revision=consumer_sharing
   WHERE private_endpoint_id=endpoint.id AND consumer_device_id=consumer_id AND state='ready';
 ELSE
  UPDATE mesh.device_alias_lease SET state='quarantined',version=version+1,updated_at=decision_at,
   quarantine_until=GREATEST(decision_at,expires_at,endpoint.expires_at)+INTERVAL '24 hours',
   provider_network_revision=provider_revision,provider_sharing_revision=provider_sharing,consumer_network_revision=consumer_revision,consumer_sharing_revision=consumer_sharing
   WHERE private_endpoint_id=endpoint.id AND state='reserved' AND
    (p_mode='quarantine_resource' AND alias_role='resource' OR p_mode='quarantine_consumer' AND alias_role='consumer_source' AND owner_device_id=consumer_id);
 END IF;
 proof:=mesh_ops.device_alias_withdrawal_proof_internal_v1(p_endpoint,p_change,p_mode);
 PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);
 RETURN proof;
EXCEPTION WHEN OTHERS THEN PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved); RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.prepare_device_alias_withdrawal_v2(UUID,UUID,UUID,BIGINT,UUID,TEXT) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;

CREATE FUNCTION mesh_ops.finalize_device_alias_withdrawal_v2(p_deployment UUID,p_endpoint UUID,p_generation BIGINT,p_change UUID,p_mode TEXT,p_events JSONB) RETURNS INTEGER
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE saved JSONB:=mesh_ops.save_device_alias_worker_context_v1(); endpoint mesh.private_endpoint%ROWTYPE; proof JSONB; expected JSONB; supplied JSONB; count_value INTEGER:=0;
BEGIN
 IF p_mode IS NULL OR p_mode NOT IN ('withdraw','quarantine_consumer','quarantine_resource') OR p_generation IS NULL OR p_generation<=0
  OR p_change IS NULL OR get_byte(uuid_send(p_change),6)>>4<>7 OR p_events IS NULL OR jsonb_typeof(p_events)<>'array'
  OR jsonb_array_length(p_events)<>2 OR octet_length(p_events::TEXT)>32768 THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid Device alias withdrawal evidence';
 END IF;
 endpoint:=mesh_ops.derive_device_alias_worker_scope_v1(p_deployment,p_endpoint);
 IF endpoint.generation<>p_generation OR endpoint.provider_network_id=endpoint.consumer_network_id OR endpoint.state='ready' THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias withdrawal endpoint changed';
 END IF;
 PERFORM set_config('mesh.change_public_id',p_change::TEXT,TRUE);
 proof:=mesh_ops.device_alias_withdrawal_proof_internal_v1(p_endpoint,p_change,p_mode);
 IF NOT COALESCE((proof->>'changed')::BOOLEAN,FALSE) THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Device alias withdrawal mutation missing'; END IF;
 FOR expected IN SELECT value FROM jsonb_array_elements(proof->'events') LOOP
  SELECT value INTO STRICT supplied FROM jsonb_array_elements(p_events) WHERE value->>'stream_id'=expected->>'stream_id';
  IF supplied->>'sequence' IS DISTINCT FROM expected->>'sequence' OR supplied->>'previous_hash' IS DISTINCT FROM expected->>'previous_hash'
   OR supplied->>'audit_payload' IS DISTINCT FROM expected->>'audit_payload' OR supplied->>'outbox_payload' IS DISTINCT FROM expected->>'outbox_payload'
   OR supplied->>'network_revision' IS DISTINCT FROM expected->>'network_revision' OR supplied->>'sharing_revision' IS DISTINCT FROM expected->>'sharing_revision'
   OR supplied->>'workspace_id' IS DISTINCT FROM expected->>'workspace_id' OR supplied->>'network_id' IS DISTINCT FROM expected->>'network_id' THEN
   RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Device alias withdrawal evidence mismatch';
  END IF;
  PERFORM mesh_audit.append_authority_evidence((expected->>'stream_id')::BIGINT,(supplied->>'event_id')::UUID,(supplied->>'outbox_id')::UUID,
   (expected->>'sequence')::BIGINT,decode(expected->>'previous_hash','hex'),decode(supplied->>'event_hash','hex'),proof->>'aggregate_kind',(proof->>'aggregate_id')::UUID,
   (proof->>'aggregate_version')::BIGINT,(expected->>'network_revision')::BIGINT,NULL::UUID,proof->>'action','sharing.client_alias',NULL::UUID,NULL::BYTEA,NULL::BYTEA,
   (expected->>'audit_payload')::JSONB,'network.revision.advanced',(expected->>'outbox_payload')::JSONB);
  count_value:=count_value+1;
 END LOOP;
 PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);
 RETURN count_value;
EXCEPTION WHEN OTHERS THEN PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved); RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.finalize_device_alias_withdrawal_v2(UUID,UUID,BIGINT,UUID,TEXT,JSONB) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;

CREATE FUNCTION mesh_ops.prepare_device_alias_resource_quarantine_v2(p_deployment UUID,p_endpoint UUID,p_generation BIGINT,p_change UUID) RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE saved JSONB:=mesh_ops.save_device_alias_worker_context_v1(); endpoint mesh.private_endpoint%ROWTYPE; scope RECORD; proof JSONB; decision_at TIMESTAMPTZ;
 provider_revision BIGINT;provider_sharing BIGINT;consumer_revision BIGINT;consumer_sharing BIGINT;
BEGIN
 IF p_generation IS NULL OR p_generation<=0 OR p_change IS NULL OR get_byte(uuid_send(p_change),6)>>4<>7 THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid Device Resource quarantine';
 END IF;
 endpoint:=mesh_ops.derive_device_alias_worker_scope_v1(p_deployment,p_endpoint);
 PERFORM set_config('mesh.change_public_id',p_change::TEXT,TRUE);
 FOR scope IN SELECT * FROM (VALUES(endpoint.provider_workspace_id,endpoint.provider_network_id),(endpoint.consumer_workspace_id,endpoint.consumer_network_id)) AS scopes(workspace_id,network_id)
  ORDER BY workspace_id,network_id LOOP
  PERFORM network_id FROM mesh_ops.network_revision WHERE workspace_id=scope.workspace_id AND network_id=scope.network_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device Resource quarantine Network unavailable'; END IF;
 END LOOP;
 SELECT * INTO STRICT endpoint FROM mesh.private_endpoint WHERE public_id=p_endpoint FOR UPDATE;
 IF endpoint.generation<>p_generation OR endpoint.provider_network_id=endpoint.consumer_network_id OR endpoint.state='ready' THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device Resource quarantine endpoint changed';
 END IF;
 PERFORM id FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND alias_role='resource' ORDER BY id FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND alias_role='resource' AND state='reserved') THEN
  PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);RETURN jsonb_build_object('changed',FALSE,'events','[]'::JSONB);
 END IF;
 decision_at:=clock_timestamp();
 FOR scope IN SELECT * FROM (VALUES(endpoint.provider_workspace_id,endpoint.provider_network_id),(endpoint.consumer_workspace_id,endpoint.consumer_network_id)) AS scopes(workspace_id,network_id)
  ORDER BY workspace_id,network_id LOOP
  UPDATE mesh_ops.network_revision SET network_revision=network_revision+1,sharing_revision=sharing_revision+1,updated_at=decision_at WHERE workspace_id=scope.workspace_id AND network_id=scope.network_id;
 END LOOP;
 SELECT network_revision,sharing_revision INTO STRICT provider_revision,provider_sharing FROM mesh_ops.network_revision WHERE workspace_id=endpoint.provider_workspace_id AND network_id=endpoint.provider_network_id;
 SELECT network_revision,sharing_revision INTO STRICT consumer_revision,consumer_sharing FROM mesh_ops.network_revision WHERE workspace_id=endpoint.consumer_workspace_id AND network_id=endpoint.consumer_network_id;
 UPDATE mesh.device_alias_lease SET state='quarantined',version=version+1,updated_at=decision_at,quarantine_until=GREATEST(decision_at,expires_at,endpoint.expires_at)+INTERVAL '24 hours',
  provider_network_revision=provider_revision,provider_sharing_revision=provider_sharing,consumer_network_revision=consumer_revision,consumer_sharing_revision=consumer_sharing
  WHERE private_endpoint_id=endpoint.id AND alias_role='resource' AND state='reserved';
 proof:=mesh_ops.device_alias_withdrawal_proof_internal_v1(p_endpoint,p_change,'quarantine_resource');
 PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);RETURN proof;
EXCEPTION WHEN OTHERS THEN PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.prepare_device_alias_resource_quarantine_v2(UUID,UUID,BIGINT,UUID) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;

-- The worker scan admits every Network pair. The earlier policy text also
-- carried the Workspace inequality, so it is replaced rather than widened.
DROP POLICY private_endpoint_alias_worker_scan ON mesh.private_endpoint;
CREATE POLICY private_endpoint_alias_worker_scan ON mesh.private_endpoint FOR SELECT TO mesh_device_alias_writer
 USING(provider_network_id<>consumer_network_id AND NULLIF(current_setting('mesh.alias_worker_endpoint_public_id',TRUE),'') IS NULL
 AND EXISTS(SELECT 1 FROM mesh.deployment WHERE deployment.id=private_endpoint.deployment_id
  AND deployment.installation_public_id=NULLIF(current_setting('mesh.alias_worker_deployment_public_id',TRUE),'')::UUID));
CREATE FUNCTION mesh_ops.load_device_alias_work_v2(p_deployment UUID,p_after_endpoint UUID,p_after_consumer UUID,p_limit INTEGER) RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE saved JSONB:=mesh_ops.save_device_alias_worker_context_v1(); name TEXT; selected RECORD;
 endpoint mesh.private_endpoint%ROWTYPE; contract mesh.trust_contract%ROWTYPE; resource mesh.resource%ROWTYPE; provider mesh.device%ROWTYPE;
 consumer mesh.device%ROWTYPE; selected_consumer RECORD; mode TEXT; decision_at TIMESTAMPTZ;
 terminal_endpoint BOOLEAN; terminal_consumer BOOLEAN; eligible BOOLEAN; claim_count INTEGER;
 resource_reserved INTEGER; source_reserved INTEGER; source_count INTEGER; readiness_state TEXT; readiness_expiry TIMESTAMPTZ;
 work JSONB:='[]'; visited INTEGER:=0; endpoint_count INTEGER:=0; endpoint_ids UUID[]; next_endpoint UUID:=p_after_endpoint; next_consumer UUID:=p_after_consumer;
BEGIN
 IF p_deployment IS NULL OR p_limit IS NULL OR p_limit<1 OR p_limit>128 OR (p_after_consumer IS NOT NULL AND p_after_endpoint IS NULL) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid Device alias work cursor';
 END IF;
 -- Clearing the closed selector set prevents caller-controlled scope widening.
 FOR name IN SELECT jsonb_object_keys(saved) LOOP PERFORM set_config(name,'',TRUE); END LOOP;
 IF NOT EXISTS(SELECT 1 FROM mesh.deployment WHERE installation_public_id=p_deployment) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Device alias work Deployment unavailable';
 END IF;
 PERFORM set_config('mesh.alias_worker_deployment_public_id',p_deployment::TEXT,TRUE);
 SELECT array_agg(page.public_id ORDER BY page.public_id) INTO endpoint_ids FROM (SELECT pending.public_id FROM mesh.private_endpoint AS pending JOIN mesh.deployment ON deployment.id=pending.deployment_id
  WHERE deployment.installation_public_id=p_deployment AND pending.provider_network_id<>pending.consumer_network_id AND pending.state<>'ready'
   AND (p_after_endpoint IS NULL OR pending.public_id>p_after_endpoint OR pending.public_id=p_after_endpoint AND p_after_consumer IS NOT NULL)
  ORDER BY pending.public_id LIMIT 128) AS page;
 -- Materialize the bounded endpoint IDs before changing per-endpoint RLS
 -- context; lazy cursor fetch must never depend on a later selector.
 FOR selected IN SELECT public_id FROM unnest(endpoint_ids) AS public_id LOOP
  endpoint_count:=endpoint_count+1;
  endpoint:=mesh_ops.derive_device_alias_worker_scope_v1(p_deployment,selected.public_id);
  decision_at:=clock_timestamp();
  SELECT * INTO STRICT contract FROM mesh.trust_contract WHERE id=endpoint.trust_contract_id;
  SELECT * INTO STRICT resource FROM mesh.resource WHERE id=contract.resource_id;
  SELECT * INTO provider FROM mesh.device WHERE id=COALESCE(
    (SELECT device_id FROM mesh.resource_device_target WHERE resource_id=resource.id AND target_generation=resource.target_generation AND state='active'),
    (SELECT owner_device_id FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND alias_role='resource' ORDER BY id LIMIT 1));
  SELECT count(*) INTO resource_reserved FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND alias_role='resource' AND state='reserved';
  terminal_endpoint:=endpoint.state<>'provisioning' OR endpoint.expires_at<=decision_at OR contract.state<>'active' OR contract.expires_at<=decision_at
   OR contract.version<>endpoint.contract_version OR contract.constraint_hash<>endpoint.constraint_hash
   OR resource.kind<>'device' OR resource.state<>'active' OR resource.deleted_at IS NOT NULL OR resource.version<>contract.resource_version
   OR resource.target_generation<>contract.target_generation OR resource.semantic_hash<>contract.resource_semantic_hash
   OR provider.id IS NULL OR provider.state<>'active' OR provider.deleted_at IS NOT NULL OR provider.expires_at<=decision_at
   OR NOT EXISTS(SELECT 1 FROM mesh.deployment WHERE id=endpoint.deployment_id AND state='active' AND recovery_state='verified' AND recovery_epoch=endpoint.recovery_epoch)
   OR NOT EXISTS(SELECT 1 FROM mesh.resource_device_target WHERE resource_id=resource.id AND target_generation=resource.target_generation AND state='active' AND workspace_id=endpoint.provider_workspace_id AND network_id=endpoint.provider_network_id AND device_id=provider.id)
   OR NOT EXISTS(SELECT 1 FROM mesh.imported_resource WHERE id=endpoint.imported_resource_id AND state='active' AND version=endpoint.imported_resource_version AND trust_contract_id=contract.id)
   OR NOT EXISTS(SELECT 1 FROM mesh.workspace AS owner WHERE owner.id=endpoint.provider_workspace_id AND owner.state='active')
   OR NOT EXISTS(SELECT 1 FROM mesh.workspace AS owner WHERE owner.id=endpoint.consumer_workspace_id AND owner.state='active')
   OR NOT EXISTS(SELECT 1 FROM mesh.network WHERE id=endpoint.provider_network_id AND workspace_id=endpoint.provider_workspace_id AND state='active' AND authority_generation=endpoint.provider_authority_generation)
   OR NOT EXISTS(SELECT 1 FROM mesh.network WHERE id=endpoint.consumer_network_id AND workspace_id=endpoint.consumer_workspace_id AND state='active' AND authority_generation=endpoint.consumer_authority_generation)
   OR EXISTS(SELECT 1 FROM mesh.device_alias_lease AS lease WHERE private_endpoint_id=endpoint.id AND alias_role='resource' AND state='reserved'
    AND (owner_device_id IS DISTINCT FROM provider.id OR expires_at<=decision_at OR session_generation IS DISTINCT FROM provider.session_generation
      OR machine_key_epoch IS DISTINCT FROM provider.current_machine_key_epoch OR node_key_epoch IS DISTINCT FROM provider.current_node_key_epoch
      OR NOT EXISTS(SELECT 1 FROM mesh.device_node_key_epoch WHERE device_id=provider.id AND epoch=provider.current_node_key_epoch AND state='active' AND public_key=lease.node_public_key)))
   OR NOT EXISTS(SELECT 1 FROM mesh.share_offer AS offer JOIN mesh.resource_export AS export ON export.id=contract.resource_export_id
    WHERE offer.id=contract.share_offer_id AND offer.state='accepted' AND offer.accepted_contract_public_id=contract.public_id
     AND export.state='active' AND export.resource_id=contract.resource_id
     AND export.resource_version=contract.resource_version AND export.target_generation=contract.target_generation
     AND export.resource_semantic_hash=contract.resource_semantic_hash AND export.constraint_hash=contract.constraint_hash
     AND export.expires_at>=contract.expires_at AND export.provider_authority_generation=contract.provider_authority_generation
     AND (export.provider_workspace_id,export.provider_network_id,export.consumer_workspace_id,export.consumer_network_id)=
      (endpoint.provider_workspace_id,endpoint.provider_network_id,endpoint.consumer_workspace_id,endpoint.consumer_network_id));
  -- Endpoint-level cleanup is independent of consumer retention. Resource
  -- quarantine invalidates every dependent projection before later cleanup.
  IF terminal_endpoint AND resource_reserved>0 THEN
   work:=work||jsonb_build_array(jsonb_build_object('endpoint_id',endpoint.public_id,'consumer_id',NULL,'generation',endpoint.generation,
    'provider_node_epoch',0,'consumer_node_epoch',0,'mode','quarantine_resource'));
   visited:=visited+1;next_endpoint:=endpoint.public_id;next_consumer:=NULL;
   IF visited=p_limit THEN
    PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);
    RETURN jsonb_build_object('items',work,'cursor',jsonb_build_object('endpoint_id',next_endpoint,'consumer_id',NULL),'done',FALSE);
   END IF;
   CONTINUE;
  END IF;
  FOR selected_consumer IN SELECT device.public_id FROM mesh.device AS device WHERE device.workspace_id=endpoint.consumer_workspace_id AND device.network_id=endpoint.consumer_network_id
   AND (endpoint.public_id IS DISTINCT FROM p_after_endpoint OR p_after_consumer IS NULL OR device.public_id>p_after_consumer)
   AND device.id IN (
    SELECT source_device_id FROM mesh.compiled_policy_imported_resource_destination WHERE imported_resource_id=endpoint.imported_resource_id AND trust_contract_id=contract.id
    UNION SELECT owner_device_id FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND alias_role='consumer_source'
    UNION SELECT consumer_device_id FROM mesh.device_alias_client_readiness WHERE private_endpoint_id=endpoint.id)
   ORDER BY device.public_id LIMIT p_limit-visited LOOP
   SELECT * INTO STRICT consumer FROM mesh.device WHERE public_id=selected_consumer.public_id;
   next_endpoint:=endpoint.public_id; next_consumer:=consumer.public_id; visited:=visited+1; mode:=NULL;
   SELECT count(*),count(*) FILTER(WHERE state='reserved') INTO source_count,source_reserved FROM mesh.device_alias_lease
    WHERE private_endpoint_id=endpoint.id AND alias_role='consumer_source' AND owner_device_id=consumer.id;
   SELECT state,expires_at INTO readiness_state,readiness_expiry FROM mesh.device_alias_client_readiness WHERE private_endpoint_id=endpoint.id AND consumer_device_id=consumer.id;
   terminal_consumer:=consumer.state<>'active' OR consumer.deleted_at IS NOT NULL OR consumer.expires_at<=decision_at OR readiness_state='withdrawn' OR readiness_expiry<=decision_at
    OR EXISTS(SELECT 1 FROM mesh.device_alias_lease AS lease WHERE private_endpoint_id=endpoint.id AND alias_role='consumer_source' AND owner_device_id=consumer.id AND state='reserved'
     AND (expires_at<=decision_at OR session_generation<>consumer.session_generation OR machine_key_epoch<>consumer.current_machine_key_epoch OR node_key_epoch<>consumer.current_node_key_epoch
      OR NOT EXISTS(SELECT 1 FROM mesh.device_node_key_epoch WHERE device_id=consumer.id AND epoch=consumer.current_node_key_epoch AND state='active' AND public_key=lease.node_public_key)));
   IF (terminal_endpoint OR COALESCE(terminal_consumer,FALSE)) AND readiness_state='ready' THEN mode:='withdraw';
   ELSIF (terminal_endpoint OR COALESCE(terminal_consumer,FALSE)) AND source_reserved>0 THEN mode:='quarantine_consumer';
   ELSIF NOT terminal_endpoint AND NOT COALESCE(terminal_consumer,FALSE) AND readiness_state IS NULL THEN
    SELECT EXISTS(SELECT 1 FROM mesh.compiled_policy_imported_resource_destination AS rule
     JOIN mesh.policy_release AS release ON release.id=rule.policy_release_id AND release.state='active'
     JOIN mesh_ops.network_revision AS revision ON revision.workspace_id=rule.workspace_id AND revision.network_id=rule.network_id AND revision.policy_revision=release.policy_revision
     WHERE rule.workspace_id=endpoint.consumer_workspace_id AND rule.network_id=endpoint.consumer_network_id AND rule.source_device_id=consumer.id
      AND rule.trust_contract_id=contract.id AND rule.imported_resource_id=endpoint.imported_resource_id AND rule.policy_revision=release.policy_revision) INTO eligible;
    SELECT count(DISTINCT device_id) INTO claim_count FROM mesh.device_alias_client_version WHERE device_id IN (provider.id,consumer.id)
     AND alias_version=1 AND (device_id=provider.id AND session_generation=provider.session_generation AND machine_key_epoch=provider.current_machine_key_epoch AND node_key_epoch=provider.current_node_key_epoch
      OR device_id=consumer.id AND session_generation=consumer.session_generation AND machine_key_epoch=consumer.current_machine_key_epoch AND node_key_epoch=consumer.current_node_key_epoch);
    IF eligible AND claim_count=2 THEN
     IF source_count=0 AND NOT EXISTS(SELECT 1 FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND alias_role='resource' AND state<>'reserved') THEN mode:='reserve';
     ELSIF source_reserved>0 AND resource_reserved>0 THEN mode:='ready'; END IF;
    END IF;
   END IF;
   IF mode IS NOT NULL THEN work:=work||jsonb_build_array(jsonb_build_object('endpoint_id',endpoint.public_id,'consumer_id',consumer.public_id,
    'generation',endpoint.generation,'provider_node_epoch',COALESCE(provider.current_node_key_epoch,0),'consumer_node_epoch',consumer.current_node_key_epoch,'mode',mode)); END IF;
   IF visited=p_limit THEN
    PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);
    RETURN jsonb_build_object('items',work,'cursor',jsonb_build_object('endpoint_id',next_endpoint,'consumer_id',next_consumer),'done',FALSE);
   END IF;
  END LOOP;
  next_endpoint:=endpoint.public_id; next_consumer:=NULL;
 END LOOP;
 PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);
 RETURN jsonb_build_object('items',work,'cursor',jsonb_build_object('endpoint_id',next_endpoint,'consumer_id',next_consumer),'done',endpoint_count<128);
EXCEPTION WHEN OTHERS THEN PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved); RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.load_device_alias_work_v2(UUID,UUID,UUID,INTEGER) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;
