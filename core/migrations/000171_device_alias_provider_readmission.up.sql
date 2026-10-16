-- Schema 171: give a resumed provider Device its shares back.
--
-- When the provider Device of a client-only share stopped being authorized
-- (suspended, its session or keys changed), the alias worker quarantined the
-- endpoint's Resource aliases. A Resource lease kept its slot for good (one
-- per endpoint and family), the worker reserved only while no Resource lease
-- was anything but reserved, and reserve v4 refused the quarantined one. So
-- after the Device was resumed the endpoint stayed without Resource aliases
-- and every consumer Device lost the share until it was revoked and created
-- again. The share's DNS name points at the endpoint's Resource Alias, so the
-- endpoint must get the same addresses back, not new ones.
-- Now each admission is new rows; the old ones stay as history:
--   * at most one reserved Resource lease per endpoint and family (a partial
--     unique index) replaces the unique index over every Resource lease;
--   * the uniqueness trigger on device_alias_lease (v3) is v2 that lets a new
--     Resource lease share its address with the quarantined Resource leases
--     of the same endpoint, owner Device and family, as v2 does for source
--     leases, and with nothing else;
--   * reserve_device_aliases_internal_v5 is v4 that only reuses a reserved
--     Resource lease, checks the address families against reserved Resource
--     leases only, and gives a resumed provider Device the endpoint's own
--     quarantined Resource alias of the other family back whatever its keys
--     (the Resource Alias family always gets the endpoint's Resource Alias);
--   * prepare_device_alias_change_v5 is v4 that calls reserve v5;
--   * load_device_alias_work_v4 is v3 that reserves when the pair lacks
--     either reserved source or reserved Resource leases, and makes ready
--     otherwise. Every other check is v3's: a provider that is not active on
--     current keys, the Resource's current target and an active, accepted
--     contract keeps the endpoint terminal, and prepare v5 rechecks the whole
--     authority under its locks as before.
-- The worker uses load v4 and prepare v5 once the operator step hands both
-- to it. Previous versions stay for the previous binary; they fail closed on
-- the history rows.

CREATE UNIQUE INDEX device_alias_resource_reserved_uidx
    ON mesh.device_alias_lease (private_endpoint_id, family) WHERE alias_role = 'resource' AND state = 'reserved';
DROP INDEX mesh.device_alias_resource_owner_uidx;

CREATE FUNCTION mesh_ops.enforce_device_alias_network_uniqueness_v3()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
DECLARE
    legacy_lease_id BIGINT;
BEGIN
    IF NEW.alias_role = 'resource' THEN
        SELECT endpoint.alias_lease_id INTO legacy_lease_id FROM mesh.private_endpoint AS endpoint
        WHERE endpoint.id = NEW.private_endpoint_id AND endpoint.resource_alias = NEW.address;
    END IF;
    IF EXISTS (
        SELECT 1 FROM mesh.device_alias_lease AS lease
        WHERE lease.deployment_id = NEW.deployment_id AND lease.address = NEW.address
          AND lease.state IN ('reserved', 'quarantined')
          AND lease.id IS DISTINCT FROM NEW.id
          AND (lease.provider_network_id IN (NEW.provider_network_id, NEW.consumer_network_id)
            OR lease.consumer_network_id IN (NEW.provider_network_id, NEW.consumer_network_id))
          AND NOT (lease.state = 'quarantined'
            AND lease.private_endpoint_id = NEW.private_endpoint_id AND lease.alias_role = NEW.alias_role
            AND lease.owner_device_id = NEW.owner_device_id AND lease.family = NEW.family)
    ) OR EXISTS (
        SELECT 1 FROM mesh.federation_alias_lease AS lease
        WHERE lease.deployment_id = NEW.deployment_id AND lease.resource_alias = NEW.address
          AND lease.state IN ('reserved', 'active')
          AND lease.id IS DISTINCT FROM legacy_lease_id
          AND (lease.provider_network_id IN (NEW.provider_network_id, NEW.consumer_network_id)
            OR lease.consumer_network_id IN (NEW.provider_network_id, NEW.consumer_network_id))
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'alias address is retained in a participating Network';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enforce_device_alias_network_uniqueness_v3() FROM PUBLIC;
DROP TRIGGER device_alias_network_uniqueness ON mesh.device_alias_lease;
CREATE TRIGGER device_alias_network_uniqueness BEFORE INSERT ON mesh.device_alias_lease
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_device_alias_network_uniqueness_v3();

CREATE FUNCTION mesh_ops.reserve_device_aliases_internal_v5(
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
        WHERE lease.private_endpoint_id = endpoint_row.id AND lease.alias_role = 'resource' AND lease.state = 'reserved')
        AND (SELECT count(*) FROM mesh.device_alias_lease AS lease
            WHERE lease.private_endpoint_id = endpoint_row.id AND lease.alias_role = 'resource' AND lease.state = 'reserved')
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
            WHERE lease.private_endpoint_id = endpoint_row.id AND lease.alias_role = 'consumer_source') >= 10000 THEN
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
              AND lease.family = family_value AND lease.owner_device_id = owner_device.id
              AND lease.state = 'reserved';
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
                -- A readmitted consumer Device gets its own quarantined source
                -- alias back while its keys are unchanged; it is retained in
                -- both Networks, so no other Device can hold it.
                candidate := NULL;
                IF role_value = 'consumer_source' THEN
                    SELECT lease.address INTO candidate FROM mesh.device_alias_lease AS lease
                    WHERE lease.private_endpoint_id = endpoint_row.id AND lease.alias_role = role_value
                      AND lease.family = family_value AND lease.owner_device_id = owner_device.id
                      AND lease.state = 'quarantined' AND lease.address_pool_id = pool_row.id
                      AND lease.address << pool_row.prefix AND lease.node_public_key = node_key
                      AND lease.machine_key_epoch = owner_device.current_machine_key_epoch
                    ORDER BY lease.id DESC LIMIT 1;
                ELSE
                    -- A resumed provider Device gets the endpoint's own
                    -- quarantined Resource alias back whatever its keys: the
                    -- share's name points at it. It is retained in both
                    -- Networks, so no other endpoint can hold it.
                    SELECT lease.address INTO candidate FROM mesh.device_alias_lease AS lease
                    WHERE lease.private_endpoint_id = endpoint_row.id AND lease.alias_role = role_value
                      AND lease.family = family_value AND lease.owner_device_id = owner_device.id
                      AND lease.state = 'quarantined' AND lease.address_pool_id = pool_row.id
                      AND lease.address << pool_row.prefix
                    ORDER BY lease.id DESC LIMIT 1;
                END IF;
                IF candidate IS NULL THEN
                    candidate := mesh_ops.allocate_network_scoped_alias_v1(endpoint_row.deployment_id,
                        pool_row.id, endpoint_row.provider_network_id, endpoint_row.consumer_network_id);
                END IF;
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
REVOKE ALL ON FUNCTION mesh_ops.reserve_device_aliases_internal_v5(UUID, UUID, BIGINT, BIGINT, BIGINT, UUID[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_share_writer, mesh_audit_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.reserve_device_aliases_internal_v5(UUID, UUID, BIGINT, BIGINT, BIGINT, UUID[])
    TO mesh_device_alias_writer;

CREATE FUNCTION mesh_ops.prepare_device_alias_change_v5(p_deployment UUID,p_endpoint UUID,p_consumer UUID,p_generation BIGINT,
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
 PERFORM mesh_ops.reserve_device_aliases_internal_v5(p_endpoint,p_consumer,p_generation,p_provider_node_epoch,p_consumer_node_epoch,p_leases);
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
  IF NOT EXISTS(SELECT 1 FROM mesh.device_alias_client_readiness WHERE private_endpoint_id=endpoint.id AND consumer_device_id=consumer.id AND state='ready') THEN
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
  IF NOT EXISTS(SELECT 1 FROM mesh_ops.load_device_alias_map_endpoint_edges_v1(fingerprint,node_key,p_endpoint) AS edge
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
REVOKE ALL ON FUNCTION mesh_ops.prepare_device_alias_change_v5(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;

CREATE FUNCTION mesh_ops.load_device_alias_work_v4(p_deployment UUID,p_after_endpoint UUID,p_after_consumer UUID,p_limit INTEGER) RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE saved JSONB:=mesh_ops.save_device_alias_worker_context_v1(); name TEXT; selected RECORD;
 endpoint mesh.private_endpoint%ROWTYPE; contract mesh.trust_contract%ROWTYPE; resource mesh.resource%ROWTYPE; provider mesh.device%ROWTYPE;
 consumer mesh.device%ROWTYPE; selected_consumer RECORD; mode TEXT; decision_at TIMESTAMPTZ;
 terminal_endpoint BOOLEAN; terminal_consumer BOOLEAN; eligible BOOLEAN; claim_count INTEGER;
 resource_reserved INTEGER; source_reserved INTEGER; source_count INTEGER; readiness_state TEXT; readiness_expiry TIMESTAMPTZ; readiness_leases UUID[];
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
   SELECT state,expires_at,lease_public_ids INTO readiness_state,readiness_expiry,readiness_leases FROM mesh.device_alias_client_readiness
    WHERE private_endpoint_id=endpoint.id AND consumer_device_id=consumer.id ORDER BY state='ready' DESC,id DESC LIMIT 1;
   terminal_consumer:=consumer.state<>'active' OR consumer.deleted_at IS NOT NULL OR consumer.expires_at<=decision_at OR readiness_state='ready' AND (readiness_expiry<=decision_at
     OR EXISTS(SELECT 1 FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND public_id=ANY(readiness_leases) AND state<>'reserved'))
    OR EXISTS(SELECT 1 FROM mesh.device_alias_lease AS lease WHERE private_endpoint_id=endpoint.id AND alias_role='consumer_source' AND owner_device_id=consumer.id AND state='reserved'
     AND (expires_at<=decision_at OR session_generation<>consumer.session_generation OR machine_key_epoch<>consumer.current_machine_key_epoch OR node_key_epoch<>consumer.current_node_key_epoch
      OR NOT EXISTS(SELECT 1 FROM mesh.device_node_key_epoch WHERE device_id=consumer.id AND epoch=consumer.current_node_key_epoch AND state='active' AND public_key=lease.node_public_key)));
   IF (terminal_endpoint OR COALESCE(terminal_consumer,FALSE)) AND readiness_state='ready' THEN mode:='withdraw';
   ELSIF (terminal_endpoint OR COALESCE(terminal_consumer,FALSE)) AND source_reserved>0 THEN mode:='quarantine_consumer';
   ELSIF NOT terminal_endpoint AND NOT COALESCE(terminal_consumer,FALSE) AND readiness_state IS DISTINCT FROM 'ready' THEN
    SELECT EXISTS(SELECT 1 FROM mesh.compiled_policy_imported_resource_destination AS rule
     JOIN mesh.policy_release AS release ON release.id=rule.policy_release_id AND release.state='active'
     JOIN mesh_ops.network_revision AS revision ON revision.workspace_id=rule.workspace_id AND revision.network_id=rule.network_id AND revision.policy_revision=release.policy_revision
     WHERE rule.workspace_id=endpoint.consumer_workspace_id AND rule.network_id=endpoint.consumer_network_id AND rule.source_device_id=consumer.id
      AND rule.trust_contract_id=contract.id AND rule.imported_resource_id=endpoint.imported_resource_id AND rule.policy_revision=release.policy_revision) INTO eligible;
    SELECT count(DISTINCT device_id) INTO claim_count FROM mesh.device_alias_client_version WHERE device_id IN (provider.id,consumer.id)
     AND alias_version=1 AND (device_id=provider.id AND session_generation=provider.session_generation AND machine_key_epoch=provider.current_machine_key_epoch AND node_key_epoch=provider.current_node_key_epoch
      OR device_id=consumer.id AND session_generation=consumer.session_generation AND machine_key_epoch=consumer.current_machine_key_epoch AND node_key_epoch=consumer.current_node_key_epoch);
    IF eligible AND claim_count=2 THEN
     IF source_reserved=0 OR resource_reserved=0 THEN mode:='reserve';
     ELSE mode:='ready'; END IF;
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
REVOKE ALL ON FUNCTION mesh_ops.load_device_alias_work_v4(UUID,UUID,UUID,INTEGER) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;
