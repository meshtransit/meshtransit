-- Storage foundation only. No serving role can reserve, read or publish these
-- aliases. Reservation does not change Private Endpoint readiness or packet ACLs.
-- Migration-only configuration reads. The derived Deployment setting is local
-- to the internal function; serving roles receive no new policy or privilege.
CREATE POLICY address_realm_alias_migrator_read ON mesh.address_realm FOR SELECT TO mesh_migrator
    USING (kind = 'federation_alias' AND deployment_id = NULLIF(
        pg_catalog.current_setting('mesh.device_alias_deployment_id', TRUE), '')::BIGINT);
CREATE POLICY address_realm_alias_migrator_lock ON mesh.address_realm FOR UPDATE TO mesh_migrator
    USING (kind = 'federation_alias' AND deployment_id = NULLIF(
        pg_catalog.current_setting('mesh.device_alias_deployment_id', TRUE), '')::BIGINT)
    WITH CHECK (kind = 'federation_alias' AND deployment_id = NULLIF(
        pg_catalog.current_setting('mesh.device_alias_deployment_id', TRUE), '')::BIGINT);
CREATE POLICY address_pool_alias_migrator_read ON mesh.address_pool FOR SELECT TO mesh_migrator
    USING (deployment_id = NULLIF(pg_catalog.current_setting('mesh.device_alias_deployment_id', TRUE), '')::BIGINT);
CREATE POLICY address_pool_alias_migrator_lock ON mesh.address_pool FOR UPDATE TO mesh_migrator
    USING (workspace_id IS NULL AND deployment_id = NULLIF(
        pg_catalog.current_setting('mesh.device_alias_deployment_id', TRUE), '')::BIGINT)
    WITH CHECK (workspace_id IS NULL AND deployment_id = NULLIF(
        pg_catalog.current_setting('mesh.device_alias_deployment_id', TRUE), '')::BIGINT);

CREATE TABLE mesh.device_alias_lease (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE CHECK (pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7),
    deployment_id BIGINT NOT NULL,
    address_realm_id BIGINT NOT NULL,
    address_pool_id BIGINT NOT NULL,
    provider_workspace_id BIGINT NOT NULL,
    provider_network_id BIGINT NOT NULL,
    consumer_workspace_id BIGINT NOT NULL,
    consumer_network_id BIGINT NOT NULL,
    private_endpoint_id BIGINT NOT NULL,
    endpoint_generation BIGINT NOT NULL CHECK (endpoint_generation > 0),
    recovery_epoch BIGINT NOT NULL CHECK (recovery_epoch > 0),
    resource_version BIGINT NOT NULL CHECK (resource_version > 0),
    target_generation BIGINT NOT NULL CHECK (target_generation > 0),
    owner_workspace_id BIGINT NOT NULL,
    owner_network_id BIGINT NOT NULL,
    owner_device_id BIGINT NOT NULL,
    session_generation BIGINT NOT NULL CHECK (session_generation > 0),
    machine_key_epoch BIGINT NOT NULL CHECK (machine_key_epoch > 0),
    node_key_epoch BIGINT NOT NULL CHECK (node_key_epoch > 0),
    node_public_key BYTEA NOT NULL CHECK (pg_catalog.octet_length(node_public_key) = 32
        AND node_public_key <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')),
    alias_role TEXT NOT NULL CHECK (alias_role IN ('resource', 'consumer_source')),
    family INTEGER NOT NULL CHECK (family IN (4, 6)),
    address INET NOT NULL CHECK (family = pg_catalog.family(address)
        AND pg_catalog.masklen(address) = CASE family WHEN 4 THEN 32 ELSE 128 END),
    expires_at TIMESTAMPTZ NOT NULL CHECK (pg_catalog.isfinite(expires_at)),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'quarantined', 'released')),
    quarantine_until TIMESTAMPTZ,
    provider_network_revision BIGINT NOT NULL CHECK (provider_network_revision > 0),
    provider_sharing_revision BIGINT NOT NULL CHECK (provider_sharing_revision > 0),
    consumer_network_revision BIGINT NOT NULL CHECK (consumer_network_revision > 0),
    consumer_sharing_revision BIGINT NOT NULL CHECK (consumer_sharing_revision > 0),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (provider_workspace_id <> consumer_workspace_id),
    CHECK ((alias_role = 'resource' AND owner_workspace_id = provider_workspace_id
            AND owner_network_id = provider_network_id)
        OR (alias_role = 'consumer_source' AND owner_workspace_id = consumer_workspace_id
            AND owner_network_id = consumer_network_id)),
    CHECK (updated_at >= created_at AND expires_at > created_at),
    CHECK ((state = 'reserved' AND quarantine_until IS NULL)
        OR (state IN ('quarantined', 'released') AND quarantine_until IS NOT NULL
            AND pg_catalog.isfinite(quarantine_until) AND quarantine_until > created_at)),
    FOREIGN KEY (deployment_id, address_realm_id)
        REFERENCES mesh.address_realm (deployment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (deployment_id, address_pool_id)
        REFERENCES mesh.address_pool (deployment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id, private_endpoint_id)
        REFERENCES mesh.private_endpoint (provider_workspace_id, provider_network_id,
            consumer_workspace_id, consumer_network_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (owner_workspace_id, owner_network_id, owner_device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (owner_workspace_id, owner_network_id, owner_device_id, machine_key_epoch)
        REFERENCES mesh.device_machine_key_epoch (workspace_id, network_id, device_id, epoch) ON DELETE RESTRICT,
    FOREIGN KEY (owner_workspace_id, owner_network_id, owner_device_id, node_key_epoch)
        REFERENCES mesh.device_node_key_epoch (workspace_id, network_id, device_id, epoch) ON DELETE RESTRICT,
    -- Retain the owner slot after withdrawal. A retry can never renew this generation.
    UNIQUE (private_endpoint_id, alias_role, owner_device_id, family)
);
CREATE UNIQUE INDEX device_alias_address_retained_uidx
    ON mesh.device_alias_lease (deployment_id, address)
    WHERE state IN ('reserved', 'quarantined');
CREATE UNIQUE INDEX device_alias_resource_owner_uidx
    ON mesh.device_alias_lease (private_endpoint_id, family) WHERE alias_role = 'resource';
CREATE INDEX device_alias_endpoint_idx ON mesh.device_alias_lease (private_endpoint_id, id);
ALTER TABLE mesh.device_alias_lease ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.device_alias_lease FORCE ROW LEVEL SECURITY;
CREATE POLICY device_alias_migrator_policy ON mesh.device_alias_lease
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.device_alias_lease FROM PUBLIC, mesh_runtime, mesh_worker,
    mesh_observer, mesh_share_writer, mesh_audit_writer;
REVOKE ALL ON SEQUENCE mesh.device_alias_lease_id_seq FROM PUBLIC, mesh_runtime,
    mesh_worker, mesh_observer, mesh_share_writer, mesh_audit_writer;

CREATE FUNCTION mesh_ops.enforce_device_alias_transition_v1()
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
        IF EXISTS (SELECT 1 FROM mesh.federation_alias_lease AS lease
            WHERE lease.deployment_id = NEW.deployment_id AND lease.resource_alias = NEW.address
              AND NOT (NEW.alias_role = 'resource' AND EXISTS (
                  SELECT 1 FROM mesh.private_endpoint AS endpoint WHERE endpoint.id = NEW.private_endpoint_id
                    AND endpoint.alias_lease_id = lease.id AND endpoint.resource_alias = NEW.address
                    AND endpoint.generation = NEW.endpoint_generation))) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Device alias conflicts with a retained legacy owner';
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
REVOKE ALL ON FUNCTION mesh_ops.enforce_device_alias_transition_v1() FROM PUBLIC;
CREATE TRIGGER device_alias_transition BEFORE INSERT OR UPDATE OR DELETE ON mesh.device_alias_lease
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_device_alias_transition_v1();
CREATE TRIGGER device_alias_authority_mutation AFTER INSERT OR UPDATE OR DELETE ON mesh.device_alias_lease
    FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('device_alias_lease', 'public_id');

-- Each mutation needs evidence in BOTH exact Network streams at the revisions
-- written into the lease. One unrelated audit event cannot cover a bilateral change.
CREATE FUNCTION mesh_audit.enforce_device_alias_evidence_v1()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
DECLARE change_id UUID; side RECORD; endpoint_public_id UUID; mutated_leases JSONB;
BEGIN
    SELECT mutation.change_public_id INTO STRICT change_id
    FROM mesh_audit.authority_mutation AS mutation
    WHERE mutation.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
      AND mutation.aggregate_kind = 'device_alias_lease' AND mutation.row_public_id = NEW.public_id
      AND mutation.after_version = NEW.version;
    SELECT endpoint.public_id INTO STRICT endpoint_public_id FROM mesh.private_endpoint AS endpoint
    WHERE endpoint.id = NEW.private_endpoint_id;
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('public_id', lease.public_id,
        'version', mutation.after_version) ORDER BY lease.public_id)
    INTO mutated_leases FROM mesh_audit.authority_mutation AS mutation
    JOIN mesh.device_alias_lease AS lease ON lease.public_id = mutation.row_public_id
    WHERE mutation.change_public_id = change_id
      AND mutation.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
      AND mutation.aggregate_kind = 'device_alias_lease' AND lease.private_endpoint_id = NEW.private_endpoint_id;
    FOR side IN SELECT * FROM (VALUES
        (NEW.provider_workspace_id, NEW.provider_network_id, NEW.provider_network_revision, NEW.provider_sharing_revision),
        (NEW.consumer_workspace_id, NEW.consumer_network_id, NEW.consumer_network_revision, NEW.consumer_sharing_revision)
    ) AS scopes(workspace_id, network_id, network_revision, sharing_revision)
    LOOP
        IF NOT EXISTS (SELECT 1 FROM mesh_audit.audit_event_identity AS identity
            JOIN mesh_audit.audit_event AS event ON event.event_identity_id = identity.id
                AND event.occurred_at = identity.occurred_at
            JOIN mesh_audit.audit_stream AS stream ON stream.id = identity.stream_id
            WHERE identity.change_public_id = change_id
              AND identity.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
              AND stream.workspace_id = side.workspace_id AND stream.network_id = side.network_id
              AND event.target_kind = 'device_alias_lease'
              AND event.payload ->> 'endpoint_public_id' = endpoint_public_id::TEXT
              AND event.payload -> 'mutated_leases' = mutated_leases
              AND event.payload ->> 'network_revision' = side.network_revision::TEXT
              AND event.payload ->> 'sharing_revision' = side.sharing_revision::TEXT)
            OR NOT EXISTS (SELECT 1 FROM mesh_ops.outbox_event AS event
                WHERE event.change_public_id = change_id
                  AND event.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
                  AND event.workspace_id = side.workspace_id AND event.network_id = side.network_id
                  AND event.network_revision = side.network_revision
                  AND event.aggregate_kind = 'device_alias_lease'
                  AND event.payload ->> 'endpoint_public_id' = endpoint_public_id::TEXT
                  AND event.payload ->> 'subsystem' = 'sharing'
                  AND event.payload ->> 'subsystem_revision' = side.sharing_revision::TEXT) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'bilateral Device alias evidence is incomplete';
        END IF;
    END LOOP;
    RETURN NULL;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_audit.enforce_device_alias_evidence_v1() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER device_alias_evidence AFTER INSERT OR UPDATE ON mesh.device_alias_lease
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION mesh_audit.enforce_device_alias_evidence_v1();

-- An internal, invoker-only migration capability. A reviewed worker command and
-- authenticated projection reader are required before runtime activation.
CREATE FUNCTION mesh_ops.reserve_device_aliases_internal_v1(
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
        OR endpoint_row.provider_workspace_id = endpoint_row.consumer_workspace_id
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
                SELECT cursor.next_offset INTO allocation_offset FROM mesh_ops.federation_alias_pool_cursor AS cursor
                WHERE cursor.address_pool_id = pool_row.id;
                maximum_offset := (1::BIGINT << (CASE family_value WHEN 4 THEN 32 ELSE 128 END
                    - pg_catalog.masklen(pool_row.prefix))) - CASE family_value WHEN 4 THEN 2 ELSE 1 END;
                candidate := NULL;
                FOR attempt IN 1..65536 LOOP
                    IF allocation_offset > maximum_offset THEN EXIT; END IF;
                    candidate := pg_catalog.set_masklen(pg_catalog.network(pool_row.prefix) + allocation_offset,
                        CASE family_value WHEN 4 THEN 32 ELSE 128 END);
                    allocation_offset := allocation_offset + 1;
                    IF NOT EXISTS (SELECT 1 FROM mesh.device_alias_lease AS lease
                            WHERE lease.deployment_id = endpoint_row.deployment_id AND lease.address = candidate
                              AND lease.state IN ('reserved', 'quarantined'))
                        AND NOT EXISTS (SELECT 1 FROM mesh.federation_alias_lease AS lease
                            WHERE lease.deployment_id = endpoint_row.deployment_id AND lease.resource_alias = candidate)
                        AND NOT EXISTS (SELECT 1 FROM mesh.node_address_lease AS lease
                            WHERE lease.address = candidate AND lease.state IN ('active', 'quarantined')) THEN EXIT; END IF;
                    candidate := NULL;
                END LOOP;
                IF candidate IS NULL THEN
                    RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Device alias candidate window is exhausted';
                END IF;
                UPDATE mesh_ops.federation_alias_pool_cursor AS cursor SET next_offset = allocation_offset,
                    version = cursor.version + 1, updated_at = decision_at WHERE cursor.address_pool_id = pool_row.id;
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
REVOKE ALL ON FUNCTION mesh_ops.reserve_device_aliases_internal_v1(UUID, UUID, BIGINT, BIGINT, BIGINT, UUID[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_share_writer, mesh_audit_writer;

CREATE FUNCTION mesh_ops.quarantine_device_aliases_internal_v1(
    p_endpoint_public_id UUID, p_expected_generation BIGINT, p_quarantine_until TIMESTAMPTZ
)
RETURNS BIGINT
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY INVOKER SET search_path = pg_catalog
AS $function$
DECLARE endpoint_row mesh.private_endpoint%ROWTYPE; decision_at TIMESTAMPTZ; revision_scope RECORD;
    provider_revision BIGINT; provider_sharing BIGINT;
    consumer_revision BIGINT; consumer_sharing BIGINT; changed_count BIGINT;
    prior_workspace TEXT := pg_catalog.current_setting('mesh.workspace_id', TRUE);
    prior_network TEXT := pg_catalog.current_setting('mesh.network_id', TRUE);
    prior_deployment TEXT := pg_catalog.current_setting('mesh.device_alias_deployment_id', TRUE);
    prior_share_provider_workspace_id TEXT := pg_catalog.current_setting('mesh.share_provider_workspace_id', TRUE);
    prior_share_provider_network_id TEXT := pg_catalog.current_setting('mesh.share_provider_network_id', TRUE);
    prior_share_consumer_workspace_id TEXT := pg_catalog.current_setting('mesh.share_consumer_workspace_id', TRUE);
    prior_share_consumer_network_id TEXT := pg_catalog.current_setting('mesh.share_consumer_network_id', TRUE);
BEGIN
    IF p_endpoint_public_id IS NULL OR p_expected_generation IS NULL OR p_expected_generation <= 0
        OR p_quarantine_until IS NULL OR NOT pg_catalog.isfinite(p_quarantine_until) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Device alias quarantine';
    END IF;
    SELECT endpoint.* INTO STRICT endpoint_row FROM mesh.private_endpoint AS endpoint
    WHERE endpoint.public_id = p_endpoint_public_id;
    PERFORM pg_catalog.set_config('mesh.share_provider_workspace_id', endpoint_row.provider_workspace_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_network_id', endpoint_row.provider_network_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_workspace_id', endpoint_row.consumer_workspace_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_network_id', endpoint_row.consumer_network_id::TEXT, TRUE);
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
    PERFORM lease.id FROM mesh.device_alias_lease AS lease
    WHERE lease.private_endpoint_id = endpoint_row.id ORDER BY lease.id FOR UPDATE;
    decision_at := pg_catalog.clock_timestamp();
    IF endpoint_row.generation <> p_expected_generation
        OR p_quarantine_until < GREATEST(endpoint_row.expires_at, decision_at) + INTERVAL '24 hours' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Device alias quarantine does not cover stale grants';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM mesh.device_alias_lease AS lease
        WHERE lease.private_endpoint_id = endpoint_row.id AND lease.state = 'reserved') THEN
    PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(prior_workspace, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(prior_network, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', COALESCE(prior_deployment, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_workspace_id', COALESCE(prior_share_provider_workspace_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_network_id', COALESCE(prior_share_provider_network_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_workspace_id', COALESCE(prior_share_consumer_workspace_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_network_id', COALESCE(prior_share_consumer_network_id, ''), TRUE);
        RETURN 0;
    END IF;
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
    UPDATE mesh.device_alias_lease AS lease SET state = 'quarantined',
        quarantine_until = p_quarantine_until, version = lease.version + 1, updated_at = decision_at,
        provider_network_revision = provider_revision, provider_sharing_revision = provider_sharing,
        consumer_network_revision = consumer_revision, consumer_sharing_revision = consumer_sharing
    WHERE lease.private_endpoint_id = endpoint_row.id AND lease.state = 'reserved';
    GET DIAGNOSTICS changed_count = ROW_COUNT;
    PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(prior_workspace, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(prior_network, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', COALESCE(prior_deployment, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_workspace_id', COALESCE(prior_share_provider_workspace_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_network_id', COALESCE(prior_share_provider_network_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_workspace_id', COALESCE(prior_share_consumer_workspace_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_network_id', COALESCE(prior_share_consumer_network_id, ''), TRUE);
    RETURN changed_count;
EXCEPTION WHEN no_data_found THEN
    PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(prior_workspace, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(prior_network, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', COALESCE(prior_deployment, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_workspace_id', COALESCE(prior_share_provider_workspace_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_network_id', COALESCE(prior_share_provider_network_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_workspace_id', COALESCE(prior_share_consumer_workspace_id, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_network_id', COALESCE(prior_share_consumer_network_id, ''), TRUE);

    RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device alias quarantine authority is unavailable';
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
REVOKE ALL ON FUNCTION mesh_ops.quarantine_device_aliases_internal_v1(UUID, BIGINT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_share_writer, mesh_audit_writer;
