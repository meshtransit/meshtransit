-- Direct Device readiness is separate from federation alias provisioning.
-- A ready row is a generation-bound proof, never a grant without current policy.
CREATE TABLE mesh.direct_device_endpoint (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    provider_workspace_id BIGINT NOT NULL,
    provider_network_id BIGINT NOT NULL,
    consumer_workspace_id BIGINT NOT NULL,
    consumer_network_id BIGINT NOT NULL,
    trust_contract_id BIGINT NOT NULL UNIQUE,
    imported_resource_id BIGINT NOT NULL UNIQUE,
    access_name_id BIGINT NOT NULL,
    resource_id BIGINT NOT NULL,
    resource_version BIGINT NOT NULL CHECK (resource_version > 0),
    target_generation BIGINT NOT NULL CHECK (target_generation > 0),
    resource_semantic_hash BYTEA NOT NULL,
    target_device_id BIGINT NOT NULL,
    target_session_generation BIGINT NOT NULL CHECK (target_session_generation > 0),
    target_machine_key_epoch BIGINT NOT NULL CHECK (target_machine_key_epoch > 0),
    target_node_key_epoch BIGINT NOT NULL CHECK (target_node_key_epoch > 0),
    target_address_lease_id BIGINT NOT NULL,
    target_address_generation BIGINT NOT NULL CHECK (target_address_generation > 0),
    resource_address INET NOT NULL,
    generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
    contract_version BIGINT NOT NULL CHECK (contract_version > 0),
    imported_resource_version BIGINT NOT NULL CHECK (imported_resource_version > 0),
    provider_authority_generation BIGINT NOT NULL CHECK (provider_authority_generation > 0),
    consumer_authority_generation BIGINT NOT NULL CHECK (consumer_authority_generation > 0),
    recovery_epoch BIGINT NOT NULL CHECK (recovery_epoch > 0),
    constraint_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ,
    CONSTRAINT direct_device_endpoint_id_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT direct_device_endpoint_scope_check CHECK (
        provider_workspace_id = consumer_workspace_id
        AND provider_network_id <> consumer_network_id
    ),
    CONSTRAINT direct_device_endpoint_address_check CHECK (
        pg_catalog.masklen(resource_address) =
            CASE pg_catalog.family(resource_address) WHEN 4 THEN 32 ELSE 128 END
    ),
    CONSTRAINT direct_device_endpoint_hash_check CHECK (
        pg_catalog.octet_length(resource_semantic_hash) = 32
        AND resource_semantic_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        AND pg_catalog.octet_length(constraint_hash) = 32
        AND constraint_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT direct_device_endpoint_state_check CHECK (
        (state = 'ready' AND ended_at IS NULL)
        OR (state IN ('revoked', 'invalidated') AND ended_at IS NOT NULL)
        OR (state = 'expired' AND ended_at IS NOT NULL AND ended_at >= expires_at)
    ),
    CONSTRAINT direct_device_endpoint_time_check CHECK (
        updated_at >= created_at AND expires_at > created_at
        AND (ended_at IS NULL OR ended_at = updated_at)
    ),
    CONSTRAINT direct_device_endpoint_workspace_fk FOREIGN KEY (
        deployment_id, provider_workspace_id
    ) REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT direct_device_endpoint_contract_fk FOREIGN KEY (
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id, trust_contract_id
    ) REFERENCES mesh.trust_contract (
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id, id
    ) ON DELETE RESTRICT,
    CONSTRAINT direct_device_endpoint_import_fk FOREIGN KEY (
        consumer_workspace_id, consumer_network_id, trust_contract_id, imported_resource_id
    ) REFERENCES mesh.imported_resource (
        workspace_id, network_id, trust_contract_id, id
    ) ON DELETE RESTRICT,
    CONSTRAINT direct_device_endpoint_name_fk FOREIGN KEY (
        consumer_workspace_id, consumer_network_id, imported_resource_id, access_name_id
    ) REFERENCES mesh.imported_resource_access_name (
        workspace_id, network_id, imported_resource_id, id
    ) ON DELETE RESTRICT,
    CONSTRAINT direct_device_endpoint_resource_fk FOREIGN KEY (
        provider_workspace_id, provider_network_id, resource_id, target_generation
    ) REFERENCES mesh.resource_device_target (
        workspace_id, network_id, resource_id, target_generation
    ) ON DELETE RESTRICT,
    CONSTRAINT direct_device_endpoint_device_fk FOREIGN KEY (
        provider_workspace_id, provider_network_id, target_device_id
    ) REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT direct_device_endpoint_lease_fk FOREIGN KEY (
        provider_workspace_id, provider_network_id, target_address_lease_id
    ) REFERENCES mesh.node_address_lease (workspace_id, network_id, id) ON DELETE RESTRICT
);

CREATE INDEX direct_device_endpoint_provider_current_idx
    ON mesh.direct_device_endpoint (
        provider_workspace_id, provider_network_id, target_device_id, id
    ) WHERE state = 'ready';
CREATE INDEX direct_device_endpoint_consumer_current_idx
    ON mesh.direct_device_endpoint (
        consumer_workspace_id, consumer_network_id, id
    ) WHERE state = 'ready';

CREATE FUNCTION mesh_ops.enforce_direct_device_endpoint_transition()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'direct Device endpoint is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'ready' OR NEW.version <> 1 OR NEW.generation <> 1
            OR NEW.created_at <> NEW.updated_at OR NEW.ended_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid direct Device readiness';
        END IF;
        RETURN NEW;
    END IF;
    IF (pg_catalog.to_jsonb(OLD) - ARRAY['state', 'version', 'updated_at', 'ended_at'])
        IS DISTINCT FROM
        (pg_catalog.to_jsonb(NEW) - ARRAY['state', 'version', 'updated_at', 'ended_at'])
        OR OLD.state <> 'ready'
        OR NEW.state NOT IN ('revoked', 'expired', 'invalidated')
        OR NEW.version <> OLD.version + 1
        OR NEW.updated_at < OLD.updated_at OR NEW.ended_at <> NEW.updated_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid direct Device withdrawal';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enforce_direct_device_endpoint_transition() FROM PUBLIC;

CREATE TRIGGER direct_device_endpoint_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.direct_device_endpoint
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_direct_device_endpoint_transition();
CREATE TRIGGER direct_device_endpoint_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.direct_device_endpoint
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'direct_device_endpoint', 'public_id'
);

ALTER TABLE mesh.direct_device_endpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.direct_device_endpoint FORCE ROW LEVEL SECURITY;
CREATE POLICY direct_device_endpoint_migrator_policy ON mesh.direct_device_endpoint
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY direct_device_endpoint_runtime_policy ON mesh.direct_device_endpoint
    FOR SELECT TO mesh_runtime USING (
        consumer_workspace_id = mesh_ops.current_workspace_id()
        AND consumer_network_id = mesh_ops.current_network_id()
    );
CREATE POLICY direct_device_endpoint_writer_policy ON mesh.direct_device_endpoint
    TO mesh_share_writer USING (
        provider_workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND provider_network_id = mesh_ops.current_share_provider_network_id()
        AND consumer_workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND consumer_network_id = mesh_ops.current_share_consumer_network_id()
    ) WITH CHECK (
        provider_workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND provider_network_id = mesh_ops.current_share_provider_network_id()
        AND consumer_workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND consumer_network_id = mesh_ops.current_share_consumer_network_id()
    );

CREATE POLICY device_direct_readiness_policy ON mesh.device
    FOR SELECT TO mesh_share_writer USING (
        workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND network_id = mesh_ops.current_share_provider_network_id()
    );
CREATE POLICY machine_key_direct_readiness_policy ON mesh.device_machine_key_epoch
    FOR SELECT TO mesh_share_writer USING (
        workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND network_id = mesh_ops.current_share_provider_network_id()
    );
CREATE POLICY node_key_direct_readiness_policy ON mesh.device_node_key_epoch
    FOR SELECT TO mesh_share_writer USING (
        workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND network_id = mesh_ops.current_share_provider_network_id()
    );
CREATE POLICY lease_direct_readiness_policy ON mesh.node_address_lease
    FOR SELECT TO mesh_share_writer USING (
        workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND network_id = mesh_ops.current_share_provider_network_id()
    );
GRANT SELECT ON mesh.device, mesh.device_machine_key_epoch,
    mesh.device_node_key_epoch, mesh.node_address_lease TO mesh_share_writer;
GRANT SELECT ON mesh.direct_device_endpoint TO mesh_runtime;
GRANT SELECT, INSERT, UPDATE ON mesh.direct_device_endpoint TO mesh_share_writer;
GRANT USAGE, SELECT ON SEQUENCE mesh.direct_device_endpoint_id_seq TO mesh_share_writer;

CREATE FUNCTION mesh_ops.activate_resource_share_v3(
    p_provider_workspace_id BIGINT, p_provider_network_id BIGINT,
    p_consumer_workspace_id BIGINT, p_consumer_network_id BIGINT,
    p_contract_public_id UUID, p_expected_contract_version BIGINT,
    p_expected_provider_sharing_revision BIGINT, p_expected_consumer_sharing_revision BIGINT,
    p_alias_lease_public_id UUID, p_private_endpoint_public_id UUID,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    provider_network_revision BIGINT, provider_sharing_revision BIGINT,
    consumer_network_revision BIGINT, consumer_sharing_revision BIGINT,
    contract_version BIGINT, imported_resource_version BIGINT,
    alias_lease_version BIGINT, private_endpoint_version BIGINT
)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    contract_row mesh.trust_contract%ROWTYPE;
    imported_row mesh.imported_resource%ROWTYPE;
    name_row mesh.imported_resource_access_name%ROWTYPE;
    device_row mesh.device%ROWTYPE;
    lease_row mesh.node_address_lease%ROWTYPE;
BEGIN
    IF p_provider_workspace_id <> p_consumer_workspace_id THEN
        RETURN QUERY SELECT * FROM mesh_ops.activate_resource_share_v2(
            p_provider_workspace_id, p_provider_network_id,
            p_consumer_workspace_id, p_consumer_network_id,
            p_contract_public_id, p_expected_contract_version,
            p_expected_provider_sharing_revision, p_expected_consumer_sharing_revision,
            p_alias_lease_public_id, p_private_endpoint_public_id, p_occurred_at
        );
        RETURN;
    END IF;
    IF p_private_endpoint_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid direct endpoint identity';
    END IF;
    SELECT activated.provider_network_revision, activated.provider_sharing_revision,
        activated.consumer_network_revision, activated.consumer_sharing_revision,
        activated.contract_version, activated.imported_resource_version
    INTO provider_network_revision, provider_sharing_revision,
        consumer_network_revision, consumer_sharing_revision,
        contract_version, imported_resource_version
    FROM mesh_ops.activate_resource_share_v1(
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id,
        p_contract_public_id, p_expected_contract_version,
        p_expected_provider_sharing_revision, p_expected_consumer_sharing_revision,
        p_occurred_at
    ) AS activated;

    SELECT contract.* INTO contract_row FROM mesh.trust_contract AS contract
    WHERE contract.public_id = p_contract_public_id AND contract.version = contract_version
      AND contract.provider_workspace_id = p_provider_workspace_id
      AND contract.provider_network_id = p_provider_network_id
      AND contract.consumer_workspace_id = p_consumer_workspace_id
      AND contract.consumer_network_id = p_consumer_network_id AND contract.state = 'active';
    SELECT imported.* INTO imported_row FROM mesh.imported_resource AS imported
    WHERE imported.trust_contract_id = contract_row.id
      AND imported.version = imported_resource_version AND imported.state = 'active';
    SELECT access_name.* INTO name_row FROM mesh.imported_resource_access_name AS access_name
    WHERE access_name.imported_resource_id = imported_row.id AND access_name.state = 'reserved';

    SELECT device.* INTO device_row
    FROM mesh.resource AS resource
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
    ;
    SELECT lease.* INTO lease_row FROM mesh.node_address_lease AS lease
    WHERE lease.workspace_id = p_provider_workspace_id AND lease.network_id = p_provider_network_id
      AND lease.device_id = device_row.id AND lease.state = 'active' AND lease.lease_role = 'primary'
      AND lease.created_at <= p_occurred_at
    ORDER BY lease.family DESC, lease.id LIMIT 1;
    IF contract_row.id IS NULL OR imported_row.id IS NULL OR name_row.id IS NULL
        OR device_row.id IS NULL OR lease_row.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'direct Device readiness is unavailable';
    END IF;

    INSERT INTO mesh.direct_device_endpoint (
        public_id, deployment_id, provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id, trust_contract_id,
        imported_resource_id, access_name_id, resource_id, resource_version,
        target_generation, resource_semantic_hash, target_device_id,
        target_session_generation, target_machine_key_epoch, target_node_key_epoch,
        target_address_lease_id, target_address_generation, resource_address,
        contract_version, imported_resource_version, provider_authority_generation,
        consumer_authority_generation, recovery_epoch, constraint_hash,
        expires_at, state, created_at, updated_at
    ) VALUES (
        p_private_endpoint_public_id, contract_row.deployment_id,
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id, contract_row.id,
        imported_row.id, name_row.id, contract_row.resource_id, contract_row.resource_version,
        contract_row.target_generation, contract_row.resource_semantic_hash, device_row.id,
        device_row.session_generation, device_row.current_machine_key_epoch, device_row.current_node_key_epoch,
        lease_row.id, lease_row.generation, lease_row.address,
        contract_row.version, imported_row.version, contract_row.provider_authority_generation,
        contract_row.consumer_authority_generation, contract_row.recovery_epoch, contract_row.constraint_hash,
        LEAST(contract_row.expires_at, device_row.expires_at), 'ready', p_occurred_at, p_occurred_at
    ) RETURNING version INTO private_endpoint_version;
    alias_lease_version := 0;
    RETURN NEXT;
END;
$function$;

-- Legacy writers also withdraw direct proof when ending a Trust Contract.
-- The existing contract transaction already owns both revision locks and evidence.
CREATE FUNCTION mesh_ops.withdraw_direct_device_endpoint_on_contract_end()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    UPDATE mesh.direct_device_endpoint AS endpoint
    SET state = NEW.state, version = endpoint.version + 1,
        updated_at = NEW.updated_at, ended_at = NEW.ended_at
    WHERE endpoint.trust_contract_id = NEW.id AND endpoint.state = 'ready'
      AND endpoint.provider_workspace_id = NEW.provider_workspace_id
      AND endpoint.provider_network_id = NEW.provider_network_id
      AND endpoint.consumer_workspace_id = NEW.consumer_workspace_id
      AND endpoint.consumer_network_id = NEW.consumer_network_id;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.withdraw_direct_device_endpoint_on_contract_end()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
CREATE TRIGGER direct_device_endpoint_contract_withdrawal
AFTER UPDATE OF state ON mesh.trust_contract
FOR EACH ROW WHEN (
    OLD.state IN ('activating', 'active') AND NEW.state IN ('revoked', 'expired', 'invalidated')
) EXECUTE FUNCTION mesh_ops.withdraw_direct_device_endpoint_on_contract_end();

CREATE FUNCTION mesh_ops.revoke_resource_share_v5(
    p_provider_workspace_id BIGINT, p_provider_network_id BIGINT,
    p_consumer_workspace_id BIGINT, p_consumer_network_id BIGINT,
    p_contract_public_id UUID, p_expected_contract_version BIGINT,
    p_expected_provider_sharing_revision BIGINT, p_expected_consumer_sharing_revision BIGINT,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    provider_network_revision BIGINT, provider_sharing_revision BIGINT,
    consumer_network_revision BIGINT, consumer_sharing_revision BIGINT,
    contract_version BIGINT, imported_resource_version BIGINT,
    access_name_version BIGINT, alias_lease_version BIGINT,
    private_endpoint_version BIGINT, dns_publication_version BIGINT
)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE direct_version BIGINT;
BEGIN
    SELECT revoked.* INTO provider_network_revision, provider_sharing_revision,
        consumer_network_revision, consumer_sharing_revision,
        contract_version, imported_resource_version, access_name_version,
        alias_lease_version, private_endpoint_version, dns_publication_version
    FROM mesh_ops.revoke_resource_share_v4(
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id,
        p_contract_public_id, p_expected_contract_version,
        p_expected_provider_sharing_revision, p_expected_consumer_sharing_revision, p_occurred_at
    ) AS revoked;
    SELECT endpoint.version INTO direct_version
    FROM mesh.direct_device_endpoint AS endpoint
    JOIN mesh.trust_contract AS contract ON contract.id = endpoint.trust_contract_id
    WHERE contract.public_id = p_contract_public_id
      AND endpoint.state = 'revoked' AND endpoint.ended_at = p_occurred_at
      AND endpoint.provider_workspace_id = p_provider_workspace_id
      AND endpoint.provider_network_id = p_provider_network_id
      AND endpoint.consumer_workspace_id = p_consumer_workspace_id
      AND endpoint.consumer_network_id = p_consumer_network_id;
    IF direct_version IS NOT NULL THEN
        IF alias_lease_version <> 0 OR private_endpoint_version <> 0 OR direct_version <> 2 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ambiguous direct Device withdrawal';
        END IF;
        private_endpoint_version := direct_version;
    END IF;
    RETURN NEXT;
END;
$function$;

-- The operator script changes function ownership before enabling runtime use.
REVOKE ALL ON FUNCTION mesh_ops.activate_resource_share_v3(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.revoke_resource_share_v5(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
