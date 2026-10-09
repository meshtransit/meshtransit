CREATE TABLE mesh_ops.federation_alias_pool_cursor (
    address_pool_id BIGINT PRIMARY KEY,
    deployment_id BIGINT NOT NULL,
    next_offset BIGINT NOT NULL DEFAULT 1 CHECK (next_offset > 0),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT federation_alias_pool_cursor_pool_fk FOREIGN KEY (
        deployment_id, address_pool_id
    ) REFERENCES mesh.address_pool (deployment_id, id) ON DELETE RESTRICT,
    UNIQUE (deployment_id, address_pool_id)
);

ALTER TABLE mesh.imported_resource
    ADD CONSTRAINT imported_resource_endpoint_binding_key UNIQUE (
        workspace_id, network_id, trust_contract_id, id
    );
ALTER TABLE mesh.imported_resource_access_name
    ADD CONSTRAINT imported_resource_access_name_endpoint_binding_key UNIQUE (
        workspace_id, network_id, imported_resource_id, id
    );

CREATE TABLE mesh.federation_alias_lease (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    address_realm_id BIGINT NOT NULL,
    address_pool_id BIGINT NOT NULL,
    provider_workspace_id BIGINT NOT NULL,
    provider_network_id BIGINT NOT NULL,
    consumer_workspace_id BIGINT NOT NULL,
    consumer_network_id BIGINT NOT NULL,
    imported_resource_id BIGINT NOT NULL,
    resource_alias INET NOT NULL,
    family INTEGER NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    activated_at TIMESTAMPTZ,
    withdrawn_at TIMESTAMPTZ,
    CONSTRAINT federation_alias_lease_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT federation_alias_lease_scope_check CHECK (
        provider_workspace_id <> consumer_workspace_id
        OR provider_network_id <> consumer_network_id
    ),
    CONSTRAINT federation_alias_lease_address_check CHECK (
        family IN (4, 6)
        AND family = pg_catalog.family(resource_alias)
        AND pg_catalog.masklen(resource_alias) = CASE family WHEN 4 THEN 32 ELSE 128 END
    ),
    CONSTRAINT federation_alias_lease_state_check CHECK (
        state IN ('reserved', 'active', 'withdrawn')
    ),
    CONSTRAINT federation_alias_lease_state_shape_check CHECK (
        (state = 'reserved' AND activated_at IS NULL AND withdrawn_at IS NULL)
        OR (state = 'active' AND activated_at IS NOT NULL AND withdrawn_at IS NULL)
        OR (state = 'withdrawn' AND withdrawn_at IS NOT NULL)
    ),
    CONSTRAINT federation_alias_lease_timestamps_check CHECK (
        updated_at >= created_at
        AND (activated_at IS NULL OR activated_at >= created_at)
        AND (withdrawn_at IS NULL OR withdrawn_at >= created_at)
    ),
    CONSTRAINT federation_alias_lease_realm_fk FOREIGN KEY (
        deployment_id, address_realm_id
    ) REFERENCES mesh.address_realm (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT federation_alias_lease_pool_fk FOREIGN KEY (
        deployment_id, address_pool_id
    ) REFERENCES mesh.address_pool (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT federation_alias_lease_provider_workspace_fk FOREIGN KEY (
        deployment_id, provider_workspace_id
    ) REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT federation_alias_lease_consumer_workspace_fk FOREIGN KEY (
        deployment_id, consumer_workspace_id
    ) REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT federation_alias_lease_provider_network_fk FOREIGN KEY (
        provider_workspace_id, provider_network_id
    ) REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT federation_alias_lease_consumer_network_fk FOREIGN KEY (
        consumer_workspace_id, consumer_network_id
    ) REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT federation_alias_lease_import_fk FOREIGN KEY (
        consumer_workspace_id, consumer_network_id, imported_resource_id
    ) REFERENCES mesh.imported_resource (workspace_id, network_id, id) ON DELETE RESTRICT,
    UNIQUE (id, resource_alias),
    UNIQUE (
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id, id
    ),
    UNIQUE (consumer_workspace_id, consumer_network_id, id),
    UNIQUE (
        consumer_workspace_id, consumer_network_id,
        imported_resource_id, id, resource_alias
    )
);

CREATE UNIQUE INDEX federation_alias_lease_current_address_uidx
    ON mesh.federation_alias_lease (address_realm_id, resource_alias)
    WHERE state IN ('reserved', 'active');
CREATE UNIQUE INDEX federation_alias_lease_current_import_uidx
    ON mesh.federation_alias_lease (
        consumer_workspace_id, consumer_network_id, imported_resource_id
    ) WHERE state IN ('reserved', 'active');
CREATE INDEX federation_alias_lease_consumer_state_id_idx
    ON mesh.federation_alias_lease (
        consumer_workspace_id, consumer_network_id, state, id
    );

CREATE TABLE mesh.private_endpoint (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    provider_workspace_id BIGINT NOT NULL,
    provider_network_id BIGINT NOT NULL,
    consumer_workspace_id BIGINT NOT NULL,
    consumer_network_id BIGINT NOT NULL,
    trust_contract_id BIGINT NOT NULL,
    imported_resource_id BIGINT NOT NULL,
    access_name_id BIGINT NOT NULL,
    alias_lease_id BIGINT NOT NULL UNIQUE,
    mode TEXT NOT NULL,
    resource_alias INET NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
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
    ready_at TIMESTAMPTZ,
    ended_at TIMESTAMPTZ,
    CONSTRAINT private_endpoint_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT private_endpoint_scope_check CHECK (
        provider_workspace_id <> consumer_workspace_id
        OR provider_network_id <> consumer_network_id
    ),
    CONSTRAINT private_endpoint_mode_check CHECK (mode = 'federation_alias'),
    CONSTRAINT private_endpoint_alias_check CHECK (
        pg_catalog.masklen(resource_alias) IN (32, 128)
        AND pg_catalog.family(resource_alias) IN (4, 6)
    ),
    CONSTRAINT private_endpoint_hash_check CHECK (
        pg_catalog.octet_length(constraint_hash) = 32
        AND constraint_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT private_endpoint_state_check CHECK (
        state IN ('provisioning', 'ready', 'revoked', 'expired', 'invalidated')
    ),
    CONSTRAINT private_endpoint_state_shape_check CHECK (
        (state = 'provisioning' AND ready_at IS NULL AND ended_at IS NULL)
        OR (state = 'ready' AND ready_at IS NOT NULL AND ended_at IS NULL)
        OR (state IN ('revoked', 'invalidated') AND ended_at IS NOT NULL)
        OR (state = 'expired' AND ended_at IS NOT NULL AND ended_at >= expires_at)
    ),
    CONSTRAINT private_endpoint_timestamps_check CHECK (
        updated_at >= created_at
        AND expires_at > created_at
        AND (ready_at IS NULL OR ready_at >= created_at)
        AND (ended_at IS NULL OR ended_at >= created_at)
    ),
    CONSTRAINT private_endpoint_provider_workspace_fk FOREIGN KEY (
        deployment_id, provider_workspace_id
    ) REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT private_endpoint_consumer_workspace_fk FOREIGN KEY (
        deployment_id, consumer_workspace_id
    ) REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT private_endpoint_contract_fk FOREIGN KEY (
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id, trust_contract_id
    ) REFERENCES mesh.trust_contract (
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id, id
    ) ON DELETE RESTRICT,
    CONSTRAINT private_endpoint_import_fk FOREIGN KEY (
        consumer_workspace_id, consumer_network_id,
        trust_contract_id, imported_resource_id
    ) REFERENCES mesh.imported_resource (
        workspace_id, network_id, trust_contract_id, id
    ) ON DELETE RESTRICT,
    CONSTRAINT private_endpoint_access_name_fk FOREIGN KEY (
        consumer_workspace_id, consumer_network_id,
        imported_resource_id, access_name_id
    ) REFERENCES mesh.imported_resource_access_name (
        workspace_id, network_id, imported_resource_id, id
    ) ON DELETE RESTRICT,
    CONSTRAINT private_endpoint_alias_lease_fk FOREIGN KEY (
        consumer_workspace_id, consumer_network_id,
        imported_resource_id, alias_lease_id, resource_alias
    ) REFERENCES mesh.federation_alias_lease (
        consumer_workspace_id, consumer_network_id,
        imported_resource_id, id, resource_alias
    ) ON DELETE RESTRICT,
    UNIQUE (
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id, id
    ),
    UNIQUE (consumer_workspace_id, consumer_network_id, id)
);

CREATE UNIQUE INDEX private_endpoint_current_import_uidx
    ON mesh.private_endpoint (
        consumer_workspace_id, consumer_network_id, imported_resource_id
    ) WHERE state IN ('provisioning', 'ready');
CREATE INDEX private_endpoint_consumer_state_id_idx
    ON mesh.private_endpoint (
        consumer_workspace_id, consumer_network_id, state, id
    );

CREATE FUNCTION mesh_ops.enforce_federation_alias_lease_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Federation Alias lease is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'reserved' OR NEW.version <> 1
            OR NEW.activated_at IS NOT NULL OR NEW.withdrawn_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Federation Alias reservation';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.public_id <> NEW.public_id
        OR OLD.deployment_id <> NEW.deployment_id
        OR OLD.address_realm_id <> NEW.address_realm_id
        OR OLD.address_pool_id <> NEW.address_pool_id
        OR OLD.provider_workspace_id <> NEW.provider_workspace_id
        OR OLD.provider_network_id <> NEW.provider_network_id
        OR OLD.consumer_workspace_id <> NEW.consumer_workspace_id
        OR OLD.consumer_network_id <> NEW.consumer_network_id
        OR OLD.imported_resource_id <> NEW.imported_resource_id
        OR OLD.resource_alias <> NEW.resource_alias
        OR OLD.family <> NEW.family
        OR OLD.generation <> NEW.generation
        OR OLD.created_at <> NEW.created_at
        OR NEW.version <> OLD.version + 1
        OR NEW.updated_at < OLD.updated_at
        OR NOT (
            (OLD.state = 'reserved' AND NEW.state IN ('active', 'withdrawn'))
            OR (OLD.state = 'active' AND NEW.state = 'withdrawn')
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Federation Alias transition';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE FUNCTION mesh_ops.enforce_private_endpoint_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Private Endpoint is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'provisioning' OR NEW.version <> 1
            OR NEW.ready_at IS NOT NULL OR NEW.ended_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Private Endpoint provisioning';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.public_id <> NEW.public_id
        OR OLD.deployment_id <> NEW.deployment_id
        OR OLD.provider_workspace_id <> NEW.provider_workspace_id
        OR OLD.provider_network_id <> NEW.provider_network_id
        OR OLD.consumer_workspace_id <> NEW.consumer_workspace_id
        OR OLD.consumer_network_id <> NEW.consumer_network_id
        OR OLD.trust_contract_id <> NEW.trust_contract_id
        OR OLD.imported_resource_id <> NEW.imported_resource_id
        OR OLD.access_name_id <> NEW.access_name_id
        OR OLD.alias_lease_id <> NEW.alias_lease_id
        OR OLD.mode <> NEW.mode
        OR OLD.resource_alias <> NEW.resource_alias
        OR OLD.generation <> NEW.generation
        OR OLD.contract_version <> NEW.contract_version
        OR OLD.imported_resource_version <> NEW.imported_resource_version
        OR OLD.provider_authority_generation <> NEW.provider_authority_generation
        OR OLD.consumer_authority_generation <> NEW.consumer_authority_generation
        OR OLD.recovery_epoch <> NEW.recovery_epoch
        OR OLD.constraint_hash <> NEW.constraint_hash
        OR OLD.expires_at <> NEW.expires_at
        OR OLD.created_at <> NEW.created_at
        OR NEW.version <> OLD.version + 1
        OR NEW.updated_at < OLD.updated_at
        OR NOT (
            (OLD.state = 'provisioning' AND NEW.state IN ('ready', 'revoked', 'expired', 'invalidated'))
            OR (OLD.state = 'ready' AND NEW.state IN ('revoked', 'expired', 'invalidated'))
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Private Endpoint transition';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER federation_alias_lease_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.federation_alias_lease
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_federation_alias_lease_transition();
CREATE TRIGGER federation_alias_lease_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.federation_alias_lease
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'federation_alias_lease', 'public_id'
);
CREATE TRIGGER private_endpoint_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.private_endpoint
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_private_endpoint_transition();
CREATE TRIGGER private_endpoint_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.private_endpoint
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'private_endpoint', 'public_id'
);

ALTER TABLE mesh.federation_alias_lease ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.federation_alias_lease FORCE ROW LEVEL SECURITY;
ALTER TABLE mesh.private_endpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.private_endpoint FORCE ROW LEVEL SECURITY;

CREATE POLICY federation_alias_lease_migrator_policy ON mesh.federation_alias_lease
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY private_endpoint_migrator_policy ON mesh.private_endpoint
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY federation_alias_lease_runtime_policy ON mesh.federation_alias_lease
    FOR SELECT TO mesh_runtime
    USING (
        consumer_workspace_id = mesh_ops.current_workspace_id()
        AND consumer_network_id = mesh_ops.current_network_id()
    );
CREATE POLICY private_endpoint_runtime_policy ON mesh.private_endpoint
    FOR SELECT TO mesh_runtime
    USING (
        consumer_workspace_id = mesh_ops.current_workspace_id()
        AND consumer_network_id = mesh_ops.current_network_id()
    );
CREATE POLICY federation_alias_lease_share_writer_policy ON mesh.federation_alias_lease
    TO mesh_share_writer
    USING (
        provider_workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND provider_network_id = mesh_ops.current_share_provider_network_id()
        AND consumer_workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND consumer_network_id = mesh_ops.current_share_consumer_network_id()
    )
    WITH CHECK (
        provider_workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND provider_network_id = mesh_ops.current_share_provider_network_id()
        AND consumer_workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND consumer_network_id = mesh_ops.current_share_consumer_network_id()
    );
CREATE POLICY private_endpoint_share_writer_policy ON mesh.private_endpoint
    TO mesh_share_writer
    USING (
        provider_workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND provider_network_id = mesh_ops.current_share_provider_network_id()
        AND consumer_workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND consumer_network_id = mesh_ops.current_share_consumer_network_id()
    )
    WITH CHECK (
        provider_workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND provider_network_id = mesh_ops.current_share_provider_network_id()
        AND consumer_workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND consumer_network_id = mesh_ops.current_share_consumer_network_id()
    );
CREATE POLICY address_realm_share_writer_federation_policy ON mesh.address_realm
    FOR SELECT TO mesh_share_writer
    USING (
        workspace_id IS NULL
        AND kind = 'federation_alias'
        AND EXISTS (
            SELECT 1
            FROM mesh.workspace AS provider_workspace
            JOIN mesh.workspace AS consumer_workspace
              ON consumer_workspace.deployment_id = provider_workspace.deployment_id
            WHERE provider_workspace.id = mesh_ops.current_share_provider_workspace_id()
              AND consumer_workspace.id = mesh_ops.current_share_consumer_workspace_id()
              AND provider_workspace.deployment_id = address_realm.deployment_id
        )
    );
CREATE POLICY address_pool_share_writer_federation_policy ON mesh.address_pool
    FOR SELECT TO mesh_share_writer
    USING (
        workspace_id IS NULL
        AND purpose = 'federation_resource_alias'
        AND EXISTS (
            SELECT 1
            FROM mesh.workspace AS provider_workspace
            JOIN mesh.workspace AS consumer_workspace
              ON consumer_workspace.deployment_id = provider_workspace.deployment_id
            WHERE provider_workspace.id = mesh_ops.current_share_provider_workspace_id()
              AND consumer_workspace.id = mesh_ops.current_share_consumer_workspace_id()
              AND provider_workspace.deployment_id = address_pool.deployment_id
        )
    );

CREATE FUNCTION mesh_ops.activate_resource_share_v2(
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
    allocation_offset BIGINT;
    maximum_offset BIGINT;
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

    INSERT INTO mesh_ops.federation_alias_pool_cursor (
        address_pool_id, deployment_id, next_offset, updated_at
    ) VALUES (
        pool_row.id, pool_row.deployment_id, 1, p_occurred_at
    ) ON CONFLICT (address_pool_id) DO NOTHING;
    SELECT cursor.next_offset INTO allocation_offset
    FROM mesh_ops.federation_alias_pool_cursor AS cursor
    WHERE cursor.address_pool_id = pool_row.id
      AND cursor.deployment_id = pool_row.deployment_id
    FOR UPDATE;
    maximum_offset := (1::BIGINT << (
        CASE pool_row.family WHEN 4 THEN 32 ELSE 128 END
        - pg_catalog.masklen(pool_row.prefix)
    )) - CASE pool_row.family WHEN 4 THEN 2 ELSE 1 END;
    IF allocation_offset IS NULL OR allocation_offset > maximum_offset THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Federation Alias pool is exhausted';
    END IF;
    allocated_alias := pg_catalog.set_masklen(
        pg_catalog.network(pool_row.prefix) + allocation_offset,
        CASE pool_row.family WHEN 4 THEN 32 ELSE 128 END
    );
    UPDATE mesh_ops.federation_alias_pool_cursor
    SET next_offset = allocation_offset + 1,
        version = version + 1,
        updated_at = p_occurred_at
    WHERE address_pool_id = pool_row.id;

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

CREATE FUNCTION mesh_ops.revoke_resource_share_v3(
    p_provider_workspace_id BIGINT,
    p_provider_network_id BIGINT,
    p_consumer_workspace_id BIGINT,
    p_consumer_network_id BIGINT,
    p_contract_public_id UUID,
    p_expected_contract_version BIGINT,
    p_expected_provider_sharing_revision BIGINT,
    p_expected_consumer_sharing_revision BIGINT,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    provider_network_revision BIGINT,
    provider_sharing_revision BIGINT,
    consumer_network_revision BIGINT,
    consumer_sharing_revision BIGINT,
    contract_version BIGINT,
    imported_resource_version BIGINT,
    access_name_version BIGINT,
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
    endpoint_alias_lease_id BIGINT;
BEGIN
    SELECT
        revoked.provider_network_revision,
        revoked.provider_sharing_revision,
        revoked.consumer_network_revision,
        revoked.consumer_sharing_revision,
        revoked.contract_version,
        revoked.imported_resource_version,
        revoked.access_name_version
    INTO
        provider_network_revision,
        provider_sharing_revision,
        consumer_network_revision,
        consumer_sharing_revision,
        contract_version,
        imported_resource_version,
        access_name_version
    FROM mesh_ops.revoke_resource_share_v2(
        p_provider_workspace_id,
        p_provider_network_id,
        p_consumer_workspace_id,
        p_consumer_network_id,
        p_contract_public_id,
        p_expected_contract_version,
        p_expected_provider_sharing_revision,
        p_expected_consumer_sharing_revision,
        p_occurred_at
    ) AS revoked;

    UPDATE mesh.private_endpoint AS endpoint
    SET state = 'revoked',
        version = endpoint.version + 1,
        updated_at = p_occurred_at,
        ended_at = p_occurred_at
    FROM mesh.trust_contract AS contract
    WHERE contract.public_id = p_contract_public_id
      AND contract.provider_workspace_id = p_provider_workspace_id
      AND contract.provider_network_id = p_provider_network_id
      AND contract.consumer_workspace_id = p_consumer_workspace_id
      AND contract.consumer_network_id = p_consumer_network_id
      AND endpoint.trust_contract_id = contract.id
      AND endpoint.provider_workspace_id = contract.provider_workspace_id
      AND endpoint.provider_network_id = contract.provider_network_id
      AND endpoint.consumer_workspace_id = contract.consumer_workspace_id
      AND endpoint.consumer_network_id = contract.consumer_network_id
      AND endpoint.state IN ('provisioning', 'ready')
    RETURNING endpoint.alias_lease_id, endpoint.version
    INTO endpoint_alias_lease_id, private_endpoint_version;

    IF endpoint_alias_lease_id IS NULL THEN
        alias_lease_version := 0;
        private_endpoint_version := 0;
    ELSE
        UPDATE mesh.federation_alias_lease AS lease
        SET state = 'withdrawn',
            version = lease.version + 1,
            updated_at = p_occurred_at,
            withdrawn_at = p_occurred_at
        WHERE lease.id = endpoint_alias_lease_id
          AND lease.provider_workspace_id = p_provider_workspace_id
          AND lease.provider_network_id = p_provider_network_id
          AND lease.consumer_workspace_id = p_consumer_workspace_id
          AND lease.consumer_network_id = p_consumer_network_id
          AND lease.state IN ('reserved', 'active')
        RETURNING lease.version INTO alias_lease_version;
        IF alias_lease_version IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Federation Alias withdrawal failed';
        END IF;
    END IF;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON
    mesh.federation_alias_lease,
    mesh.private_endpoint,
    mesh_ops.federation_alias_pool_cursor
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON SEQUENCE
    mesh.federation_alias_lease_id_seq,
    mesh.private_endpoint_id_seq
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.enforce_federation_alias_lease_transition()
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.enforce_private_endpoint_transition()
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.activate_resource_share_v2(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.revoke_resource_share_v3(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;

GRANT SELECT ON mesh.address_realm, mesh.address_pool TO mesh_share_writer;
GRANT SELECT, INSERT, UPDATE ON mesh_ops.federation_alias_pool_cursor TO mesh_share_writer;
GRANT SELECT, INSERT, UPDATE ON
    mesh.federation_alias_lease,
    mesh.private_endpoint
TO mesh_share_writer;
GRANT SELECT ON mesh.federation_alias_lease, mesh.private_endpoint TO mesh_runtime;
GRANT USAGE, SELECT ON SEQUENCE
    mesh.federation_alias_lease_id_seq,
    mesh.private_endpoint_id_seq
TO mesh_share_writer;
