ALTER TABLE mesh.private_endpoint
    ADD CONSTRAINT private_endpoint_publication_binding_key UNIQUE (
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id,
        imported_resource_id, access_name_id, id,
        alias_lease_id, resource_alias, generation
    );
ALTER TABLE mesh.imported_resource_access_name
    ADD CONSTRAINT imported_resource_access_name_publication_binding_key UNIQUE (
        workspace_id, network_id, imported_resource_id, id, access_name
    );

CREATE TABLE mesh.private_endpoint_readiness (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    provider_workspace_id BIGINT NOT NULL,
    provider_network_id BIGINT NOT NULL,
    consumer_workspace_id BIGINT NOT NULL,
    consumer_network_id BIGINT NOT NULL,
    private_endpoint_id BIGINT NOT NULL UNIQUE,
    imported_resource_id BIGINT NOT NULL,
    access_name_id BIGINT NOT NULL,
    alias_lease_id BIGINT NOT NULL,
    target_device_public_id UUID NOT NULL,
    endpoint_generation BIGINT NOT NULL CHECK (endpoint_generation > 0),
    resource_alias INET NOT NULL,
    route_snapshot_hash BYTEA NOT NULL,
    reconciler_id TEXT NOT NULL,
    provider_route_revision BIGINT NOT NULL CHECK (provider_route_revision > 0),
    consumer_route_revision BIGINT NOT NULL CHECK (consumer_route_revision > 0),
    observed_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT private_endpoint_readiness_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT private_endpoint_readiness_scope_check CHECK (
        provider_workspace_id <> consumer_workspace_id
        OR provider_network_id <> consumer_network_id
    ),
    CONSTRAINT private_endpoint_readiness_alias_check CHECK (
        pg_catalog.masklen(resource_alias) IN (32, 128)
        AND pg_catalog.family(resource_alias) IN (4, 6)
    ),
    CONSTRAINT private_endpoint_readiness_hash_check CHECK (
        pg_catalog.octet_length(route_snapshot_hash) = 32
        AND route_snapshot_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT private_endpoint_readiness_reconciler_check CHECK (
        pg_catalog.char_length(reconciler_id) BETWEEN 1 AND 128
        AND reconciler_id = pg_catalog.btrim(reconciler_id)
        AND reconciler_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT private_endpoint_readiness_timestamps_check CHECK (
        observed_at <= created_at
    ),
    CONSTRAINT private_endpoint_readiness_provider_workspace_fk FOREIGN KEY (
        deployment_id, provider_workspace_id
    ) REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT private_endpoint_readiness_consumer_workspace_fk FOREIGN KEY (
        deployment_id, consumer_workspace_id
    ) REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT private_endpoint_readiness_endpoint_fk FOREIGN KEY (
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id,
        imported_resource_id, access_name_id, private_endpoint_id,
        alias_lease_id, resource_alias, endpoint_generation
    ) REFERENCES mesh.private_endpoint (
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id,
        imported_resource_id, access_name_id, id,
        alias_lease_id, resource_alias, generation
    ) ON DELETE RESTRICT,
    CONSTRAINT private_endpoint_readiness_target_device_fk FOREIGN KEY (
        target_device_public_id
    ) REFERENCES mesh.device (public_id) ON DELETE RESTRICT
);

CREATE INDEX private_endpoint_readiness_consumer_id_idx
    ON mesh.private_endpoint_readiness (
        consumer_workspace_id, consumer_network_id, id
    );

CREATE TABLE mesh.imported_resource_dns_publication (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    provider_workspace_id BIGINT NOT NULL,
    provider_network_id BIGINT NOT NULL,
    consumer_workspace_id BIGINT NOT NULL,
    consumer_network_id BIGINT NOT NULL,
    imported_resource_id BIGINT NOT NULL,
    access_name_id BIGINT NOT NULL,
    private_endpoint_id BIGINT NOT NULL,
    alias_lease_id BIGINT NOT NULL,
    access_name TEXT NOT NULL,
    resource_alias INET NOT NULL,
    endpoint_generation BIGINT NOT NULL CHECK (endpoint_generation > 0),
    dns_revision BIGINT NOT NULL CHECK (dns_revision > 0),
    route_revision BIGINT NOT NULL CHECK (route_revision > 0),
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    withdrawn_at TIMESTAMPTZ,
    CONSTRAINT imported_resource_dns_publication_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT imported_resource_dns_publication_scope_check CHECK (
        provider_workspace_id <> consumer_workspace_id
        OR provider_network_id <> consumer_network_id
    ),
    CONSTRAINT imported_resource_dns_publication_name_check CHECK (
        pg_catalog.char_length(access_name) BETWEEN 3 AND 253
        AND access_name = pg_catalog.lower(access_name)
        AND access_name !~ '[.]$'
    ),
    CONSTRAINT imported_resource_dns_publication_alias_check CHECK (
        pg_catalog.masklen(resource_alias) IN (32, 128)
        AND pg_catalog.family(resource_alias) IN (4, 6)
    ),
    CONSTRAINT imported_resource_dns_publication_state_check CHECK (
        state IN ('published', 'withdrawn')
    ),
    CONSTRAINT imported_resource_dns_publication_state_shape_check CHECK (
        (state = 'published' AND version = 1 AND withdrawn_at IS NULL)
        OR (state = 'withdrawn' AND version = 2 AND withdrawn_at IS NOT NULL)
    ),
    CONSTRAINT imported_resource_dns_publication_timestamps_check CHECK (
        updated_at >= created_at
        AND (withdrawn_at IS NULL OR withdrawn_at >= created_at)
    ),
    CONSTRAINT imported_resource_dns_publication_provider_workspace_fk FOREIGN KEY (
        deployment_id, provider_workspace_id
    ) REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT imported_resource_dns_publication_consumer_workspace_fk FOREIGN KEY (
        deployment_id, consumer_workspace_id
    ) REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT imported_resource_dns_publication_access_name_fk FOREIGN KEY (
        consumer_workspace_id, consumer_network_id,
        imported_resource_id, access_name_id, access_name
    ) REFERENCES mesh.imported_resource_access_name (
        workspace_id, network_id, imported_resource_id, id, access_name
    ) ON DELETE RESTRICT,
    CONSTRAINT imported_resource_dns_publication_endpoint_fk FOREIGN KEY (
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id,
        imported_resource_id, access_name_id, private_endpoint_id,
        alias_lease_id, resource_alias, endpoint_generation
    ) REFERENCES mesh.private_endpoint (
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id,
        imported_resource_id, access_name_id, id,
        alias_lease_id, resource_alias, generation
    ) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX imported_resource_dns_publication_current_name_uidx
    ON mesh.imported_resource_dns_publication (
        consumer_workspace_id, consumer_network_id, access_name
    ) WHERE state = 'published';
CREATE UNIQUE INDEX imported_resource_dns_publication_current_endpoint_uidx
    ON mesh.imported_resource_dns_publication (private_endpoint_id)
    WHERE state = 'published';
CREATE INDEX imported_resource_dns_publication_consumer_state_id_idx
    ON mesh.imported_resource_dns_publication (
        consumer_workspace_id, consumer_network_id, state, id
    );

CREATE FUNCTION mesh_ops.reject_private_endpoint_readiness_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Private Endpoint readiness proof';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Private Endpoint readiness proof is immutable';
END;
$function$;

CREATE FUNCTION mesh_ops.enforce_imported_resource_dns_publication_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Imported Resource DNS publication is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'published' OR NEW.version <> 1 OR NEW.withdrawn_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Imported Resource DNS publication';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.public_id <> NEW.public_id
        OR OLD.deployment_id <> NEW.deployment_id
        OR OLD.provider_workspace_id <> NEW.provider_workspace_id
        OR OLD.provider_network_id <> NEW.provider_network_id
        OR OLD.consumer_workspace_id <> NEW.consumer_workspace_id
        OR OLD.consumer_network_id <> NEW.consumer_network_id
        OR OLD.imported_resource_id <> NEW.imported_resource_id
        OR OLD.access_name_id <> NEW.access_name_id
        OR OLD.private_endpoint_id <> NEW.private_endpoint_id
        OR OLD.alias_lease_id <> NEW.alias_lease_id
        OR OLD.access_name <> NEW.access_name
        OR OLD.resource_alias <> NEW.resource_alias
        OR OLD.endpoint_generation <> NEW.endpoint_generation
        OR OLD.dns_revision <> NEW.dns_revision
        OR OLD.route_revision <> NEW.route_revision
        OR OLD.created_at <> NEW.created_at
        OR OLD.state <> 'published' OR NEW.state <> 'withdrawn'
        OR NEW.version <> 2 OR NEW.updated_at < OLD.updated_at
        OR NEW.withdrawn_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Imported Resource DNS transition';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER private_endpoint_readiness_immutable
BEFORE INSERT OR UPDATE OR DELETE ON mesh.private_endpoint_readiness
FOR EACH ROW EXECUTE FUNCTION mesh_ops.reject_private_endpoint_readiness_change();
CREATE TRIGGER private_endpoint_readiness_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.private_endpoint_readiness
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'private_endpoint_readiness', 'public_id'
);
CREATE TRIGGER imported_resource_dns_publication_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.imported_resource_dns_publication
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_imported_resource_dns_publication_transition();
CREATE TRIGGER imported_resource_dns_publication_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.imported_resource_dns_publication
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'imported_resource_dns_publication', 'public_id'
);

ALTER TABLE mesh.private_endpoint_readiness ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.private_endpoint_readiness FORCE ROW LEVEL SECURITY;
ALTER TABLE mesh.imported_resource_dns_publication ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.imported_resource_dns_publication FORCE ROW LEVEL SECURITY;

CREATE POLICY private_endpoint_readiness_migrator_policy
    ON mesh.private_endpoint_readiness TO mesh_migrator
    USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY imported_resource_dns_publication_migrator_policy
    ON mesh.imported_resource_dns_publication TO mesh_migrator
    USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY private_endpoint_readiness_runtime_policy
    ON mesh.private_endpoint_readiness FOR SELECT TO mesh_runtime
    USING (
        consumer_workspace_id = mesh_ops.current_workspace_id()
        AND consumer_network_id = mesh_ops.current_network_id()
    );
CREATE POLICY imported_resource_dns_publication_runtime_policy
    ON mesh.imported_resource_dns_publication FOR SELECT TO mesh_runtime
    USING (
        consumer_workspace_id = mesh_ops.current_workspace_id()
        AND consumer_network_id = mesh_ops.current_network_id()
    );

CREATE FUNCTION mesh_ops.lock_private_endpoint_network_revision_internal_v1(
    p_workspace_id BIGINT,
    p_network_id BIGINT,
    p_expected_network_revision BIGINT,
    p_expected_dns_revision BIGINT,
    p_expected_route_revision BIGINT,
    p_expected_sharing_revision BIGINT
)
RETURNS VOID
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
BEGIN
    IF p_workspace_id <= 0 OR p_network_id <= 0
        OR p_expected_network_revision <= 0 OR p_expected_dns_revision <= 0
        OR p_expected_route_revision <= 0 OR p_expected_sharing_revision <= 0 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Private Endpoint revision lock';
    END IF;
    PERFORM pg_catalog.set_config('mesh.workspace_id', p_workspace_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', p_network_id::TEXT, TRUE);
    PERFORM revision.network_id
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = p_workspace_id
      AND revision.network_id = p_network_id
      AND revision.network_revision = p_expected_network_revision
      AND revision.dns_revision = p_expected_dns_revision
      AND revision.route_revision = p_expected_route_revision
      AND revision.sharing_revision = p_expected_sharing_revision
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Private Endpoint publication revision changed';
    END IF;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.lock_private_endpoint_network_revision_internal_v1(
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.assert_private_endpoint_scope_internal_v1(
    p_deployment_id BIGINT,
    p_deployment_public_id UUID,
    p_recovery_epoch BIGINT,
    p_provider_workspace_id BIGINT,
    p_provider_network_id BIGINT,
    p_provider_authority_generation BIGINT,
    p_consumer_workspace_id BIGINT,
    p_consumer_network_id BIGINT,
    p_consumer_authority_generation BIGINT
)
RETURNS VOID
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    IF p_deployment_id <= 0 OR p_deployment_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR p_recovery_epoch <= 0
        OR p_provider_workspace_id <= 0 OR p_provider_network_id <= 0
        OR p_provider_authority_generation <= 0
        OR p_consumer_workspace_id <= 0 OR p_consumer_network_id <= 0
        OR p_consumer_authority_generation <= 0
        OR (p_provider_workspace_id, p_provider_network_id)
            = (p_consumer_workspace_id, p_consumer_network_id) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Private Endpoint scope proof';
    END IF;

    PERFORM pg_catalog.set_config(
        'mesh.share_provider_workspace_id', p_provider_workspace_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_provider_network_id', p_provider_network_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_consumer_workspace_id', p_consumer_workspace_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_consumer_network_id', p_consumer_network_id::TEXT, TRUE
    );

    PERFORM deployment.id
    FROM mesh.deployment AS deployment
    JOIN mesh.workspace AS provider_workspace
      ON provider_workspace.deployment_id = deployment.id
     AND provider_workspace.id = p_provider_workspace_id
     AND provider_workspace.state = 'active'
    JOIN mesh.network AS provider_network
      ON provider_network.workspace_id = provider_workspace.id
     AND provider_network.id = p_provider_network_id
     AND provider_network.state = 'active'
     AND provider_network.authority_generation = p_provider_authority_generation
    JOIN mesh.workspace AS consumer_workspace
      ON consumer_workspace.deployment_id = deployment.id
     AND consumer_workspace.id = p_consumer_workspace_id
     AND consumer_workspace.state = 'active'
    JOIN mesh.network AS consumer_network
      ON consumer_network.workspace_id = consumer_workspace.id
     AND consumer_network.id = p_consumer_network_id
     AND consumer_network.state = 'active'
     AND consumer_network.authority_generation = p_consumer_authority_generation
    WHERE deployment.id = p_deployment_id
      AND deployment.installation_public_id = p_deployment_public_id
      AND deployment.state = 'active'
      AND deployment.recovery_epoch = p_recovery_epoch;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Private Endpoint scope authority changed';
    END IF;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.assert_private_endpoint_scope_internal_v1(
    BIGINT, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.list_private_endpoint_publication_candidates_v1(
    p_deployment_public_id UUID,
    p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    decision_at TIMESTAMPTZ := pg_catalog.clock_timestamp();
    result JSONB;
BEGIN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    IF p_deployment_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 128 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Private Endpoint publication selection';
    END IF;

    SELECT COALESCE(
        pg_catalog.jsonb_agg(candidate.payload ORDER BY candidate.endpoint_public_id),
        '[]'::JSONB
    ) INTO result
    FROM (
        SELECT endpoint.public_id AS endpoint_public_id,
            pg_catalog.jsonb_build_object(
                'deployment_public_id', p_deployment_public_id,
                'endpoint_public_id', endpoint.public_id,
                'endpoint_version', endpoint.version,
                'endpoint_generation', endpoint.generation,
                'alias_lease_version', lease.version,
                'contract_version', contract.version,
                'imported_resource_version', imported.version,
                'target_device_id', device.public_id,
                'target_generation', contract.target_generation,
                'target_addresses', (
                    SELECT COALESCE(
                        pg_catalog.jsonb_agg(address.address::TEXT ORDER BY address.family),
                        '[]'::JSONB
                    )
                    FROM mesh.node_address_lease AS address
                    WHERE address.workspace_id = contract.provider_workspace_id
                      AND address.network_id = contract.provider_network_id
                      AND address.device_id = device.id
                      AND address.state = 'active'
                      AND address.lease_role = 'primary'
                ),
                'resource_alias', endpoint.resource_alias::TEXT,
                'access_name', access_name.access_name,
                'constraint_hash', pg_catalog.encode(endpoint.constraint_hash, 'hex'),
                'expires_at', endpoint.expires_at
            ) AS payload
        FROM mesh.private_endpoint AS endpoint
        JOIN mesh.deployment AS deployment
          ON deployment.id = endpoint.deployment_id
         AND deployment.installation_public_id = p_deployment_public_id
         AND deployment.state = 'active'
         AND deployment.recovery_epoch = endpoint.recovery_epoch
        JOIN mesh.trust_contract AS contract
          ON contract.id = endpoint.trust_contract_id
         AND contract.version = endpoint.contract_version
         AND contract.state = 'active'
         AND contract.expires_at = endpoint.expires_at
        JOIN mesh.imported_resource AS imported
          ON imported.id = endpoint.imported_resource_id
         AND imported.version = endpoint.imported_resource_version
         AND imported.state = 'active'
        JOIN mesh.imported_resource_access_name AS access_name
          ON access_name.id = endpoint.access_name_id
         AND access_name.imported_resource_id = imported.id
         AND access_name.state = 'reserved'
        JOIN mesh.federation_alias_lease AS lease
          ON lease.id = endpoint.alias_lease_id
         AND lease.resource_alias = endpoint.resource_alias
         AND lease.state = 'reserved'
        JOIN mesh.resource AS resource
          ON resource.id = contract.resource_id
         AND resource.workspace_id = contract.provider_workspace_id
         AND resource.network_id = contract.provider_network_id
         AND resource.version = contract.resource_version
         AND resource.target_generation = contract.target_generation
         AND resource.semantic_hash = contract.resource_semantic_hash
         AND resource.state = 'active'
        JOIN mesh.resource_device_target AS target
          ON target.resource_id = resource.id
         AND target.workspace_id = resource.workspace_id
         AND target.network_id = resource.network_id
         AND target.target_generation = resource.target_generation
         AND target.state = 'active'
        JOIN mesh.device AS device
          ON device.id = target.device_id
         AND device.workspace_id = target.workspace_id
         AND device.network_id = target.network_id
         AND device.state = 'active'
         AND device.expires_at > decision_at
        WHERE endpoint.state = 'provisioning'
          AND endpoint.version = 1
          AND endpoint.expires_at > decision_at
          AND lease.version = 1
          AND EXISTS (
              SELECT 1
              FROM mesh.node_address_lease AS address
              WHERE address.workspace_id = contract.provider_workspace_id
                AND address.network_id = contract.provider_network_id
                AND address.device_id = device.id
                AND address.state = 'active'
                AND address.lease_role = 'primary'
          )
        ORDER BY endpoint.public_id
        LIMIT p_limit
    ) AS candidate;
    RETURN result;
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.list_private_endpoint_publication_candidates_v1(UUID, INTEGER)
FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_private_endpoint_publication_candidates_v1(UUID, INTEGER)
TO mesh_worker;

CREATE FUNCTION mesh_ops.read_private_endpoint_publication_snapshot_v1(
    p_deployment_public_id UUID,
    p_endpoint_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    endpoint_row mesh.private_endpoint%ROWTYPE;
    contract_row mesh.trust_contract%ROWTYPE;
    imported_row mesh.imported_resource%ROWTYPE;
    access_name_row mesh.imported_resource_access_name%ROWTYPE;
    lease_row mesh.federation_alias_lease%ROWTYPE;
    resource_row mesh.resource%ROWTYPE;
    target_row mesh.resource_device_target%ROWTYPE;
    device_row mesh.device%ROWTYPE;
    target_addresses JSONB;
    decision_at TIMESTAMPTZ := pg_catalog.clock_timestamp();
    provider_workspace_internal_id BIGINT;
    provider_network_internal_id BIGINT;
    consumer_workspace_internal_id BIGINT;
    consumer_network_internal_id BIGINT;
    provider_network_revision BIGINT;
    provider_dns_revision BIGINT;
    provider_route_revision BIGINT;
    provider_sharing_revision BIGINT;
    consumer_network_revision BIGINT;
    consumer_dns_revision BIGINT;
    consumer_route_revision BIGINT;
    consumer_sharing_revision BIGINT;
    provider_stream_id BIGINT;
    provider_stream_sequence BIGINT;
    provider_stream_hash BYTEA;
    consumer_stream_id BIGINT;
    consumer_stream_sequence BIGINT;
    consumer_stream_hash BYTEA;
BEGIN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', '', TRUE);
    IF p_deployment_public_id IS NULL OR p_endpoint_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_endpoint_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Private Endpoint publication snapshot';
    END IF;
    SELECT endpoint.*
    INTO STRICT endpoint_row
    FROM mesh.private_endpoint AS endpoint
    WHERE endpoint.public_id = p_endpoint_public_id
      AND endpoint.state = 'provisioning'
      AND endpoint.version = 1
      AND endpoint.expires_at > decision_at;

    provider_workspace_internal_id := endpoint_row.provider_workspace_id;
    provider_network_internal_id := endpoint_row.provider_network_id;
    consumer_workspace_internal_id := endpoint_row.consumer_workspace_id;
    consumer_network_internal_id := endpoint_row.consumer_network_id;

    PERFORM mesh_ops.assert_private_endpoint_scope_internal_v1(
        endpoint_row.deployment_id,
        p_deployment_public_id,
        endpoint_row.recovery_epoch,
        provider_workspace_internal_id,
        provider_network_internal_id,
        endpoint_row.provider_authority_generation,
        consumer_workspace_internal_id,
        consumer_network_internal_id,
        endpoint_row.consumer_authority_generation
    );

    SELECT contract.* INTO STRICT contract_row
    FROM mesh.trust_contract AS contract
    WHERE contract.id = endpoint_row.trust_contract_id
      AND contract.version = endpoint_row.contract_version
      AND contract.state = 'active'
      AND contract.expires_at = endpoint_row.expires_at
      AND contract.constraint_hash = endpoint_row.constraint_hash;
    PERFORM export.id
    FROM mesh.resource_export AS export
    WHERE export.id = contract_row.resource_export_id
      AND export.state = 'active'
      AND export.expires_at >= contract_row.expires_at
      AND export.constraint_hash = contract_row.constraint_hash;
    IF NOT FOUND THEN
        RAISE no_data_found;
    END IF;
    SELECT imported.* INTO STRICT imported_row
    FROM mesh.imported_resource AS imported
    WHERE imported.id = endpoint_row.imported_resource_id
      AND imported.version = endpoint_row.imported_resource_version
      AND imported.state = 'active';
    SELECT access_name.* INTO STRICT access_name_row
    FROM mesh.imported_resource_access_name AS access_name
    WHERE access_name.id = endpoint_row.access_name_id
      AND access_name.imported_resource_id = imported_row.id
      AND access_name.state = 'reserved';
    SELECT lease.* INTO STRICT lease_row
    FROM mesh.federation_alias_lease AS lease
    WHERE lease.id = endpoint_row.alias_lease_id
      AND lease.resource_alias = endpoint_row.resource_alias
      AND lease.state = 'reserved';
    SELECT resource.* INTO STRICT resource_row
    FROM mesh.resource AS resource
    WHERE resource.id = contract_row.resource_id
      AND resource.workspace_id = contract_row.provider_workspace_id
      AND resource.network_id = contract_row.provider_network_id
      AND resource.version = contract_row.resource_version
      AND resource.target_generation = contract_row.target_generation
      AND resource.semantic_hash = contract_row.resource_semantic_hash
      AND resource.state = 'active';
    SELECT target.* INTO STRICT target_row
    FROM mesh.resource_device_target AS target
    WHERE target.resource_id = resource_row.id
      AND target.workspace_id = resource_row.workspace_id
      AND target.network_id = resource_row.network_id
      AND target.target_generation = resource_row.target_generation
      AND target.state = 'active';
    SELECT device.* INTO STRICT device_row
    FROM mesh.device AS device
    WHERE device.id = target_row.device_id
      AND device.workspace_id = target_row.workspace_id
      AND device.network_id = target_row.network_id
      AND device.state = 'active'
      AND device.expires_at > decision_at;
    SELECT COALESCE(
        pg_catalog.jsonb_agg(address.address::TEXT ORDER BY address.family),
        '[]'::JSONB
    ) INTO target_addresses
    FROM mesh.node_address_lease AS address
    WHERE address.workspace_id = contract_row.provider_workspace_id
      AND address.network_id = contract_row.provider_network_id
      AND address.device_id = device_row.id
      AND address.state = 'active'
      AND address.lease_role = 'primary';
    IF target_addresses = '[]'::JSONB THEN
        RAISE no_data_found;
    END IF;

    PERFORM pg_catalog.set_config(
        'mesh.workspace_id', provider_workspace_internal_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.network_id', provider_network_internal_id::TEXT, TRUE
    );
    SELECT
        revision.network_revision,
        revision.dns_revision,
        revision.route_revision,
        revision.sharing_revision
    INTO STRICT
        provider_network_revision,
        provider_dns_revision,
        provider_route_revision,
        provider_sharing_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = provider_workspace_internal_id
      AND revision.network_id = provider_network_internal_id;
    SELECT stream.id, stream.next_sequence, stream.latest_event_hash
    INTO STRICT provider_stream_id, provider_stream_sequence, provider_stream_hash
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.workspace_id = provider_workspace_internal_id
      AND stream.network_id = provider_network_internal_id
      AND stream.scope_kind = 'network';

    PERFORM pg_catalog.set_config(
        'mesh.workspace_id', consumer_workspace_internal_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.network_id', consumer_network_internal_id::TEXT, TRUE
    );
    SELECT
        revision.network_revision,
        revision.dns_revision,
        revision.route_revision,
        revision.sharing_revision
    INTO STRICT
        consumer_network_revision,
        consumer_dns_revision,
        consumer_route_revision,
        consumer_sharing_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = consumer_workspace_internal_id
      AND revision.network_id = consumer_network_internal_id;
    SELECT stream.id, stream.next_sequence, stream.latest_event_hash
    INTO STRICT consumer_stream_id, consumer_stream_sequence, consumer_stream_hash
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.workspace_id = consumer_workspace_internal_id
      AND stream.network_id = consumer_network_internal_id
      AND stream.scope_kind = 'network';

    PERFORM pg_catalog.set_config('mesh.workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', '', TRUE);
    RETURN pg_catalog.jsonb_build_object(
        'deployment_public_id', p_deployment_public_id,
        'endpoint_public_id', p_endpoint_public_id,
        'endpoint_version', endpoint_row.version,
        'endpoint_generation', endpoint_row.generation,
        'alias_lease_version', lease_row.version,
        'contract_version', contract_row.version,
        'imported_resource_version', imported_row.version,
        'target_device_id', device_row.public_id,
        'target_generation', resource_row.target_generation,
        'target_addresses', target_addresses,
        'resource_alias', endpoint_row.resource_alias::TEXT,
        'access_name', access_name_row.access_name,
        'constraint_hash', pg_catalog.encode(endpoint_row.constraint_hash, 'hex'),
        'expires_at', endpoint_row.expires_at,
        'snapshot_at', decision_at,
        'provider_network_revision', provider_network_revision,
        'provider_dns_revision', provider_dns_revision,
        'provider_route_revision', provider_route_revision,
        'provider_sharing_revision', provider_sharing_revision,
        'consumer_network_revision', consumer_network_revision,
        'consumer_dns_revision', consumer_dns_revision,
        'consumer_route_revision', consumer_route_revision,
        'consumer_sharing_revision', consumer_sharing_revision,
        'provider_stream_id', provider_stream_id,
        'provider_stream_sequence', provider_stream_sequence,
        'provider_stream_hash', pg_catalog.encode(provider_stream_hash, 'hex'),
        'consumer_stream_id', consumer_stream_id,
        'consumer_stream_sequence', consumer_stream_sequence,
        'consumer_stream_hash', pg_catalog.encode(consumer_stream_hash, 'hex')
    );
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', '', TRUE);
    RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_private_endpoint_publication_snapshot_v1(UUID, UUID)
FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_private_endpoint_publication_snapshot_v1(UUID, UUID)
TO mesh_worker;

CREATE FUNCTION mesh_ops.publish_private_endpoint_v1(
    p_deployment_public_id UUID,
    p_endpoint_public_id UUID,
    p_expected_endpoint_version BIGINT,
    p_expected_endpoint_generation BIGINT,
    p_expected_alias_lease_version BIGINT,
    p_expected_contract_version BIGINT,
    p_expected_imported_resource_version BIGINT,
    p_expected_provider_network_revision BIGINT,
    p_expected_provider_dns_revision BIGINT,
    p_expected_provider_route_revision BIGINT,
    p_expected_provider_sharing_revision BIGINT,
    p_expected_consumer_network_revision BIGINT,
    p_expected_consumer_dns_revision BIGINT,
    p_expected_consumer_route_revision BIGINT,
    p_expected_consumer_sharing_revision BIGINT,
    p_change_public_id UUID,
    p_readiness_public_id UUID,
    p_dns_publication_public_id UUID,
    p_route_snapshot_hash BYTEA,
    p_reconciler_id TEXT,
    p_observed_at TIMESTAMPTZ,
    p_provider_stream_id BIGINT,
    p_provider_event_public_id UUID,
    p_provider_outbox_public_id UUID,
    p_provider_stream_sequence BIGINT,
    p_provider_previous_hash BYTEA,
    p_provider_event_hash BYTEA,
    p_provider_audit_payload JSONB,
    p_provider_outbox_payload JSONB,
    p_consumer_stream_id BIGINT,
    p_consumer_event_public_id UUID,
    p_consumer_outbox_public_id UUID,
    p_consumer_stream_sequence BIGINT,
    p_consumer_previous_hash BYTEA,
    p_consumer_event_hash BYTEA,
    p_consumer_audit_payload JSONB,
    p_consumer_outbox_payload JSONB
)
RETURNS TABLE (
    provider_network_revision BIGINT,
    provider_dns_revision BIGINT,
    provider_route_revision BIGINT,
    provider_sharing_revision BIGINT,
    consumer_network_revision BIGINT,
    consumer_dns_revision BIGINT,
    consumer_route_revision BIGINT,
    consumer_sharing_revision BIGINT,
    alias_lease_version BIGINT,
    private_endpoint_version BIGINT,
    readiness_version BIGINT,
    dns_publication_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    endpoint_row mesh.private_endpoint%ROWTYPE;
    contract_row mesh.trust_contract%ROWTYPE;
    imported_row mesh.imported_resource%ROWTYPE;
    access_name_row mesh.imported_resource_access_name%ROWTYPE;
    lease_row mesh.federation_alias_lease%ROWTYPE;
    resource_row mesh.resource%ROWTYPE;
    target_row mesh.resource_device_target%ROWTYPE;
    device_row mesh.device%ROWTYPE;
    provider_workspace_internal_id BIGINT;
    provider_network_internal_id BIGINT;
    consumer_workspace_internal_id BIGINT;
    consumer_network_internal_id BIGINT;
    decision_at TIMESTAMPTZ := pg_catalog.clock_timestamp();
    transaction_value BIGINT := (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT;
    appended_sequence BIGINT;
BEGIN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    IF p_deployment_public_id IS NULL OR p_endpoint_public_id IS NULL
        OR p_change_public_id IS NULL OR p_readiness_public_id IS NULL
        OR p_dns_publication_public_id IS NULL
        OR p_expected_endpoint_version <> 1
        OR p_expected_endpoint_generation <= 0
        OR p_expected_alias_lease_version <> 1
        OR p_expected_contract_version <= 0
        OR p_expected_imported_resource_version <= 0
        OR p_expected_provider_network_revision <= 0
        OR p_expected_provider_dns_revision <= 0
        OR p_expected_provider_route_revision <= 0
        OR p_expected_provider_sharing_revision <= 0
        OR p_expected_consumer_network_revision <= 0
        OR p_expected_consumer_dns_revision <= 0
        OR p_expected_consumer_route_revision <= 0
        OR p_expected_consumer_sharing_revision <= 0
        OR p_route_snapshot_hash IS NULL
        OR pg_catalog.octet_length(p_route_snapshot_hash) <> 32
        OR p_route_snapshot_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_reconciler_id IS NULL
        OR pg_catalog.char_length(p_reconciler_id) NOT BETWEEN 1 AND 128
        OR p_reconciler_id <> pg_catalog.btrim(p_reconciler_id)
        OR p_reconciler_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR p_observed_at IS NULL OR p_observed_at > decision_at
        OR p_provider_stream_id <= 0 OR p_consumer_stream_id <= 0
        OR p_provider_stream_id = p_consumer_stream_id
        OR p_provider_stream_sequence <= 0 OR p_consumer_stream_sequence <= 0
        OR p_provider_previous_hash IS NULL
        OR pg_catalog.octet_length(p_provider_previous_hash) <> 32
        OR p_consumer_previous_hash IS NULL
        OR pg_catalog.octet_length(p_consumer_previous_hash) <> 32
        OR p_provider_event_hash IS NULL
        OR pg_catalog.octet_length(p_provider_event_hash) <> 32
        OR p_provider_event_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_consumer_event_hash IS NULL
        OR pg_catalog.octet_length(p_consumer_event_hash) <> 32
        OR p_consumer_event_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_provider_audit_payload IS NULL
        OR pg_catalog.jsonb_typeof(p_provider_audit_payload) <> 'object'
        OR p_provider_outbox_payload IS NULL
        OR pg_catalog.jsonb_typeof(p_provider_outbox_payload) <> 'object'
        OR p_consumer_audit_payload IS NULL
        OR pg_catalog.jsonb_typeof(p_consumer_audit_payload) <> 'object'
        OR p_consumer_outbox_payload IS NULL
        OR pg_catalog.jsonb_typeof(p_consumer_outbox_payload) <> 'object'
        OR (SELECT pg_catalog.count(*) FROM (
            SELECT DISTINCT value
            FROM pg_catalog.unnest(ARRAY[
                p_endpoint_public_id, p_change_public_id, p_readiness_public_id,
                p_dns_publication_public_id, p_provider_event_public_id,
                p_provider_outbox_public_id, p_consumer_event_public_id,
                p_consumer_outbox_public_id
            ]::UUID[]) AS identity(value)
        ) AS unique_identity) <> 8 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Private Endpoint publication proof';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.unnest(ARRAY[
            p_deployment_public_id, p_endpoint_public_id, p_change_public_id,
            p_readiness_public_id, p_dns_publication_public_id,
            p_provider_event_public_id, p_provider_outbox_public_id,
            p_consumer_event_public_id, p_consumer_outbox_public_id
        ]::UUID[]) AS identity(value)
        WHERE pg_catalog.get_byte(pg_catalog.uuid_send(identity.value), 6) >> 4 <> 7
           OR pg_catalog.get_byte(pg_catalog.uuid_send(identity.value), 8) & 192 <> 128
    ) OR EXISTS (
        SELECT 1 FROM mesh_audit.authority_mutation AS mutation
        WHERE mutation.change_public_id = p_change_public_id
           OR mutation.transaction_id = transaction_value
    ) OR EXISTS (
        SELECT 1 FROM mesh_audit.audit_event_identity AS event
        WHERE event.change_public_id = p_change_public_id
           OR event.transaction_id = transaction_value
    ) OR EXISTS (
        SELECT 1 FROM mesh_ops.outbox_event AS event
        WHERE event.change_public_id = p_change_public_id
           OR event.transaction_id = transaction_value
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Private Endpoint publication requires a fresh owned unit';
    END IF;

    SELECT endpoint.*
    INTO STRICT endpoint_row
    FROM mesh.private_endpoint AS endpoint
    JOIN mesh.deployment AS deployment
      ON deployment.id = endpoint.deployment_id
     AND deployment.installation_public_id = p_deployment_public_id
    WHERE endpoint.public_id = p_endpoint_public_id;

    provider_workspace_internal_id := endpoint_row.provider_workspace_id;
    provider_network_internal_id := endpoint_row.provider_network_id;
    consumer_workspace_internal_id := endpoint_row.consumer_workspace_id;
    consumer_network_internal_id := endpoint_row.consumer_network_id;

    PERFORM pg_catalog.set_config(
        'mesh.share_provider_workspace_id', provider_workspace_internal_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_provider_network_id', provider_network_internal_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_consumer_workspace_id', consumer_workspace_internal_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_consumer_network_id', consumer_network_internal_id::TEXT, TRUE
    );

    IF (provider_workspace_internal_id, provider_network_internal_id)
        < (consumer_workspace_internal_id, consumer_network_internal_id) THEN
        PERFORM mesh_ops.lock_private_endpoint_network_revision_internal_v1(
            provider_workspace_internal_id, provider_network_internal_id,
            p_expected_provider_network_revision, p_expected_provider_dns_revision,
            p_expected_provider_route_revision, p_expected_provider_sharing_revision
        );
        PERFORM mesh_ops.lock_private_endpoint_network_revision_internal_v1(
            consumer_workspace_internal_id, consumer_network_internal_id,
            p_expected_consumer_network_revision, p_expected_consumer_dns_revision,
            p_expected_consumer_route_revision, p_expected_consumer_sharing_revision
        );
    ELSE
        PERFORM mesh_ops.lock_private_endpoint_network_revision_internal_v1(
            consumer_workspace_internal_id, consumer_network_internal_id,
            p_expected_consumer_network_revision, p_expected_consumer_dns_revision,
            p_expected_consumer_route_revision, p_expected_consumer_sharing_revision
        );
        PERFORM mesh_ops.lock_private_endpoint_network_revision_internal_v1(
            provider_workspace_internal_id, provider_network_internal_id,
            p_expected_provider_network_revision, p_expected_provider_dns_revision,
            p_expected_provider_route_revision, p_expected_provider_sharing_revision
        );
    END IF;

    PERFORM mesh_ops.assert_private_endpoint_scope_internal_v1(
        endpoint_row.deployment_id,
        p_deployment_public_id,
        endpoint_row.recovery_epoch,
        provider_workspace_internal_id,
        provider_network_internal_id,
        endpoint_row.provider_authority_generation,
        consumer_workspace_internal_id,
        consumer_network_internal_id,
        endpoint_row.consumer_authority_generation
    );

    SELECT endpoint.*
    INTO STRICT endpoint_row
    FROM mesh.private_endpoint AS endpoint
    JOIN mesh.deployment AS deployment
      ON deployment.id = endpoint.deployment_id
     AND deployment.installation_public_id = p_deployment_public_id
     AND deployment.state = 'active'
     AND deployment.recovery_epoch = endpoint.recovery_epoch
    JOIN mesh.trust_contract AS contract
      ON contract.id = endpoint.trust_contract_id
     AND contract.version = p_expected_contract_version
     AND contract.version = endpoint.contract_version
     AND contract.state = 'active'
     AND contract.expires_at = endpoint.expires_at
    JOIN mesh.resource_export AS export
      ON export.id = contract.resource_export_id
     AND export.state = 'active'
     AND export.expires_at >= contract.expires_at
     AND export.constraint_hash = contract.constraint_hash
    JOIN mesh.imported_resource AS imported
      ON imported.id = endpoint.imported_resource_id
     AND imported.version = p_expected_imported_resource_version
     AND imported.version = endpoint.imported_resource_version
     AND imported.state = 'active'
    JOIN mesh.imported_resource_access_name AS access_name
      ON access_name.id = endpoint.access_name_id
     AND access_name.imported_resource_id = imported.id
     AND access_name.state = 'reserved'
    JOIN mesh.federation_alias_lease AS lease
      ON lease.id = endpoint.alias_lease_id
     AND lease.resource_alias = endpoint.resource_alias
     AND lease.version = p_expected_alias_lease_version
     AND lease.state = 'reserved'
    JOIN mesh.resource AS resource
      ON resource.id = contract.resource_id
     AND resource.workspace_id = contract.provider_workspace_id
     AND resource.network_id = contract.provider_network_id
     AND resource.version = contract.resource_version
     AND resource.target_generation = contract.target_generation
     AND resource.semantic_hash = contract.resource_semantic_hash
     AND resource.state = 'active'
    JOIN mesh.resource_device_target AS target
      ON target.resource_id = resource.id
     AND target.workspace_id = resource.workspace_id
     AND target.network_id = resource.network_id
     AND target.target_generation = resource.target_generation
     AND target.state = 'active'
    JOIN mesh.device AS device
      ON device.id = target.device_id
     AND device.workspace_id = target.workspace_id
     AND device.network_id = target.network_id
     AND device.state = 'active'
     AND device.expires_at > decision_at
    WHERE endpoint.public_id = p_endpoint_public_id
      AND endpoint.provider_workspace_id = provider_workspace_internal_id
      AND endpoint.provider_network_id = provider_network_internal_id
      AND endpoint.consumer_workspace_id = consumer_workspace_internal_id
      AND endpoint.consumer_network_id = consumer_network_internal_id
      AND endpoint.version = p_expected_endpoint_version
      AND endpoint.generation = p_expected_endpoint_generation
      AND endpoint.state = 'provisioning'
      AND endpoint.expires_at > decision_at
      AND endpoint.constraint_hash = contract.constraint_hash
      AND p_observed_at >= endpoint.created_at
      AND EXISTS (
          SELECT 1 FROM mesh.node_address_lease AS address
          WHERE address.workspace_id = contract.provider_workspace_id
            AND address.network_id = contract.provider_network_id
            AND address.device_id = device.id
            AND address.state = 'active'
            AND address.lease_role = 'primary'
      )
    FOR UPDATE OF endpoint, contract, imported, access_name, lease, resource, target, device;

    SELECT contract.* INTO STRICT contract_row
    FROM mesh.trust_contract AS contract
    WHERE contract.id = endpoint_row.trust_contract_id;
    SELECT imported.* INTO STRICT imported_row
    FROM mesh.imported_resource AS imported
    WHERE imported.id = endpoint_row.imported_resource_id;
    SELECT access_name.* INTO STRICT access_name_row
    FROM mesh.imported_resource_access_name AS access_name
    WHERE access_name.id = endpoint_row.access_name_id;
    SELECT lease.* INTO STRICT lease_row
    FROM mesh.federation_alias_lease AS lease
    WHERE lease.id = endpoint_row.alias_lease_id;
    SELECT resource.* INTO STRICT resource_row
    FROM mesh.resource AS resource
    WHERE resource.id = contract_row.resource_id;
    SELECT target.* INTO STRICT target_row
    FROM mesh.resource_device_target AS target
    WHERE target.resource_id = resource_row.id
      AND target.target_generation = resource_row.target_generation;
    SELECT device.* INTO STRICT device_row
    FROM mesh.device AS device
    WHERE device.id = target_row.device_id;

    IF NOT EXISTS (
        SELECT 1 FROM mesh_audit.audit_stream AS stream
        WHERE stream.id = p_provider_stream_id
          AND stream.workspace_id = provider_workspace_internal_id
          AND stream.network_id = provider_network_internal_id
          AND stream.scope_kind = 'network'
    ) OR NOT EXISTS (
        SELECT 1 FROM mesh_audit.audit_stream AS stream
        WHERE stream.id = p_consumer_stream_id
          AND stream.workspace_id = consumer_workspace_internal_id
          AND stream.network_id = consumer_network_internal_id
          AND stream.scope_kind = 'network'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Private Endpoint publication stream mismatch';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.federation_alias_lease AS lease
    SET state = 'active', version = lease.version + 1,
        updated_at = decision_at, activated_at = decision_at
    WHERE lease.id = lease_row.id AND lease.version = p_expected_alias_lease_version
      AND lease.state = 'reserved'
    RETURNING lease.version INTO alias_lease_version;
    UPDATE mesh.private_endpoint AS endpoint
    SET state = 'ready', version = endpoint.version + 1,
        updated_at = decision_at, ready_at = decision_at
    WHERE endpoint.id = endpoint_row.id AND endpoint.version = p_expected_endpoint_version
      AND endpoint.state = 'provisioning'
    RETURNING endpoint.version INTO private_endpoint_version;
    IF alias_lease_version <> 2 OR private_endpoint_version <> 2 THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Private Endpoint publication target changed';
    END IF;

    PERFORM pg_catalog.set_config(
        'mesh.workspace_id', provider_workspace_internal_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.network_id', provider_network_internal_id::TEXT, TRUE
    );
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        route_revision = revision.route_revision + 1,
        sharing_revision = revision.sharing_revision + 1,
        updated_at = decision_at
    WHERE revision.workspace_id = provider_workspace_internal_id
      AND revision.network_id = provider_network_internal_id
    RETURNING revision.network_revision, revision.dns_revision,
        revision.route_revision, revision.sharing_revision
    INTO provider_network_revision, provider_dns_revision,
        provider_route_revision, provider_sharing_revision;
    PERFORM pg_catalog.set_config(
        'mesh.workspace_id', consumer_workspace_internal_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.network_id', consumer_network_internal_id::TEXT, TRUE
    );
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        dns_revision = revision.dns_revision + 1,
        route_revision = revision.route_revision + 1,
        sharing_revision = revision.sharing_revision + 1,
        updated_at = decision_at
    WHERE revision.workspace_id = consumer_workspace_internal_id
      AND revision.network_id = consumer_network_internal_id
    RETURNING revision.network_revision, revision.dns_revision,
        revision.route_revision, revision.sharing_revision
    INTO consumer_network_revision, consumer_dns_revision,
        consumer_route_revision, consumer_sharing_revision;
    PERFORM pg_catalog.set_config('mesh.workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', '', TRUE);

    INSERT INTO mesh.private_endpoint_readiness (
        public_id, deployment_id,
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id,
        private_endpoint_id, imported_resource_id, access_name_id, alias_lease_id,
        target_device_public_id, endpoint_generation, resource_alias,
        route_snapshot_hash, reconciler_id,
        provider_route_revision, consumer_route_revision,
        observed_at, created_at
    ) VALUES (
        p_readiness_public_id, endpoint_row.deployment_id,
        endpoint_row.provider_workspace_id, endpoint_row.provider_network_id,
        endpoint_row.consumer_workspace_id, endpoint_row.consumer_network_id,
        endpoint_row.id, endpoint_row.imported_resource_id,
        endpoint_row.access_name_id, endpoint_row.alias_lease_id,
        device_row.public_id, endpoint_row.generation, endpoint_row.resource_alias,
        p_route_snapshot_hash, p_reconciler_id,
        provider_route_revision, consumer_route_revision,
        p_observed_at, decision_at
    ) RETURNING version INTO readiness_version;

    INSERT INTO mesh.imported_resource_dns_publication (
        public_id, deployment_id,
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id,
        imported_resource_id, access_name_id, private_endpoint_id, alias_lease_id,
        access_name, resource_alias, endpoint_generation,
        dns_revision, route_revision, state, created_at, updated_at
    ) VALUES (
        p_dns_publication_public_id, endpoint_row.deployment_id,
        endpoint_row.provider_workspace_id, endpoint_row.provider_network_id,
        endpoint_row.consumer_workspace_id, endpoint_row.consumer_network_id,
        endpoint_row.imported_resource_id, endpoint_row.access_name_id,
        endpoint_row.id, endpoint_row.alias_lease_id,
        access_name_row.access_name, endpoint_row.resource_alias, endpoint_row.generation,
        consumer_dns_revision, consumer_route_revision,
        'published', decision_at, decision_at
    ) RETURNING version INTO dns_publication_version;

    IF readiness_version <> 1 OR dns_publication_version <> 1
        OR (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = p_change_public_id
              AND mutation.transaction_id = transaction_value) <> 4
        OR NOT EXISTS (
            SELECT 1 FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = p_change_public_id
              AND mutation.transaction_id = transaction_value
              AND mutation.aggregate_kind = 'federation_alias_lease'
              AND mutation.row_public_id = lease_row.public_id
              AND mutation.operation = 'update'
              AND mutation.before_version = 1 AND mutation.after_version = 2
        ) OR NOT EXISTS (
            SELECT 1 FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = p_change_public_id
              AND mutation.transaction_id = transaction_value
              AND mutation.aggregate_kind = 'private_endpoint'
              AND mutation.row_public_id = endpoint_row.public_id
              AND mutation.operation = 'update'
              AND mutation.before_version = 1 AND mutation.after_version = 2
        ) OR NOT EXISTS (
            SELECT 1 FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = p_change_public_id
              AND mutation.transaction_id = transaction_value
              AND mutation.aggregate_kind = 'private_endpoint_readiness'
              AND mutation.row_public_id = p_readiness_public_id
              AND mutation.operation = 'insert'
              AND mutation.before_version IS NULL AND mutation.after_version = 1
        ) OR NOT EXISTS (
            SELECT 1 FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = p_change_public_id
              AND mutation.transaction_id = transaction_value
              AND mutation.aggregate_kind = 'imported_resource_dns_publication'
              AND mutation.row_public_id = p_dns_publication_public_id
              AND mutation.operation = 'insert'
              AND mutation.before_version IS NULL AND mutation.after_version = 1
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Private Endpoint publication mutation set is invalid';
    END IF;

    IF p_provider_audit_payload <> pg_catalog.jsonb_build_object(
        'endpoint_public_id', endpoint_row.public_id,
        'readiness_public_id', p_readiness_public_id,
        'dns_publication_public_id', p_dns_publication_public_id,
        'authority_side', 'provider',
        'reconciler_id', p_reconciler_id,
        'endpoint_generation', endpoint_row.generation,
        'resource_alias', endpoint_row.resource_alias::TEXT,
        'route_snapshot_hash', pg_catalog.encode(p_route_snapshot_hash, 'hex'),
        'network_revision', provider_network_revision,
        'dns_revision', provider_dns_revision,
        'route_revision', provider_route_revision,
        'sharing_revision', provider_sharing_revision
    ) OR p_consumer_audit_payload <> pg_catalog.jsonb_build_object(
        'endpoint_public_id', endpoint_row.public_id,
        'readiness_public_id', p_readiness_public_id,
        'dns_publication_public_id', p_dns_publication_public_id,
        'authority_side', 'consumer',
        'reconciler_id', p_reconciler_id,
        'endpoint_generation', endpoint_row.generation,
        'resource_alias', endpoint_row.resource_alias::TEXT,
        'route_snapshot_hash', pg_catalog.encode(p_route_snapshot_hash, 'hex'),
        'network_revision', consumer_network_revision,
        'dns_revision', consumer_dns_revision,
        'route_revision', consumer_route_revision,
        'sharing_revision', consumer_sharing_revision
    ) OR p_provider_outbox_payload <> pg_catalog.jsonb_build_object(
        'endpoint_public_id', endpoint_row.public_id,
        'network_revision', provider_network_revision,
        'dns_revision', provider_dns_revision,
        'route_revision', provider_route_revision,
        'subsystem', 'sharing',
        'subsystem_revision', provider_sharing_revision
    ) OR p_consumer_outbox_payload <> pg_catalog.jsonb_build_object(
        'endpoint_public_id', endpoint_row.public_id,
        'network_revision', consumer_network_revision,
        'dns_revision', consumer_dns_revision,
        'route_revision', consumer_route_revision,
        'subsystem', 'sharing',
        'subsystem_revision', consumer_sharing_revision
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Private Endpoint publication evidence payload mismatch';
    END IF;

    appended_sequence := mesh_audit.append_authority_evidence(
        p_provider_stream_id, p_provider_event_public_id, p_provider_outbox_public_id,
        p_provider_stream_sequence, p_provider_previous_hash, p_provider_event_hash,
        'private_endpoint', endpoint_row.public_id, private_endpoint_version,
        provider_network_revision, NULL::UUID, 'private_endpoint.published',
        'system.reconcile', endpoint_row.public_id, NULL::BYTEA, p_route_snapshot_hash,
        p_provider_audit_payload, 'sharing.private_endpoint.published',
        p_provider_outbox_payload
    );
    IF appended_sequence <> p_provider_stream_sequence THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'provider publication evidence changed';
    END IF;
    appended_sequence := mesh_audit.append_authority_evidence(
        p_consumer_stream_id, p_consumer_event_public_id, p_consumer_outbox_public_id,
        p_consumer_stream_sequence, p_consumer_previous_hash, p_consumer_event_hash,
        'private_endpoint', endpoint_row.public_id, private_endpoint_version,
        consumer_network_revision, NULL::UUID, 'private_endpoint.published',
        'system.reconcile', endpoint_row.public_id, NULL::BYTEA, p_route_snapshot_hash,
        p_consumer_audit_payload, 'sharing.private_endpoint.published',
        p_consumer_outbox_payload
    );
    IF appended_sequence <> p_consumer_stream_sequence THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'consumer publication evidence changed';
    END IF;
    RETURN NEXT;
EXCEPTION
    WHEN no_data_found THEN
        PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
        PERFORM pg_catalog.set_config('mesh.change_public_id', '', TRUE);
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Private Endpoint publication authority changed';
    WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
        PERFORM pg_catalog.set_config('mesh.change_public_id', '', TRUE);
        RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.publish_private_endpoint_v1(
    UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, BYTEA, TEXT, TIMESTAMPTZ,
    BIGINT, UUID, UUID, BIGINT, BYTEA, BYTEA, JSONB, JSONB,
    BIGINT, UUID, UUID, BIGINT, BYTEA, BYTEA, JSONB, JSONB
) FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.publish_private_endpoint_v1(
    UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, BYTEA, TEXT, TIMESTAMPTZ,
    BIGINT, UUID, UUID, BIGINT, BYTEA, BYTEA, JSONB, JSONB,
    BIGINT, UUID, UUID, BIGINT, BYTEA, BYTEA, JSONB, JSONB
) TO mesh_worker;

CREATE FUNCTION mesh_ops.withdraw_private_endpoint_publication_internal_v1(
    p_provider_workspace_id BIGINT,
    p_provider_network_id BIGINT,
    p_consumer_workspace_id BIGINT,
    p_consumer_network_id BIGINT,
    p_contract_public_id UUID,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    provider_network_revision BIGINT,
    consumer_network_revision BIGINT,
    dns_publication_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    withdrawn_publication_id BIGINT;
    previous_workspace_scope TEXT := pg_catalog.current_setting('mesh.workspace_id', TRUE);
    previous_network_scope TEXT := pg_catalog.current_setting('mesh.network_id', TRUE);
BEGIN
    IF p_provider_workspace_id <= 0 OR p_provider_network_id <= 0
        OR p_consumer_workspace_id <= 0 OR p_consumer_network_id <= 0
        OR (p_provider_workspace_id = p_consumer_workspace_id
            AND p_provider_network_id = p_consumer_network_id)
        OR p_contract_public_id IS NULL OR p_occurred_at IS NULL
        OR p_provider_workspace_id <> mesh_ops.current_share_provider_workspace_id()
        OR p_provider_network_id <> mesh_ops.current_share_provider_network_id()
        OR p_consumer_workspace_id <> mesh_ops.current_share_consumer_workspace_id()
        OR p_consumer_network_id <> mesh_ops.current_share_consumer_network_id() THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Private Endpoint withdrawal scope';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM mesh.trust_contract AS contract
        WHERE contract.public_id = p_contract_public_id
          AND contract.provider_workspace_id = p_provider_workspace_id
          AND contract.provider_network_id = p_provider_network_id
          AND contract.consumer_workspace_id = p_consumer_workspace_id
          AND contract.consumer_network_id = p_consumer_network_id
          AND contract.state IN ('revoked', 'expired', 'invalidated')
          AND contract.ended_at = p_occurred_at
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Private Endpoint withdrawal authority is unavailable';
    END IF;

    UPDATE mesh.imported_resource_dns_publication AS publication
    SET state = 'withdrawn', version = publication.version + 1,
        updated_at = p_occurred_at, withdrawn_at = p_occurred_at
    FROM mesh.private_endpoint AS endpoint
    JOIN mesh.trust_contract AS contract
      ON contract.id = endpoint.trust_contract_id
    WHERE contract.public_id = p_contract_public_id
      AND contract.provider_workspace_id = p_provider_workspace_id
      AND contract.provider_network_id = p_provider_network_id
      AND contract.consumer_workspace_id = p_consumer_workspace_id
      AND contract.consumer_network_id = p_consumer_network_id
      AND publication.private_endpoint_id = endpoint.id
      AND publication.provider_workspace_id = endpoint.provider_workspace_id
      AND publication.provider_network_id = endpoint.provider_network_id
      AND publication.consumer_workspace_id = endpoint.consumer_workspace_id
      AND publication.consumer_network_id = endpoint.consumer_network_id
      AND publication.state = 'published'
    RETURNING publication.id, publication.version
    INTO withdrawn_publication_id, dns_publication_version;

    IF withdrawn_publication_id IS NULL THEN
        dns_publication_version := 0;
        provider_network_revision := 0;
        consumer_network_revision := 0;
        RETURN NEXT;
        RETURN;
    END IF;
    PERFORM pg_catalog.set_config('mesh.workspace_id', p_provider_workspace_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', p_provider_network_id::TEXT, TRUE);
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        route_revision = revision.route_revision + 1,
        updated_at = p_occurred_at
    WHERE revision.workspace_id = p_provider_workspace_id
      AND revision.network_id = p_provider_network_id
    RETURNING revision.network_revision INTO provider_network_revision;
    PERFORM pg_catalog.set_config('mesh.workspace_id', p_consumer_workspace_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', p_consumer_network_id::TEXT, TRUE);
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        dns_revision = revision.dns_revision + 1,
        route_revision = revision.route_revision + 1,
        updated_at = p_occurred_at
    WHERE revision.workspace_id = p_consumer_workspace_id
      AND revision.network_id = p_consumer_network_id
    RETURNING revision.network_revision INTO consumer_network_revision;
    PERFORM pg_catalog.set_config(
        'mesh.workspace_id', COALESCE(previous_workspace_scope, ''), TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.network_id', COALESCE(previous_network_scope, ''), TRUE
    );
    IF dns_publication_version <> 2
        OR provider_network_revision IS NULL
        OR consumer_network_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Private Endpoint publication withdrawal failed';
    END IF;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.withdraw_private_endpoint_publication_internal_v1(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.withdraw_private_endpoint_publication_internal_v1(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, TIMESTAMPTZ
) TO mesh_share_writer;

CREATE FUNCTION mesh_ops.revoke_resource_share_v4(
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
    private_endpoint_version BIGINT,
    dns_publication_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    withdrawal_provider_network_revision BIGINT;
    withdrawal_consumer_network_revision BIGINT;
BEGIN
    SELECT
        revoked.provider_network_revision,
        revoked.provider_sharing_revision,
        revoked.consumer_network_revision,
        revoked.consumer_sharing_revision,
        revoked.contract_version,
        revoked.imported_resource_version,
        revoked.access_name_version,
        revoked.alias_lease_version,
        revoked.private_endpoint_version
    INTO
        provider_network_revision,
        provider_sharing_revision,
        consumer_network_revision,
        consumer_sharing_revision,
        contract_version,
        imported_resource_version,
        access_name_version,
        alias_lease_version,
        private_endpoint_version
    FROM mesh_ops.revoke_resource_share_v3(
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

    SELECT
        withdrawn.provider_network_revision,
        withdrawn.consumer_network_revision,
        withdrawn.dns_publication_version
    INTO
        withdrawal_provider_network_revision,
        withdrawal_consumer_network_revision,
        dns_publication_version
    FROM mesh_ops.withdraw_private_endpoint_publication_internal_v1(
        p_provider_workspace_id,
        p_provider_network_id,
        p_consumer_workspace_id,
        p_consumer_network_id,
        p_contract_public_id,
        p_occurred_at
    ) AS withdrawn;
    IF dns_publication_version > 0 THEN
        provider_network_revision := withdrawal_provider_network_revision;
        consumer_network_revision := withdrawal_consumer_network_revision;
    END IF;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON
    mesh.private_endpoint_readiness,
    mesh.imported_resource_dns_publication
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON SEQUENCE
    mesh.private_endpoint_readiness_id_seq,
    mesh.imported_resource_dns_publication_id_seq
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.reject_private_endpoint_readiness_change()
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.enforce_imported_resource_dns_publication_transition()
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.revoke_resource_share_v4(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;

GRANT SELECT ON
    mesh.private_endpoint_readiness,
    mesh.imported_resource_dns_publication
TO mesh_runtime;
