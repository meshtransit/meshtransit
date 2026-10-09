ALTER TABLE mesh.private_endpoint
    ADD CONSTRAINT private_endpoint_internal_generation_key UNIQUE (id, generation);

CREATE POLICY workspace_private_endpoint_reconciliation_policy ON mesh.workspace
    FOR SELECT TO mesh_migrator
    USING (
        id IN (
            mesh_ops.current_share_provider_workspace_id(),
            mesh_ops.current_share_consumer_workspace_id()
        )
    );
CREATE POLICY network_private_endpoint_reconciliation_policy ON mesh.network
    FOR SELECT TO mesh_migrator
    USING (
        (
            workspace_id = mesh_ops.current_share_provider_workspace_id()
            AND id = mesh_ops.current_share_provider_network_id()
        ) OR (
            workspace_id = mesh_ops.current_share_consumer_workspace_id()
            AND id = mesh_ops.current_share_consumer_network_id()
        )
    );

CREATE TABLE mesh_ops.private_endpoint_route_intent (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    private_endpoint_id BIGINT NOT NULL UNIQUE,
    endpoint_generation BIGINT NOT NULL CHECK (endpoint_generation > 0),
    target_device_public_id UUID NOT NULL,
    target_generation BIGINT NOT NULL CHECK (target_generation > 0),
    target_addresses JSONB NOT NULL,
    route_snapshot_hash BYTEA NOT NULL,
    reconciler_id TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT private_endpoint_route_intent_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT private_endpoint_route_intent_hash_check CHECK (
        pg_catalog.octet_length(route_snapshot_hash) = 32
        AND route_snapshot_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT private_endpoint_route_intent_target_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(target_device_public_id), 6) >> 4 = 7
        AND pg_catalog.jsonb_typeof(target_addresses) = 'array'
        AND pg_catalog.jsonb_array_length(target_addresses) BETWEEN 1 AND 2
    ),
    CONSTRAINT private_endpoint_route_intent_reconciler_check CHECK (
        pg_catalog.char_length(reconciler_id) BETWEEN 1 AND 128
        AND reconciler_id = pg_catalog.btrim(reconciler_id)
        AND reconciler_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT private_endpoint_route_intent_timestamps_check CHECK (
        observed_at <= created_at
    ),
    CONSTRAINT private_endpoint_route_intent_deployment_fk FOREIGN KEY (deployment_id)
        REFERENCES mesh.deployment (id) ON DELETE RESTRICT,
    CONSTRAINT private_endpoint_route_intent_endpoint_fk FOREIGN KEY (
        private_endpoint_id, endpoint_generation
    ) REFERENCES mesh.private_endpoint (id, generation) ON DELETE RESTRICT,
    CONSTRAINT private_endpoint_route_intent_target_device_fk FOREIGN KEY (
        target_device_public_id
    ) REFERENCES mesh.device (public_id) ON DELETE RESTRICT
);

CREATE FUNCTION mesh_ops.reject_private_endpoint_route_intent_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Private Endpoint route intent is immutable';
END;
$function$;

CREATE TRIGGER private_endpoint_route_intent_immutable
BEFORE INSERT OR UPDATE OR DELETE ON mesh_ops.private_endpoint_route_intent
FOR EACH ROW EXECUTE FUNCTION mesh_ops.reject_private_endpoint_route_intent_change();

ALTER TABLE mesh_ops.private_endpoint_route_intent ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.private_endpoint_route_intent FORCE ROW LEVEL SECURITY;
CREATE POLICY private_endpoint_route_intent_migrator_policy
    ON mesh_ops.private_endpoint_route_intent TO mesh_migrator
    USING (TRUE) WITH CHECK (TRUE);

CREATE FUNCTION mesh_ops.read_private_endpoint_publication_snapshot_v2(
    p_deployment_public_id UUID,
    p_endpoint_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    base JSONB;
    endpoint_row mesh.private_endpoint%ROWTYPE;
    provider_workspace_public_id UUID;
    provider_network_public_id UUID;
    consumer_workspace_public_id UUID;
    consumer_network_public_id UUID;
    traffic JSONB;
    canonical_target_addresses JSONB;
BEGIN
    base := mesh_ops.read_private_endpoint_publication_snapshot_v1(
        p_deployment_public_id, p_endpoint_public_id
    );
    SELECT endpoint.* INTO STRICT endpoint_row
    FROM mesh.private_endpoint AS endpoint
    WHERE endpoint.public_id = p_endpoint_public_id;

    PERFORM pg_catalog.set_config(
        'mesh.share_provider_workspace_id', endpoint_row.provider_workspace_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_provider_network_id', endpoint_row.provider_network_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_consumer_workspace_id', endpoint_row.consumer_workspace_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_consumer_network_id', endpoint_row.consumer_network_id::TEXT, TRUE
    );

    SELECT workspace.public_id, network.public_id
    INTO STRICT provider_workspace_public_id, provider_network_public_id
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.id = endpoint_row.provider_network_id
    WHERE workspace.id = endpoint_row.provider_workspace_id;
    SELECT workspace.public_id, network.public_id
    INTO STRICT consumer_workspace_public_id, consumer_network_public_id
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.id = endpoint_row.consumer_network_id
    WHERE workspace.id = endpoint_row.consumer_workspace_id;

    SELECT COALESCE(
        pg_catalog.jsonb_agg(
            pg_catalog.jsonb_build_object(
                'protocol', constraint_row.protocol,
                'destination_port_ranges', constraint_row.port_ranges
            ) ORDER BY constraint_row.protocol_order
        ),
        '[]'::JSONB
    ) INTO traffic
    FROM (
        SELECT export_constraint.protocol,
            CASE export_constraint.protocol
                WHEN 'tcp' THEN 1 WHEN 'udp' THEN 2 ELSE 3
            END AS protocol_order,
            CASE WHEN export_constraint.protocol = 'icmp' THEN '[]'::JSONB ELSE (
                SELECT COALESCE(
                    pg_catalog.jsonb_agg(
                        pg_catalog.jsonb_build_object(
                            'first', pg_catalog.lower(port_range),
                            'last', pg_catalog.upper(port_range) - 1
                        ) ORDER BY pg_catalog.lower(port_range)
                    ),
                    '[]'::JSONB
                )
                FROM pg_catalog.unnest(export_constraint.destination_ports) AS port_range
            ) END AS port_ranges
        FROM mesh.resource_export_constraint AS export_constraint
        JOIN mesh.trust_contract AS contract
          ON contract.id = endpoint_row.trust_contract_id
         AND contract.resource_export_id = export_constraint.resource_export_id
        ORDER BY protocol_order
    ) AS constraint_row;
    IF traffic = '[]'::JSONB THEN
        RAISE no_data_found;
    END IF;
    SELECT COALESCE(
        pg_catalog.jsonb_agg(
            pg_catalog.host(address.value::INET) ORDER BY address.ordinality
        ),
        '[]'::JSONB
    ) INTO canonical_target_addresses
    FROM pg_catalog.jsonb_array_elements_text(base->'target_addresses')
        WITH ORDINALITY AS address(value, ordinality);
    IF canonical_target_addresses = '[]'::JSONB THEN
        RAISE no_data_found;
    END IF;

    base := base || pg_catalog.jsonb_build_object(
        'provider_workspace_public_id', provider_workspace_public_id,
        'provider_network_public_id', provider_network_public_id,
        'consumer_workspace_public_id', consumer_workspace_public_id,
        'consumer_network_public_id', consumer_network_public_id,
        'target_addresses', canonical_target_addresses,
        'resource_alias', pg_catalog.host(endpoint_row.resource_alias),
        'traffic', traffic
    );
    PERFORM pg_catalog.set_config('mesh.share_provider_workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_network_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_network_id', '', TRUE);
    RETURN base;
EXCEPTION WHEN no_data_found THEN
    PERFORM pg_catalog.set_config('mesh.share_provider_workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_network_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_network_id', '', TRUE);
    RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Private Endpoint publication authority changed';
WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.share_provider_workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_network_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_network_id', '', TRUE);
    RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_private_endpoint_publication_snapshot_v2(UUID, UUID)
FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_private_endpoint_publication_snapshot_v2(UUID, UUID)
TO mesh_worker;

CREATE FUNCTION mesh_ops.stage_private_endpoint_route_v1(
    p_deployment_public_id UUID,
    p_endpoint_public_id UUID,
    p_expected_endpoint_version BIGINT,
    p_expected_endpoint_generation BIGINT,
    p_intent_public_id UUID,
    p_route_snapshot_hash BYTEA,
    p_reconciler_id TEXT,
    p_observed_at TIMESTAMPTZ
)
RETURNS BYTEA
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    snapshot JSONB;
    endpoint_internal_id BIGINT;
    deployment_internal_id BIGINT;
    stored_hash BYTEA;
    decision_at TIMESTAMPTZ := pg_catalog.clock_timestamp();
BEGIN
    IF p_deployment_public_id IS NULL OR p_endpoint_public_id IS NULL
        OR p_intent_public_id IS NULL
        OR p_expected_endpoint_version <> 1 OR p_expected_endpoint_generation <= 0
        OR p_route_snapshot_hash IS NULL
        OR pg_catalog.octet_length(p_route_snapshot_hash) <> 32
        OR p_route_snapshot_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_reconciler_id IS NULL
        OR pg_catalog.char_length(p_reconciler_id) NOT BETWEEN 1 AND 128
        OR p_reconciler_id <> pg_catalog.btrim(p_reconciler_id)
        OR p_reconciler_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR p_observed_at IS NULL OR p_observed_at > decision_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Private Endpoint route intent';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.unnest(ARRAY[
            p_deployment_public_id, p_endpoint_public_id, p_intent_public_id
        ]::UUID[]) AS identity(value)
        WHERE pg_catalog.get_byte(pg_catalog.uuid_send(identity.value), 6) >> 4 <> 7
           OR pg_catalog.get_byte(pg_catalog.uuid_send(identity.value), 8) & 192 <> 128
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Private Endpoint route intent identity';
    END IF;

    snapshot := mesh_ops.read_private_endpoint_publication_snapshot_v2(
        p_deployment_public_id, p_endpoint_public_id
    );
    IF (snapshot->>'endpoint_version')::BIGINT <> p_expected_endpoint_version
        OR (snapshot->>'endpoint_generation')::BIGINT <> p_expected_endpoint_generation THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Private Endpoint route intent authority changed';
    END IF;
    SELECT endpoint.id, endpoint.deployment_id
    INTO STRICT endpoint_internal_id, deployment_internal_id
    FROM mesh.private_endpoint AS endpoint
    WHERE endpoint.public_id = p_endpoint_public_id;

    INSERT INTO mesh_ops.private_endpoint_route_intent (
        public_id, deployment_id, private_endpoint_id, endpoint_generation,
        target_device_public_id, target_generation, target_addresses,
        route_snapshot_hash, reconciler_id, observed_at, created_at
    ) VALUES (
        p_intent_public_id, deployment_internal_id, endpoint_internal_id,
        p_expected_endpoint_generation,
        (snapshot->>'target_device_id')::UUID,
        (snapshot->>'target_generation')::BIGINT,
        snapshot->'target_addresses', p_route_snapshot_hash,
        p_reconciler_id, p_observed_at, decision_at
    ) ON CONFLICT (private_endpoint_id) DO NOTHING;

    SELECT intent.route_snapshot_hash INTO STRICT stored_hash
    FROM mesh_ops.private_endpoint_route_intent AS intent
    WHERE intent.private_endpoint_id = endpoint_internal_id
      AND intent.endpoint_generation = p_expected_endpoint_generation;
    IF stored_hash <> p_route_snapshot_hash THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Private Endpoint route intent conflicts';
    END IF;
    RETURN stored_hash;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.stage_private_endpoint_route_v1(
    UUID, UUID, BIGINT, BIGINT, UUID, BYTEA, TEXT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.stage_private_endpoint_route_v1(
    UUID, UUID, BIGINT, BIGINT, UUID, BYTEA, TEXT, TIMESTAMPTZ
) TO mesh_worker;

CREATE FUNCTION mesh_ops.private_endpoint_withdrawal_reason_internal_v1(
    p_endpoint_id BIGINT,
    p_decision_at TIMESTAMPTZ
)
RETURNS TEXT
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    endpoint_row mesh.private_endpoint%ROWTYPE;
BEGIN
    IF p_endpoint_id <= 0 OR p_decision_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Private Endpoint withdrawal decision';
    END IF;
    SELECT endpoint.* INTO STRICT endpoint_row
    FROM mesh.private_endpoint AS endpoint
    WHERE endpoint.id = p_endpoint_id
      AND endpoint.state IN ('provisioning', 'ready');
    IF endpoint_row.expires_at <= p_decision_at THEN
        RETURN 'expired';
    END IF;
    PERFORM pg_catalog.set_config(
        'mesh.share_provider_workspace_id', endpoint_row.provider_workspace_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_provider_network_id', endpoint_row.provider_network_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_consumer_workspace_id', endpoint_row.consumer_workspace_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_consumer_network_id', endpoint_row.consumer_network_id::TEXT, TRUE
    );
    IF NOT EXISTS (
        SELECT 1
        FROM mesh.deployment AS deployment
        JOIN mesh.workspace AS provider_workspace
          ON provider_workspace.deployment_id = deployment.id
         AND provider_workspace.id = endpoint_row.provider_workspace_id
         AND provider_workspace.state = 'active'
        JOIN mesh.network AS provider_network
          ON provider_network.workspace_id = provider_workspace.id
         AND provider_network.id = endpoint_row.provider_network_id
         AND provider_network.state = 'active'
         AND provider_network.authority_generation = endpoint_row.provider_authority_generation
        JOIN mesh.workspace AS consumer_workspace
          ON consumer_workspace.deployment_id = deployment.id
         AND consumer_workspace.id = endpoint_row.consumer_workspace_id
         AND consumer_workspace.state = 'active'
        JOIN mesh.network AS consumer_network
          ON consumer_network.workspace_id = consumer_workspace.id
         AND consumer_network.id = endpoint_row.consumer_network_id
         AND consumer_network.state = 'active'
         AND consumer_network.authority_generation = endpoint_row.consumer_authority_generation
        JOIN mesh.trust_contract AS contract
          ON contract.id = endpoint_row.trust_contract_id
         AND contract.version = endpoint_row.contract_version
         AND contract.state = 'active'
         AND contract.expires_at = endpoint_row.expires_at
         AND contract.constraint_hash = endpoint_row.constraint_hash
        JOIN mesh.resource_export AS export
          ON export.id = contract.resource_export_id
         AND export.state = 'active'
         AND export.expires_at >= contract.expires_at
         AND export.constraint_hash = contract.constraint_hash
        JOIN mesh.imported_resource AS imported
          ON imported.id = endpoint_row.imported_resource_id
         AND imported.version = endpoint_row.imported_resource_version
         AND imported.state = 'active'
        JOIN mesh.imported_resource_access_name AS access_name
          ON access_name.id = endpoint_row.access_name_id
         AND access_name.imported_resource_id = imported.id
         AND access_name.state = 'reserved'
        JOIN mesh.federation_alias_lease AS lease
          ON lease.id = endpoint_row.alias_lease_id
         AND lease.resource_alias = endpoint_row.resource_alias
         AND (
            (endpoint_row.state = 'provisioning' AND lease.state = 'reserved')
            OR (endpoint_row.state = 'ready' AND lease.state = 'active')
         )
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
         AND device.expires_at > p_decision_at
        WHERE deployment.id = endpoint_row.deployment_id
          AND deployment.state = 'active'
          AND deployment.recovery_epoch = endpoint_row.recovery_epoch
          AND EXISTS (
              SELECT 1 FROM mesh.node_address_lease AS address
              WHERE address.workspace_id = contract.provider_workspace_id
                AND address.network_id = contract.provider_network_id
                AND address.device_id = device.id
                AND address.state = 'active'
                AND address.lease_role = 'primary'
          )
          AND NOT EXISTS (
              SELECT 1
              FROM mesh_ops.private_endpoint_route_intent AS intent
              WHERE intent.private_endpoint_id = endpoint_row.id
                AND intent.endpoint_generation = endpoint_row.generation
                AND (
                    intent.target_device_public_id <> device.public_id
                    OR intent.target_generation <> resource.target_generation
                    OR intent.target_addresses <> (
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
                    )
                )
          )
          AND (
              endpoint_row.state <> 'ready'
              OR EXISTS (
                  SELECT 1
                  FROM mesh.private_endpoint_readiness AS readiness
                  JOIN mesh.imported_resource_dns_publication AS publication
                    ON publication.private_endpoint_id = endpoint_row.id
                   AND publication.state = 'published'
                  WHERE readiness.private_endpoint_id = endpoint_row.id
                    AND readiness.endpoint_generation = endpoint_row.generation
              )
          )
    ) THEN
        PERFORM pg_catalog.set_config('mesh.share_provider_workspace_id', '', TRUE);
        PERFORM pg_catalog.set_config('mesh.share_provider_network_id', '', TRUE);
        PERFORM pg_catalog.set_config('mesh.share_consumer_workspace_id', '', TRUE);
        PERFORM pg_catalog.set_config('mesh.share_consumer_network_id', '', TRUE);
        RETURN 'invalidated';
    END IF;
    PERFORM pg_catalog.set_config('mesh.share_provider_workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_network_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_network_id', '', TRUE);
    RETURN NULL;
EXCEPTION WHEN no_data_found THEN
    PERFORM pg_catalog.set_config('mesh.share_provider_workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_network_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_network_id', '', TRUE);
    RETURN NULL;
WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.share_provider_workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_network_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_network_id', '', TRUE);
    RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.private_endpoint_withdrawal_reason_internal_v1(BIGINT, TIMESTAMPTZ)
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.list_private_endpoint_withdrawal_candidates_v1(
    p_deployment_public_id UUID,
    p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    decision_at TIMESTAMPTZ := pg_catalog.clock_timestamp();
    result JSONB;
BEGIN
    IF p_deployment_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 128 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Private Endpoint withdrawal selection';
    END IF;
    SELECT COALESCE(
        pg_catalog.jsonb_agg(candidate.payload ORDER BY candidate.endpoint_public_id),
        '[]'::JSONB
    ) INTO result
    FROM (
        SELECT endpoint.public_id AS endpoint_public_id,
            pg_catalog.jsonb_build_object(
                'endpoint_public_id', endpoint.public_id,
                'endpoint_generation', endpoint.generation
            ) AS payload
        FROM mesh.private_endpoint AS endpoint
        JOIN mesh.deployment AS deployment
          ON deployment.id = endpoint.deployment_id
         AND deployment.installation_public_id = p_deployment_public_id
        LEFT JOIN mesh_ops.private_endpoint_route_intent AS intent
          ON intent.private_endpoint_id = endpoint.id
         AND intent.endpoint_generation = endpoint.generation
        LEFT JOIN mesh.private_endpoint_readiness AS readiness
          ON readiness.private_endpoint_id = endpoint.id
         AND readiness.endpoint_generation = endpoint.generation
        WHERE endpoint.state IN ('provisioning', 'ready')
          AND NOT (
              intent.route_snapshot_hash IS NOT NULL
              AND readiness.route_snapshot_hash IS NOT NULL
              AND intent.route_snapshot_hash <> readiness.route_snapshot_hash
          )
          AND mesh_ops.private_endpoint_withdrawal_reason_internal_v1(
              endpoint.id, decision_at
          ) IS NOT NULL
        ORDER BY endpoint.public_id
        LIMIT p_limit
    ) AS candidate;
    RETURN result;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.list_private_endpoint_withdrawal_candidates_v1(UUID, INTEGER)
FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_private_endpoint_withdrawal_candidates_v1(UUID, INTEGER)
TO mesh_worker;

CREATE FUNCTION mesh_ops.read_private_endpoint_withdrawal_snapshot_v1(
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
    contract_version_value BIGINT;
    imported_resource_version_value BIGINT;
    access_name_version_value BIGINT;
    alias_lease_version_value BIGINT;
    dns_publication_version_value BIGINT := 0;
    route_snapshot_hash_value BYTEA;
    route_present_value BOOLEAN;
    intent_hash BYTEA;
    readiness_hash BYTEA;
    reason_value TEXT;
    decision_at TIMESTAMPTZ := pg_catalog.clock_timestamp();
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
    PERFORM pg_catalog.set_config('mesh.workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', '', TRUE);
    IF p_deployment_public_id IS NULL OR p_endpoint_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_endpoint_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Private Endpoint withdrawal snapshot';
    END IF;
    SELECT endpoint.* INTO STRICT endpoint_row
    FROM mesh.private_endpoint AS endpoint
    JOIN mesh.deployment AS deployment
      ON deployment.id = endpoint.deployment_id
     AND deployment.installation_public_id = p_deployment_public_id
    WHERE endpoint.public_id = p_endpoint_public_id
      AND endpoint.state IN ('provisioning', 'ready');

    reason_value := mesh_ops.private_endpoint_withdrawal_reason_internal_v1(
        endpoint_row.id, decision_at
    );
    IF reason_value IS NULL THEN
        RAISE no_data_found;
    END IF;
    SELECT intent.route_snapshot_hash INTO intent_hash
    FROM mesh_ops.private_endpoint_route_intent AS intent
    WHERE intent.private_endpoint_id = endpoint_row.id
      AND intent.endpoint_generation = endpoint_row.generation;
    SELECT readiness.route_snapshot_hash INTO readiness_hash
    FROM mesh.private_endpoint_readiness AS readiness
    WHERE readiness.private_endpoint_id = endpoint_row.id
      AND readiness.endpoint_generation = endpoint_row.generation;
    IF intent_hash IS NOT NULL AND readiness_hash IS NOT NULL
        AND intent_hash <> readiness_hash THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Private Endpoint route evidence conflicts';
    END IF;
    route_present_value := readiness_hash IS NOT NULL OR intent_hash IS NOT NULL;
    route_snapshot_hash_value := COALESCE(
        readiness_hash,
        intent_hash,
        pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    );

    SELECT contract.version, imported.version, access_name.version, lease.version
    INTO STRICT contract_version_value, imported_resource_version_value,
        access_name_version_value, alias_lease_version_value
    FROM mesh.trust_contract AS contract
    JOIN mesh.imported_resource AS imported
      ON imported.id = endpoint_row.imported_resource_id
     AND imported.trust_contract_id = contract.id
    JOIN mesh.imported_resource_access_name AS access_name
      ON access_name.id = endpoint_row.access_name_id
     AND access_name.imported_resource_id = imported.id
    JOIN mesh.federation_alias_lease AS lease
      ON lease.id = endpoint_row.alias_lease_id
     AND lease.resource_alias = endpoint_row.resource_alias
    WHERE contract.id = endpoint_row.trust_contract_id;
    SELECT publication.version INTO dns_publication_version_value
    FROM mesh.imported_resource_dns_publication AS publication
    WHERE publication.private_endpoint_id = endpoint_row.id
      AND publication.state = 'published';
    dns_publication_version_value := COALESCE(dns_publication_version_value, 0);

    PERFORM pg_catalog.set_config(
        'mesh.workspace_id', endpoint_row.provider_workspace_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.network_id', endpoint_row.provider_network_id::TEXT, TRUE
    );
    SELECT revision.network_revision, revision.dns_revision,
        revision.route_revision, revision.sharing_revision
    INTO STRICT provider_network_revision, provider_dns_revision,
        provider_route_revision, provider_sharing_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = endpoint_row.provider_workspace_id
      AND revision.network_id = endpoint_row.provider_network_id;
    SELECT stream.id, stream.next_sequence, stream.latest_event_hash
    INTO STRICT provider_stream_id, provider_stream_sequence, provider_stream_hash
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.workspace_id = endpoint_row.provider_workspace_id
      AND stream.network_id = endpoint_row.provider_network_id
      AND stream.scope_kind = 'network';

    PERFORM pg_catalog.set_config(
        'mesh.workspace_id', endpoint_row.consumer_workspace_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.network_id', endpoint_row.consumer_network_id::TEXT, TRUE
    );
    SELECT revision.network_revision, revision.dns_revision,
        revision.route_revision, revision.sharing_revision
    INTO STRICT consumer_network_revision, consumer_dns_revision,
        consumer_route_revision, consumer_sharing_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = endpoint_row.consumer_workspace_id
      AND revision.network_id = endpoint_row.consumer_network_id;
    SELECT stream.id, stream.next_sequence, stream.latest_event_hash
    INTO STRICT consumer_stream_id, consumer_stream_sequence, consumer_stream_hash
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.workspace_id = endpoint_row.consumer_workspace_id
      AND stream.network_id = endpoint_row.consumer_network_id
      AND stream.scope_kind = 'network';

    PERFORM pg_catalog.set_config('mesh.workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', '', TRUE);
    RETURN pg_catalog.jsonb_build_object(
        'deployment_public_id', p_deployment_public_id,
        'endpoint_public_id', endpoint_row.public_id,
        'endpoint_version', endpoint_row.version,
        'endpoint_generation', endpoint_row.generation,
        'alias_lease_version', alias_lease_version_value,
        'contract_version', contract_version_value,
        'imported_resource_version', imported_resource_version_value,
        'access_name_version', access_name_version_value,
        'dns_publication_version', dns_publication_version_value,
        'resource_alias', pg_catalog.host(endpoint_row.resource_alias),
        'route_snapshot_hash', pg_catalog.encode(route_snapshot_hash_value, 'hex'),
        'route_present', route_present_value,
        'reason', reason_value,
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
EXCEPTION WHEN no_data_found THEN
    PERFORM pg_catalog.set_config('mesh.workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', '', TRUE);
    RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Private Endpoint withdrawal authority changed';
WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', '', TRUE);
    RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_private_endpoint_withdrawal_snapshot_v1(UUID, UUID)
FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_private_endpoint_withdrawal_snapshot_v1(UUID, UUID)
TO mesh_worker;

CREATE FUNCTION mesh_ops.finalize_private_endpoint_withdrawal_v1(
    p_deployment_public_id UUID,
    p_endpoint_public_id UUID,
    p_expected_endpoint_version BIGINT,
    p_expected_endpoint_generation BIGINT,
    p_expected_alias_lease_version BIGINT,
    p_expected_contract_version BIGINT,
    p_expected_imported_resource_version BIGINT,
    p_expected_access_name_version BIGINT,
    p_expected_dns_publication_version BIGINT,
    p_expected_provider_network_revision BIGINT,
    p_expected_provider_dns_revision BIGINT,
    p_expected_provider_route_revision BIGINT,
    p_expected_provider_sharing_revision BIGINT,
    p_expected_consumer_network_revision BIGINT,
    p_expected_consumer_dns_revision BIGINT,
    p_expected_consumer_route_revision BIGINT,
    p_expected_consumer_sharing_revision BIGINT,
    p_change_public_id UUID,
    p_route_snapshot_hash BYTEA,
    p_terminal_hash BYTEA,
    p_reconciler_id TEXT,
    p_reason TEXT,
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
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    endpoint_row mesh.private_endpoint%ROWTYPE;
    contract_row mesh.trust_contract%ROWTYPE;
    imported_row mesh.imported_resource%ROWTYPE;
    access_name_row mesh.imported_resource_access_name%ROWTYPE;
    lease_row mesh.federation_alias_lease%ROWTYPE;
    publication_row mesh.imported_resource_dns_publication%ROWTYPE;
    decision_at TIMESTAMPTZ := pg_catalog.clock_timestamp();
    reason_value TEXT;
    intent_hash BYTEA;
    readiness_hash BYTEA;
    transaction_value BIGINT := (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT;
    expected_mutations BIGINT;
    appended_sequence BIGINT;
    action_value TEXT;
BEGIN
    PERFORM pg_catalog.set_config('mesh.workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', '', TRUE);
    IF p_deployment_public_id IS NULL OR p_endpoint_public_id IS NULL
        OR p_change_public_id IS NULL
        OR p_expected_endpoint_version <= 0 OR p_expected_endpoint_generation <= 0
        OR p_expected_alias_lease_version <= 0 OR p_expected_contract_version <= 0
        OR p_expected_imported_resource_version <= 0 OR p_expected_access_name_version <= 0
        OR p_expected_dns_publication_version < 0
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
        OR p_terminal_hash IS NULL OR pg_catalog.octet_length(p_terminal_hash) <> 32
        OR p_terminal_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_terminal_hash = p_route_snapshot_hash
        OR p_reconciler_id IS NULL
        OR pg_catalog.char_length(p_reconciler_id) NOT BETWEEN 1 AND 128
        OR p_reconciler_id <> pg_catalog.btrim(p_reconciler_id)
        OR p_reconciler_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR p_reason NOT IN ('expired', 'invalidated')
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
        OR pg_catalog.jsonb_typeof(p_consumer_outbox_payload) <> 'object' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Private Endpoint withdrawal proof';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.unnest(ARRAY[
            p_deployment_public_id, p_endpoint_public_id, p_change_public_id,
            p_provider_event_public_id, p_provider_outbox_public_id,
            p_consumer_event_public_id, p_consumer_outbox_public_id
        ]::UUID[]) AS identity(value)
        WHERE identity.value IS NULL
           OR pg_catalog.get_byte(pg_catalog.uuid_send(identity.value), 6) >> 4 <> 7
           OR pg_catalog.get_byte(pg_catalog.uuid_send(identity.value), 8) & 192 <> 128
    ) OR (SELECT pg_catalog.count(*) FROM (
        SELECT DISTINCT value FROM pg_catalog.unnest(ARRAY[
            p_endpoint_public_id, p_change_public_id,
            p_provider_event_public_id, p_provider_outbox_public_id,
            p_consumer_event_public_id, p_consumer_outbox_public_id
        ]::UUID[]) AS identity(value)
    ) AS unique_identity) <> 6 OR EXISTS (
        SELECT 1 FROM mesh_audit.authority_mutation AS mutation
        WHERE mutation.change_public_id = p_change_public_id
           OR mutation.transaction_id = transaction_value
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Private Endpoint withdrawal requires a fresh owned unit';
    END IF;

    SELECT endpoint.* INTO STRICT endpoint_row
    FROM mesh.private_endpoint AS endpoint
    JOIN mesh.deployment AS deployment
      ON deployment.id = endpoint.deployment_id
     AND deployment.installation_public_id = p_deployment_public_id
    WHERE endpoint.public_id = p_endpoint_public_id;

    PERFORM pg_catalog.set_config(
        'mesh.share_provider_workspace_id', endpoint_row.provider_workspace_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_provider_network_id', endpoint_row.provider_network_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_consumer_workspace_id', endpoint_row.consumer_workspace_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_consumer_network_id', endpoint_row.consumer_network_id::TEXT, TRUE
    );

    IF (endpoint_row.provider_workspace_id, endpoint_row.provider_network_id)
        < (endpoint_row.consumer_workspace_id, endpoint_row.consumer_network_id) THEN
        PERFORM mesh_ops.lock_private_endpoint_network_revision_internal_v1(
            endpoint_row.provider_workspace_id, endpoint_row.provider_network_id,
            p_expected_provider_network_revision, p_expected_provider_dns_revision,
            p_expected_provider_route_revision, p_expected_provider_sharing_revision
        );
        PERFORM mesh_ops.lock_private_endpoint_network_revision_internal_v1(
            endpoint_row.consumer_workspace_id, endpoint_row.consumer_network_id,
            p_expected_consumer_network_revision, p_expected_consumer_dns_revision,
            p_expected_consumer_route_revision, p_expected_consumer_sharing_revision
        );
    ELSE
        PERFORM mesh_ops.lock_private_endpoint_network_revision_internal_v1(
            endpoint_row.consumer_workspace_id, endpoint_row.consumer_network_id,
            p_expected_consumer_network_revision, p_expected_consumer_dns_revision,
            p_expected_consumer_route_revision, p_expected_consumer_sharing_revision
        );
        PERFORM mesh_ops.lock_private_endpoint_network_revision_internal_v1(
            endpoint_row.provider_workspace_id, endpoint_row.provider_network_id,
            p_expected_provider_network_revision, p_expected_provider_dns_revision,
            p_expected_provider_route_revision, p_expected_provider_sharing_revision
        );
    END IF;

    SELECT endpoint.* INTO STRICT endpoint_row
    FROM mesh.private_endpoint AS endpoint
    WHERE endpoint.public_id = p_endpoint_public_id
      AND endpoint.version = p_expected_endpoint_version
      AND endpoint.generation = p_expected_endpoint_generation
      AND endpoint.state IN ('provisioning', 'ready')
    FOR UPDATE;
    reason_value := mesh_ops.private_endpoint_withdrawal_reason_internal_v1(
        endpoint_row.id, decision_at
    );
    IF reason_value IS DISTINCT FROM p_reason THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Private Endpoint withdrawal decision changed';
    END IF;

    SELECT contract.* INTO STRICT contract_row
    FROM mesh.trust_contract AS contract
    WHERE contract.id = endpoint_row.trust_contract_id
      AND contract.version = p_expected_contract_version
      AND contract.state IN ('activating', 'active')
    FOR UPDATE;
    SELECT imported.* INTO STRICT imported_row
    FROM mesh.imported_resource AS imported
    WHERE imported.id = endpoint_row.imported_resource_id
      AND imported.version = p_expected_imported_resource_version
      AND imported.state IN ('activating', 'active')
    FOR UPDATE;
    SELECT access_name.* INTO STRICT access_name_row
    FROM mesh.imported_resource_access_name AS access_name
    WHERE access_name.id = endpoint_row.access_name_id
      AND access_name.version = p_expected_access_name_version
      AND access_name.state = 'reserved'
    FOR UPDATE;
    SELECT lease.* INTO STRICT lease_row
    FROM mesh.federation_alias_lease AS lease
    WHERE lease.id = endpoint_row.alias_lease_id
      AND lease.version = p_expected_alias_lease_version
      AND lease.state IN ('reserved', 'active')
    FOR UPDATE;

    SELECT intent.route_snapshot_hash INTO intent_hash
    FROM mesh_ops.private_endpoint_route_intent AS intent
    WHERE intent.private_endpoint_id = endpoint_row.id
      AND intent.endpoint_generation = endpoint_row.generation;
    SELECT readiness.route_snapshot_hash INTO readiness_hash
    FROM mesh.private_endpoint_readiness AS readiness
    WHERE readiness.private_endpoint_id = endpoint_row.id
      AND readiness.endpoint_generation = endpoint_row.generation;
    IF (
        readiness_hash IS NULL AND intent_hash IS NULL
        AND p_route_snapshot_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ) OR (
        COALESCE(readiness_hash, intent_hash) IS NOT NULL
        AND COALESCE(readiness_hash, intent_hash) <> p_route_snapshot_hash
    ) OR (
        readiness_hash IS NOT NULL AND intent_hash IS NOT NULL
        AND readiness_hash <> intent_hash
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Private Endpoint withdrawal route evidence changed';
    END IF;

    IF p_expected_dns_publication_version > 0 THEN
        SELECT publication.* INTO STRICT publication_row
        FROM mesh.imported_resource_dns_publication AS publication
        WHERE publication.private_endpoint_id = endpoint_row.id
          AND publication.version = p_expected_dns_publication_version
          AND publication.state = 'published'
        FOR UPDATE;
    ELSIF EXISTS (
        SELECT 1 FROM mesh.imported_resource_dns_publication AS publication
        WHERE publication.private_endpoint_id = endpoint_row.id
          AND publication.state = 'published'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Private Endpoint DNS publication changed';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.trust_contract AS contract
    SET state = p_reason, version = contract.version + 1,
        updated_at = decision_at, ended_at = decision_at
    WHERE contract.id = contract_row.id
    RETURNING contract.version INTO contract_version;
    UPDATE mesh.imported_resource AS imported
    SET state = p_reason, version = imported.version + 1,
        updated_at = decision_at, ended_at = decision_at
    WHERE imported.id = imported_row.id
    RETURNING imported.version INTO imported_resource_version;
    UPDATE mesh.imported_resource_access_name AS access_name
    SET state = 'withdrawn', version = access_name.version + 1,
        updated_at = decision_at, withdrawn_at = decision_at
    WHERE access_name.id = access_name_row.id
    RETURNING access_name.version INTO access_name_version;
    UPDATE mesh.private_endpoint AS endpoint
    SET state = p_reason, version = endpoint.version + 1,
        updated_at = decision_at, ended_at = decision_at
    WHERE endpoint.id = endpoint_row.id
    RETURNING endpoint.version INTO private_endpoint_version;
    UPDATE mesh.federation_alias_lease AS lease
    SET state = 'withdrawn', version = lease.version + 1,
        updated_at = decision_at, withdrawn_at = decision_at
    WHERE lease.id = lease_row.id
    RETURNING lease.version INTO alias_lease_version;
    IF p_expected_dns_publication_version > 0 THEN
        UPDATE mesh.imported_resource_dns_publication AS publication
        SET state = 'withdrawn', version = publication.version + 1,
            updated_at = decision_at, withdrawn_at = decision_at
        WHERE publication.id = publication_row.id
        RETURNING publication.version INTO dns_publication_version;
    ELSE
        dns_publication_version := 0;
    END IF;

    PERFORM pg_catalog.set_config(
        'mesh.workspace_id', endpoint_row.provider_workspace_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.network_id', endpoint_row.provider_network_id::TEXT, TRUE
    );
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        route_revision = revision.route_revision + 1,
        sharing_revision = revision.sharing_revision + 1,
        updated_at = decision_at
    WHERE revision.workspace_id = endpoint_row.provider_workspace_id
      AND revision.network_id = endpoint_row.provider_network_id
    RETURNING revision.network_revision, revision.dns_revision,
        revision.route_revision, revision.sharing_revision
    INTO provider_network_revision, provider_dns_revision,
        provider_route_revision, provider_sharing_revision;
    PERFORM pg_catalog.set_config(
        'mesh.workspace_id', endpoint_row.consumer_workspace_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.network_id', endpoint_row.consumer_network_id::TEXT, TRUE
    );
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        dns_revision = revision.dns_revision + 1,
        route_revision = revision.route_revision + 1,
        sharing_revision = revision.sharing_revision + 1,
        updated_at = decision_at
    WHERE revision.workspace_id = endpoint_row.consumer_workspace_id
      AND revision.network_id = endpoint_row.consumer_network_id
    RETURNING revision.network_revision, revision.dns_revision,
        revision.route_revision, revision.sharing_revision
    INTO consumer_network_revision, consumer_dns_revision,
        consumer_route_revision, consumer_sharing_revision;

    expected_mutations := CASE WHEN p_expected_dns_publication_version > 0 THEN 6 ELSE 5 END;
    IF (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation AS mutation
        WHERE mutation.change_public_id = p_change_public_id
          AND mutation.transaction_id = transaction_value) <> expected_mutations THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Private Endpoint withdrawal mutation set is invalid';
    END IF;

    IF p_provider_audit_payload <> pg_catalog.jsonb_build_object(
        'endpoint_public_id', endpoint_row.public_id,
        'authority_side', 'provider',
        'reconciler_id', p_reconciler_id,
        'endpoint_generation', endpoint_row.generation,
        'resource_alias', endpoint_row.resource_alias::TEXT,
        'reason', p_reason,
        'route_snapshot_hash', pg_catalog.encode(p_route_snapshot_hash, 'hex'),
        'terminal_hash', pg_catalog.encode(p_terminal_hash, 'hex'),
        'network_revision', provider_network_revision,
        'dns_revision', provider_dns_revision,
        'route_revision', provider_route_revision,
        'sharing_revision', provider_sharing_revision
    ) OR p_consumer_audit_payload <> pg_catalog.jsonb_build_object(
        'endpoint_public_id', endpoint_row.public_id,
        'authority_side', 'consumer',
        'reconciler_id', p_reconciler_id,
        'endpoint_generation', endpoint_row.generation,
        'resource_alias', endpoint_row.resource_alias::TEXT,
        'reason', p_reason,
        'route_snapshot_hash', pg_catalog.encode(p_route_snapshot_hash, 'hex'),
        'terminal_hash', pg_catalog.encode(p_terminal_hash, 'hex'),
        'network_revision', consumer_network_revision,
        'dns_revision', consumer_dns_revision,
        'route_revision', consumer_route_revision,
        'sharing_revision', consumer_sharing_revision
    ) OR p_provider_outbox_payload <> pg_catalog.jsonb_build_object(
        'endpoint_public_id', endpoint_row.public_id,
        'reason', p_reason,
        'network_revision', provider_network_revision,
        'dns_revision', provider_dns_revision,
        'route_revision', provider_route_revision,
        'subsystem', 'sharing',
        'subsystem_revision', provider_sharing_revision
    ) OR p_consumer_outbox_payload <> pg_catalog.jsonb_build_object(
        'endpoint_public_id', endpoint_row.public_id,
        'reason', p_reason,
        'network_revision', consumer_network_revision,
        'dns_revision', consumer_dns_revision,
        'route_revision', consumer_route_revision,
        'subsystem', 'sharing',
        'subsystem_revision', consumer_sharing_revision
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Private Endpoint withdrawal evidence payload mismatch';
    END IF;

    action_value := 'private_endpoint.' || p_reason;
    appended_sequence := mesh_audit.append_authority_evidence(
        p_provider_stream_id, p_provider_event_public_id, p_provider_outbox_public_id,
        p_provider_stream_sequence, p_provider_previous_hash, p_provider_event_hash,
        'private_endpoint', endpoint_row.public_id, private_endpoint_version,
        provider_network_revision, NULL::UUID, action_value,
        'system.reconcile', endpoint_row.public_id, p_route_snapshot_hash, p_terminal_hash,
        p_provider_audit_payload, 'sharing.private_endpoint.withdrawn',
        p_provider_outbox_payload
    );
    IF appended_sequence <> p_provider_stream_sequence THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'provider withdrawal evidence changed';
    END IF;
    appended_sequence := mesh_audit.append_authority_evidence(
        p_consumer_stream_id, p_consumer_event_public_id, p_consumer_outbox_public_id,
        p_consumer_stream_sequence, p_consumer_previous_hash, p_consumer_event_hash,
        'private_endpoint', endpoint_row.public_id, private_endpoint_version,
        consumer_network_revision, NULL::UUID, action_value,
        'system.reconcile', endpoint_row.public_id, p_route_snapshot_hash, p_terminal_hash,
        p_consumer_audit_payload, 'sharing.private_endpoint.withdrawn',
        p_consumer_outbox_payload
    );
    IF appended_sequence <> p_consumer_stream_sequence THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'consumer withdrawal evidence changed';
    END IF;
    PERFORM pg_catalog.set_config('mesh.workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', '', TRUE);
    RETURN NEXT;
EXCEPTION
    WHEN no_data_found THEN
        PERFORM pg_catalog.set_config('mesh.workspace_id', '', TRUE);
        PERFORM pg_catalog.set_config('mesh.network_id', '', TRUE);
        PERFORM pg_catalog.set_config('mesh.change_public_id', '', TRUE);
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Private Endpoint withdrawal authority changed';
    WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.workspace_id', '', TRUE);
        PERFORM pg_catalog.set_config('mesh.network_id', '', TRUE);
        PERFORM pg_catalog.set_config('mesh.change_public_id', '', TRUE);
        RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.finalize_private_endpoint_withdrawal_v1(
    UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, BYTEA, BYTEA, TEXT, TEXT,
    BIGINT, UUID, UUID, BIGINT, BYTEA, BYTEA, JSONB, JSONB,
    BIGINT, UUID, UUID, BIGINT, BYTEA, BYTEA, JSONB, JSONB
) FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.finalize_private_endpoint_withdrawal_v1(
    UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, BYTEA, BYTEA, TEXT, TEXT,
    BIGINT, UUID, UUID, BIGINT, BYTEA, BYTEA, JSONB, JSONB,
    BIGINT, UUID, UUID, BIGINT, BYTEA, BYTEA, JSONB, JSONB
) TO mesh_worker;

REVOKE ALL ON mesh_ops.private_endpoint_route_intent
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON SEQUENCE mesh_ops.private_endpoint_route_intent_id_seq
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.reject_private_endpoint_route_intent_change()
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE OR REPLACE FUNCTION mesh_ops.reject_private_endpoint_readiness_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 OR NOT EXISTS (
            SELECT 1
            FROM mesh_ops.private_endpoint_route_intent AS intent
            WHERE intent.private_endpoint_id = NEW.private_endpoint_id
              AND intent.endpoint_generation = NEW.endpoint_generation
              AND intent.route_snapshot_hash = NEW.route_snapshot_hash
              AND intent.reconciler_id = NEW.reconciler_id
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Private Endpoint readiness proof';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Private Endpoint readiness proof is immutable';
END;
$function$;
