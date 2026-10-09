DO $database_privileges$
BEGIN
    EXECUTE pg_catalog.format(
        'REVOKE ALL ON DATABASE %I FROM PUBLIC',
        pg_catalog.current_database()
    );
END;
$database_privileges$;

CREATE TABLE mesh.identity_provider (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    issuer TEXT NOT NULL,
    issuer_digest_algorithm TEXT NOT NULL,
    issuer_digest_key_id TEXT NOT NULL,
    issuer_digest BYTEA NOT NULL,
    protocol TEXT NOT NULL,
    authority_kind TEXT NOT NULL,
    discovery_uri TEXT NOT NULL,
    jwks_uri TEXT NOT NULL,
    current_generation BIGINT NOT NULL CHECK (current_generation > 0),
    recovery_state TEXT NOT NULL,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT identity_provider_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT identity_provider_issuer_check CHECK (
        pg_catalog.char_length(issuer) BETWEEN 1 AND 2048
        AND issuer = pg_catalog.btrim(issuer)
        AND pg_catalog.starts_with(issuer, 'https://')
    ),
    CONSTRAINT identity_provider_issuer_digest_algorithm_check CHECK (
        issuer_digest_algorithm = 'hmac-sha256-v1'
    ),
    CONSTRAINT identity_provider_issuer_digest_key_id_check CHECK (
        pg_catalog.char_length(issuer_digest_key_id) BETWEEN 1 AND 128
        AND issuer_digest_key_id = pg_catalog.btrim(issuer_digest_key_id)
        AND issuer_digest_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT identity_provider_issuer_digest_check CHECK (
        pg_catalog.octet_length(issuer_digest) = 32
    ),
    CONSTRAINT identity_provider_protocol_check CHECK (protocol = 'oidc'),
    CONSTRAINT identity_provider_authority_kind_check CHECK (
        authority_kind IN ('managed_oidc', 'external_oidc')
    ),
    CONSTRAINT identity_provider_discovery_uri_check CHECK (
        pg_catalog.char_length(discovery_uri) BETWEEN 1 AND 2048
        AND discovery_uri = pg_catalog.btrim(discovery_uri)
        AND pg_catalog.starts_with(discovery_uri, 'https://')
    ),
    CONSTRAINT identity_provider_jwks_uri_check CHECK (
        pg_catalog.char_length(jwks_uri) BETWEEN 1 AND 2048
        AND jwks_uri = pg_catalog.btrim(jwks_uri)
        AND pg_catalog.starts_with(jwks_uri, 'https://')
    ),
    CONSTRAINT identity_provider_recovery_state_check CHECK (
        recovery_state IN ('verified', 'quarantined')
    ),
    CONSTRAINT identity_provider_state_check CHECK (
        state IN ('active', 'suspended', 'deleted')
    ),
    CONSTRAINT identity_provider_deletion_check CHECK (
        (state = 'deleted' AND deleted_at IS NOT NULL)
        OR (state <> 'deleted' AND deleted_at IS NULL)
    ),
    CONSTRAINT identity_provider_deployment_fk FOREIGN KEY (deployment_id)
        REFERENCES mesh.deployment (id) ON DELETE RESTRICT,
    CONSTRAINT identity_provider_timestamps_check CHECK (
        updated_at >= created_at
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    ),
    UNIQUE (deployment_id, id),
    UNIQUE (deployment_id, issuer),
    UNIQUE (deployment_id, issuer_digest_key_id, issuer_digest)
);

CREATE INDEX identity_provider_deployment_state_idx
    ON mesh.identity_provider (deployment_id, state, id);

CREATE TABLE mesh.identity_provider_generation (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    identity_provider_id BIGINT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    trust_configuration_semantic_hash BYTEA NOT NULL,
    recovery_mode TEXT NOT NULL,
    recovery_evidence_reference TEXT,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT identity_provider_generation_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT identity_provider_generation_semantic_hash_check CHECK (
        pg_catalog.octet_length(trust_configuration_semantic_hash) = 32
    ),
    CONSTRAINT identity_provider_generation_recovery_mode_check CHECK (
        recovery_mode IN ('initial', 'continuous', 'lossy', 'unproven')
    ),
    CONSTRAINT identity_provider_generation_recovery_evidence_check CHECK (
        (
            recovery_mode = 'initial'
            AND recovery_evidence_reference IS NULL
        )
        OR (
            recovery_mode <> 'initial'
            AND recovery_evidence_reference IS NOT NULL
            AND pg_catalog.char_length(recovery_evidence_reference) BETWEEN 1 AND 512
            AND recovery_evidence_reference = pg_catalog.btrim(recovery_evidence_reference)
            AND recovery_evidence_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
        )
    ),
    CONSTRAINT identity_provider_generation_state_check CHECK (
        state IN ('current', 'superseded', 'revoked')
    ),
    CONSTRAINT identity_provider_generation_validity_check CHECK (
        (state = 'current' AND valid_until IS NULL)
        OR (
            state IN ('superseded', 'revoked')
            AND valid_until IS NOT NULL
            AND valid_until >= valid_from
        )
    ),
    CONSTRAINT identity_provider_generation_provider_fk FOREIGN KEY (
        deployment_id,
        identity_provider_id
    ) REFERENCES mesh.identity_provider (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT identity_provider_generation_timestamps_check CHECK (
        updated_at >= created_at
    ),
    UNIQUE (deployment_id, identity_provider_id, generation),
    UNIQUE (identity_provider_id, id)
);

CREATE UNIQUE INDEX identity_provider_generation_current_uidx
    ON mesh.identity_provider_generation (identity_provider_id)
    WHERE state = 'current';
CREATE INDEX identity_provider_generation_history_idx
    ON mesh.identity_provider_generation (identity_provider_id, generation DESC);

ALTER TABLE mesh.identity_provider
    ADD CONSTRAINT identity_provider_current_generation_fk FOREIGN KEY (
        deployment_id,
        id,
        current_generation
    ) REFERENCES mesh.identity_provider_generation (
        deployment_id,
        identity_provider_id,
        generation
    ) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE mesh.identity_provider_client (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    identity_provider_id BIGINT NOT NULL,
    client_kind TEXT NOT NULL,
    client_id TEXT NOT NULL,
    allowed_flows TEXT[] NOT NULL,
    allowed_scopes TEXT[] NOT NULL,
    allowed_algorithms TEXT[] NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    post_logout_redirect_uris TEXT[] NOT NULL,
    pkce_s256_required BOOLEAN NOT NULL,
    client_auth_method TEXT NOT NULL,
    credential_reference TEXT,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT identity_provider_client_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT identity_provider_client_kind_check CHECK (
        client_kind IN ('confidential', 'public')
    ),
    CONSTRAINT identity_provider_client_id_check CHECK (
        pg_catalog.char_length(client_id) BETWEEN 1 AND 255
        AND client_id = pg_catalog.btrim(client_id)
    ),
    CONSTRAINT identity_provider_client_flows_check CHECK (
        COALESCE(pg_catalog.array_ndims(allowed_flows), 1) = 1
        AND pg_catalog.cardinality(allowed_flows) BETWEEN 1 AND 4
        AND pg_catalog.array_position(allowed_flows, NULL) IS NULL
        AND allowed_flows <@ ARRAY['authorization_code', 'device_authorization']::TEXT[]
        AND pg_catalog.octet_length(
            pg_catalog.array_to_string(allowed_flows, ',')
        ) <= 128
    ),
    CONSTRAINT identity_provider_client_scopes_check CHECK (
        COALESCE(pg_catalog.array_ndims(allowed_scopes), 1) = 1
        AND pg_catalog.cardinality(allowed_scopes) BETWEEN 1 AND 32
        AND pg_catalog.array_position(allowed_scopes, NULL) IS NULL
        AND 'openid' = ANY (allowed_scopes)
        AND pg_catalog.octet_length(
            pg_catalog.array_to_string(allowed_scopes, ',')
        ) <= 4096
    ),
    CONSTRAINT identity_provider_client_algorithms_check CHECK (
        COALESCE(pg_catalog.array_ndims(allowed_algorithms), 1) = 1
        AND pg_catalog.cardinality(allowed_algorithms) BETWEEN 1 AND 8
        AND pg_catalog.array_position(allowed_algorithms, NULL) IS NULL
        AND allowed_algorithms <@ ARRAY['RS256', 'PS256', 'ES256']::TEXT[]
        AND pg_catalog.octet_length(
            pg_catalog.array_to_string(allowed_algorithms, ',')
        ) <= 512
    ),
    CONSTRAINT identity_provider_client_redirects_check CHECK (
        COALESCE(pg_catalog.array_ndims(redirect_uris), 1) = 1
        AND pg_catalog.array_position(redirect_uris, NULL) IS NULL
        AND pg_catalog.octet_length(
            pg_catalog.array_to_string(redirect_uris, ',')
        ) <= 65536
        AND (
            (
                'authorization_code' = ANY (allowed_flows)
                AND pg_catalog.cardinality(redirect_uris) BETWEEN 1 AND 32
            )
            OR (
                NOT ('authorization_code' = ANY (allowed_flows))
                AND pg_catalog.cardinality(redirect_uris) = 0
            )
        )
    ),
    CONSTRAINT identity_provider_client_logout_redirects_check CHECK (
        COALESCE(pg_catalog.array_ndims(post_logout_redirect_uris), 1) = 1
        AND pg_catalog.cardinality(post_logout_redirect_uris) BETWEEN 0 AND 32
        AND pg_catalog.array_position(post_logout_redirect_uris, NULL) IS NULL
        AND pg_catalog.octet_length(
            pg_catalog.array_to_string(post_logout_redirect_uris, ',')
        ) <= 65536
    ),
    CONSTRAINT identity_provider_client_pkce_check CHECK (pkce_s256_required),
    CONSTRAINT identity_provider_client_auth_method_check CHECK (
        (
            client_kind = 'public'
            AND client_auth_method = 'none'
            AND credential_reference IS NULL
        )
        OR (
            client_kind = 'confidential'
            AND client_auth_method IN ('client_secret_basic', 'private_key_jwt')
            AND credential_reference IS NOT NULL
            AND pg_catalog.char_length(credential_reference) BETWEEN 1 AND 512
            AND credential_reference = pg_catalog.btrim(credential_reference)
            AND credential_reference ~ '^[A-Za-z][A-Za-z0-9+.-]*://[A-Za-z0-9][A-Za-z0-9._:/-]*$'
        )
    ),
    CONSTRAINT identity_provider_client_state_check CHECK (
        state IN ('active', 'suspended', 'deleted')
    ),
    CONSTRAINT identity_provider_client_deletion_check CHECK (
        (state = 'deleted' AND deleted_at IS NOT NULL)
        OR (state <> 'deleted' AND deleted_at IS NULL)
    ),
    CONSTRAINT identity_provider_client_provider_fk FOREIGN KEY (
        deployment_id,
        identity_provider_id
    ) REFERENCES mesh.identity_provider (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT identity_provider_client_timestamps_check CHECK (
        updated_at >= created_at
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    ),
    UNIQUE (deployment_id, identity_provider_id, id),
    UNIQUE (identity_provider_id, client_id)
);

CREATE INDEX identity_provider_client_provider_state_idx
    ON mesh.identity_provider_client (identity_provider_id, state, id);

CREATE TABLE mesh.workspace_identity_provider (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    identity_provider_id BIGINT NOT NULL,
    identity_provider_client_id BIGINT NOT NULL,
    organization_digest_algorithm TEXT,
    organization_digest_key_id TEXT,
    organization_digest BYTEA,
    admission_mode TEXT NOT NULL,
    minimum_assurance TEXT,
    routing_priority INTEGER NOT NULL,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT workspace_identity_provider_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT workspace_identity_provider_organization_digest_check CHECK (
        (
            organization_digest_algorithm IS NULL
            AND organization_digest_key_id IS NULL
            AND organization_digest IS NULL
        )
        OR (
            organization_digest_algorithm IS NOT NULL
            AND organization_digest_algorithm = 'hmac-sha256-v1'
            AND organization_digest_key_id IS NOT NULL
            AND organization_digest IS NOT NULL
            AND pg_catalog.char_length(organization_digest_key_id) BETWEEN 1 AND 128
            AND organization_digest_key_id = pg_catalog.btrim(organization_digest_key_id)
            AND organization_digest_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND pg_catalog.octet_length(organization_digest) = 32
        )
    ),
    CONSTRAINT workspace_identity_provider_admission_mode_check CHECK (
        admission_mode IN ('invitation_only', 'explicit_membership', 'approved_jit')
    ),
    CONSTRAINT workspace_identity_provider_minimum_assurance_check CHECK (
        minimum_assurance IS NULL
        OR (
            pg_catalog.char_length(minimum_assurance) BETWEEN 1 AND 255
            AND minimum_assurance = pg_catalog.btrim(minimum_assurance)
        )
    ),
    CONSTRAINT workspace_identity_provider_routing_priority_check CHECK (
        routing_priority BETWEEN 0 AND 10000
    ),
    CONSTRAINT workspace_identity_provider_state_check CHECK (
        state IN ('active', 'suspended', 'deleted')
    ),
    CONSTRAINT workspace_identity_provider_deletion_check CHECK (
        (state = 'deleted' AND deleted_at IS NOT NULL)
        OR (state <> 'deleted' AND deleted_at IS NULL)
    ),
    CONSTRAINT workspace_identity_provider_workspace_fk FOREIGN KEY (
        workspace_id,
        deployment_id
    ) REFERENCES mesh.workspace (id, deployment_id) ON DELETE RESTRICT,
    CONSTRAINT workspace_identity_provider_provider_fk FOREIGN KEY (
        deployment_id,
        identity_provider_id
    ) REFERENCES mesh.identity_provider (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT workspace_identity_provider_client_fk FOREIGN KEY (
        deployment_id,
        identity_provider_id,
        identity_provider_client_id
    ) REFERENCES mesh.identity_provider_client (
        deployment_id,
        identity_provider_id,
        id
    ) ON DELETE RESTRICT,
    CONSTRAINT workspace_identity_provider_timestamps_check CHECK (
        updated_at >= created_at
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    ),
    UNIQUE (workspace_id, id)
);

CREATE UNIQUE INDEX workspace_identity_provider_route_uidx
    ON mesh.workspace_identity_provider (
        workspace_id,
        identity_provider_id,
        identity_provider_client_id,
        organization_digest_key_id,
        organization_digest
    ) NULLS NOT DISTINCT;
CREATE UNIQUE INDEX workspace_identity_provider_priority_active_uidx
    ON mesh.workspace_identity_provider (workspace_id, routing_priority)
    WHERE state = 'active' AND deleted_at IS NULL;
CREATE INDEX workspace_identity_provider_client_idx
    ON mesh.workspace_identity_provider (
        deployment_id,
        identity_provider_id,
        identity_provider_client_id
    );

CREATE FUNCTION mesh_ops.enforce_identity_provider_current_generation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    provider_internal_id BIGINT;
    expected_generation BIGINT;
    matching_current_generations BIGINT;
BEGIN
    IF TG_TABLE_NAME = 'identity_provider' THEN
        IF TG_OP = 'DELETE' THEN
            provider_internal_id := OLD.id;
        ELSE
            provider_internal_id := NEW.id;
        END IF;
    ELSE
        IF TG_OP = 'DELETE' THEN
            provider_internal_id := OLD.identity_provider_id;
        ELSE
            provider_internal_id := NEW.identity_provider_id;
        END IF;
    END IF;

    SELECT provider.current_generation
    INTO expected_generation
    FROM mesh.identity_provider AS provider
    WHERE provider.id = provider_internal_id;

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT pg_catalog.count(*)
    INTO matching_current_generations
    FROM mesh.identity_provider_generation AS generation
    WHERE generation.identity_provider_id = provider_internal_id
      AND generation.generation = expected_generation
      AND generation.state = 'current'
      AND generation.valid_until IS NULL;

    IF matching_current_generations <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'identity provider current generation is inconsistent';
    END IF;
    RETURN NULL;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.enforce_identity_provider_current_generation() FROM PUBLIC;

CREATE CONSTRAINT TRIGGER identity_provider_current_generation_state_check
AFTER INSERT OR UPDATE OR DELETE ON mesh.identity_provider
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_identity_provider_current_generation();

CREATE CONSTRAINT TRIGGER identity_provider_generation_current_check
AFTER INSERT OR UPDATE OR DELETE ON mesh.identity_provider_generation
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_identity_provider_current_generation();

ALTER TABLE mesh.workspace_identity_provider ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.workspace_identity_provider FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_identity_provider_migrator_policy
    ON mesh.workspace_identity_provider
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY workspace_identity_provider_exact_scope_policy
    ON mesh.workspace_identity_provider
    TO mesh_runtime
    USING (workspace_id = mesh_ops.current_workspace_id())
    WITH CHECK (workspace_id = mesh_ops.current_workspace_id());

CREATE TRIGGER identity_provider_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.identity_provider
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('identity_provider', 'public_id');
CREATE TRIGGER identity_provider_generation_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.identity_provider_generation
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'identity_provider_generation',
    'public_id'
);
CREATE TRIGGER identity_provider_client_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.identity_provider_client
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'identity_provider_client',
    'public_id'
);
CREATE TRIGGER workspace_identity_provider_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.workspace_identity_provider
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'workspace_identity_provider',
    'public_id'
);

REVOKE ALL ON ALL TABLES IN SCHEMA mesh FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mesh FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mesh, mesh_ops, mesh_audit FROM PUBLIC;

REVOKE ALL ON
    mesh.identity_provider,
    mesh.identity_provider_generation,
    mesh.identity_provider_client,
    mesh.workspace_identity_provider
    FROM mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
