ALTER TABLE mesh.identity_provider
    ADD COLUMN authorization_endpoint TEXT,
    ADD COLUMN token_endpoint TEXT;

ALTER TABLE mesh.identity_provider
    ADD CONSTRAINT identity_provider_oidc_endpoints_check CHECK (
        (
            authorization_endpoint IS NULL
            AND token_endpoint IS NULL
        )
        OR (
            authorization_endpoint IS NOT NULL
            AND pg_catalog.char_length(authorization_endpoint) BETWEEN 1 AND 2048
            AND authorization_endpoint = pg_catalog.btrim(authorization_endpoint)
            AND pg_catalog.starts_with(authorization_endpoint, 'https://')
            AND token_endpoint IS NOT NULL
            AND pg_catalog.char_length(token_endpoint) BETWEEN 1 AND 2048
            AND token_endpoint = pg_catalog.btrim(token_endpoint)
            AND pg_catalog.starts_with(token_endpoint, 'https://')
        )
    );

ALTER TABLE mesh.auth_transaction
    ADD COLUMN binding_semantic_hash BYTEA;

ALTER TABLE mesh.auth_transaction
    ADD CONSTRAINT auth_transaction_binding_semantic_hash_check CHECK (
        binding_semantic_hash IS NULL
        OR pg_catalog.octet_length(binding_semantic_hash) = 32
    );

CREATE INDEX auth_transaction_open_expiry_idx
    ON mesh.auth_transaction (expires_at, id)
    WHERE state IN ('pending', 'consuming');

CREATE POLICY workspace_oidc_auth_transaction_scope_policy ON mesh.workspace
    FOR SELECT
    TO mesh_migrator
    USING (
        public_id = NULLIF(
            pg_catalog.current_setting('mesh.requested_workspace_public_id', TRUE),
            ''
        )::UUID
    );

CREATE POLICY workspace_oidc_auth_transaction_lock_policy ON mesh.workspace
    FOR UPDATE
    TO mesh_migrator
    USING (
        public_id = NULLIF(
            pg_catalog.current_setting('mesh.requested_workspace_public_id', TRUE),
            ''
        )::UUID
    )
    WITH CHECK (
        public_id = NULLIF(
            pg_catalog.current_setting('mesh.requested_workspace_public_id', TRUE),
            ''
        )::UUID
    );

CREATE FUNCTION mesh_audit.lock_deployment_stream_head(
    p_deployment_public_id UUID
)
RETURNS TABLE (
    stream_internal_id BIGINT,
    next_sequence BIGINT,
    latest_event_hash BYTEA
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_audit, mesh
AS $function$
BEGIN
    IF p_deployment_public_id IS NULL
        OR pg_catalog.get_byte(
            pg_catalog.uuid_send(p_deployment_public_id),
            6
        ) >> 4 <> 7 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'Deployment audit stream is unavailable';
    END IF;

    RETURN QUERY
    SELECT
        stream.id,
        stream.next_sequence,
        stream.latest_event_hash
    FROM mesh_audit.audit_stream AS stream
    JOIN mesh.deployment AS deployment
      ON deployment.id = stream.deployment_id
    WHERE stream.scope_kind = 'deployment'
      AND stream.workspace_id IS NULL
      AND stream.network_id IS NULL
      AND deployment.installation_public_id = p_deployment_public_id
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL
    FOR UPDATE OF stream;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'Deployment audit stream is unavailable';
    END IF;
END;
$function$;

CREATE FUNCTION mesh_ops.create_oidc_auth_transaction_v1(
    p_transaction_public_id UUID,
    p_deployment_public_id UUID,
    p_workspace_public_id UUID,
    p_provider_public_id UUID,
    p_client_public_id UUID,
    p_provider_generation BIGINT,
    p_recovery_epoch BIGINT,
    p_issuer TEXT,
    p_discovery_uri TEXT,
    p_authorization_endpoint TEXT,
    p_token_endpoint TEXT,
    p_jwks_uri TEXT,
    p_oidc_client_id TEXT,
    p_client_auth_method TEXT,
    p_scopes TEXT[],
    p_allowed_algorithms TEXT[],
    p_redirect_id TEXT,
    p_redirect_uri TEXT,
    p_return_route_id TEXT,
    p_state_digest_algorithm TEXT,
    p_state_digest_key_id TEXT,
    p_state_digest BYTEA,
    p_nonce_digest_algorithm TEXT,
    p_nonce_digest_key_id TEXT,
    p_nonce_digest BYTEA,
    p_verifier_encryption_algorithm TEXT,
    p_verifier_encryption_key_id TEXT,
    p_verifier_ciphertext BYTEA,
    p_binding_semantic_hash BYTEA,
    p_created_at TIMESTAMPTZ,
    p_expires_at TIMESTAMPTZ
)
RETURNS TABLE (
    transaction_public_id UUID,
    transaction_version BIGINT,
    transaction_created_at TIMESTAMPTZ,
    transaction_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    resolved_deployment_id BIGINT;
    resolved_workspace_id BIGINT;
    resolved_provider_id BIGINT;
    resolved_client_id BIGINT;
BEGIN
    IF p_created_at IS NULL
        OR p_expires_at IS NULL
        OR p_created_at < pg_catalog.transaction_timestamp() - INTERVAL '2 minutes'
        OR p_created_at > pg_catalog.transaction_timestamp() + INTERVAL '30 seconds'
        OR p_expires_at <= pg_catalog.transaction_timestamp()
        OR p_expires_at <= p_created_at
        OR p_expires_at > p_created_at + INTERVAL '10 minutes'
        OR p_binding_semantic_hash IS NULL
        OR pg_catalog.octet_length(p_binding_semantic_hash) <> 32 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'invalid OIDC authentication transaction lifetime or binding';
    END IF;

    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id',
        p_workspace_public_id::TEXT,
        TRUE
    );

    BEGIN
        SELECT
            deployment.id,
            workspace.id,
            provider.id,
            client.id
        INTO STRICT
            resolved_deployment_id,
            resolved_workspace_id,
            resolved_provider_id,
            resolved_client_id
        FROM mesh.deployment AS deployment
        JOIN mesh.workspace AS workspace
          ON workspace.deployment_id = deployment.id
        JOIN mesh.identity_provider AS provider
          ON provider.deployment_id = deployment.id
        JOIN mesh.identity_provider_generation AS generation
          ON generation.deployment_id = provider.deployment_id
         AND generation.identity_provider_id = provider.id
         AND generation.generation = provider.current_generation
        JOIN mesh.identity_provider_client AS client
          ON client.deployment_id = provider.deployment_id
         AND client.identity_provider_id = provider.id
        JOIN mesh.workspace_identity_provider AS workspace_provider
          ON workspace_provider.deployment_id = deployment.id
         AND workspace_provider.workspace_id = workspace.id
         AND workspace_provider.identity_provider_id = provider.id
         AND workspace_provider.identity_provider_client_id = client.id
        WHERE deployment.installation_public_id = p_deployment_public_id
          AND deployment.state = 'active'
          AND deployment.recovery_state = 'verified'
          AND deployment.deleted_at IS NULL
          AND deployment.recovery_epoch = p_recovery_epoch
          AND workspace.public_id = p_workspace_public_id
          AND workspace.state = 'active'
          AND workspace.deleted_at IS NULL
          AND provider.public_id = p_provider_public_id
          AND provider.state = 'active'
          AND provider.recovery_state = 'verified'
          AND provider.deleted_at IS NULL
          AND provider.current_generation = p_provider_generation
          AND provider.issuer = p_issuer
          AND provider.discovery_uri = p_discovery_uri
          AND provider.authorization_endpoint = p_authorization_endpoint
          AND provider.token_endpoint = p_token_endpoint
          AND provider.jwks_uri = p_jwks_uri
          AND generation.state = 'current'
          AND generation.valid_from <= pg_catalog.transaction_timestamp()
          AND generation.valid_until IS NULL
          AND client.public_id = p_client_public_id
          AND client.state = 'active'
          AND client.deleted_at IS NULL
          AND client.client_kind = 'confidential'
          AND client.client_id = p_oidc_client_id
          AND client.client_auth_method = p_client_auth_method
          AND client.pkce_s256_required
          AND 'authorization_code' = ANY (client.allowed_flows)
          AND client.allowed_scopes = p_scopes
          AND client.allowed_algorithms = p_allowed_algorithms
          AND p_redirect_uri = ANY (client.redirect_uris)
          AND workspace_provider.state = 'active'
          AND workspace_provider.deleted_at IS NULL
          AND workspace_provider.organization_digest_algorithm IS NULL
          AND workspace_provider.organization_digest_key_id IS NULL
          AND workspace_provider.organization_digest IS NULL
        FOR SHARE OF
            deployment,
            workspace,
            provider,
            generation,
            client,
            workspace_provider;
    EXCEPTION
        WHEN no_data_found OR too_many_rows THEN
            PERFORM pg_catalog.set_config(
                'mesh.requested_workspace_public_id',
                '',
                TRUE
            );
            RAISE EXCEPTION USING
                ERRCODE = '23503',
                MESSAGE = 'OIDC login route is unavailable';
        WHEN OTHERS THEN
            PERFORM pg_catalog.set_config(
                'mesh.requested_workspace_public_id',
                '',
                TRUE
            );
            RAISE;
    END;

    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id',
        '',
        TRUE
    );

    RETURN QUERY
    INSERT INTO mesh.auth_transaction AS auth (
        public_id,
        deployment_id,
        workspace_id,
        identity_provider_id,
        identity_provider_client_id,
        principal_id,
        flow_kind,
        operation_kind,
        operation_semantic_hash,
        state_digest_algorithm,
        state_digest_key_id,
        state_digest,
        nonce_digest_algorithm,
        nonce_digest_key_id,
        nonce_digest,
        pkce_verifier_encryption_algorithm,
        pkce_verifier_encryption_key_id,
        pkce_verifier_ciphertext,
        redirect_id,
        return_route_id,
        expected_organization_digest_algorithm,
        expected_organization_digest_key_id,
        expected_organization_digest,
        provider_generation,
        deployment_recovery_epoch,
        account_session_generation,
        expires_at,
        consumed_at,
        consumed_result_kind,
        consumed_result_public_id,
        failure_class,
        state,
        version,
        created_at,
        updated_at,
        binding_semantic_hash
    ) VALUES (
        p_transaction_public_id,
        resolved_deployment_id,
        resolved_workspace_id,
        resolved_provider_id,
        resolved_client_id,
        NULL,
        'browser_authorization_code',
        'login',
        NULL,
        p_state_digest_algorithm,
        p_state_digest_key_id,
        p_state_digest,
        p_nonce_digest_algorithm,
        p_nonce_digest_key_id,
        p_nonce_digest,
        p_verifier_encryption_algorithm,
        p_verifier_encryption_key_id,
        p_verifier_ciphertext,
        p_redirect_id,
        p_return_route_id,
        NULL,
        NULL,
        NULL,
        p_provider_generation,
        p_recovery_epoch,
        NULL,
        p_expires_at,
        NULL,
        NULL,
        NULL,
        NULL,
        'pending',
        1,
        p_created_at,
        p_created_at,
        p_binding_semantic_hash
    )
    RETURNING
        auth.public_id,
        auth.version,
        auth.created_at,
        auth.expires_at;
END;
$function$;

CREATE FUNCTION mesh_ops.load_oidc_auth_transaction_creation_v1(
    p_deployment_public_id UUID,
    p_transaction_public_id UUID,
    p_binding_semantic_hash BYTEA
)
RETURNS TABLE (
    transaction_public_id UUID,
    transaction_version BIGINT,
    transaction_created_at TIMESTAMPTZ,
    transaction_expires_at TIMESTAMPTZ
)
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
    SELECT
        auth.public_id,
        1::BIGINT,
        auth.created_at,
        auth.expires_at
    FROM mesh.auth_transaction AS auth
    JOIN mesh.deployment AS deployment
      ON deployment.id = auth.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND auth.public_id = p_transaction_public_id
      AND auth.binding_semantic_hash = p_binding_semantic_hash
    LIMIT 1
$function$;

REVOKE ALL ON FUNCTION mesh_audit.lock_deployment_stream_head(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_audit.lock_deployment_stream_head(UUID)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_audit.lock_deployment_stream_head(UUID)
    TO mesh_runtime;

REVOKE ALL ON FUNCTION mesh_ops.create_oidc_auth_transaction_v1(
    UUID, UUID, UUID, UUID, UUID, BIGINT, BIGINT,
    TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT[],
    TEXT, TEXT, TEXT, TEXT, TEXT, BYTEA, TEXT, TEXT, BYTEA,
    TEXT, TEXT, BYTEA, BYTEA, TIMESTAMPTZ, TIMESTAMPTZ
) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.create_oidc_auth_transaction_v1(
    UUID, UUID, UUID, UUID, UUID, BIGINT, BIGINT,
    TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT[],
    TEXT, TEXT, TEXT, TEXT, TEXT, BYTEA, TEXT, TEXT, BYTEA,
    TEXT, TEXT, BYTEA, BYTEA, TIMESTAMPTZ, TIMESTAMPTZ
) FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.create_oidc_auth_transaction_v1(
    UUID, UUID, UUID, UUID, UUID, BIGINT, BIGINT,
    TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT[],
    TEXT, TEXT, TEXT, TEXT, TEXT, BYTEA, TEXT, TEXT, BYTEA,
    TEXT, TEXT, BYTEA, BYTEA, TIMESTAMPTZ, TIMESTAMPTZ
) TO mesh_runtime;

REVOKE ALL ON FUNCTION mesh_ops.load_oidc_auth_transaction_creation_v1(
    UUID, UUID, BYTEA
) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_oidc_auth_transaction_creation_v1(
    UUID, UUID, BYTEA
) FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_oidc_auth_transaction_creation_v1(
    UUID, UUID, BYTEA
) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_audit REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
