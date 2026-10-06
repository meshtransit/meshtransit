-- ADR-050 implementation step 6: browser login no longer depends on one
-- configured Workspace. The OIDC route proves only the Deployment, provider,
-- generation and client; any provisioned Account may sign in, and Core binds
-- the Account Session to one Workspace chosen among the Account's active
-- memberships whose Workspace routes this provider and client. Preference:
-- the Workspace of the Account's most recent Session, then a Workspace the
-- Account owns, then the oldest membership.
--
-- New auth transactions store workspace_id NULL. The v2 functions below are
-- the v1 functions without Workspace scope; v1 stays for rollback.
-- resolve_oidc_login_subject_v1 additionally accepts a Workspace-less auth
-- transaction, so issue_oidc_existing_subject_v1 (unchanged) issues the
-- Session for the Workspace chosen by resolve_oidc_login_subject_v2.

-- Candidate Workspaces of the signing-in principal are readable only while
-- resolve_oidc_login_subject_v2 sets mesh.login_candidate_principal_id.
CREATE POLICY workspace_login_candidate_read ON mesh.workspace
    FOR SELECT TO mesh_migrator
    USING (id IN (
        SELECT membership.workspace_id FROM mesh.workspace_membership AS membership
        WHERE membership.principal_id = NULLIF(
            pg_catalog.current_setting('mesh.login_candidate_principal_id', TRUE), '')::BIGINT
    ));

-- Route admission proves the provider, generation and client, and that at
-- least one active Workspace routing row exists for them. Which Workspace the
-- Account enters is decided by resolve_oidc_login_subject_v2.
CREATE FUNCTION mesh_ops.admit_oidc_login_route_v2(
    p_deployment_public_id UUID,
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
    p_redirect_uri TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    candidate_id UUID;
    candidate_endpoint TEXT;
    admitted BOOLEAN;
BEGIN
    -- Do not preserve a caller-selected requested scope, including invalid
    -- parameters. Exact joins remain mandatory even with FORCE-RLS protection.
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);

    FOREACH candidate_id IN ARRAY ARRAY[
        p_deployment_public_id, p_provider_public_id, p_client_public_id
    ] LOOP
        IF candidate_id IS NULL
            OR pg_catalog.get_byte(pg_catalog.uuid_send(candidate_id), 6) >> 4 <> 7
            OR pg_catalog.get_byte(pg_catalog.uuid_send(candidate_id), 8) >> 6 <> 2 THEN
            RETURN FALSE;
        END IF;
    END LOOP;

    FOREACH candidate_endpoint IN ARRAY ARRAY[
        p_issuer, p_discovery_uri, p_authorization_endpoint,
        p_token_endpoint, p_jwks_uri, p_redirect_uri
    ] LOOP
        IF candidate_endpoint IS NULL
            OR pg_catalog.octet_length(candidate_endpoint) NOT BETWEEN 1 AND 2048
            OR candidate_endpoint <> pg_catalog.btrim(candidate_endpoint)
            OR NOT pg_catalog.starts_with(candidate_endpoint, 'https://') THEN
            RETURN FALSE;
        END IF;
    END LOOP;

    IF p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_recovery_epoch IS NULL OR p_recovery_epoch <= 0
        OR p_oidc_client_id IS NULL
        OR pg_catalog.octet_length(p_oidc_client_id) NOT BETWEEN 1 AND 255
        OR p_client_auth_method IS NULL
        OR p_client_auth_method NOT IN ('client_secret_basic', 'private_key_jwt')
        OR p_scopes IS NULL
        OR pg_catalog.array_ndims(p_scopes) <> 1
        OR pg_catalog.cardinality(p_scopes) NOT BETWEEN 1 AND 32
        OR pg_catalog.array_position(p_scopes, NULL) IS NOT NULL
        OR NOT ('openid' = ANY (p_scopes))
        OR p_allowed_algorithms IS NULL
        OR pg_catalog.array_ndims(p_allowed_algorithms) <> 1
        OR pg_catalog.cardinality(p_allowed_algorithms) NOT BETWEEN 1 AND 8
        OR pg_catalog.array_position(p_allowed_algorithms, NULL) IS NOT NULL
        OR NOT (p_allowed_algorithms <@ ARRAY['RS256', 'PS256', 'ES256']::TEXT[]) THEN
        RETURN FALSE;
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.unnest(p_scopes) AS scope(value)
        WHERE pg_catalog.octet_length(scope.value) NOT BETWEEN 1 AND 128
    ) THEN
        RETURN FALSE;
    END IF;

    SELECT EXISTS (
            SELECT 1
            FROM mesh.deployment AS deployment
            JOIN mesh.identity_provider AS provider
              ON provider.deployment_id = deployment.id
            JOIN mesh.identity_provider_generation AS generation
              ON generation.deployment_id = provider.deployment_id
             AND generation.identity_provider_id = provider.id
             AND generation.generation = provider.current_generation
            JOIN mesh.identity_provider_client AS client
              ON client.deployment_id = provider.deployment_id
             AND client.identity_provider_id = provider.id
            WHERE deployment.installation_public_id = p_deployment_public_id
              AND deployment.state = 'active'
              AND deployment.recovery_state = 'verified'
              AND deployment.deleted_at IS NULL
              AND deployment.recovery_epoch = p_recovery_epoch
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
              AND EXISTS (
                  SELECT 1 FROM mesh.workspace_identity_provider AS routing
                  WHERE routing.deployment_id = deployment.id
                    AND routing.identity_provider_id = provider.id
                    AND routing.identity_provider_client_id = client.id
                    AND routing.state = 'active'
                    AND routing.deleted_at IS NULL
                    AND routing.organization_digest_algorithm IS NULL
                    AND routing.organization_digest_key_id IS NULL
                    AND routing.organization_digest IS NULL
              )
    ) INTO STRICT admitted;
    RETURN admitted;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.admit_oidc_login_route_v2(
    UUID, UUID, UUID, BIGINT, BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT[], TEXT
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer;
GRANT EXECUTE ON FUNCTION mesh_ops.admit_oidc_login_route_v2(
    UUID, UUID, UUID, BIGINT, BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT[], TEXT
) TO mesh_runtime;

-- New browser login transactions carry no Workspace (workspace_id NULL).
CREATE FUNCTION mesh_ops.create_oidc_auth_transaction_v2(
    p_transaction_public_id UUID,
    p_deployment_public_id UUID,
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

    BEGIN
        SELECT
            deployment.id,
            provider.id,
            client.id
        INTO STRICT
            resolved_deployment_id,
            resolved_provider_id,
            resolved_client_id
        FROM mesh.deployment AS deployment
        JOIN mesh.identity_provider AS provider
          ON provider.deployment_id = deployment.id
        JOIN mesh.identity_provider_generation AS generation
          ON generation.deployment_id = provider.deployment_id
         AND generation.identity_provider_id = provider.id
         AND generation.generation = provider.current_generation
        JOIN mesh.identity_provider_client AS client
          ON client.deployment_id = provider.deployment_id
         AND client.identity_provider_id = provider.id
        WHERE deployment.installation_public_id = p_deployment_public_id
          AND deployment.state = 'active'
          AND deployment.recovery_state = 'verified'
          AND deployment.deleted_at IS NULL
          AND deployment.recovery_epoch = p_recovery_epoch
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
          AND EXISTS (
              SELECT 1 FROM mesh.workspace_identity_provider AS routing
              WHERE routing.deployment_id = deployment.id
                AND routing.identity_provider_id = provider.id
                AND routing.identity_provider_client_id = client.id
                AND routing.state = 'active'
                AND routing.deleted_at IS NULL
                AND routing.organization_digest_algorithm IS NULL
                AND routing.organization_digest_key_id IS NULL
                AND routing.organization_digest IS NULL
          )
        FOR SHARE OF
            deployment,
            provider,
            generation,
            client;
    EXCEPTION
        WHEN no_data_found OR too_many_rows THEN
            RAISE EXCEPTION USING
                ERRCODE = '23503',
                MESSAGE = 'OIDC login route is unavailable';
    END;

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
        NULL,
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
REVOKE ALL ON FUNCTION mesh_ops.create_oidc_auth_transaction_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT[],
    TEXT, TEXT, TEXT, TEXT, TEXT, BYTEA, TEXT, TEXT, BYTEA, TEXT, TEXT, BYTEA, BYTEA, TIMESTAMPTZ, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer;
GRANT EXECUTE ON FUNCTION mesh_ops.create_oidc_auth_transaction_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT[],
    TEXT, TEXT, TEXT, TEXT, TEXT, BYTEA, TEXT, TEXT, BYTEA, TEXT, TEXT, BYTEA, BYTEA, TIMESTAMPTZ, TIMESTAMPTZ
) TO mesh_runtime;

CREATE FUNCTION mesh_ops.load_oidc_pending_browser_v2(
    p_deployment_public_id UUID,
    p_provider_public_id UUID, p_client_public_id UUID,
    p_provider_generation BIGINT, p_recovery_epoch BIGINT,
    p_issuer TEXT, p_discovery_uri TEXT, p_authorization_endpoint TEXT,
    p_token_endpoint TEXT, p_jwks_uri TEXT, p_oidc_client_id TEXT,
    p_client_auth_method TEXT, p_scopes TEXT[], p_allowed_algorithms TEXT[],
    p_redirect_uri TEXT, p_state_algorithm TEXT, p_state_key_id TEXT,
    p_state_digest BYTEA, p_redirect_id TEXT, p_return_route_id TEXT
)
RETURNS TABLE (
    transaction_public_id UUID, transaction_version BIGINT, transaction_state TEXT,
    transaction_flow_kind TEXT, transaction_operation_kind TEXT,
    transaction_state_algorithm TEXT, transaction_state_key_id TEXT, transaction_state_digest BYTEA,
    transaction_nonce_algorithm TEXT, transaction_nonce_key_id TEXT, transaction_nonce_digest BYTEA,
    transaction_cipher_algorithm TEXT, transaction_cipher_key_id TEXT, transaction_ciphertext BYTEA,
    transaction_binding_hash BYTEA, transaction_created_at TIMESTAMPTZ, transaction_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    observed_at TIMESTAMPTZ;
BEGIN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    IF p_state_algorithm IS DISTINCT FROM 'hmac-sha256-v1'
        OR p_state_key_id IS NULL OR pg_catalog.octet_length(p_state_key_id) NOT BETWEEN 1 AND 128
        OR p_state_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR p_state_digest IS NULL OR pg_catalog.octet_length(p_state_digest) <> 32
        OR p_redirect_id IS NULL OR pg_catalog.octet_length(p_redirect_id) NOT BETWEEN 1 AND 128
        OR p_redirect_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR p_return_route_id IS NULL OR pg_catalog.octet_length(p_return_route_id) NOT BETWEEN 1 AND 128
        OR p_return_route_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$' THEN
        RETURN;
    END IF;
    -- Reuse the reviewed parameter/lifecycle admission, but not its cleared GUC
    -- or its earlier snapshot. The lookup owns scope and repeats exact authority.
    IF NOT mesh_ops.admit_oidc_login_route_v2(
        p_deployment_public_id, p_provider_public_id, p_client_public_id,
        p_provider_generation, p_recovery_epoch, p_issuer, p_discovery_uri,
        p_authorization_endpoint, p_token_endpoint, p_jwks_uri, p_oidc_client_id,
        p_client_auth_method, p_scopes, p_allowed_algorithms, p_redirect_uri
    ) THEN RETURN; END IF;
    BEGIN
        observed_at := pg_catalog.clock_timestamp();
        RETURN QUERY
        SELECT auth.public_id, auth.version, auth.state, auth.flow_kind, auth.operation_kind,
            auth.state_digest_algorithm, auth.state_digest_key_id, auth.state_digest,
            auth.nonce_digest_algorithm, auth.nonce_digest_key_id, auth.nonce_digest,
            auth.pkce_verifier_encryption_algorithm, auth.pkce_verifier_encryption_key_id,
            auth.pkce_verifier_ciphertext, auth.binding_semantic_hash, auth.created_at, auth.expires_at
        FROM mesh.auth_transaction AS auth
        JOIN mesh.deployment AS deployment ON deployment.id = auth.deployment_id
        JOIN mesh.identity_provider AS provider ON provider.deployment_id = deployment.id AND provider.id = auth.identity_provider_id
        JOIN mesh.identity_provider_generation AS generation
          ON generation.deployment_id = provider.deployment_id AND generation.identity_provider_id = provider.id
         AND generation.generation = provider.current_generation
        JOIN mesh.identity_provider_client AS client
          ON client.deployment_id = provider.deployment_id AND client.identity_provider_id = provider.id
         AND client.id = auth.identity_provider_client_id
        WHERE deployment.installation_public_id = p_deployment_public_id
          AND deployment.state = 'active' AND deployment.recovery_state = 'verified'
          AND deployment.deleted_at IS NULL AND deployment.recovery_epoch = p_recovery_epoch
          AND provider.public_id = p_provider_public_id AND provider.state = 'active'
          AND provider.recovery_state = 'verified' AND provider.deleted_at IS NULL
          AND provider.current_generation = p_provider_generation
          AND provider.issuer = p_issuer AND provider.discovery_uri = p_discovery_uri
          AND provider.authorization_endpoint = p_authorization_endpoint AND provider.token_endpoint = p_token_endpoint
          AND provider.jwks_uri = p_jwks_uri AND generation.state = 'current'
          AND generation.valid_from <= observed_at AND generation.valid_until IS NULL
          AND client.public_id = p_client_public_id AND client.state = 'active' AND client.deleted_at IS NULL
          AND client.client_kind = 'confidential' AND client.client_id = p_oidc_client_id
          AND client.client_auth_method = p_client_auth_method AND client.pkce_s256_required
          AND 'authorization_code' = ANY (client.allowed_flows)
          AND client.allowed_scopes = p_scopes AND client.allowed_algorithms = p_allowed_algorithms
          AND p_redirect_uri = ANY (client.redirect_uris)
          AND EXISTS (
              SELECT 1 FROM mesh.workspace_identity_provider AS routing
              WHERE routing.deployment_id = deployment.id AND routing.identity_provider_id = provider.id
                AND routing.identity_provider_client_id = client.id AND routing.state = 'active'
                AND routing.deleted_at IS NULL AND routing.organization_digest_algorithm IS NULL
                AND routing.organization_digest_key_id IS NULL AND routing.organization_digest IS NULL
          )
          AND auth.workspace_id IS NULL
          AND auth.provider_generation = p_provider_generation AND auth.deployment_recovery_epoch = p_recovery_epoch
          AND auth.state_digest_algorithm = p_state_algorithm AND auth.state_digest_key_id = p_state_key_id
          AND auth.state_digest = p_state_digest AND auth.redirect_id = p_redirect_id AND auth.return_route_id = p_return_route_id
          AND auth.state = 'pending' AND auth.version = 1 AND auth.flow_kind = 'browser_authorization_code'
          AND auth.operation_kind = 'login' AND auth.principal_id IS NULL AND auth.account_session_generation IS NULL
          AND auth.operation_semantic_hash IS NULL AND auth.consumed_at IS NULL
          AND auth.expected_organization_digest_algorithm IS NULL AND auth.expected_organization_digest_key_id IS NULL
          AND auth.expected_organization_digest IS NULL AND auth.consumed_result_kind IS NULL
          AND auth.consumed_result_public_id IS NULL AND auth.failure_class IS NULL
          AND auth.binding_semantic_hash IS NOT NULL
          AND pg_catalog.octet_length(auth.pkce_verifier_ciphertext) BETWEEN 95 AND 222
          AND auth.created_at <= observed_at AND auth.expires_at > observed_at
          AND auth.expires_at <= auth.created_at + INTERVAL '10 minutes';
    EXCEPTION WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
        RAISE;
    END;
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.load_oidc_pending_browser_v2(
    UUID, UUID, UUID, BIGINT, BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT[], TEXT,
    TEXT, TEXT, BYTEA, TEXT, TEXT
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_oidc_pending_browser_v2(
    UUID, UUID, UUID, BIGINT, BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT[], TEXT,
    TEXT, TEXT, BYTEA, TEXT, TEXT
) TO mesh_runtime;

CREATE FUNCTION mesh_ops.claim_oidc_browser_v2(
    p_deployment_public_id UUID,
    p_provider_public_id UUID, p_client_public_id UUID,
    p_provider_generation BIGINT, p_recovery_epoch BIGINT,
    p_issuer TEXT, p_discovery_uri TEXT, p_authorization_endpoint TEXT,
    p_token_endpoint TEXT, p_jwks_uri TEXT, p_oidc_client_id TEXT,
    p_client_auth_method TEXT, p_scopes TEXT[], p_allowed_algorithms TEXT[],
    p_redirect_uri TEXT, p_state_algorithm TEXT, p_state_key_id TEXT,
    p_state_digest BYTEA, p_redirect_id TEXT, p_return_route_id TEXT,
    p_transaction_public_id UUID, p_expected_version BIGINT, p_binding_hash BYTEA
)
RETURNS TABLE (
    transaction_public_id UUID, transaction_version BIGINT,
    transaction_created_at TIMESTAMPTZ, transaction_expires_at TIMESTAMPTZ,
    transaction_consumed_at TIMESTAMPTZ, transaction_binding_hash BYTEA
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    observed_at TIMESTAMPTZ;
    target mesh.auth_transaction%ROWTYPE;
BEGIN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    IF p_transaction_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_transaction_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_transaction_public_id), 8) >> 6 <> 2
        OR p_expected_version IS DISTINCT FROM 1
        OR p_binding_hash IS NULL OR pg_catalog.octet_length(p_binding_hash) <> 32
        OR p_state_algorithm IS DISTINCT FROM 'hmac-sha256-v1'
        OR p_state_key_id IS NULL OR pg_catalog.octet_length(p_state_key_id) NOT BETWEEN 1 AND 128
        OR p_state_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR p_state_digest IS NULL OR pg_catalog.octet_length(p_state_digest) <> 32
        OR p_redirect_id IS NULL OR pg_catalog.octet_length(p_redirect_id) NOT BETWEEN 1 AND 128
        OR p_redirect_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR p_return_route_id IS NULL OR pg_catalog.octet_length(p_return_route_id) NOT BETWEEN 1 AND 128
        OR p_return_route_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$' THEN RETURN; END IF;
    IF NOT mesh_ops.admit_oidc_login_route_v2(
        p_deployment_public_id, p_provider_public_id, p_client_public_id,
        p_provider_generation, p_recovery_epoch, p_issuer, p_discovery_uri,
        p_authorization_endpoint, p_token_endpoint, p_jwks_uri, p_oidc_client_id,
        p_client_auth_method, p_scopes, p_allowed_algorithms, p_redirect_uri
    ) THEN RETURN; END IF;
    BEGIN
        <<claim>>
        BEGIN
            -- Serial lock statements, not a planner-dependent multi-table OF list.
            -- Fixed authority classes; auth next, audit last. No Workspace is
            -- locked: the Workspace is chosen and locked at Session issuance.
            PERFORM 1 FROM mesh.deployment WHERE installation_public_id = p_deployment_public_id ORDER BY id FOR SHARE;
            IF NOT FOUND THEN EXIT claim; END IF;
            PERFORM 1 FROM mesh.identity_provider AS provider
              JOIN mesh.deployment AS deployment ON deployment.id = provider.deployment_id
              WHERE deployment.installation_public_id = p_deployment_public_id AND provider.public_id = p_provider_public_id
              ORDER BY provider.id FOR SHARE OF provider;
            IF NOT FOUND THEN EXIT claim; END IF;
            PERFORM 1 FROM mesh.identity_provider_generation AS generation
              JOIN mesh.identity_provider AS provider ON provider.id = generation.identity_provider_id AND provider.deployment_id = generation.deployment_id
              WHERE provider.public_id = p_provider_public_id AND generation.generation = p_provider_generation
              ORDER BY generation.id FOR SHARE OF generation;
            IF NOT FOUND THEN EXIT claim; END IF;
            PERFORM 1 FROM mesh.identity_provider_client AS client
              JOIN mesh.identity_provider AS provider ON provider.id = client.identity_provider_id AND provider.deployment_id = client.deployment_id
              WHERE provider.public_id = p_provider_public_id AND client.public_id = p_client_public_id
              ORDER BY client.id FOR SHARE OF client;
            IF NOT FOUND THEN EXIT claim; END IF;
            SELECT auth.* INTO target FROM mesh.auth_transaction AS auth
              JOIN mesh.deployment AS deployment ON deployment.id = auth.deployment_id
              WHERE deployment.installation_public_id = p_deployment_public_id AND auth.public_id = p_transaction_public_id
              FOR UPDATE OF auth;
            IF NOT FOUND THEN EXIT claim; END IF;
            observed_at := pg_catalog.clock_timestamp();
            -- New statement snapshot after every authority/auth lock wait.
            IF NOT EXISTS (
                SELECT 1 FROM mesh.auth_transaction AS auth
                JOIN mesh.deployment AS deployment ON deployment.id = auth.deployment_id
                JOIN mesh.identity_provider AS provider ON provider.id = auth.identity_provider_id AND provider.deployment_id = deployment.id
                JOIN mesh.identity_provider_generation AS generation ON generation.identity_provider_id = provider.id
                  AND generation.deployment_id = provider.deployment_id AND generation.generation = provider.current_generation
                JOIN mesh.identity_provider_client AS client ON client.id = auth.identity_provider_client_id
                  AND client.identity_provider_id = provider.id AND client.deployment_id = deployment.id
                WHERE auth.id = target.id AND deployment.installation_public_id = p_deployment_public_id
                  AND deployment.state = 'active' AND deployment.recovery_state = 'verified'
                  AND deployment.deleted_at IS NULL AND deployment.recovery_epoch = p_recovery_epoch
                  AND provider.public_id = p_provider_public_id AND provider.state = 'active'
                  AND provider.recovery_state = 'verified' AND provider.deleted_at IS NULL AND provider.current_generation = p_provider_generation
                  AND provider.issuer = p_issuer AND provider.discovery_uri = p_discovery_uri
                  AND provider.authorization_endpoint = p_authorization_endpoint AND provider.token_endpoint = p_token_endpoint
                  AND provider.jwks_uri = p_jwks_uri AND generation.state = 'current'
                  AND generation.valid_from <= observed_at AND generation.valid_until IS NULL
                  AND client.public_id = p_client_public_id AND client.state = 'active' AND client.deleted_at IS NULL
                  AND client.client_kind = 'confidential' AND client.client_id = p_oidc_client_id
                  AND client.client_auth_method = p_client_auth_method AND client.pkce_s256_required
                  AND 'authorization_code' = ANY (client.allowed_flows) AND client.allowed_scopes = p_scopes
                  AND client.allowed_algorithms = p_allowed_algorithms AND p_redirect_uri = ANY (client.redirect_uris)
                  AND EXISTS (
                      SELECT 1 FROM mesh.workspace_identity_provider AS routing
                      WHERE routing.deployment_id = deployment.id AND routing.identity_provider_id = provider.id
                        AND routing.identity_provider_client_id = client.id AND routing.state = 'active'
                        AND routing.deleted_at IS NULL AND routing.organization_digest_algorithm IS NULL
                        AND routing.organization_digest_key_id IS NULL AND routing.organization_digest IS NULL
                  )
                  AND auth.workspace_id IS NULL
                  AND auth.provider_generation = p_provider_generation AND auth.deployment_recovery_epoch = p_recovery_epoch
                  AND auth.state_digest_algorithm = p_state_algorithm AND auth.state_digest_key_id = p_state_key_id
                  AND auth.state_digest = p_state_digest AND auth.redirect_id = p_redirect_id AND auth.return_route_id = p_return_route_id
                  AND auth.state = 'pending' AND auth.version = p_expected_version AND auth.binding_semantic_hash = p_binding_hash
                  AND auth.flow_kind = 'browser_authorization_code' AND auth.operation_kind = 'login'
                  AND auth.principal_id IS NULL AND auth.account_session_generation IS NULL AND auth.operation_semantic_hash IS NULL
                  AND auth.consumed_at IS NULL AND auth.consumed_result_kind IS NULL AND auth.consumed_result_public_id IS NULL AND auth.failure_class IS NULL
                  AND auth.expected_organization_digest_algorithm IS NULL AND auth.expected_organization_digest_key_id IS NULL AND auth.expected_organization_digest IS NULL
                  AND auth.state_digest_algorithm = 'hmac-sha256-v1' AND auth.nonce_digest_algorithm = 'hmac-sha256-v1'
                  AND auth.state_digest_key_id = auth.nonce_digest_key_id
                  AND auth.pkce_verifier_encryption_algorithm = 'aead-aes-256-gcm-v1'
                  AND pg_catalog.octet_length(auth.pkce_verifier_ciphertext) BETWEEN 95 AND 222
                  AND auth.created_at <= observed_at AND auth.expires_at > observed_at
                  AND auth.expires_at <= auth.created_at + INTERVAL '10 minutes'
            ) THEN EXIT claim; END IF;
            RETURN QUERY UPDATE mesh.auth_transaction AS auth
              SET state = 'consuming', version = auth.version + 1, consumed_at = observed_at,
                  updated_at = GREATEST(observed_at, auth.updated_at)
              WHERE auth.id = target.id AND auth.state = 'pending' AND auth.version = 1
              RETURNING auth.public_id, auth.version, auth.created_at, auth.expires_at, auth.consumed_at, auth.binding_semantic_hash;
        END claim;
    EXCEPTION WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
        RAISE;
    END;
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.claim_oidc_browser_v2(
    UUID, UUID, UUID, BIGINT, BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
    TEXT, TEXT[], TEXT[], TEXT, TEXT, TEXT, BYTEA, TEXT, TEXT, UUID, BIGINT, BYTEA
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.claim_oidc_browser_v2(
    UUID, UUID, UUID, BIGINT, BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
    TEXT, TEXT[], TEXT[], TEXT, TEXT, TEXT, BYTEA, TEXT, TEXT, UUID, BIGINT, BYTEA
) TO mesh_runtime;

CREATE FUNCTION mesh_ops.fail_oidc_browser_v2(
    p_deployment_public_id UUID,
    p_provider_public_id UUID,
    p_client_public_id UUID,
    p_provider_generation BIGINT,
    p_recovery_epoch BIGINT,
    p_transaction_public_id UUID,
    p_expected_version BIGINT,
    p_binding_hash BYTEA,
    p_consumed_at TIMESTAMPTZ
)
RETURNS TABLE (
    transaction_public_id UUID,
    transaction_version BIGINT,
    transaction_created_at TIMESTAMPTZ,
    transaction_expires_at TIMESTAMPTZ,
    transaction_consumed_at TIMESTAMPTZ,
    transaction_binding_hash BYTEA,
    terminal_state TEXT,
    terminal_failure_class TEXT,
    terminal_at TIMESTAMPTZ,
    stream_internal_id BIGINT,
    next_sequence BIGINT,
    latest_event_hash BYTEA
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    resolved_auth_id BIGINT;
    resolved_consumed_at TIMESTAMPTZ;
    resolved_expires_at TIMESTAMPTZ;
    resolved_head_id BIGINT;
    resolved_sequence BIGINT;
    resolved_head_hash BYTEA;
    finished_at TIMESTAMPTZ;
    finished_state TEXT;
    finished_class TEXT;
BEGIN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    IF p_deployment_public_id IS NULL
        OR p_provider_public_id IS NULL OR p_client_public_id IS NULL
        OR p_transaction_public_id IS NULL OR p_expected_version IS DISTINCT FROM 2
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_recovery_epoch IS NULL OR p_recovery_epoch <= 0
        OR p_binding_hash IS NULL OR pg_catalog.octet_length(p_binding_hash) <> 32
        OR p_consumed_at IS NULL OR NOT pg_catalog.isfinite(p_consumed_at) THEN
        RETURN;
    END IF;

    BEGIN
        -- Only immutable scope is resolved. No current-route admission, tenant
        -- lock or provider/Workspace lifecycle check may strand encrypted proof.
        SELECT auth.id, auth.consumed_at, auth.expires_at
        INTO resolved_auth_id, resolved_consumed_at, resolved_expires_at
        FROM mesh.auth_transaction AS auth
        JOIN mesh.deployment AS deployment ON deployment.id = auth.deployment_id
        JOIN mesh.identity_provider AS provider ON provider.deployment_id = auth.deployment_id AND provider.id = auth.identity_provider_id
        JOIN mesh.identity_provider_client AS client ON client.deployment_id = auth.deployment_id AND client.identity_provider_id = auth.identity_provider_id AND client.id = auth.identity_provider_client_id
        WHERE deployment.installation_public_id = p_deployment_public_id
          AND auth.workspace_id IS NULL
          AND provider.public_id = p_provider_public_id
          AND client.public_id = p_client_public_id
          AND auth.public_id = p_transaction_public_id
          AND auth.provider_generation = p_provider_generation
          AND auth.deployment_recovery_epoch = p_recovery_epoch
          AND auth.version = p_expected_version
          AND auth.binding_semantic_hash = p_binding_hash
          AND auth.consumed_at = p_consumed_at
          AND auth.state = 'consuming'
          AND auth.flow_kind = 'browser_authorization_code'
          AND auth.operation_kind = 'login'
          AND auth.principal_id IS NULL
          AND auth.consumed_result_kind IS NULL
          AND auth.consumed_result_public_id IS NULL
          AND auth.failure_class IS NULL
          AND auth.pkce_verifier_ciphertext IS NOT NULL
        FOR UPDATE OF auth;
        PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    EXCEPTION WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
        RAISE;
    END;
    IF resolved_auth_id IS NULL THEN RETURN; END IF;

    -- Audit head last. This existing narrow helper requires active/verified
    -- Deployment; recovery-quarantine cleanup is a separate controlled gate.
    SELECT head.stream_internal_id, head.next_sequence, head.latest_event_hash
    INTO STRICT resolved_head_id, resolved_sequence, resolved_head_hash
    FROM mesh_audit.lock_deployment_stream_head(p_deployment_public_id) AS head;
    finished_at := pg_catalog.clock_timestamp();
    IF finished_at < resolved_consumed_at THEN RETURN; END IF;
    IF finished_at < resolved_expires_at THEN
        finished_state := 'failed'; finished_class := 'authentication_failed';
    ELSE
        finished_state := 'expired'; finished_class := 'deadline_expired';
    END IF;

    RETURN QUERY
    UPDATE mesh.auth_transaction AS auth
    SET state = finished_state,
        failure_class = finished_class,
        pkce_verifier_encryption_algorithm = NULL,
        pkce_verifier_encryption_key_id = NULL,
        pkce_verifier_ciphertext = NULL,
        version = auth.version + 1,
        updated_at = GREATEST(auth.updated_at, finished_at)
    WHERE auth.id = resolved_auth_id AND auth.state = 'consuming' AND auth.version = 2
    RETURNING auth.public_id, auth.version, auth.created_at, auth.expires_at,
        auth.consumed_at, auth.binding_semantic_hash, auth.state, auth.failure_class,
        finished_at, resolved_head_id, resolved_sequence, resolved_head_hash;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.fail_oidc_browser_v2(UUID,UUID,UUID,BIGINT,BIGINT,UUID,BIGINT,BYTEA,TIMESTAMPTZ)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.fail_oidc_browser_v2(UUID,UUID,UUID,BIGINT,BIGINT,UUID,BIGINT,BYTEA,TIMESTAMPTZ) TO mesh_runtime;

-- Unchanged except one predicate: a Workspace-less auth transaction (v2) may
-- resolve for the Workspace chosen by resolve_oidc_login_subject_v2.
CREATE OR REPLACE FUNCTION mesh_ops.resolve_oidc_login_subject_v1(
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
    p_redirect_uri TEXT,
    p_transaction_public_id UUID,
    p_transaction_version BIGINT,
    p_binding_hash BYTEA,
    p_consumed_at TIMESTAMPTZ,
    p_redirect_id TEXT,
    p_return_route_id TEXT,
    p_subject_algorithm TEXT,
    p_active_key_id TEXT,
    p_active_digest BYTEA,
    p_previous_key_id TEXT,
    p_previous_digest BYTEA
)
RETURNS TABLE (
    transaction_public_id UUID,
    transaction_version BIGINT,
    transaction_consumed_at TIMESTAMPTZ,
    transaction_binding_hash BYTEA,
    principal_public_id UUID,
    subject_public_id UUID,
    membership_public_id UUID,
    subject_version BIGINT,
    account_version BIGINT,
    membership_version BIGINT,
    principal_authority_generation BIGINT,
    account_session_generation BIGINT,
    membership_authority_generation BIGINT,
    subject_algorithm TEXT,
    subject_key_id TEXT,
    subject_digest BYTEA,
    evaluated_at TIMESTAMPTZ,
    membership_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    candidate_key_id TEXT;
    candidate_label TEXT;
BEGIN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    IF p_transaction_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_transaction_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_transaction_public_id), 8) >> 6 <> 2
        OR p_transaction_version IS NULL OR p_transaction_version <> 2
        OR p_binding_hash IS NULL OR pg_catalog.octet_length(p_binding_hash) <> 32
        OR p_consumed_at IS NULL OR NOT pg_catalog.isfinite(p_consumed_at)
        OR p_subject_algorithm IS NULL OR p_subject_algorithm <> 'hmac-sha256-v1'
        OR p_active_key_id IS NULL
        OR p_active_digest IS NULL OR pg_catalog.octet_length(p_active_digest) <> 32
        OR p_active_digest = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR (p_previous_key_id IS NULL) <> (p_previous_digest IS NULL)
        OR p_client_auth_method IS NULL OR p_client_auth_method <> 'client_secret_basic' THEN
        RETURN;
    END IF;
    IF p_previous_key_id IS NOT NULL AND (
        p_previous_key_id = p_active_key_id
        OR pg_catalog.octet_length(p_previous_digest) <> 32
        OR p_previous_digest = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ) THEN
        RETURN;
    END IF;
    FOREACH candidate_key_id IN ARRAY ARRAY[p_active_key_id, p_previous_key_id] LOOP
        IF candidate_key_id IS NOT NULL AND (
            pg_catalog.octet_length(candidate_key_id) NOT BETWEEN 1 AND 128
            OR candidate_key_id <> pg_catalog.btrim(candidate_key_id)
            OR candidate_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        ) THEN
            RETURN;
        END IF;
    END LOOP;
    FOREACH candidate_label IN ARRAY ARRAY[p_redirect_id, p_return_route_id] LOOP
        IF candidate_label IS NULL
            OR pg_catalog.octet_length(candidate_label) NOT BETWEEN 1 AND 128
            OR candidate_label <> pg_catalog.btrim(candidate_label)
            OR candidate_label !~ '^[a-z][a-z0-9._:-]*$' THEN
            RETURN;
        END IF;
    END LOOP;

    -- Reuse the released bounded route-parameter/admission gate, but never treat
    -- that earlier snapshot as final: every authority predicate repeats below.
    IF NOT mesh_ops.admit_oidc_login_route_v1(
        p_deployment_public_id, p_workspace_public_id, p_provider_public_id, p_client_public_id,
        p_provider_generation, p_recovery_epoch, p_issuer, p_discovery_uri,
        p_authorization_endpoint, p_token_endpoint, p_jwks_uri, p_oidc_client_id,
        p_client_auth_method, p_scopes, p_allowed_algorithms, p_redirect_uri
    ) THEN
        RETURN;
    END IF;

    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id', p_workspace_public_id::TEXT, TRUE
    );
    RETURN QUERY
    WITH matched_subject AS MATERIALIZED (
        SELECT subject.public_id, subject.deployment_id, subject.identity_provider_id,
            subject.principal_id, subject.version, subject.state, subject.deleted_at,
            subject.subject_digest_algorithm, subject.subject_digest_key_id, subject.subject_digest
        FROM mesh.identity_subject AS subject
        JOIN mesh.identity_provider AS provider
          ON provider.deployment_id = subject.deployment_id
         AND provider.id = subject.identity_provider_id
        JOIN mesh.deployment AS deployment ON deployment.id = subject.deployment_id
        WHERE deployment.installation_public_id = p_deployment_public_id
          AND provider.public_id = p_provider_public_id
          AND subject.subject_digest_algorithm = p_subject_algorithm
          AND (
              (subject.subject_digest_key_id = p_active_key_id AND subject.subject_digest = p_active_digest)
              OR (subject.subject_digest_key_id = p_previous_key_id AND subject.subject_digest = p_previous_digest)
          )
        LIMIT 2
    ), decision AS MATERIALIZED (
        SELECT pg_catalog.clock_timestamp() AS at
    )
    SELECT auth.public_id, auth.version, auth.consumed_at, auth.binding_semantic_hash,
        principal.public_id, subject.public_id, membership.public_id,
        subject.version, account.version, membership.version,
        principal.authority_generation, account.session_generation, membership.authority_generation,
        subject.subject_digest_algorithm, subject.subject_digest_key_id, subject.subject_digest,
        decision.at, membership.expires_at
    FROM matched_subject AS subject
    CROSS JOIN decision
    JOIN mesh.deployment AS deployment ON deployment.id = subject.deployment_id
    JOIN mesh.workspace AS workspace ON workspace.deployment_id = deployment.id
    JOIN mesh.identity_provider AS provider
      ON provider.deployment_id = deployment.id AND provider.id = subject.identity_provider_id
    JOIN mesh.identity_provider_generation AS generation
      ON generation.deployment_id = deployment.id
     AND generation.identity_provider_id = provider.id
     AND generation.generation = provider.current_generation
    JOIN mesh.identity_provider_client AS client
      ON client.deployment_id = deployment.id AND client.identity_provider_id = provider.id
    JOIN mesh.workspace_identity_provider AS workspace_provider
      ON workspace_provider.deployment_id = deployment.id
     AND workspace_provider.workspace_id = workspace.id
     AND workspace_provider.identity_provider_id = provider.id
     AND workspace_provider.identity_provider_client_id = client.id
    JOIN mesh.principal AS principal
      ON principal.deployment_id = deployment.id AND principal.id = subject.principal_id
    JOIN mesh.account AS account
      ON account.deployment_id = deployment.id AND account.principal_id = principal.id
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = deployment.id
     AND membership.workspace_id = workspace.id AND membership.principal_id = principal.id
    JOIN mesh.auth_transaction AS auth
      ON auth.deployment_id = deployment.id
     AND (auth.workspace_id IS NULL OR auth.workspace_id = workspace.id)
     AND auth.identity_provider_id = provider.id AND auth.identity_provider_client_id = client.id
    WHERE (SELECT pg_catalog.count(*) FROM matched_subject) = 1
      AND deployment.installation_public_id = p_deployment_public_id
      AND deployment.state = 'active' AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL AND deployment.recovery_epoch = p_recovery_epoch
      AND workspace.public_id = p_workspace_public_id
      AND workspace.state = 'active' AND workspace.deleted_at IS NULL
      AND provider.public_id = p_provider_public_id
      AND provider.state = 'active' AND provider.recovery_state = 'verified'
      AND provider.deleted_at IS NULL AND provider.current_generation = p_provider_generation
      AND provider.issuer = p_issuer AND provider.discovery_uri = p_discovery_uri
      AND provider.authorization_endpoint = p_authorization_endpoint
      AND provider.token_endpoint = p_token_endpoint AND provider.jwks_uri = p_jwks_uri
      AND generation.state = 'current' AND generation.valid_from <= decision.at
      AND generation.valid_until IS NULL
      AND client.public_id = p_client_public_id AND client.state = 'active'
      AND client.deleted_at IS NULL AND client.client_kind = 'confidential'
      AND client.client_id = p_oidc_client_id AND client.client_auth_method = p_client_auth_method
      AND client.pkce_s256_required AND 'authorization_code' = ANY (client.allowed_flows)
      AND client.allowed_scopes = p_scopes AND client.allowed_algorithms = p_allowed_algorithms
      AND p_redirect_uri = ANY (client.redirect_uris)
      AND workspace_provider.state = 'active' AND workspace_provider.deleted_at IS NULL
      AND workspace_provider.organization_digest_algorithm IS NULL
      AND workspace_provider.organization_digest_key_id IS NULL
      AND workspace_provider.organization_digest IS NULL
      AND principal.kind = 'account' AND principal.state = 'active' AND principal.deleted_at IS NULL
      AND account.recovery_state = 'verified'
      AND subject.state = 'active' AND subject.deleted_at IS NULL
      AND membership.state = 'active' AND membership.valid_from <= decision.at
      AND (membership.expires_at IS NULL OR membership.expires_at > decision.at)
      AND auth.public_id = p_transaction_public_id AND auth.version = p_transaction_version
      AND auth.state = 'consuming' AND auth.flow_kind = 'browser_authorization_code'
      AND auth.operation_kind = 'login' AND auth.principal_id IS NULL
      AND auth.provider_generation = p_provider_generation
      AND auth.deployment_recovery_epoch = p_recovery_epoch
      AND auth.binding_semantic_hash = p_binding_hash AND auth.consumed_at = p_consumed_at
      AND auth.redirect_id = p_redirect_id AND auth.return_route_id = p_return_route_id
      AND auth.consumed_at <= decision.at AND auth.expires_at > decision.at
      AND auth.consumed_result_kind IS NULL AND auth.consumed_result_public_id IS NULL
      AND auth.failure_class IS NULL
    LIMIT 1;
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    RAISE;
END;
$function$;

-- Chooses the Workspace for a Workspace-less login and resolves the subject
-- there through resolve_oidc_login_subject_v1. Candidates are the principal's
-- active memberships in active Workspaces that route this provider and client.
-- Order: most recent Session in that Workspace, owned Workspace, oldest
-- membership, internal ID. No candidate means the Account cannot sign in.
CREATE FUNCTION mesh_ops.resolve_oidc_login_subject_v2(
    p_deployment_public_id UUID,
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
    p_redirect_uri TEXT,
    p_transaction_public_id UUID,
    p_transaction_version BIGINT,
    p_binding_hash BYTEA,
    p_consumed_at TIMESTAMPTZ,
    p_redirect_id TEXT,
    p_return_route_id TEXT,
    p_subject_algorithm TEXT,
    p_active_key_id TEXT,
    p_active_digest BYTEA,
    p_previous_key_id TEXT,
    p_previous_digest BYTEA
)
RETURNS TABLE (
    transaction_public_id UUID,
    transaction_version BIGINT,
    transaction_consumed_at TIMESTAMPTZ,
    transaction_binding_hash BYTEA,
    principal_public_id UUID,
    subject_public_id UUID,
    membership_public_id UUID,
    subject_version BIGINT,
    account_version BIGINT,
    membership_version BIGINT,
    principal_authority_generation BIGINT,
    account_session_generation BIGINT,
    membership_authority_generation BIGINT,
    subject_algorithm TEXT,
    subject_key_id TEXT,
    subject_digest BYTEA,
    evaluated_at TIMESTAMPTZ,
    membership_expires_at TIMESTAMPTZ,
    workspace_public_id UUID
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $resolve$
#variable_conflict use_column
DECLARE
    matched_count BIGINT;
    candidate_principal_id BIGINT;
    chosen_workspace UUID;
    decision_at TIMESTAMPTZ := pg_catalog.clock_timestamp();
BEGIN
    -- Never keep a caller-selected Workspace scope, as every login function does.
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    IF p_subject_algorithm IS DISTINCT FROM 'hmac-sha256-v1' OR p_active_key_id IS NULL
        OR p_active_digest IS NULL OR pg_catalog.octet_length(p_active_digest) <> 32
        OR (p_previous_key_id IS NULL) <> (p_previous_digest IS NULL) THEN
        RETURN;
    END IF;
    -- The Workspace-less transaction must exist for this exact route before
    -- any candidate is considered.
    IF NOT EXISTS (
        SELECT 1 FROM mesh.auth_transaction AS auth
        JOIN mesh.deployment AS deployment ON deployment.id = auth.deployment_id
        JOIN mesh.identity_provider AS provider
          ON provider.deployment_id = auth.deployment_id AND provider.id = auth.identity_provider_id
        JOIN mesh.identity_provider_client AS client
          ON client.deployment_id = auth.deployment_id AND client.id = auth.identity_provider_client_id
        WHERE deployment.installation_public_id = p_deployment_public_id
          AND provider.public_id = p_provider_public_id AND client.public_id = p_client_public_id
          AND auth.public_id = p_transaction_public_id AND auth.workspace_id IS NULL
          AND auth.state = 'consuming' AND auth.version = p_transaction_version
    ) THEN
        RETURN;
    END IF;

    SELECT pg_catalog.count(*), pg_catalog.min(subject.principal_id)
    INTO matched_count, candidate_principal_id
    FROM mesh.identity_subject AS subject
    JOIN mesh.identity_provider AS provider
      ON provider.deployment_id = subject.deployment_id AND provider.id = subject.identity_provider_id
    JOIN mesh.deployment AS deployment ON deployment.id = subject.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND provider.public_id = p_provider_public_id
      AND subject.subject_digest_algorithm = p_subject_algorithm
      AND (
          (subject.subject_digest_key_id = p_active_key_id AND subject.subject_digest = p_active_digest)
          OR (subject.subject_digest_key_id = p_previous_key_id AND subject.subject_digest = p_previous_digest)
      );
    IF matched_count <> 1 THEN
        RETURN;
    END IF;

    PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', candidate_principal_id::TEXT, TRUE);
    BEGIN
        SELECT workspace.public_id INTO chosen_workspace
        FROM mesh.workspace_membership AS membership
        JOIN mesh.workspace AS workspace
          ON workspace.deployment_id = membership.deployment_id AND workspace.id = membership.workspace_id
        JOIN mesh.identity_provider AS provider
          ON provider.deployment_id = membership.deployment_id AND provider.public_id = p_provider_public_id
        JOIN mesh.identity_provider_client AS client
          ON client.deployment_id = provider.deployment_id AND client.identity_provider_id = provider.id
         AND client.public_id = p_client_public_id
        JOIN mesh.workspace_identity_provider AS routing
          ON routing.deployment_id = workspace.deployment_id AND routing.workspace_id = workspace.id
         AND routing.identity_provider_id = provider.id AND routing.identity_provider_client_id = client.id
        WHERE membership.principal_id = candidate_principal_id
          AND membership.state = 'active' AND membership.valid_from <= decision_at
          AND (membership.expires_at IS NULL OR membership.expires_at > decision_at)
          AND workspace.state = 'active' AND workspace.deleted_at IS NULL
          AND routing.state = 'active' AND routing.deleted_at IS NULL
          AND routing.organization_digest_algorithm IS NULL
          AND routing.organization_digest_key_id IS NULL AND routing.organization_digest IS NULL
        ORDER BY (
            SELECT pg_catalog.max(session.issued_at) FROM mesh.account_session AS session
            WHERE session.deployment_id = membership.deployment_id
              AND session.principal_id = candidate_principal_id
              AND session.login_workspace_id = workspace.id
        ) DESC NULLS LAST,
            (workspace.owner_principal_id = candidate_principal_id) DESC,
            membership.valid_from, workspace.id
        LIMIT 1;
    EXCEPTION WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', '', TRUE);
        RAISE;
    END;
    PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', '', TRUE);
    IF chosen_workspace IS NULL THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT resolved.transaction_public_id, resolved.transaction_version, resolved.transaction_consumed_at,
        resolved.transaction_binding_hash, resolved.principal_public_id, resolved.subject_public_id,
        resolved.membership_public_id, resolved.subject_version, resolved.account_version,
        resolved.membership_version, resolved.principal_authority_generation,
        resolved.account_session_generation, resolved.membership_authority_generation,
        resolved.subject_algorithm, resolved.subject_key_id, resolved.subject_digest,
        resolved.evaluated_at, resolved.membership_expires_at, chosen_workspace
    FROM mesh_ops.resolve_oidc_login_subject_v1(
        p_deployment_public_id, chosen_workspace, p_provider_public_id, p_client_public_id,
        p_provider_generation, p_recovery_epoch, p_issuer, p_discovery_uri, p_authorization_endpoint,
        p_token_endpoint, p_jwks_uri, p_oidc_client_id, p_client_auth_method, p_scopes,
        p_allowed_algorithms, p_redirect_uri, p_transaction_public_id, p_transaction_version,
        p_binding_hash, p_consumed_at, p_redirect_id, p_return_route_id, p_subject_algorithm,
        p_active_key_id, p_active_digest, p_previous_key_id, p_previous_digest
    ) AS resolved;
END;
$resolve$;
REVOKE ALL ON FUNCTION mesh_ops.resolve_oidc_login_subject_v2(
    UUID,UUID,UUID,BIGINT,BIGINT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT[],TEXT[],TEXT,
    UUID,BIGINT,BYTEA,TIMESTAMPTZ,TEXT,TEXT,TEXT,TEXT,BYTEA,TEXT,BYTEA
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.resolve_oidc_login_subject_v2(
    UUID,UUID,UUID,BIGINT,BIGINT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT[],TEXT[],TEXT,
    UUID,BIGINT,BYTEA,TIMESTAMPTZ,TEXT,TEXT,TEXT,TEXT,BYTEA,TEXT,BYTEA
) TO mesh_runtime;

-- Abandoned browser expiry also covers Workspace-less (v2) transactions.
CREATE OR REPLACE FUNCTION mesh_ops.list_due_oidc_browser_v1(p_deployment_public_id UUID, p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    decision_at TIMESTAMPTZ := pg_catalog.clock_timestamp();
    result JSONB;
BEGIN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    IF p_deployment_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 128 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid browser expiry selection';
    END IF;
    SELECT COALESCE(pg_catalog.jsonb_agg(
        pg_catalog.jsonb_build_object(
            'deployment_public_id', p_deployment_public_id,
            'transaction_public_id', candidate.public_id,
            'state', candidate.state, 'version', candidate.version,
            'created_at', candidate.created_at, 'expires_at', candidate.expires_at,
            'consumed_at', candidate.consumed_at,
            'binding_hash', pg_catalog.encode(candidate.binding_semantic_hash, 'hex')
        ) ORDER BY candidate.expires_at, candidate.id
    ), '[]'::JSONB) INTO result
    FROM (
        SELECT auth.id, auth.public_id, auth.state, auth.version, auth.created_at,
            auth.expires_at, auth.consumed_at, auth.binding_semantic_hash
        FROM mesh.auth_transaction AS auth
        WHERE auth.deployment_id = (
            SELECT deployment.id FROM mesh.deployment AS deployment
            WHERE deployment.installation_public_id = p_deployment_public_id
        )
          AND auth.state IN ('pending', 'consuming') AND auth.expires_at <= decision_at
          AND ((auth.state = 'pending' AND auth.version = 1 AND auth.consumed_at IS NULL)
            OR (auth.state = 'consuming' AND auth.version = 2 AND auth.consumed_at < auth.expires_at))
          AND auth.flow_kind = 'browser_authorization_code' AND auth.operation_kind = 'login'
          AND auth.principal_id IS NULL
          AND auth.account_session_generation IS NULL AND auth.operation_semantic_hash IS NULL
          AND auth.expected_organization_digest_algorithm IS NULL
          AND auth.expected_organization_digest_key_id IS NULL
          AND auth.expected_organization_digest IS NULL
          AND auth.consumed_result_kind IS NULL AND auth.consumed_result_public_id IS NULL
          AND auth.failure_class IS NULL AND auth.pkce_verifier_ciphertext IS NOT NULL
          AND auth.binding_semantic_hash IS NOT NULL
          AND auth.binding_semantic_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        ORDER BY auth.expires_at, auth.id LIMIT p_limit
    ) AS candidate;
    RETURN result;
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    RAISE;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.expire_oidc_browser_v1(
    p_deployment_public_id UUID, p_transaction_public_id UUID, p_expected_version BIGINT,
    p_created_at TIMESTAMPTZ, p_expires_at TIMESTAMPTZ, p_consumed_at TIMESTAMPTZ, p_binding_hash BYTEA
)
RETURNS TABLE (
    transaction_version BIGINT, transaction_consumed_at TIMESTAMPTZ, expired_at TIMESTAMPTZ,
    stream_internal_id BIGINT, next_sequence BIGINT, latest_event_hash BYTEA
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    auth_row mesh.auth_transaction%ROWTYPE;
    head_id BIGINT;
    head_sequence BIGINT;
    head_hash BYTEA;
    decision_at TIMESTAMPTZ;
    change_id UUID;
    transaction_value BIGINT := (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT;
BEGIN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    IF p_deployment_public_id IS NULL OR p_transaction_public_id IS NULL
        OR p_expected_version IS NULL OR p_expected_version NOT IN (1, 2)
        OR p_created_at IS NULL OR p_expires_at IS NULL OR p_binding_hash IS NULL
        OR pg_catalog.octet_length(p_binding_hash) <> 32
        OR p_binding_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex') THEN RETURN; END IF;
    change_id := pg_catalog.current_setting('mesh.change_public_id', TRUE)::UUID;
    IF change_id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(change_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(change_id), 8) & 192 <> 128
        OR change_id = p_transaction_public_id
        OR EXISTS (SELECT 1 FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = change_id)
        OR EXISTS (SELECT 1 FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.transaction_id = transaction_value) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'browser expiry requires fresh owned unit';
    END IF;
    SELECT auth.* INTO auth_row
    FROM mesh.auth_transaction AS auth
    JOIN mesh.deployment AS deployment ON deployment.id = auth.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND auth.public_id = p_transaction_public_id AND auth.version = p_expected_version
      AND auth.created_at = p_created_at AND auth.expires_at = p_expires_at
      AND auth.consumed_at IS NOT DISTINCT FROM p_consumed_at
      AND auth.binding_semantic_hash = p_binding_hash
      AND ((auth.state = 'pending' AND auth.version = 1 AND auth.consumed_at IS NULL)
        OR (auth.state = 'consuming' AND auth.version = 2 AND auth.consumed_at < auth.expires_at))
      AND auth.flow_kind = 'browser_authorization_code' AND auth.operation_kind = 'login'
      AND auth.principal_id IS NULL
      AND auth.account_session_generation IS NULL AND auth.operation_semantic_hash IS NULL
      AND auth.expected_organization_digest_algorithm IS NULL
      AND auth.expected_organization_digest_key_id IS NULL AND auth.expected_organization_digest IS NULL
      AND auth.consumed_result_kind IS NULL AND auth.consumed_result_public_id IS NULL
      AND auth.failure_class IS NULL AND auth.pkce_verifier_ciphertext IS NOT NULL
    FOR UPDATE OF auth;
    IF NOT FOUND THEN RETURN; END IF;

    -- Exact existing stream, no current serving/recovery admission. This gate
    -- grants only proof erasure; no generic head capability is exposed to worker.
    SELECT stream.id, stream.next_sequence, stream.latest_event_hash
    INTO head_id, head_sequence, head_hash FROM mesh_audit.audit_stream AS stream
    WHERE stream.deployment_id = auth_row.deployment_id AND stream.scope_kind = 'deployment'
      AND stream.workspace_id IS NULL AND stream.network_id IS NULL FOR UPDATE OF stream;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'browser expiry stream unavailable';
    END IF;
    decision_at := pg_catalog.clock_timestamp();
    IF decision_at < auth_row.expires_at OR decision_at < auth_row.updated_at THEN
        -- A rejected post-lock decision must not let a direct caller continue
        -- with another Auth while retaining this row/head acquisition order.
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'browser expiry deadline not due';
    END IF;
    UPDATE mesh.auth_transaction AS auth
    SET state = 'expired', version = auth.version + 1, failure_class = 'deadline_expired',
        consumed_at = COALESCE(auth.consumed_at, decision_at), updated_at = decision_at,
        pkce_verifier_encryption_algorithm = NULL, pkce_verifier_encryption_key_id = NULL,
        pkce_verifier_ciphertext = NULL WHERE auth.id = auth_row.id;
    RETURN QUERY SELECT auth_row.version + 1, COALESCE(auth_row.consumed_at, decision_at),
        decision_at, head_id, head_sequence, head_hash;
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    RAISE;
END;
$function$;

