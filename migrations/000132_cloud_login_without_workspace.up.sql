-- Schema 132: a Cloud deployment admits sign-in before it has a Workspace.
--
-- Schema 101's login functions required the provider client to route at least
-- one Workspace, so an empty Cloud deployment (bootstrapped without Accounts
-- for self sign-up, schema 131) could not start a sign-in at all. A Cloud
-- deployment whose provider client routes no Workspace at all may now start,
-- load and claim a browser sign-in; once any route exists (active, suspended
-- or organization-bound), the schema 101 rule applies unchanged, so a
-- suspended or organization-only binding still refuses. Admission grants nothing:
-- the subject must still resolve to an Account with an active membership in a
-- routed Workspace, which only an invitation or a self sign-up creates.
-- Self-hosted deployments keep requiring a route.


CREATE OR REPLACE FUNCTION mesh_ops.admit_oidc_login_route_v2(
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
              AND ((deployment.profile = 'cloud' AND NOT EXISTS (
                SELECT 1 FROM mesh.workspace_identity_provider AS any_routing
                WHERE any_routing.deployment_id = deployment.id
                  AND any_routing.identity_provider_id = provider.id
                  AND any_routing.identity_provider_client_id = client.id
              )) OR EXISTS (
                  SELECT 1 FROM mesh.workspace_identity_provider AS routing
                  WHERE routing.deployment_id = deployment.id
                    AND routing.identity_provider_id = provider.id
                    AND routing.identity_provider_client_id = client.id
                    AND routing.state = 'active'
                    AND routing.deleted_at IS NULL
                    AND routing.organization_digest_algorithm IS NULL
                    AND routing.organization_digest_key_id IS NULL
                    AND routing.organization_digest IS NULL
              ))
    ) INTO STRICT admitted;
    RETURN admitted;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.create_oidc_auth_transaction_v2(
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
          AND ((deployment.profile = 'cloud' AND NOT EXISTS (
                SELECT 1 FROM mesh.workspace_identity_provider AS any_routing
                WHERE any_routing.deployment_id = deployment.id
                  AND any_routing.identity_provider_id = provider.id
                  AND any_routing.identity_provider_client_id = client.id
              )) OR EXISTS (
              SELECT 1 FROM mesh.workspace_identity_provider AS routing
              WHERE routing.deployment_id = deployment.id
                AND routing.identity_provider_id = provider.id
                AND routing.identity_provider_client_id = client.id
                AND routing.state = 'active'
                AND routing.deleted_at IS NULL
                AND routing.organization_digest_algorithm IS NULL
                AND routing.organization_digest_key_id IS NULL
                AND routing.organization_digest IS NULL
          ))
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

CREATE OR REPLACE FUNCTION mesh_ops.load_oidc_pending_browser_v2(
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
          AND ((deployment.profile = 'cloud' AND NOT EXISTS (
                SELECT 1 FROM mesh.workspace_identity_provider AS any_routing
                WHERE any_routing.deployment_id = deployment.id
                  AND any_routing.identity_provider_id = provider.id
                  AND any_routing.identity_provider_client_id = client.id
              )) OR EXISTS (
              SELECT 1 FROM mesh.workspace_identity_provider AS routing
              WHERE routing.deployment_id = deployment.id AND routing.identity_provider_id = provider.id
                AND routing.identity_provider_client_id = client.id AND routing.state = 'active'
                AND routing.deleted_at IS NULL AND routing.organization_digest_algorithm IS NULL
                AND routing.organization_digest_key_id IS NULL AND routing.organization_digest IS NULL
          ))
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

CREATE OR REPLACE FUNCTION mesh_ops.claim_oidc_browser_v2(
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
                  AND ((deployment.profile = 'cloud' AND NOT EXISTS (
                SELECT 1 FROM mesh.workspace_identity_provider AS any_routing
                WHERE any_routing.deployment_id = deployment.id
                  AND any_routing.identity_provider_id = provider.id
                  AND any_routing.identity_provider_client_id = client.id
              )) OR EXISTS (
                      SELECT 1 FROM mesh.workspace_identity_provider AS routing
                      WHERE routing.deployment_id = deployment.id AND routing.identity_provider_id = provider.id
                        AND routing.identity_provider_client_id = client.id AND routing.state = 'active'
                        AND routing.deleted_at IS NULL AND routing.organization_digest_algorithm IS NULL
                        AND routing.organization_digest_key_id IS NULL AND routing.organization_digest IS NULL
                  ))
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
