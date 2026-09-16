-- Read-only pre-claim evidence. This grants neither consumption nor exchange.
-- Access path: existing unique public IDs and deployment/state-digest uniqueness;
-- no new table/index or serving-role table grants. Creation v1 remains unchanged.
CREATE FUNCTION mesh_ops.load_oidc_pending_browser_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID,
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
    IF NOT mesh_ops.admit_oidc_login_route_v1(
        p_deployment_public_id, p_workspace_public_id, p_provider_public_id, p_client_public_id,
        p_provider_generation, p_recovery_epoch, p_issuer, p_discovery_uri,
        p_authorization_endpoint, p_token_endpoint, p_jwks_uri, p_oidc_client_id,
        p_client_auth_method, p_scopes, p_allowed_algorithms, p_redirect_uri
    ) THEN RETURN; END IF;
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', p_workspace_public_id::TEXT, TRUE);
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
        JOIN mesh.workspace AS workspace ON workspace.deployment_id = deployment.id AND workspace.id = auth.workspace_id
        JOIN mesh.identity_provider AS provider ON provider.deployment_id = deployment.id AND provider.id = auth.identity_provider_id
        JOIN mesh.identity_provider_generation AS generation
          ON generation.deployment_id = provider.deployment_id AND generation.identity_provider_id = provider.id
         AND generation.generation = provider.current_generation
        JOIN mesh.identity_provider_client AS client
          ON client.deployment_id = provider.deployment_id AND client.identity_provider_id = provider.id
         AND client.id = auth.identity_provider_client_id
        JOIN mesh.workspace_identity_provider AS workspace_provider
          ON workspace_provider.deployment_id = deployment.id AND workspace_provider.workspace_id = workspace.id
         AND workspace_provider.identity_provider_id = provider.id AND workspace_provider.identity_provider_client_id = client.id
        WHERE deployment.installation_public_id = p_deployment_public_id
          AND deployment.state = 'active' AND deployment.recovery_state = 'verified'
          AND deployment.deleted_at IS NULL AND deployment.recovery_epoch = p_recovery_epoch
          AND workspace.public_id = p_workspace_public_id AND workspace.state = 'active' AND workspace.deleted_at IS NULL
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
          AND workspace_provider.state = 'active' AND workspace_provider.deleted_at IS NULL
          AND workspace_provider.organization_digest_algorithm IS NULL
          AND workspace_provider.organization_digest_key_id IS NULL AND workspace_provider.organization_digest IS NULL
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

REVOKE ALL ON FUNCTION mesh_ops.load_oidc_pending_browser_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT,
    TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT[], TEXT,
    TEXT, TEXT, BYTEA, TEXT, TEXT
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_oidc_pending_browser_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT,
    TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT[], TEXT,
    TEXT, TEXT, BYTEA, TEXT, TEXT
) TO mesh_runtime;
