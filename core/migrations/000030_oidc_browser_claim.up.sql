-- Single-use consumption only. No token exchange, session, or verifier release.
-- Existing unique public IDs provide bounded access; released functions stay intact.
CREATE FUNCTION mesh_ops.claim_oidc_browser_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID,
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
    IF NOT mesh_ops.admit_oidc_login_route_v1(
        p_deployment_public_id, p_workspace_public_id, p_provider_public_id, p_client_public_id,
        p_provider_generation, p_recovery_epoch, p_issuer, p_discovery_uri,
        p_authorization_endpoint, p_token_endpoint, p_jwks_uri, p_oidc_client_id,
        p_client_auth_method, p_scopes, p_allowed_algorithms, p_redirect_uri
    ) THEN RETURN; END IF;
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', p_workspace_public_id::TEXT, TRUE);
    BEGIN
        <<claim>>
        BEGIN
            -- Serial lock statements, not a planner-dependent multi-table OF list.
            -- One Workspace, then fixed authority classes; auth next, audit last.
            PERFORM 1 FROM mesh.workspace WHERE public_id = p_workspace_public_id ORDER BY id FOR SHARE;
            IF NOT FOUND THEN EXIT claim; END IF;
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
            PERFORM 1 FROM mesh.workspace_identity_provider AS workspace_provider
              JOIN mesh.workspace AS workspace ON workspace.id = workspace_provider.workspace_id AND workspace.deployment_id = workspace_provider.deployment_id
              JOIN mesh.identity_provider AS provider ON provider.id = workspace_provider.identity_provider_id AND provider.deployment_id = workspace_provider.deployment_id
              JOIN mesh.identity_provider_client AS client ON client.id = workspace_provider.identity_provider_client_id AND client.deployment_id = workspace_provider.deployment_id
              WHERE workspace.public_id = p_workspace_public_id AND provider.public_id = p_provider_public_id AND client.public_id = p_client_public_id
              ORDER BY workspace_provider.id FOR SHARE OF workspace_provider;
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
                JOIN mesh.workspace AS workspace ON workspace.id = auth.workspace_id AND workspace.deployment_id = deployment.id
                JOIN mesh.identity_provider AS provider ON provider.id = auth.identity_provider_id AND provider.deployment_id = deployment.id
                JOIN mesh.identity_provider_generation AS generation ON generation.identity_provider_id = provider.id
                  AND generation.deployment_id = provider.deployment_id AND generation.generation = provider.current_generation
                JOIN mesh.identity_provider_client AS client ON client.id = auth.identity_provider_client_id
                  AND client.identity_provider_id = provider.id AND client.deployment_id = deployment.id
                JOIN mesh.workspace_identity_provider AS workspace_provider ON workspace_provider.workspace_id = workspace.id
                  AND workspace_provider.deployment_id = deployment.id AND workspace_provider.identity_provider_id = provider.id
                  AND workspace_provider.identity_provider_client_id = client.id
                WHERE auth.id = target.id AND deployment.installation_public_id = p_deployment_public_id
                  AND deployment.state = 'active' AND deployment.recovery_state = 'verified'
                  AND deployment.deleted_at IS NULL AND deployment.recovery_epoch = p_recovery_epoch
                  AND workspace.public_id = p_workspace_public_id AND workspace.state = 'active' AND workspace.deleted_at IS NULL
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
                  AND workspace_provider.state = 'active' AND workspace_provider.deleted_at IS NULL
                  AND workspace_provider.organization_digest_algorithm IS NULL AND workspace_provider.organization_digest_key_id IS NULL
                  AND workspace_provider.organization_digest IS NULL
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

REVOKE ALL ON FUNCTION mesh_ops.claim_oidc_browser_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
    TEXT, TEXT[], TEXT[], TEXT, TEXT, TEXT, BYTEA, TEXT, TEXT, UUID, BIGINT, BYTEA
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer;
GRANT EXECUTE ON FUNCTION mesh_ops.claim_oidc_browser_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
    TEXT, TEXT[], TEXT[], TEXT, TEXT, TEXT, BYTEA, TEXT, TEXT, UUID, BIGINT, BYTEA
) TO mesh_runtime;
