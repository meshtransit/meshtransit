-- This read-only preparation gate is not a revocation lease or a membership
-- grant. Creation retains its independent locked recheck after discovery.
-- Access path: unique public IDs, exact Deployment/provider generation and
-- Workspace/provider/client tuple; one statement snapshot, no row locks.
CREATE FUNCTION mesh_ops.admit_oidc_login_route_v1(
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
        p_deployment_public_id, p_workspace_public_id,
        p_provider_public_id, p_client_public_id
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

    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id', p_workspace_public_id::TEXT, TRUE
    );
    BEGIN
        SELECT EXISTS (
            SELECT 1
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
        ) INTO STRICT admitted;
    EXCEPTION WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
        RAISE;
    END;
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    RETURN admitted;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.admit_oidc_login_route_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT,
    TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT[], TEXT
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer;

GRANT EXECUTE ON FUNCTION mesh_ops.admit_oidc_login_route_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT,
    TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT[], TEXT
) TO mesh_runtime;
