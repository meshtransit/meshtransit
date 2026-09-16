-- Additive no-grant primary read. Existing subject composite uniqueness bounds
-- each candidate to one row; inspect both before lifecycle/member filtering.
-- No columns/indexes/backfill or reader/writer generation change. No row locks,
-- raw subjects, last-seen updates, identity provisioning or Session issuance.
CREATE FUNCTION mesh_ops.resolve_oidc_login_subject_v1(
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
      ON auth.deployment_id = deployment.id AND auth.workspace_id = workspace.id
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

REVOKE ALL ON FUNCTION mesh_ops.resolve_oidc_login_subject_v1(
    UUID,UUID,UUID,UUID,BIGINT,BIGINT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT[],TEXT[],TEXT,
    UUID,BIGINT,BYTEA,TIMESTAMPTZ,TEXT,TEXT,TEXT,TEXT,BYTEA,TEXT,BYTEA
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer;

GRANT EXECUTE ON FUNCTION mesh_ops.resolve_oidc_login_subject_v1(
    UUID,UUID,UUID,UUID,BIGINT,BIGINT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT[],TEXT[],TEXT,
    UUID,BIGINT,BYTEA,TIMESTAMPTZ,TEXT,TEXT,TEXT,TEXT,BYTEA,TEXT,BYTEA
) TO mesh_runtime;
