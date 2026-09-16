-- Additive no-grant cleanup. Released claim/read functions are unchanged.
CREATE FUNCTION mesh_ops.fail_oidc_browser_v1(
    p_deployment_public_id UUID,
    p_workspace_public_id UUID,
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
    IF p_deployment_public_id IS NULL OR p_workspace_public_id IS NULL
        OR p_provider_public_id IS NULL OR p_client_public_id IS NULL
        OR p_transaction_public_id IS NULL OR p_expected_version IS DISTINCT FROM 2
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_recovery_epoch IS NULL OR p_recovery_epoch <= 0
        OR p_binding_hash IS NULL OR pg_catalog.octet_length(p_binding_hash) <> 32
        OR p_consumed_at IS NULL OR NOT pg_catalog.isfinite(p_consumed_at) THEN
        RETURN;
    END IF;

    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', p_workspace_public_id::TEXT, TRUE);
    BEGIN
        -- Only immutable scope is resolved. No current-route admission, tenant
        -- lock or provider/Workspace lifecycle check may strand encrypted proof.
        SELECT auth.id, auth.consumed_at, auth.expires_at
        INTO resolved_auth_id, resolved_consumed_at, resolved_expires_at
        FROM mesh.auth_transaction AS auth
        JOIN mesh.deployment AS deployment ON deployment.id = auth.deployment_id
        JOIN mesh.workspace AS workspace ON workspace.deployment_id = auth.deployment_id AND workspace.id = auth.workspace_id
        JOIN mesh.identity_provider AS provider ON provider.deployment_id = auth.deployment_id AND provider.id = auth.identity_provider_id
        JOIN mesh.identity_provider_client AS client ON client.deployment_id = auth.deployment_id AND client.identity_provider_id = auth.identity_provider_id AND client.id = auth.identity_provider_client_id
        WHERE deployment.installation_public_id = p_deployment_public_id
          AND workspace.public_id = p_workspace_public_id
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

ALTER FUNCTION mesh_ops.fail_oidc_browser_v1(UUID,UUID,UUID,UUID,BIGINT,BIGINT,UUID,BIGINT,BYTEA,TIMESTAMPTZ) OWNER TO mesh_migrator;
REVOKE ALL ON FUNCTION mesh_ops.fail_oidc_browser_v1(UUID,UUID,UUID,UUID,BIGINT,BIGINT,UUID,BIGINT,BYTEA,TIMESTAMPTZ) FROM PUBLIC, mesh_worker, mesh_observer;
GRANT EXECUTE ON FUNCTION mesh_ops.fail_oidc_browser_v1(UUID,UUID,UUID,UUID,BIGINT,BIGINT,UUID,BIGINT,BYTEA,TIMESTAMPTZ) TO mesh_runtime;
