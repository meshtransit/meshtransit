-- Renew only an authenticated, still-live session. The caller supplies the
-- exact digest and current version; the runtime cannot update the table.
CREATE FUNCTION mesh_ops.touch_account_session_v1(
    p_session_public_id UUID,
    p_expected_version BIGINT,
    p_deployment_public_id UUID,
    p_recovery_epoch BIGINT,
    p_digest_algorithm TEXT,
    p_digest_key_id TEXT,
    p_digest BYTEA
)
RETURNS TABLE (session_version BIGINT, last_used_at TIMESTAMPTZ, idle_expires_at TIMESTAMPTZ)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    observed_at TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    resolved_workspace_id BIGINT;
    previous_workspace_id TEXT;
BEGIN
    IF p_session_public_id IS NULL OR p_expected_version IS NULL OR p_expected_version < 1
        OR p_deployment_public_id IS NULL OR p_recovery_epoch IS NULL OR p_recovery_epoch < 1
        OR p_digest_algorithm IS DISTINCT FROM 'hmac-sha256-v1'
        OR p_digest_key_id IS NULL OR pg_catalog.char_length(p_digest_key_id) NOT BETWEEN 1 AND 128
        OR p_digest_key_id <> pg_catalog.btrim(p_digest_key_id)
        OR p_digest_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR p_digest IS NULL OR pg_catalog.octet_length(p_digest) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid account session touch input';
    END IF;

    SELECT session.login_workspace_id INTO resolved_workspace_id
    FROM mesh.account_session AS session
    JOIN mesh.deployment AS deployment ON deployment.id = session.deployment_id
    WHERE session.public_id = p_session_public_id
      AND deployment.installation_public_id = p_deployment_public_id
      AND session.token_digest_algorithm = p_digest_algorithm
      AND session.token_digest_key_id = p_digest_key_id
      AND session.token_digest = p_digest;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    previous_workspace_id := pg_catalog.current_setting('mesh.workspace_id', TRUE);
    PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(resolved_workspace_id::TEXT, ''), TRUE);
    BEGIN
        RETURN QUERY
        UPDATE mesh.account_session AS session
        SET last_used_at = observed_at,
            idle_expires_at = LEAST(observed_at + INTERVAL '1 hour', session.absolute_expires_at),
            version = session.version + 1,
            updated_at = observed_at
        FROM mesh.deployment AS deployment
        WHERE session.deployment_id = deployment.id
          AND session.public_id = p_session_public_id
          AND session.version = p_expected_version
          AND deployment.installation_public_id = p_deployment_public_id
          AND deployment.recovery_epoch = p_recovery_epoch
          AND session.deployment_recovery_epoch = p_recovery_epoch
          AND session.token_digest_algorithm = p_digest_algorithm
          AND session.token_digest_key_id = p_digest_key_id
          AND session.token_digest = p_digest
          AND session.state = 'active'
          AND session.idle_expires_at > observed_at
          AND session.absolute_expires_at > observed_at
          AND session.last_used_at <= observed_at - INTERVAL '15 minutes'
        RETURNING session.version, session.last_used_at, session.idle_expires_at;
    EXCEPTION WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(previous_workspace_id, ''), TRUE);
        RAISE;
    END;
    PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(previous_workspace_id, ''), TRUE);
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.touch_account_session_v1(UUID, BIGINT, UUID, BIGINT, TEXT, TEXT, BYTEA)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.touch_account_session_v1(UUID, BIGINT, UUID, BIGINT, TEXT, TEXT, BYTEA)
    TO mesh_runtime;
