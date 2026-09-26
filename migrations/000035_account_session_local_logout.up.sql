CREATE FUNCTION mesh_ops.logout_account_session_v1(
    p_expected_deployment_public_id UUID,
    p_expected_recovery_epoch BIGINT,
    p_token_digest_algorithm TEXT,
    p_token_digest_key_id TEXT,
    p_token_digest BYTEA
)
RETURNS TABLE (
    session_public_id UUID,
    session_version BIGINT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    observed_at TIMESTAMPTZ;
BEGIN
    IF p_expected_deployment_public_id IS NULL
        OR pg_catalog.get_byte(
            pg_catalog.uuid_send(p_expected_deployment_public_id),
            6
        ) >> 4 <> 7
        OR p_expected_recovery_epoch IS NULL
        OR p_expected_recovery_epoch <= 0
        OR p_token_digest_algorithm IS NULL
        OR p_token_digest_algorithm <> 'hmac-sha256-v1'
        OR p_token_digest_key_id IS NULL
        OR pg_catalog.char_length(p_token_digest_key_id) NOT BETWEEN 1 AND 128
        OR p_token_digest_key_id <> pg_catalog.btrim(p_token_digest_key_id)
        OR p_token_digest_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR p_token_digest IS NULL
        OR pg_catalog.octet_length(p_token_digest) <> 32 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid account session logout input';
    END IF;

    observed_at := pg_catalog.clock_timestamp();

    RETURN QUERY
    UPDATE mesh.account_session AS session
    SET
        state = 'revoked',
        ended_at = observed_at,
        end_reason = 'local_logout',
        version = session.version + 1,
        updated_at = observed_at
    FROM mesh.deployment AS deployment
    WHERE deployment.id = session.deployment_id
      AND deployment.installation_public_id = p_expected_deployment_public_id
      AND deployment.recovery_epoch = p_expected_recovery_epoch
      AND session.deployment_recovery_epoch = p_expected_recovery_epoch
      AND session.token_digest_algorithm = p_token_digest_algorithm
      AND session.token_digest_key_id = p_token_digest_key_id
      AND session.token_digest = p_token_digest
      AND session.state = 'active'
    RETURNING session.public_id, session.version;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.logout_account_session_v1(
    UUID,
    BIGINT,
    TEXT,
    TEXT,
    BYTEA
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

GRANT EXECUTE ON FUNCTION mesh_ops.logout_account_session_v1(
    UUID,
    BIGINT,
    TEXT,
    TEXT,
    BYTEA
) TO mesh_runtime;
