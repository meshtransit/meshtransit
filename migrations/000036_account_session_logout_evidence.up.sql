CREATE FUNCTION mesh_ops.logout_account_session_v2(
    p_expected_deployment_public_id UUID,
    p_expected_recovery_epoch BIGINT,
    p_token_digest_algorithm TEXT,
    p_token_digest_key_id TEXT,
    p_token_digest BYTEA
)
RETURNS TABLE (
    session_public_id UUID,
    session_version BIGINT,
    principal_public_id UUID,
    ended_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    revoked_session_public_id UUID;
    revoked_session_version BIGINT;
BEGIN
    SELECT
        revoked.session_public_id,
        revoked.session_version
    INTO
        revoked_session_public_id,
        revoked_session_version
    FROM mesh_ops.logout_account_session_v1(
        p_expected_deployment_public_id,
        p_expected_recovery_epoch,
        p_token_digest_algorithm,
        p_token_digest_key_id,
        p_token_digest
    ) AS revoked;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        session.public_id,
        session.version,
        principal.public_id,
        session.ended_at
    FROM mesh.account_session AS session
    JOIN mesh.principal AS principal
      ON principal.deployment_id = session.deployment_id
     AND principal.id = session.principal_id
    WHERE session.public_id = revoked_session_public_id
      AND session.version = revoked_session_version
      AND session.state = 'revoked'
      AND session.end_reason = 'local_logout'
      AND session.ended_at IS NOT NULL;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'account session logout evidence is unavailable';
    END IF;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.logout_account_session_v2(
    UUID,
    BIGINT,
    TEXT,
    TEXT,
    BYTEA
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

GRANT EXECUTE ON FUNCTION mesh_ops.logout_account_session_v2(
    UUID,
    BIGINT,
    TEXT,
    TEXT,
    BYTEA
) TO mesh_runtime;
