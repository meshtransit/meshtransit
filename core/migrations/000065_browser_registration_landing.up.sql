-- A browser link names an intent. A current SSO Account Session is required
-- before the browser receives even the requested Device hostname.
CREATE FUNCTION mesh_ops.read_browser_registration_landing_v1(
    p_deployment_public_id UUID,
    p_recovery_epoch BIGINT,
    p_session_digest_key_id TEXT,
    p_session_digest BYTEA,
    p_intent_token_digest BYTEA
)
RETURNS TABLE (
    intent_public_id UUID,
    intent_state TEXT,
    requested_hostname TEXT,
    intent_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    IF p_deployment_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR p_recovery_epoch IS NULL OR p_recovery_epoch <= 0
        OR p_session_digest_key_id IS NULL
        OR pg_catalog.char_length(p_session_digest_key_id) NOT BETWEEN 1 AND 128
        OR p_session_digest_key_id <> pg_catalog.btrim(p_session_digest_key_id)
        OR p_session_digest_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR p_session_digest IS NULL OR pg_catalog.octet_length(p_session_digest) <> 32
        OR p_intent_token_digest IS NULL
        OR pg_catalog.octet_length(p_intent_token_digest) <> 32 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid browser registration landing input';
    END IF;

    RETURN QUERY
    SELECT intent.public_id, intent.state, intent.requested_hostname, intent.expires_at
    FROM mesh_ops.resolve_account_session_v2(
        p_deployment_public_id,
        p_recovery_epoch,
        'hmac-sha256-v1',
        p_session_digest_key_id,
        p_session_digest
    ) AS admitted
    JOIN mesh.deployment AS deployment
      ON deployment.installation_public_id = admitted.deployment_public_id
     AND deployment.recovery_epoch = admitted.deployment_recovery_epoch
     AND deployment.state = 'active'
     AND deployment.recovery_state = 'verified'
     AND deployment.deleted_at IS NULL
    JOIN mesh.browser_registration_intent AS intent
      ON intent.deployment_id = deployment.id
     AND intent.issued_recovery_epoch = admitted.deployment_recovery_epoch
     AND intent.token_digest_algorithm = 'sha256-domain-v1'
     AND intent.token_digest = p_intent_token_digest
     AND intent.state IN ('pending', 'approved')
     AND intent.expires_at > pg_catalog.transaction_timestamp()
    WHERE admitted.login_workspace_public_id IS NOT NULL
    LIMIT 1;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_browser_registration_landing_v1(
    UUID, BIGINT, TEXT, BYTEA, BYTEA
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_browser_registration_landing_v1(
    UUID, BIGINT, TEXT, BYTEA, BYTEA
) TO mesh_runtime;
