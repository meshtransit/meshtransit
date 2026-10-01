CREATE FUNCTION mesh_ops.read_browser_registration_followup_v1(
    p_deployment_public_id UUID,
    p_recovery_epoch BIGINT,
    p_token_digest BYTEA,
    p_machine_key BYTEA,
    p_machine_key_fingerprint BYTEA,
    p_requested_node_key BYTEA,
    p_requested_hostname TEXT
)
RETURNS TABLE (
    intent_public_id UUID,
    intent_state TEXT,
    pending_registration_public_id UUID,
    intent_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    IF p_deployment_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR p_recovery_epoch IS NULL OR p_recovery_epoch <= 0
        OR p_token_digest IS NULL OR pg_catalog.octet_length(p_token_digest) <> 32
        OR p_machine_key IS NULL OR pg_catalog.octet_length(p_machine_key) <> 32
        OR p_machine_key_fingerprint IS NULL
        OR pg_catalog.octet_length(p_machine_key_fingerprint) <> 32
        OR p_requested_node_key IS NULL
        OR pg_catalog.octet_length(p_requested_node_key) <> 32
        OR p_requested_hostname IS NULL
        OR pg_catalog.char_length(p_requested_hostname) NOT BETWEEN 1 AND 253 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid browser registration followup input';
    END IF;

    RETURN QUERY
    SELECT
        intent.public_id,
        intent.state,
        intent.pending_registration_public_id,
        intent.expires_at
    FROM mesh.browser_registration_intent AS intent
    JOIN mesh.deployment AS deployment
      ON deployment.id = intent.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND deployment.recovery_epoch = p_recovery_epoch
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL
      AND intent.issued_recovery_epoch = p_recovery_epoch
      AND intent.token_digest_algorithm = 'sha256-domain-v1'
      AND intent.token_digest = p_token_digest
      AND intent.machine_key = p_machine_key
      AND intent.machine_key_fingerprint = p_machine_key_fingerprint
      AND intent.requested_node_key = p_requested_node_key
      AND intent.requested_hostname = p_requested_hostname
      AND intent.state IN ('pending', 'approved')
      AND intent.expires_at > pg_catalog.transaction_timestamp()
    LIMIT 1;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_browser_registration_followup_v1(
    UUID, BIGINT, BYTEA, BYTEA, BYTEA, BYTEA, TEXT
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_browser_registration_followup_v1(
    UUID, BIGINT, BYTEA, BYTEA, BYTEA, BYTEA, TEXT
) TO mesh_runtime;
