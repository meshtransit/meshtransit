CREATE FUNCTION mesh_ops.issue_browser_registration_intent_v1(
    p_deployment_public_id UUID,
    p_recovery_epoch BIGINT,
    p_intent_public_id UUID,
    p_machine_key BYTEA,
    p_machine_key_fingerprint BYTEA,
    p_requested_node_key BYTEA,
    p_requested_hostname TEXT,
    p_token_nonce BYTEA,
    p_token_key_id TEXT,
    p_token_digest BYTEA,
    p_expires_at TIMESTAMPTZ
)
RETURNS TABLE (
    intent_public_id UUID,
    issued_recovery_epoch BIGINT,
    token_nonce BYTEA,
    token_key_id TEXT,
    token_digest BYTEA,
    intent_state TEXT,
    intent_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    deployment_internal_id BIGINT;
    current_intent mesh.browser_registration_intent%ROWTYPE;
    previous_change_public_id TEXT;
BEGIN
    IF p_deployment_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR p_recovery_epoch IS NULL OR p_recovery_epoch <= 0
        OR p_intent_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_intent_public_id), 6) >> 4 <> 7
        OR p_machine_key IS NULL OR pg_catalog.octet_length(p_machine_key) <> 32
        OR p_machine_key = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_machine_key_fingerprint IS NULL
        OR pg_catalog.octet_length(p_machine_key_fingerprint) <> 32
        OR p_requested_node_key IS NULL
        OR pg_catalog.octet_length(p_requested_node_key) <> 32
        OR p_requested_node_key = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_requested_hostname IS NULL
        OR pg_catalog.char_length(p_requested_hostname) NOT BETWEEN 1 AND 253
        OR p_requested_hostname <> pg_catalog.btrim(p_requested_hostname)
        OR p_token_nonce IS NULL OR pg_catalog.octet_length(p_token_nonce) <> 32
        OR p_token_nonce = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_token_key_id IS NULL
        OR pg_catalog.char_length(p_token_key_id) NOT BETWEEN 1 AND 128
        OR p_token_key_id <> pg_catalog.btrim(p_token_key_id)
        OR p_token_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR p_token_digest IS NULL OR pg_catalog.octet_length(p_token_digest) <> 32
        OR p_token_digest = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_expires_at IS NULL
        OR p_expires_at <= pg_catalog.transaction_timestamp() + INTERVAL '1 minute'
        OR p_expires_at > pg_catalog.transaction_timestamp() + INTERVAL '15 minutes' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid browser registration intent input';
    END IF;

    SELECT deployment.id INTO deployment_internal_id
    FROM mesh.deployment AS deployment
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND deployment.recovery_epoch = p_recovery_epoch
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL
    FOR SHARE;
    IF deployment_internal_id IS NULL THEN
        RETURN;
    END IF;

    previous_change_public_id := pg_catalog.current_setting('mesh.change_public_id', TRUE);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_intent_public_id::TEXT, TRUE);

    SELECT * INTO current_intent
    FROM mesh.browser_registration_intent AS intent
    WHERE intent.deployment_id = deployment_internal_id
      AND intent.machine_key_fingerprint = p_machine_key_fingerprint
      AND intent.state IN ('pending', 'approved')
    FOR UPDATE;
    IF FOUND AND (
        current_intent.expires_at <= pg_catalog.transaction_timestamp()
        OR current_intent.issued_recovery_epoch <> p_recovery_epoch
    ) THEN
        UPDATE mesh.browser_registration_intent AS intent
        SET state = 'expired',
            version = intent.version + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE intent.id = current_intent.id;
        current_intent.id := NULL;
    END IF;

    IF current_intent.id IS NULL THEN
        INSERT INTO mesh.browser_registration_intent (
            public_id, deployment_id, issued_recovery_epoch,
            machine_key, machine_key_fingerprint,
            requested_node_key, requested_hostname,
            token_nonce, token_key_id, token_digest_algorithm, token_digest,
            state, expires_at
        ) VALUES (
            p_intent_public_id, deployment_internal_id, p_recovery_epoch,
            p_machine_key, p_machine_key_fingerprint,
            p_requested_node_key, p_requested_hostname,
            p_token_nonce, p_token_key_id, 'sha256-domain-v1', p_token_digest,
            'pending', p_expires_at
        ) ON CONFLICT DO NOTHING
        RETURNING * INTO current_intent;

        IF current_intent.id IS NULL THEN
            SELECT * INTO current_intent
            FROM mesh.browser_registration_intent AS intent
            WHERE intent.deployment_id = deployment_internal_id
              AND intent.machine_key_fingerprint = p_machine_key_fingerprint
              AND intent.state IN ('pending', 'approved')
            FOR UPDATE;
        END IF;
    END IF;

    IF current_intent.id IS NULL
        OR current_intent.expires_at <= pg_catalog.transaction_timestamp()
        OR current_intent.issued_recovery_epoch <> p_recovery_epoch
        OR current_intent.machine_key <> p_machine_key
        OR current_intent.requested_node_key <> p_requested_node_key
        OR current_intent.requested_hostname <> p_requested_hostname THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            MESSAGE = 'browser registration intent conflict';
    END IF;

    RETURN QUERY SELECT
        current_intent.public_id,
        current_intent.issued_recovery_epoch,
        current_intent.token_nonce,
        current_intent.token_key_id,
        current_intent.token_digest,
        current_intent.state,
        current_intent.expires_at;
    PERFORM pg_catalog.set_config(
        'mesh.change_public_id', COALESCE(previous_change_public_id, ''), TRUE
    );
EXCEPTION
    WHEN OTHERS THEN
        PERFORM pg_catalog.set_config(
            'mesh.change_public_id', COALESCE(previous_change_public_id, ''), TRUE
        );
        RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.issue_browser_registration_intent_v1(
    UUID, BIGINT, UUID, BYTEA, BYTEA, BYTEA, TEXT, BYTEA, TEXT, BYTEA, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.issue_browser_registration_intent_v1(
    UUID, BIGINT, UUID, BYTEA, BYTEA, BYTEA, TEXT, BYTEA, TEXT, BYTEA, TIMESTAMPTZ
) TO mesh_runtime;
