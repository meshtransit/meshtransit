-- The Noise-authenticated Followup never carries an SSO credential or a
-- Network ID. This lock resolves the exact approved Session and Network from
-- durable approval evidence, then rechecks current authority before a Device
-- transaction can mutate anything. It deliberately does not commit a Device.
CREATE FUNCTION mesh_ops.lock_browser_registration_completion_authority_v2(
    p_deployment_public_id UUID,
    p_recovery_epoch BIGINT,
    p_intent_token_digest BYTEA,
    p_machine_key BYTEA,
    p_machine_key_fingerprint BYTEA,
    p_requested_node_key BYTEA,
    p_requested_hostname TEXT
)
RETURNS TABLE (
    intent_internal_id BIGINT,
    intent_public_id UUID,
    registration_internal_id BIGINT,
    registration_public_id UUID,
    registration_version BIGINT,
    workspace_internal_id BIGINT,
    workspace_public_id UUID,
    network_internal_id BIGINT,
    network_public_id UUID,
    profile_internal_id BIGINT,
    profile_public_id UUID,
    principal_internal_id BIGINT,
    principal_public_id UUID,
    session_public_id UUID,
    current_network_revision BIGINT,
    node_lifetime_seconds BIGINT,
    ephemeral_mode TEXT,
    request_hash BYTEA
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    candidate RECORD;
    authority RECORD;
    pending_row mesh.pending_registration%ROWTYPE;
    expected_request_hash BYTEA;
    v_session_digest_key_id TEXT;
    v_session_digest BYTEA;
    v_now TIMESTAMPTZ;
BEGIN
    IF p_deployment_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR p_recovery_epoch IS NULL OR p_recovery_epoch <= 0
        OR p_intent_token_digest IS NULL
        OR pg_catalog.octet_length(p_intent_token_digest) <> 32
        OR p_machine_key IS NULL OR pg_catalog.octet_length(p_machine_key) <> 32
        OR p_machine_key_fingerprint IS NULL
        OR pg_catalog.octet_length(p_machine_key_fingerprint) <> 32
        OR p_requested_node_key IS NULL
        OR pg_catalog.octet_length(p_requested_node_key) <> 32
        OR p_requested_hostname IS NULL
        OR pg_catalog.char_length(p_requested_hostname) NOT BETWEEN 1 AND 253 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid browser completion authority input';
    END IF;

    -- This first read only locates immutable approval references. The nested
    -- lock below rechecks every one after locking the intent and authority.
    SELECT intent.id AS intent_id,
           intent.public_id AS intent_public_id,
           intent.pending_registration_public_id AS registration_public_id,
           intent.approved_session_public_id AS session_public_id,
           intent.approved_workspace_public_id AS workspace_public_id,
           intent.approved_network_public_id AS network_public_id
    INTO candidate
    FROM mesh.browser_registration_intent AS intent
    WHERE intent.issued_recovery_epoch=p_recovery_epoch
      AND intent.token_digest_algorithm='sha256-domain-v1'
      AND intent.token_digest=p_intent_token_digest
      AND intent.machine_key=p_machine_key
      AND intent.machine_key_fingerprint=p_machine_key_fingerprint
      AND intent.requested_node_key=p_requested_node_key
      AND intent.requested_hostname=p_requested_hostname
      AND intent.state='approved';
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT session.token_digest_key_id, session.token_digest
    INTO v_session_digest_key_id, v_session_digest
    FROM mesh.account_session AS session
    WHERE session.public_id=candidate.session_public_id;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT * INTO authority
    FROM mesh_ops.lock_browser_registration_approval_authority_v2(
        p_deployment_public_id, p_recovery_epoch,
        v_session_digest_key_id, v_session_digest,
        p_intent_token_digest, candidate.workspace_public_id, candidate.network_public_id, 'approved'
    );
    IF NOT FOUND OR authority.intent_internal_id <> candidate.intent_id
        OR authority.intent_public_id <> candidate.intent_public_id
        OR authority.workspace_public_id <> candidate.workspace_public_id
        OR authority.network_public_id <> candidate.network_public_id
        OR authority.session_public_id <> candidate.session_public_id
        OR authority.machine_key <> p_machine_key
        OR authority.machine_key_fingerprint <> p_machine_key_fingerprint
        OR authority.requested_node_key <> p_requested_node_key
        OR authority.requested_hostname <> p_requested_hostname THEN
        RETURN;
    END IF;

    SELECT registration.* INTO pending_row
    FROM mesh.pending_registration AS registration
    WHERE registration.public_id=candidate.registration_public_id
      AND registration.workspace_id=authority.workspace_internal_id
      AND registration.network_id=authority.network_internal_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    expected_request_hash := pg_catalog.sha256(
        pg_catalog.convert_to('meshtransit/browser-registration-approval/v1', 'UTF8')
        || pg_catalog.uuid_send(authority.intent_public_id)
        || pg_catalog.uuid_send(authority.workspace_public_id)
        || pg_catalog.uuid_send(authority.network_public_id)
        || pg_catalog.uuid_send(authority.profile_public_id)
        || pg_catalog.uuid_send(authority.principal_public_id)
        || pg_catalog.uuid_send(authority.session_public_id)
        || authority.machine_key
        || authority.requested_node_key
        || pg_catalog.convert_to(authority.requested_hostname, 'UTF8')
        || pg_catalog.int8send(p_recovery_epoch)
    );
    v_now := pg_catalog.clock_timestamp();
    IF pending_row.state <> 'authorized'
        OR pending_row.authorization_kind <> 'interactive'
        OR pending_row.browser_authorization_public_id <> authority.intent_public_id
        OR pending_row.authorized_principal_id <> authority.principal_internal_id
        OR pending_row.enrollment_profile_id <> authority.profile_internal_id
        OR pending_row.machine_key_fingerprint <> p_machine_key_fingerprint
        OR pending_row.requested_node_key <> p_requested_node_key
        OR pending_row.intent_format_version <> 2
        OR pending_row.request_hash <> expected_request_hash
        OR pending_row.device_id IS NOT NULL
        OR pending_row.expires_at <= v_now
        OR authority.intent_expires_at <= v_now THEN
        RETURN;
    END IF;

    SELECT profile.node_lifetime_seconds, profile.ephemeral_mode
    INTO node_lifetime_seconds, ephemeral_mode
    FROM mesh.enrollment_profile AS profile
    WHERE profile.id=authority.profile_internal_id
      AND profile.workspace_id=authority.workspace_internal_id
      AND profile.network_id=authority.network_internal_id
      AND profile.state='active'
      AND profile.deleted_at IS NULL
      AND profile.interactive_authorization_enabled;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    intent_internal_id := authority.intent_internal_id;
    intent_public_id := authority.intent_public_id;
    registration_internal_id := pending_row.id;
    registration_public_id := pending_row.public_id;
    registration_version := pending_row.version;
    workspace_internal_id := authority.workspace_internal_id;
    workspace_public_id := authority.workspace_public_id;
    network_internal_id := authority.network_internal_id;
    network_public_id := authority.network_public_id;
    profile_internal_id := authority.profile_internal_id;
    profile_public_id := authority.profile_public_id;
    principal_internal_id := authority.principal_internal_id;
    principal_public_id := authority.principal_public_id;
    session_public_id := authority.session_public_id;
    current_network_revision := authority.current_network_revision;
    request_hash := expected_request_hash;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.lock_browser_registration_completion_authority_v2(
    UUID, BIGINT, BYTEA, BYTEA, BYTEA, BYTEA, TEXT
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_browser_registration_completion_authority_v2(
    UUID, BIGINT, BYTEA, BYTEA, BYTEA, BYTEA, TEXT
) TO mesh_runtime;

