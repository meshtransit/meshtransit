-- This function is called inside the browser approval write transaction. It
-- owns no commit: every row it validates remains locked until the caller
-- inserts the authorized registration, appends audit/outbox, and commits.
CREATE FUNCTION mesh_ops.lock_browser_registration_approval_authority_v1(
    p_deployment_public_id UUID,
    p_recovery_epoch BIGINT,
    p_session_digest_key_id TEXT,
    p_session_digest BYTEA,
    p_intent_token_digest BYTEA,
    p_network_public_id UUID,
    p_expected_intent_state TEXT DEFAULT 'pending'
)
RETURNS TABLE (
    intent_internal_id BIGINT,
    intent_public_id UUID,
    session_internal_id BIGINT,
    session_public_id UUID,
    principal_internal_id BIGINT,
    principal_public_id UUID,
    workspace_internal_id BIGINT,
    workspace_public_id UUID,
    network_internal_id BIGINT,
    network_public_id UUID,
    profile_internal_id BIGINT,
    profile_public_id UUID,
    current_network_revision BIGINT,
    machine_key BYTEA,
    machine_key_fingerprint BYTEA,
    requested_node_key BYTEA,
    requested_hostname TEXT,
    intent_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    intent_row mesh.browser_registration_intent%ROWTYPE;
    admitted RECORD;
    v_deployment_id BIGINT;
    v_workspace_id BIGINT;
    v_network_id BIGINT;
    v_session_id BIGINT;
    v_principal_id BIGINT;
    v_profile_id BIGINT;
    v_revision BIGINT;
    v_principal_public_id UUID;
    v_profile_public_id UUID;
    v_now TIMESTAMPTZ;
    v_authorized BOOLEAN := FALSE;
    previous_requested_workspace TEXT;
    previous_requested_network TEXT;
    request_scope_saved BOOLEAN := FALSE;
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
        OR pg_catalog.octet_length(p_intent_token_digest) <> 32
        OR p_network_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_network_public_id), 6) >> 4 <> 7
        OR p_expected_intent_state IS NULL
        OR p_expected_intent_state NOT IN ('pending', 'approved') THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid browser approval authority input';
    END IF;

    -- The intent is this request's idempotency root and always locks first.
    SELECT intent.* INTO intent_row
    FROM mesh.browser_registration_intent AS intent
    JOIN mesh.deployment AS deployment ON deployment.id = intent.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND intent.issued_recovery_epoch = p_recovery_epoch
      AND intent.token_digest_algorithm = 'sha256-domain-v1'
      AND intent.token_digest = p_intent_token_digest
      AND intent.state = p_expected_intent_state
    FOR UPDATE OF intent;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT deployment.id INTO v_deployment_id
    FROM mesh.deployment AS deployment
    WHERE deployment.id = intent_row.deployment_id
      AND deployment.installation_public_id = p_deployment_public_id
      AND deployment.recovery_epoch = p_recovery_epoch
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT * INTO admitted
    FROM mesh_ops.resolve_account_session_v2(
        p_deployment_public_id, p_recovery_epoch, 'hmac-sha256-v1',
        p_session_digest_key_id, p_session_digest
    );
    IF NOT FOUND OR admitted.login_workspace_public_id IS NULL THEN
        RETURN;
    END IF;

    previous_requested_workspace := pg_catalog.current_setting(
        'mesh.requested_workspace_public_id', TRUE
    );
    previous_requested_network := pg_catalog.current_setting(
        'mesh.requested_network_public_id', TRUE
    );
    request_scope_saved := TRUE;
    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id',
        admitted.login_workspace_public_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.requested_network_public_id', p_network_public_id::TEXT, TRUE
    );

    <<approval>>
    BEGIN

    -- Workspace, Network revision, then aggregate roots follow the global
    -- transaction lock order. The browser-selected Network is only a filter.
    SELECT workspace.id INTO v_workspace_id
    FROM mesh.workspace AS workspace
    WHERE workspace.public_id = admitted.login_workspace_public_id
      AND workspace.deployment_id = v_deployment_id
      AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL
    FOR SHARE;
    IF NOT FOUND THEN
        EXIT approval;
    END IF;
    SELECT network.id INTO v_network_id
    FROM mesh.network AS network
    WHERE network.workspace_id = v_workspace_id
      AND network.public_id = p_network_public_id;
    IF NOT FOUND THEN
        EXIT approval;
    END IF;
    PERFORM * FROM mesh_ops.set_network_scope(
        admitted.login_workspace_public_id, p_network_public_id
    );
    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id',
        admitted.login_workspace_public_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.requested_network_public_id', p_network_public_id::TEXT, TRUE
    );
    SELECT revision.network_revision INTO v_revision
    FROM mesh_ops.lock_network_revision() AS revision;
    IF NOT FOUND THEN
        EXIT approval;
    END IF;

    SELECT session.id, session.principal_id INTO v_session_id, v_principal_id
    FROM mesh.account_session AS session
    WHERE session.public_id = admitted.session_public_id
      AND session.deployment_id = v_deployment_id
      AND session.login_workspace_id = v_workspace_id
      AND session.version = admitted.session_version
      AND session.principal_authority_generation = admitted.principal_authority_generation
      AND session.account_session_generation = admitted.account_session_generation
      AND session.provider_generation = admitted.provider_generation
      AND session.deployment_recovery_epoch = p_recovery_epoch
      AND session.state = 'active'
    FOR SHARE;
    IF NOT FOUND THEN
        EXIT approval;
    END IF;

    SELECT principal.public_id INTO v_principal_public_id
    FROM mesh.principal AS principal
    WHERE principal.id = v_principal_id
      AND principal.deployment_id = v_deployment_id
      AND principal.public_id = admitted.principal_public_id
      AND principal.kind = 'account'
      AND principal.state = 'active'
      AND principal.deleted_at IS NULL
      AND principal.authority_generation = admitted.principal_authority_generation
    FOR SHARE;
    IF NOT FOUND THEN
        EXIT approval;
    END IF;
    PERFORM 1 FROM mesh.account AS account
    WHERE account.deployment_id = v_deployment_id
      AND account.principal_id = v_principal_id
      AND account.recovery_state = 'verified'
      AND account.session_generation = admitted.account_session_generation
    FOR SHARE;
    IF NOT FOUND THEN
        EXIT approval;
    END IF;
    PERFORM 1
    FROM mesh.account_session AS session
    JOIN mesh.identity_subject AS subject
      ON subject.deployment_id = session.deployment_id
     AND subject.identity_provider_id = session.identity_provider_id
     AND subject.principal_id = session.principal_id
     AND subject.id = session.identity_subject_id
     AND subject.public_id = admitted.identity_subject_public_id
     AND subject.state = 'active'
    JOIN mesh.identity_provider AS provider
      ON provider.deployment_id = session.deployment_id
     AND provider.id = session.identity_provider_id
     AND provider.state = 'active'
     AND provider.recovery_state = 'verified'
     AND provider.current_generation = admitted.provider_generation
    JOIN mesh.identity_provider_client AS client
      ON client.deployment_id = session.deployment_id
     AND client.identity_provider_id = session.identity_provider_id
     AND client.id = session.identity_provider_client_id
     AND client.state = 'active'
    WHERE session.id = v_session_id
    FOR SHARE OF subject, provider, client;
    IF NOT FOUND THEN
        EXIT approval;
    END IF;

    PERFORM 1 FROM mesh.network AS network
    WHERE network.id = v_network_id
      AND network.workspace_id = v_workspace_id
      AND network.public_id = p_network_public_id
      AND network.state = 'active'
      AND network.deleted_at IS NULL
    FOR SHARE;
    IF NOT FOUND THEN
        EXIT approval;
    END IF;
    PERFORM 1
    FROM mesh.workspace_membership AS membership
    WHERE membership.deployment_id = v_deployment_id
      AND membership.workspace_id = v_workspace_id
      AND membership.principal_id = v_principal_id
      AND membership.state = 'active'
      AND membership.valid_from <= pg_catalog.clock_timestamp()
      AND (membership.expires_at IS NULL
           OR membership.expires_at > pg_catalog.clock_timestamp())
      AND EXISTS (
          SELECT 1 FROM mesh.network_membership AS network_membership
          WHERE network_membership.deployment_id = v_deployment_id
            AND network_membership.workspace_id = v_workspace_id
            AND network_membership.network_id = v_network_id
            AND network_membership.principal_id = v_principal_id
            AND network_membership.workspace_membership_id = membership.id
            AND network_membership.state = 'active'
            AND network_membership.valid_from <= pg_catalog.clock_timestamp()
            AND (network_membership.expires_at IS NULL
                 OR network_membership.expires_at > pg_catalog.clock_timestamp())
      )
    FOR SHARE;
    IF NOT FOUND THEN
        EXIT approval;
    END IF;
    PERFORM 1 FROM mesh.network_membership AS membership
    WHERE membership.deployment_id = v_deployment_id
      AND membership.workspace_id = v_workspace_id
      AND membership.network_id = v_network_id
      AND membership.principal_id = v_principal_id
      AND membership.state = 'active'
      AND membership.valid_from <= pg_catalog.clock_timestamp()
      AND (membership.expires_at IS NULL
           OR membership.expires_at > pg_catalog.clock_timestamp())
    FOR SHARE;
    IF NOT FOUND THEN
        EXIT approval;
    END IF;

    SELECT profile.id, profile.public_id INTO v_profile_id, v_profile_public_id
    FROM mesh.enrollment_profile AS profile
    WHERE profile.workspace_id = v_workspace_id
      AND profile.network_id = v_network_id
      AND profile.state = 'active'
      AND profile.deleted_at IS NULL
      AND profile.interactive_authorization_enabled
    FOR SHARE;
    IF NOT FOUND THEN
        EXIT approval;
    END IF;

    -- Re-resolve after every lock wait and check live wall time, rather than
    -- relying on the transaction's potentially old timestamp.
    PERFORM 1 FROM mesh_ops.resolve_account_session_v2(
        p_deployment_public_id, p_recovery_epoch, 'hmac-sha256-v1',
        p_session_digest_key_id, p_session_digest
    ) AS current_session
    WHERE current_session.session_public_id = admitted.session_public_id
      AND current_session.session_version = admitted.session_version
      AND current_session.login_workspace_public_id = admitted.login_workspace_public_id
      AND current_session.principal_public_id = admitted.principal_public_id;
    v_now := pg_catalog.clock_timestamp();
    IF NOT FOUND OR intent_row.expires_at <= v_now OR NOT EXISTS (
        SELECT 1 FROM mesh.account_session AS session
        WHERE session.id = v_session_id
          AND session.idle_expires_at > v_now
          AND session.absolute_expires_at > v_now
    ) THEN
        EXIT approval;
    END IF;

    PERFORM 1
    FROM mesh.workspace_membership AS workspace_member
    JOIN mesh.network_membership AS network_member
      ON network_member.deployment_id = workspace_member.deployment_id
     AND network_member.workspace_id = workspace_member.workspace_id
     AND network_member.principal_id = workspace_member.principal_id
     AND network_member.workspace_membership_id = workspace_member.id
    WHERE workspace_member.deployment_id = v_deployment_id
      AND workspace_member.workspace_id = v_workspace_id
      AND workspace_member.principal_id = v_principal_id
      AND workspace_member.state = 'active'
      AND workspace_member.valid_from <= v_now
      AND (workspace_member.expires_at IS NULL OR workspace_member.expires_at > v_now)
      AND network_member.network_id = v_network_id
      AND network_member.state = 'active'
      AND network_member.valid_from <= v_now
      AND (network_member.expires_at IS NULL OR network_member.expires_at > v_now);
    IF NOT FOUND THEN
        EXIT approval;
    END IF;

    intent_internal_id := intent_row.id;
    intent_public_id := intent_row.public_id;
    session_internal_id := v_session_id;
    session_public_id := admitted.session_public_id;
    principal_internal_id := v_principal_id;
    principal_public_id := v_principal_public_id;
    workspace_internal_id := v_workspace_id;
    workspace_public_id := admitted.login_workspace_public_id;
    network_internal_id := v_network_id;
    network_public_id := p_network_public_id;
    profile_internal_id := v_profile_id;
    profile_public_id := v_profile_public_id;
    current_network_revision := v_revision;
    machine_key := intent_row.machine_key;
    machine_key_fingerprint := intent_row.machine_key_fingerprint;
    requested_node_key := intent_row.requested_node_key;
    requested_hostname := intent_row.requested_hostname;
    intent_expires_at := intent_row.expires_at;
    v_authorized := TRUE;
    END approval;

    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id',
        COALESCE(previous_requested_workspace, ''), TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.requested_network_public_id',
        COALESCE(previous_requested_network, ''), TRUE
    );
    IF v_authorized THEN
        RETURN NEXT;
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        IF request_scope_saved THEN
            PERFORM pg_catalog.set_config(
                'mesh.requested_workspace_public_id',
                COALESCE(previous_requested_workspace, ''), TRUE
            );
            PERFORM pg_catalog.set_config(
                'mesh.requested_network_public_id',
                COALESCE(previous_requested_network, ''), TRUE
            );
        END IF;
        RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.lock_browser_registration_approval_authority_v1(
    UUID, BIGINT, TEXT, BYTEA, BYTEA, UUID, TEXT
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_browser_registration_approval_authority_v1(
    UUID, BIGINT, TEXT, BYTEA, BYTEA, UUID, TEXT
) TO mesh_runtime;
