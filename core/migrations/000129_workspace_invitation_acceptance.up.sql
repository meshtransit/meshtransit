-- Schema 129: accept a Workspace invitation at sign-in (L2 of
-- docs/device-lifecycle.md, R1-21).
--
-- preview_workspace_invitation_v1 lets the holder of a link see what it is
-- for before signing in: the Workspace, the inviter, the invited address and
-- the role. It answers only for a pending, unexpired invitation.
--
-- accept_workspace_invitation_v1 runs inside a browser sign-in, after the
-- provider's code is exchanged and before the subject is resolved. It binds
-- to the exact consuming login transaction and route, like
-- resolve_oidc_login_subject_v2, and to the invitation by its token digest.
-- The link is the proof: whoever completes the sign-in with it joins. Then:
--   * an unknown identity gets an Account (display name: the invited
--     address) and its identity subject under the active key;
--   * a person with no membership becomes an active member, joins every
--     active Network of the Workspace (so they can register Devices) and gets
--     the invited role;
--   * an active member keeps their membership and gains the role;
--   * a suspended member is refused (MTV05): an invitation never lifts a
--     suspension.
-- The invitation becomes accepted, so the link works once. The caller
-- appends evidence on the Workspace stream, with the accepting principal as
-- the actor, in the same transaction, then resolves the subject as usual.
--
-- Errors: 22023 invalid input, 42501 the transaction or route does not match,
-- P0002 no pending invitation for the token, MTV05 the member is suspended.

CREATE FUNCTION mesh_ops.preview_workspace_invitation_v1(p_token_digest BYTEA, p_evaluated_at TIMESTAMPTZ)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_invitation mesh.workspace_invitation%ROWTYPE;
    v_result JSONB;
BEGIN
    IF p_token_digest IS NULL OR pg_catalog.octet_length(p_token_digest) <> 32 THEN
        RETURN NULL;
    END IF;
    SELECT * INTO v_invitation FROM mesh.workspace_invitation AS invitation
    WHERE invitation.token_digest = p_token_digest AND invitation.state = 'pending'
      AND invitation.expires_at > GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at);
    IF v_invitation.id IS NULL THEN
        RETURN NULL;
    END IF;
    -- Schema 16's scope policy admits exactly this Workspace for the read.
    PERFORM pg_catalog.set_config('mesh.workspace_id', v_invitation.workspace_id::TEXT, TRUE);
    SELECT pg_catalog.jsonb_build_object(
        'workspace_name', workspace.display_name,
        'inviter_name', COALESCE(account.display_name, ''),
        'email', v_invitation.email,
        'role', v_invitation.role_key,
        'expires_at', v_invitation.expires_at
    ) INTO v_result
    FROM mesh.workspace AS workspace
    LEFT JOIN mesh.account AS account ON account.principal_id = v_invitation.invited_by_principal_id
    WHERE workspace.id = v_invitation.workspace_id AND workspace.state = 'active' AND workspace.deleted_at IS NULL;
    PERFORM pg_catalog.set_config('mesh.workspace_id', '', TRUE);
    RETURN v_result;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.preview_workspace_invitation_v1(BYTEA, TIMESTAMPTZ)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.preview_workspace_invitation_v1(BYTEA, TIMESTAMPTZ) TO mesh_runtime;

CREATE FUNCTION mesh_ops.accept_workspace_invitation_v1(
    p_deployment_public_id UUID, p_provider_public_id UUID, p_client_public_id UUID,
    p_provider_generation BIGINT, p_recovery_epoch BIGINT,
    p_transaction_public_id UUID, p_transaction_version BIGINT, p_binding_hash BYTEA,
    p_consumed_at TIMESTAMPTZ, p_subject_algorithm TEXT, p_active_key_id TEXT, p_active_digest BYTEA,
    p_previous_key_id TEXT, p_previous_digest BYTEA, p_token_digest BYTEA,
    p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_auth RECORD;
    v_invitation mesh.workspace_invitation%ROWTYPE;
    v_workspace RECORD;
    v_principal BIGINT;
    v_principal_public UUID;
    v_matched BIGINT;
    v_created BOOLEAN := FALSE;
    v_membership mesh.workspace_membership%ROWTYPE;
    v_joined BOOLEAN := FALSE;
    v_networks INTEGER := 0;
    v_role_added BOOLEAN := FALSE;
BEGIN
    IF p_subject_algorithm IS DISTINCT FROM 'hmac-sha256-v1' OR p_active_key_id IS NULL
        OR p_active_digest IS NULL OR pg_catalog.octet_length(p_active_digest) <> 32
        OR (p_previous_key_id IS NULL) <> (p_previous_digest IS NULL)
        OR p_token_digest IS NULL OR pg_catalog.octet_length(p_token_digest) <> 32
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invitation acceptance input is invalid';
    END IF;
    -- The exact consuming, Workspace-less browser login of this route.
    SELECT auth.deployment_id, auth.identity_provider_id, auth.identity_provider_client_id INTO v_auth
    FROM mesh.auth_transaction AS auth
    JOIN mesh.deployment AS deployment ON deployment.id = auth.deployment_id
    JOIN mesh.identity_provider AS provider
      ON provider.deployment_id = auth.deployment_id AND provider.id = auth.identity_provider_id
    JOIN mesh.identity_provider_client AS client
      ON client.deployment_id = auth.deployment_id AND client.id = auth.identity_provider_client_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND deployment.state = 'active' AND deployment.recovery_epoch = p_recovery_epoch
      AND provider.public_id = p_provider_public_id AND provider.current_generation = p_provider_generation
      AND client.public_id = p_client_public_id
      AND auth.public_id = p_transaction_public_id AND auth.workspace_id IS NULL
      AND auth.state = 'consuming' AND auth.version = p_transaction_version
      AND auth.flow_kind = 'browser_authorization_code' AND auth.operation_kind = 'login'
      AND auth.principal_id IS NULL AND auth.binding_semantic_hash = p_binding_hash
      AND auth.consumed_at = p_consumed_at AND auth.expires_at > v_now
      AND auth.consumed_result_kind IS NULL AND auth.failure_class IS NULL;
    IF v_auth.deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'sign-in transaction does not match';
    END IF;

    SELECT * INTO v_invitation FROM mesh.workspace_invitation AS invitation
    WHERE invitation.token_digest = p_token_digest AND invitation.deployment_id = v_auth.deployment_id
    FOR UPDATE;
    IF v_invitation.id IS NULL OR v_invitation.state <> 'pending' OR v_invitation.expires_at <= v_now THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'no pending invitation for this link';
    END IF;
    -- The Workspace must admit this provider and client. Its exact scope lets
    -- the policies admit the Workspace, its Networks and its members.
    PERFORM pg_catalog.set_config('mesh.workspace_id', v_invitation.workspace_id::TEXT, TRUE);
    SELECT workspace.id, workspace.public_id, workspace.deployment_id INTO v_workspace
    FROM mesh.workspace AS workspace
    JOIN mesh.workspace_identity_provider AS routing
      ON routing.deployment_id = workspace.deployment_id AND routing.workspace_id = workspace.id
     AND routing.identity_provider_id = v_auth.identity_provider_id
     AND routing.identity_provider_client_id = v_auth.identity_provider_client_id
    WHERE workspace.id = v_invitation.workspace_id AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL AND routing.state = 'active' AND routing.deleted_at IS NULL
      AND routing.organization_digest IS NULL
    FOR UPDATE OF workspace;
    IF v_workspace.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'no pending invitation for this link';
    END IF;
    PERFORM mesh_ops.enter_workspace_management_scope_v1(v_workspace.public_id);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    SELECT pg_catalog.count(*), pg_catalog.min(subject.principal_id) INTO v_matched, v_principal
    FROM mesh.identity_subject AS subject
    WHERE subject.deployment_id = v_auth.deployment_id
      AND subject.identity_provider_id = v_auth.identity_provider_id
      AND subject.subject_digest_algorithm = p_subject_algorithm
      AND subject.state <> 'deleted'
      AND ((subject.subject_digest_key_id = p_active_key_id AND subject.subject_digest = p_active_digest)
           OR (subject.subject_digest_key_id = p_previous_key_id AND subject.subject_digest = p_previous_digest));
    IF v_matched > 1 THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'the identity is ambiguous';
    END IF;
    IF v_matched = 0 THEN
        INSERT INTO mesh.principal (public_id, deployment_id, kind, state)
        VALUES (pg_catalog.uuidv7(), v_auth.deployment_id, 'account', 'active')
        RETURNING id INTO v_principal;
        INSERT INTO mesh.account (public_id, deployment_id, principal_id, display_name, recovery_state)
        VALUES (pg_catalog.uuidv7(), v_auth.deployment_id, v_principal, v_invitation.email, 'verified');
        INSERT INTO mesh.identity_subject (
            public_id, deployment_id, identity_provider_id, principal_id, subject_digest_algorithm,
            subject_digest_key_id, subject_digest, last_seen_at, state
        ) VALUES (
            pg_catalog.uuidv7(), v_auth.deployment_id, v_auth.identity_provider_id, v_principal,
            p_subject_algorithm, p_active_key_id, p_active_digest, v_now, 'active'
        );
        v_created := TRUE;
    END IF;
    SELECT principal.public_id INTO v_principal_public FROM mesh.principal AS principal
    WHERE principal.id = v_principal AND principal.kind = 'account' AND principal.state = 'active'
      AND principal.deleted_at IS NULL;
    IF v_principal_public IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'the account is not active';
    END IF;

    SELECT * INTO v_membership FROM mesh.workspace_membership AS membership
    WHERE membership.workspace_id = v_workspace.id AND membership.principal_id = v_principal
      AND membership.state <> 'revoked'
    FOR UPDATE;
    IF v_membership.id IS NOT NULL AND v_membership.state = 'suspended' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTV05', MESSAGE = 'a suspended member cannot accept an invitation';
    END IF;
    IF v_membership.id IS NULL THEN
        INSERT INTO mesh.workspace_membership (public_id, deployment_id, workspace_id, principal_id, state, valid_from)
        VALUES (pg_catalog.uuidv7(), v_workspace.deployment_id, v_workspace.id, v_principal, 'active', v_now)
        RETURNING * INTO v_membership;
        v_joined := TRUE;
        -- Schema 50's projection policy admits this Workspace's Networks.
        PERFORM pg_catalog.set_config('mesh.console_management_scope_workspace_public_id',
            v_workspace.public_id::TEXT, TRUE);
        INSERT INTO mesh.network_membership (
            public_id, deployment_id, workspace_id, network_id, principal_id, workspace_membership_id,
            state, valid_from
        )
        SELECT pg_catalog.uuidv7(), v_workspace.deployment_id, network.workspace_id, network.id, v_principal,
            v_membership.id, 'active', v_now
        FROM mesh.network AS network
        WHERE network.workspace_id = v_workspace.id AND network.state = 'active' AND network.deleted_at IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM mesh.network_membership AS existing
              WHERE existing.workspace_id = network.workspace_id AND existing.network_id = network.id
                AND existing.principal_id = v_principal AND existing.state <> 'revoked'
          )
        ORDER BY network.id;
        GET DIAGNOSTICS v_networks = ROW_COUNT;
        PERFORM pg_catalog.set_config('mesh.console_management_scope_workspace_public_id', '', TRUE);
    END IF;
    IF v_invitation.role_key IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM mesh.workspace_role_assignment AS assignment
        WHERE assignment.workspace_membership_id = v_membership.id AND assignment.role_key = v_invitation.role_key
          AND assignment.network_id IS NULL AND assignment.state = 'active'
    ) AND NOT EXISTS (
        SELECT 1 FROM mesh.workspace AS owned WHERE owned.id = v_workspace.id AND owned.owner_principal_id = v_principal
    ) THEN
        INSERT INTO mesh.workspace_role_assignment (
            public_id, deployment_id, workspace_id, network_id, principal_id, workspace_membership_id,
            role_key, state, valid_from, created_at, updated_at
        ) VALUES (
            pg_catalog.uuidv7(), v_workspace.deployment_id, v_workspace.id, NULL, v_principal, v_membership.id,
            v_invitation.role_key, 'active', v_now, v_now, v_now
        );
        v_role_added := TRUE;
    END IF;
    UPDATE mesh.workspace_invitation SET state = 'accepted', accepted_by_principal_id = v_principal,
        accepted_at = v_now, version = version + 1, updated_at = v_now
    WHERE id = v_invitation.id
    RETURNING * INTO v_invitation;

    RETURN pg_catalog.jsonb_build_object(
        'invitation_id', v_invitation.public_id,
        'invitation_version', v_invitation.version,
        'workspace_id', v_workspace.public_id,
        'principal_id', v_principal_public,
        'account_created', v_created,
        'joined', v_joined,
        'network_count', v_networks,
        'role', CASE WHEN v_role_added THEN v_invitation.role_key END
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.accept_workspace_invitation_v1(
    UUID, UUID, UUID, BIGINT, BIGINT, UUID, BIGINT, BYTEA, TIMESTAMPTZ, TEXT, TEXT, BYTEA, TEXT, BYTEA, BYTEA, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.accept_workspace_invitation_v1(
    UUID, UUID, UUID, BIGINT, BIGINT, UUID, BIGINT, BYTEA, TIMESTAMPTZ, TEXT, TEXT, BYTEA, TEXT, BYTEA, BYTEA, UUID
) TO mesh_runtime;
