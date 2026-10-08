-- Schema 128: Workspace invitations, administration side (L2 of
-- docs/device-lifecycle.md, R1-21).
--
-- An administrator (member.invite) invites one email address, optionally
-- with one Workspace-wide role the administrator could grant. The invitation
-- holds only a domain-separated SHA-256 digest of a 256-bit bearer token; the
-- application builds the link from the token, shows it to the inviter once
-- and emails it. Resending rotates the token, so an older link stops working.
-- Acceptance at sign-in is a later schema.
--
-- An invitation is pending until it is accepted, revoked or past expires_at
-- (reported as expired; no worker needs to run). One pending invitation per
-- address and Workspace; at most 200 pending per Workspace.
--
-- Errors: 22023 invalid input, 42501 not authorized or role beyond the
-- delegation ceiling, P0002 unknown invitation, 40001 stale version, MTV01 a
-- pending invitation exists for this address, MTV02 too many pending, MTV03
-- the invitation is not pending, MTV04 resent too soon.

CREATE TABLE mesh.workspace_invitation (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    email TEXT NOT NULL,
    role_key TEXT,
    token_digest BYTEA NOT NULL UNIQUE,
    state TEXT NOT NULL DEFAULT 'pending',
    expires_at TIMESTAMPTZ NOT NULL,
    invited_by_principal_id BIGINT NOT NULL,
    accepted_by_principal_id BIGINT,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    delivery_state TEXT NOT NULL DEFAULT 'pending',
    last_sent_at TIMESTAMPTZ,
    send_count INTEGER NOT NULL DEFAULT 0,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT workspace_invitation_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT workspace_invitation_email_check CHECK (
        email = pg_catalog.lower(email)
        AND pg_catalog.char_length(email) BETWEEN 3 AND 254
        AND email ~ '^[a-z0-9.!#$%&''*+/=?^_`{|}~-]+@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
    ),
    CONSTRAINT workspace_invitation_role_fk FOREIGN KEY (role_key) REFERENCES mesh.builtin_role (role_key),
    CONSTRAINT workspace_invitation_token_check CHECK (pg_catalog.octet_length(token_digest) = 32),
    CONSTRAINT workspace_invitation_state_check CHECK (
        (state = 'pending' AND accepted_at IS NULL AND accepted_by_principal_id IS NULL AND revoked_at IS NULL)
        OR (state = 'accepted' AND accepted_at IS NOT NULL AND accepted_by_principal_id IS NOT NULL
            AND revoked_at IS NULL)
        OR (state = 'revoked' AND revoked_at IS NOT NULL AND accepted_at IS NULL)
    ),
    CONSTRAINT workspace_invitation_delivery_check CHECK (
        delivery_state IN ('pending', 'sent', 'failed', 'not_configured')
        AND send_count BETWEEN 0 AND 1000
    ),
    CONSTRAINT workspace_invitation_timestamps_check CHECK (
        updated_at >= created_at AND expires_at > created_at
    ),
    CONSTRAINT workspace_invitation_workspace_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT workspace_invitation_inviter_fk FOREIGN KEY (invited_by_principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT,
    CONSTRAINT workspace_invitation_acceptor_fk FOREIGN KEY (accepted_by_principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX workspace_invitation_pending_email_uidx
    ON mesh.workspace_invitation (workspace_id, email) WHERE state = 'pending';
CREATE INDEX workspace_invitation_workspace_created_idx
    ON mesh.workspace_invitation (workspace_id, created_at DESC, id);

ALTER TABLE mesh.workspace_invitation ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.workspace_invitation FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_invitation_migrator_policy ON mesh.workspace_invitation
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.workspace_invitation FROM PUBLIC;

CREATE FUNCTION mesh_ops.enforce_workspace_invitation_transition_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Workspace invitations are retained';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.public_id <> OLD.public_id OR NEW.deployment_id <> OLD.deployment_id
            OR NEW.workspace_id <> OLD.workspace_id OR NEW.email <> OLD.email
            OR NEW.role_key IS DISTINCT FROM OLD.role_key
            OR NEW.invited_by_principal_id <> OLD.invited_by_principal_id
            OR NEW.created_at <> OLD.created_at OR NEW.version <> OLD.version + 1 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Workspace invitation binding is immutable';
        END IF;
        IF OLD.state <> 'pending' THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Workspace invitation is final';
        END IF;
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER workspace_invitation_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.workspace_invitation
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_workspace_invitation_transition_v1();
CREATE TRIGGER workspace_invitation_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.workspace_invitation
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('workspace_invitation', 'public_id');

-- The Workspace a Session manages with one permission: scope, deployment,
-- actor and the authority to record with the change.
CREATE FUNCTION mesh_ops.authorize_workspace_people_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_permission TEXT, p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (deployment_id BIGINT, workspace_id BIGINT, actor_id BIGINT, authority JSONB)
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT;
    v_deployment BIGINT;
    v_grant RECORD;
    v_actor BIGINT;
BEGIN
    IF p_workspace_public_id IS NULL OR p_evaluated_at IS NULL
        OR p_permission NOT IN ('member.read', 'member.invite', 'member.manage') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Workspace people scope input is invalid';
    END IF;
    v_workspace := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF v_workspace IS NULL OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, v_workspace) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Workspace people scope is unavailable';
    END IF;
    SELECT workspace.deployment_id INTO v_deployment FROM mesh.workspace AS workspace
    WHERE workspace.id = v_workspace AND workspace.state = 'active' AND workspace.deleted_at IS NULL;
    IF v_deployment IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Workspace people scope is unavailable';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_permission, p_evaluated_at
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Workspace people action is not authorized';
    END IF;
    SELECT principal.id INTO STRICT v_actor FROM mesh.principal AS principal
    WHERE principal.public_id = p_principal_public_id;
    RETURN QUERY SELECT v_deployment, v_workspace, v_actor, pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
        'binding_id', v_grant.role_binding_public_id,
        'role_id', v_grant.role_definition_public_id,
        'binding_generation', COALESCE(v_grant.binding_authority_generation, 0),
        'membership_generation', COALESCE(v_grant.membership_authority_generation, 0),
        'owner_generation', COALESCE(v_grant.workspace_owner_authority_generation, 0)
    ));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.authorize_workspace_people_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TEXT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The invitation document; state reads expired once a pending invitation is
-- past its expiry.
CREATE FUNCTION mesh_ops.workspace_invitation_document_internal_v1(
    p_invitation mesh.workspace_invitation, p_now TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'invitation_id', p_invitation.public_id,
        'email', p_invitation.email,
        'role', p_invitation.role_key,
        'state', CASE WHEN p_invitation.state = 'pending' AND p_invitation.expires_at <= p_now
                      THEN 'expired' ELSE p_invitation.state END,
        'expires_at', p_invitation.expires_at,
        'invited_by', pg_catalog.jsonb_build_object(
            'principal_id', inviter.public_id,
            'display_name', COALESCE(account.display_name, '')),
        'delivery_state', p_invitation.delivery_state,
        'last_sent_at', p_invitation.last_sent_at,
        'send_count', p_invitation.send_count,
        'created_at', p_invitation.created_at,
        'version', p_invitation.version
    )
    FROM mesh.principal AS inviter
    LEFT JOIN mesh.account AS account ON account.principal_id = inviter.id
    WHERE inviter.id = p_invitation.invited_by_principal_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.workspace_invitation_document_internal_v1(mesh.workspace_invitation, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- create | resend | revoke | delivered | delivery_failed | not_configured.
CREATE FUNCTION mesh_ops.change_workspace_invitation_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_invitation_public_id UUID, p_action TEXT,
    p_email TEXT, p_role_key TEXT, p_token_digest BYTEA, p_expires_at TIMESTAMPTZ,
    p_expected_version BIGINT, p_change_public_id UUID, p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
SET join_collapse_limit = 1
SET from_collapse_limit = 1
SET plan_cache_mode = force_generic_plan
AS $function$
DECLARE
    v_scope RECORD;
    v_invitation mesh.workspace_invitation%ROWTYPE;
    v_before JSONB;
    v_role RECORD;
    v_workspace_name TEXT;
    v_now TIMESTAMPTZ := GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at);
BEGIN
    IF p_action NOT IN ('create', 'resend', 'revoke', 'delivered', 'delivery_failed', 'not_configured')
        OR p_invitation_public_id IS NULL OR p_change_public_id IS NULL OR p_evaluated_at IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_invitation_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_action IN ('create', 'resend')) <> (p_token_digest IS NOT NULL AND p_expires_at IS NOT NULL)
        OR (p_action = 'create') <> (p_email IS NOT NULL)
        OR (p_action <> 'create' AND (p_expected_version IS NULL OR p_expected_version < 1))
        OR (p_action <> 'create' AND p_role_key IS NOT NULL)
        OR (p_token_digest IS NOT NULL AND pg_catalog.octet_length(p_token_digest) <> 32)
        OR (p_expires_at IS NOT NULL AND (p_expires_at <= v_now OR p_expires_at > v_now + INTERVAL '30 days')) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Workspace invitation change is invalid';
    END IF;
    SELECT * INTO v_scope FROM mesh_ops.authorize_workspace_people_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'member.invite', v_now
    );
    -- Invitations of one Workspace are serialized by its row lock.
    SELECT workspace.display_name INTO v_workspace_name FROM mesh.workspace AS workspace
    WHERE workspace.id = v_scope.workspace_id FOR UPDATE;

    IF p_action = 'create' THEN
        IF p_role_key IS NOT NULL THEN
            SELECT * INTO v_role FROM mesh.builtin_role AS role WHERE role.role_key = p_role_key;
            IF v_role.role_key IS NULL THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Workspace role is unknown';
            END IF;
            IF NOT (v_role.assignable_by && mesh_ops.workspace_role_assigners_v1(
                    v_scope.workspace_id, v_scope.actor_id, v_now)) THEN
                RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'role exceeds the delegation ceiling';
            END IF;
        END IF;
        -- An expired pending invitation for the address no longer blocks.
        PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
        UPDATE mesh.workspace_invitation AS invitation
        SET state = 'revoked', revoked_at = v_now, version = invitation.version + 1, updated_at = v_now
        WHERE invitation.workspace_id = v_scope.workspace_id AND invitation.email = p_email
          AND invitation.state = 'pending' AND invitation.expires_at <= v_now;
        IF EXISTS (
            SELECT 1 FROM mesh.workspace_invitation AS invitation
            WHERE invitation.workspace_id = v_scope.workspace_id AND invitation.email = p_email
              AND invitation.state = 'pending'
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTV01', MESSAGE = 'this address already has a pending invitation';
        END IF;
        IF (SELECT pg_catalog.count(*) FROM mesh.workspace_invitation AS invitation
            WHERE invitation.workspace_id = v_scope.workspace_id AND invitation.state = 'pending'
              AND invitation.expires_at > v_now) >= 200 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTV02', MESSAGE = 'the Workspace has 200 pending invitations';
        END IF;
        INSERT INTO mesh.workspace_invitation (
            public_id, deployment_id, workspace_id, email, role_key, token_digest, expires_at,
            invited_by_principal_id, created_at, updated_at
        ) VALUES (
            p_invitation_public_id, v_scope.deployment_id, v_scope.workspace_id, p_email, p_role_key,
            p_token_digest, p_expires_at, v_scope.actor_id, v_now, v_now
        ) RETURNING * INTO v_invitation;
        v_before := NULL;
    ELSE
        SELECT * INTO v_invitation FROM mesh.workspace_invitation AS invitation
        WHERE invitation.workspace_id = v_scope.workspace_id AND invitation.public_id = p_invitation_public_id
        FOR UPDATE;
        IF v_invitation.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Workspace invitation is unavailable';
        END IF;
        IF v_invitation.version <> p_expected_version THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Workspace invitation changed';
        END IF;
        IF v_invitation.state <> 'pending'
            OR (p_action IN ('delivered', 'delivery_failed', 'not_configured')
                AND v_invitation.delivery_state <> 'pending') THEN
            RAISE EXCEPTION USING ERRCODE = 'MTV03', MESSAGE = 'Workspace invitation is not pending';
        END IF;
        IF p_action = 'resend' AND v_invitation.last_sent_at IS NOT NULL
            AND v_invitation.last_sent_at > v_now - INTERVAL '1 minute' THEN
            RAISE EXCEPTION USING ERRCODE = 'MTV04', MESSAGE = 'wait a minute before resending';
        END IF;
        v_before := mesh_ops.workspace_invitation_document_internal_v1(v_invitation, v_now);
        PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
        UPDATE mesh.workspace_invitation AS invitation SET
            token_digest = CASE WHEN p_action = 'resend' THEN p_token_digest ELSE invitation.token_digest END,
            expires_at = CASE WHEN p_action = 'resend' THEN p_expires_at ELSE invitation.expires_at END,
            state = CASE WHEN p_action = 'revoke' THEN 'revoked' ELSE invitation.state END,
            revoked_at = CASE WHEN p_action = 'revoke' THEN v_now ELSE invitation.revoked_at END,
            delivery_state = CASE p_action
                WHEN 'resend' THEN 'pending'
                WHEN 'delivered' THEN 'sent'
                WHEN 'delivery_failed' THEN 'failed'
                WHEN 'not_configured' THEN 'not_configured'
                ELSE invitation.delivery_state END,
            last_sent_at = CASE WHEN p_action = 'delivered' THEN v_now ELSE invitation.last_sent_at END,
            send_count = invitation.send_count + CASE WHEN p_action = 'delivered' THEN 1 ELSE 0 END,
            version = invitation.version + 1, updated_at = v_now
        WHERE invitation.id = v_invitation.id
        RETURNING * INTO v_invitation;
    END IF;

    RETURN pg_catalog.jsonb_build_object(
        'before', v_before,
        'invitation', mesh_ops.workspace_invitation_document_internal_v1(v_invitation, v_now),
        'workspace_name', v_workspace_name,
        'authority', v_scope.authority
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.change_workspace_invitation_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT, TEXT, TEXT, BYTEA,
    TIMESTAMPTZ, BIGINT, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_workspace_invitation_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT, TEXT, TEXT, BYTEA,
    TIMESTAMPTZ, BIGINT, UUID, TIMESTAMPTZ
) TO mesh_runtime;

-- Pending invitations and those settled in the last 30 days, newest first.
CREATE FUNCTION mesh_ops.list_workspace_invitations_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
SET join_collapse_limit = 1
SET from_collapse_limit = 1
SET plan_cache_mode = force_generic_plan
AS $function$
DECLARE
    v_scope RECORD;
    v_now TIMESTAMPTZ := GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at);
BEGIN
    SELECT * INTO v_scope FROM mesh_ops.authorize_workspace_people_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'member.invite', v_now
    );
    RETURN pg_catalog.jsonb_build_object(
        'invitations', COALESCE((
            SELECT pg_catalog.jsonb_agg(
                mesh_ops.workspace_invitation_document_internal_v1(listed, v_now)
                ORDER BY listed.created_at DESC, listed.public_id DESC)
            FROM (
                SELECT invitation.* FROM mesh.workspace_invitation AS invitation
                WHERE invitation.workspace_id = v_scope.workspace_id
                  AND (invitation.state = 'pending' OR invitation.updated_at > v_now - INTERVAL '30 days')
                ORDER BY invitation.created_at DESC, invitation.public_id DESC
                LIMIT 500
            ) AS listed
        ), '[]'::JSONB)
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_workspace_invitations_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_workspace_invitations_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TIMESTAMPTZ
) TO mesh_runtime;
