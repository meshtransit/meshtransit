-- Schema 162: an Account's Console sessions can be ended everywhere.
--
-- Every session resolver requires account.session_generation to equal the
-- generation the session was issued under, but nothing ever advanced it, so
-- a stolen session cookie could only be ended one at a time. Three writers:
--
-- logout_all_account_sessions_v1: the person, from one of their own active
-- sessions, advances the generation and ends every active session of the
-- Account ('logout_all'), including the one they used. Runtime role.
-- Lock order, as in the session resolvers: sessions by id, then the Account.
--
-- revoke_workspace_member_sessions_v1: an administrator with member.manage
-- ends the sessions a member signed in to this Workspace ('administrative'),
-- under the same guards as suspending the member (schema 127): never the
-- owner or themselves, never a member holding a role above the delegation
-- ceiling. The Account spans other Workspaces, so the generation is left
-- alone and sessions signed in elsewhere stay; suspending the member is what
-- cuts them off here. When no session matches, nothing changes and the caller
-- records nothing. Runtime role.
--
-- change_account_recovery_v1: the operator, as the migration role, ends
-- every session of an Account ('administrative') or quarantines it (ending
-- every session, 'account_suspended'), and releases a quarantined Account.
-- Login and every session resolver already refuse a quarantined Account.
-- Not granted to any runtime role.
--
-- Callers append one audit/outbox record per change.

CREATE FUNCTION mesh_ops.logout_all_account_sessions_v1(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT,
    p_change_public_id UUID
)
RETURNS TABLE (
    account_public_id UUID,
    account_version BIGINT,
    session_generation BIGINT,
    sessions_ended INTEGER,
    ended_at TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
SET join_collapse_limit = 1
SET from_collapse_limit = 1
SET plan_cache_mode = force_generic_plan
AS $function$
#variable_conflict use_column
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_actor RECORD;
    v_account mesh.account%ROWTYPE;
    v_version BIGINT;
    v_deployment BIGINT;
    v_principal BIGINT;
    v_count INTEGER;
BEGIN
    IF p_change_public_id IS NULL OR p_session_version IS NULL OR p_session_version <= 0
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid sign-out input';
    END IF;
    -- Session resolvers lock a session, then its Account. Every writer here
    -- does the same: the Account's active sessions in id order, then the
    -- Account, so concurrent sign-outs, operator changes and requests queue
    -- instead of deadlocking. The Account row also serializes them with
    -- logins; the UPDATE below catches a session a login added meanwhile. A
    -- generation that moved means another sign-out already ended this session.
    SELECT session.deployment_id, session.principal_id INTO v_deployment, v_principal
    FROM mesh.account_session AS session WHERE session.public_id = p_session_public_id;
    PERFORM 1 FROM mesh.account_session AS session
    WHERE session.deployment_id = v_deployment AND session.principal_id = v_principal
      AND session.state = 'active'
    ORDER BY session.id
    FOR UPDATE;
    SELECT * INTO v_account FROM mesh.account AS account
    WHERE account.deployment_id = v_deployment AND account.principal_id = v_principal
    FOR UPDATE;
    IF v_account.id IS NULL OR v_account.session_generation <> p_account_session_generation
        OR v_account.recovery_state <> 'verified' THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Account Session is not active';
    END IF;
    -- The Console renews a session while it is used, which advances its
    -- version. The version the caller authenticated with may be older; every
    -- other binding below is still exact.
    SELECT session.version INTO v_version FROM mesh.account_session AS session
    WHERE session.public_id = p_session_public_id AND session.state = 'active'
      AND session.version >= p_session_version;
    SELECT * INTO v_actor FROM mesh_ops.resolve_account_session_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        v_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, v_now);
    IF NOT FOUND OR v_actor.principal_id <> v_principal OR v_actor.deployment_id <> v_deployment THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Account Session is not active';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.account AS account
    SET session_generation = account.session_generation + 1, version = account.version + 1,
        updated_at = GREATEST(v_now, account.updated_at)
    WHERE account.id = v_account.id
    RETURNING * INTO v_account;
    UPDATE mesh.account_session AS session
    SET state = 'revoked', ended_at = v_now, end_reason = 'logout_all',
        version = session.version + 1, updated_at = GREATEST(v_now, session.updated_at)
    WHERE session.deployment_id = v_deployment AND session.principal_id = v_principal
      AND session.state = 'active';
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN QUERY SELECT v_account.public_id, v_account.version, v_account.session_generation, v_count, v_now;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.logout_all_account_sessions_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.logout_all_account_sessions_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID
) TO mesh_runtime;

-- Errors: 22023 invalid input, 42501 not authorized or a role above the
-- delegation ceiling, P0002 unknown member, MTM01 the member is not active,
-- MTM02 the member is the owner or the actor.
CREATE FUNCTION mesh_ops.revoke_workspace_member_sessions_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_member_public_id UUID,
    p_change_public_id UUID, p_evaluated_at TIMESTAMPTZ
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
    v_workspace BIGINT;
    v_owner BIGINT;
    v_grant RECORD;
    v_actor BIGINT;
    v_member BIGINT;
    v_membership mesh.workspace_membership%ROWTYPE;
    v_sessions INTEGER := 0;
    v_now TIMESTAMPTZ := GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at);
BEGIN
    IF p_member_public_id IS NULL OR p_change_public_id IS NULL OR p_evaluated_at IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Workspace member change is invalid';
    END IF;
    v_workspace := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF v_workspace IS NULL OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, v_workspace) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Workspace member change is not authorized';
    END IF;
    -- Member changes in one Workspace are serialized by its row lock.
    SELECT workspace.owner_principal_id INTO v_owner FROM mesh.workspace AS workspace
    WHERE workspace.id = v_workspace AND workspace.state = 'active' AND workspace.deleted_at IS NULL
    FOR UPDATE;
    IF v_owner IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Workspace member change is not authorized';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'member.manage', v_now
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Workspace member change is not authorized';
    END IF;
    SELECT principal.id INTO STRICT v_actor FROM mesh.principal AS principal
    WHERE principal.public_id = p_principal_public_id;

    SELECT principal.id INTO v_member FROM mesh.principal AS principal
    WHERE principal.public_id = p_member_public_id AND principal.kind = 'account' AND principal.deleted_at IS NULL;
    SELECT * INTO v_membership FROM mesh.workspace_membership AS membership
    WHERE membership.workspace_id = v_workspace AND membership.principal_id = v_member
      AND membership.state <> 'revoked'
    FOR UPDATE;
    IF v_membership.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Workspace member is unavailable';
    END IF;
    IF v_member = v_owner OR v_member = v_actor THEN
        RAISE EXCEPTION USING ERRCODE = 'MTM02', MESSAGE = 'nobody ends the sessions of the owner or themselves';
    END IF;
    IF EXISTS (
        SELECT 1 FROM mesh.workspace_role_assignment AS assignment
        JOIN mesh.builtin_role AS role ON role.role_key = assignment.role_key
        WHERE assignment.workspace_id = v_workspace AND assignment.workspace_membership_id = v_membership.id
          AND assignment.state = 'active'
          AND NOT (role.assignable_by && mesh_ops.workspace_role_assigners_v1(v_workspace, v_actor, v_now))
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'the member holds a role beyond the delegation ceiling';
    END IF;
    -- A suspended member has no session here: suspending ended them.
    IF v_membership.state <> 'active' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTM01', MESSAGE = 'Workspace member is not in that state';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    PERFORM 1 FROM mesh.account_session AS session
    WHERE session.deployment_id = v_membership.deployment_id AND session.principal_id = v_member
      AND session.login_workspace_id = v_workspace AND session.state = 'active'
    ORDER BY session.id
    FOR UPDATE;
    UPDATE mesh.account_session AS session
    SET state = 'revoked', ended_at = v_now, end_reason = 'administrative',
        version = session.version + 1, updated_at = GREATEST(v_now, session.updated_at)
    WHERE session.deployment_id = v_membership.deployment_id AND session.principal_id = v_member
      AND session.login_workspace_id = v_workspace
      AND session.state = 'active';
    GET DIAGNOSTICS v_sessions = ROW_COUNT;

    RETURN pg_catalog.jsonb_build_object(
        'member', mesh_ops.workspace_member_document_internal_v1(v_membership),
        'sessions_ended', v_sessions,
        'authority', pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
            'binding_id', v_grant.role_binding_public_id,
            'role_id', v_grant.role_definition_public_id,
            'binding_generation', COALESCE(v_grant.binding_authority_generation, 0),
            'membership_generation', COALESCE(v_grant.membership_authority_generation, 0),
            'owner_generation', COALESCE(v_grant.workspace_owner_authority_generation, 0)
        ))
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.revoke_workspace_member_sessions_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.revoke_workspace_member_sessions_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ
) TO mesh_runtime;

-- Runs with the caller's rights: only the migration role can change these
-- rows. Actions: 'revoke_sessions' and 'quarantine' advance the session
-- generation and end every active session; 'quarantine' also sets
-- recovery_state, and 'release' clears it. Errors: 22023 invalid input,
-- P0002 unknown Account, MTA01 release of an Account that is not quarantined.
CREATE FUNCTION mesh_ops.change_account_recovery_v1(
    p_principal_public_id UUID,
    p_action TEXT,
    p_change_public_id UUID
)
RETURNS TABLE (
    deployment_public_id UUID,
    account_public_id UUID,
    account_version BIGINT,
    session_generation BIGINT,
    recovery_state TEXT,
    sessions_ended INTEGER,
    changed_at TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY INVOKER
SET search_path = pg_catalog
SET join_collapse_limit = 1
SET from_collapse_limit = 1
SET plan_cache_mode = force_generic_plan
AS $function$
#variable_conflict use_column
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_account mesh.account%ROWTYPE;
    v_deployment UUID;
    v_count INTEGER := 0;
BEGIN
    IF p_principal_public_id IS NULL OR p_change_public_id IS NULL
        OR p_action IS NULL OR p_action NOT IN ('revoke_sessions', 'quarantine', 'release')
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Account recovery input';
    END IF;
    SELECT account.* INTO v_account FROM mesh.account AS account
    JOIN mesh.principal AS principal
      ON principal.deployment_id = account.deployment_id AND principal.id = account.principal_id
    WHERE principal.public_id = p_principal_public_id AND principal.kind = 'account'
      AND principal.deleted_at IS NULL;
    -- Sessions in id order, then the Account, as the session resolvers lock.
    PERFORM 1 FROM mesh.account_session AS session
    WHERE session.deployment_id = v_account.deployment_id AND session.principal_id = v_account.principal_id
      AND session.state = 'active'
    ORDER BY session.id
    FOR UPDATE;
    SELECT account.* INTO v_account FROM mesh.account AS account
    WHERE account.id = v_account.id
    FOR UPDATE;
    IF v_account.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Account is unavailable';
    END IF;
    IF p_action = 'release' AND v_account.recovery_state <> 'quarantined' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTA01', MESSAGE = 'Account is not quarantined';
    END IF;
    SELECT deployment.installation_public_id INTO STRICT v_deployment
    FROM mesh.deployment AS deployment WHERE deployment.id = v_account.deployment_id;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.account AS account
    SET session_generation = account.session_generation
            + CASE WHEN p_action = 'release' THEN 0 ELSE 1 END,
        recovery_state = CASE p_action
            WHEN 'quarantine' THEN 'quarantined'
            WHEN 'release' THEN 'verified'
            ELSE account.recovery_state END,
        version = account.version + 1, updated_at = GREATEST(v_now, account.updated_at)
    WHERE account.id = v_account.id
    RETURNING * INTO v_account;
    IF p_action <> 'release' THEN
        UPDATE mesh.account_session AS session
        SET state = 'revoked', ended_at = v_now,
            end_reason = CASE WHEN p_action = 'quarantine' THEN 'account_suspended' ELSE 'administrative' END,
            version = session.version + 1, updated_at = GREATEST(v_now, session.updated_at)
        WHERE session.deployment_id = v_account.deployment_id AND session.principal_id = v_account.principal_id
          AND session.state = 'active';
        GET DIAGNOSTICS v_count = ROW_COUNT;
    END IF;
    RETURN QUERY SELECT v_deployment, v_account.public_id, v_account.version, v_account.session_generation,
        v_account.recovery_state, v_count, v_now;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.change_account_recovery_v1(UUID, TEXT, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- These are checked by every session resolver, and no operation advances
-- them yet. They are kept for the recovery operations that will.
COMMENT ON COLUMN mesh.principal.authority_generation IS
    'Reserved: checked by session resolvers; no operation advances it yet.';
COMMENT ON COLUMN mesh.deployment.recovery_epoch IS
    'Reserved: checked by session resolvers; no operation advances it yet.';
COMMENT ON COLUMN mesh.deployment.recovery_state IS
    'Reserved: checked by session resolvers; no operation sets quarantined yet.';
COMMENT ON COLUMN mesh.identity_provider.current_generation IS
    'Reserved: checked by session resolvers; no operation advances it yet.';
COMMENT ON COLUMN mesh.identity_provider.recovery_state IS
    'Reserved: checked by session resolvers; no operation sets quarantined yet.';
COMMENT ON COLUMN mesh.account.session_generation IS
    'Advanced by logout_all_account_sessions_v1 and change_account_recovery_v1; ends every session issued before.';
COMMENT ON COLUMN mesh.account.recovery_state IS
    'Set by change_account_recovery_v1; login and session resolvers refuse a quarantined Account.';
