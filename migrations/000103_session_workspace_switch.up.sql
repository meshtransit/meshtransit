-- ADR-050 step 7: an Account Session moves between the Workspaces its Account
-- may enter, without signing in again.
--
-- The account_session trigger allows login_workspace_id to change only inside
-- switch_account_session_workspace_v1, which names the exact Session in
-- mesh.account_session_workspace_switch and increments its version. Every
-- other column binding stays immutable.

CREATE OR REPLACE FUNCTION mesh_ops.enforce_human_auth_state_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'human authentication history cannot be deleted';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF (TG_TABLE_NAME = 'auth_transaction' AND NEW.state <> 'pending')
            OR (TG_TABLE_NAME = 'account_session' AND NEW.state <> 'active')
            OR (TG_TABLE_NAME = 'identity_link_request' AND NEW.state <> 'pending')
            OR (TG_TABLE_NAME = 'oidc_logout_replay' AND NEW.state <> 'processing') THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'invalid initial human authentication state';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.version <> OLD.version + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'invalid human authentication row version transition';
    END IF;

    IF TG_TABLE_NAME = 'auth_transaction' THEN
        IF (pg_catalog.to_jsonb(NEW) - ARRAY[
                'state',
                'consumed_at',
                'consumed_result_kind',
                'consumed_result_public_id',
                'failure_class',
                'pkce_verifier_encryption_algorithm',
                'pkce_verifier_encryption_key_id',
                'pkce_verifier_ciphertext',
                'version',
                'updated_at'
            ]::TEXT[]) IS DISTINCT FROM
            (pg_catalog.to_jsonb(OLD) - ARRAY[
                'state',
                'consumed_at',
                'consumed_result_kind',
                'consumed_result_public_id',
                'failure_class',
                'pkce_verifier_encryption_algorithm',
                'pkce_verifier_encryption_key_id',
                'pkce_verifier_ciphertext',
                'version',
                'updated_at'
            ]::TEXT[]) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'authentication transaction binding is immutable';
        END IF;
        IF NOT (
            (OLD.state = 'pending' AND NEW.state IN ('consuming', 'failed', 'expired'))
            OR (
                OLD.state = 'consuming'
                AND NEW.state IN ('succeeded', 'failed', 'expired')
            )
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'invalid authentication transaction state transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'account_session' THEN
        -- ADR-050 D4: an active Session may move to another Workspace only
        -- through switch_account_session_workspace_v1, which names this exact
        -- Session in mesh.account_session_workspace_switch and bumps version.
        IF NEW.login_workspace_id IS DISTINCT FROM OLD.login_workspace_id AND NOT (
            pg_catalog.current_setting('mesh.account_session_workspace_switch', TRUE) = NEW.public_id::TEXT
            AND OLD.state = 'active' AND NEW.state = 'active'
            AND NEW.version = OLD.version + 1
            AND NEW.login_workspace_id IS NOT NULL
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'account session binding is immutable';
        END IF;
        IF (pg_catalog.to_jsonb(NEW) - ARRAY[
                'state',
                'last_used_at',
                'idle_expires_at',
                'ended_at',
                'end_reason',
                'version',
                'updated_at',
                'login_workspace_id'
            ]::TEXT[]) IS DISTINCT FROM
            (pg_catalog.to_jsonb(OLD) - ARRAY[
                'state',
                'last_used_at',
                'idle_expires_at',
                'ended_at',
                'end_reason',
                'version',
                'updated_at',
                'login_workspace_id'
            ]::TEXT[])
            OR NEW.last_used_at < OLD.last_used_at
            OR NEW.idle_expires_at < OLD.idle_expires_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'account session binding is immutable';
        END IF;
        IF OLD.state <> 'active'
            OR NEW.state NOT IN ('active', 'revoked', 'expired') THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'invalid account session state transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'identity_link_request' THEN
        IF (pg_catalog.to_jsonb(NEW) - ARRAY[
                'state',
                'resolved_at',
                'result_identity_subject_id',
                'version',
                'updated_at'
            ]::TEXT[]) IS DISTINCT FROM
            (pg_catalog.to_jsonb(OLD) - ARRAY[
                'state',
                'resolved_at',
                'result_identity_subject_id',
                'version',
                'updated_at'
            ]::TEXT[])
            OR OLD.state <> 'pending'
            OR NEW.state NOT IN ('linked', 'rejected', 'expired') THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'invalid identity link request transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'oidc_logout_replay' THEN
        IF (pg_catalog.to_jsonb(NEW) - ARRAY[
                'state',
                'processed_at',
                'processing_result',
                'version',
                'updated_at'
            ]::TEXT[]) IS DISTINCT FROM
            (pg_catalog.to_jsonb(OLD) - ARRAY[
                'state',
                'processed_at',
                'processing_result',
                'version',
                'updated_at'
            ]::TEXT[])
            OR OLD.state <> 'processing'
            OR NEW.state NOT IN ('completed', 'failed') THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'invalid OIDC logout replay transition';
        END IF;
    ELSE
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'invalid human authentication trigger configuration';
    END IF;

    RETURN NEW;
END;
$function$;

-- Workspaces the signed-in Account may switch to: active memberships in active
-- Workspaces that route the Session's provider and client. Bounded to 100,
-- ordered by name. Reuses workspace_login_candidate_read (migration 101).
CREATE FUNCTION mesh_ops.list_session_workspaces_v1(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    actor RECORD;
    evaluated TIMESTAMPTZ := pg_catalog.clock_timestamp();
    result JSONB;
BEGIN
    SELECT * INTO actor FROM mesh_ops.resolve_account_session_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, evaluated);
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', actor.principal_id::TEXT, TRUE);
    BEGIN
        SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'workspace_id', candidate.public_id,
            'display_name', candidate.display_name,
            'display_code', candidate.display_code,
            'owner', candidate.owner,
            'current', candidate.current
        ) ORDER BY candidate.name_key, candidate.public_id), '[]'::JSONB)
        INTO result
        FROM (
            SELECT workspace.public_id, workspace.display_name, workspace.name_key,
                identity.display_code,
                workspace.owner_principal_id = actor.principal_id AS owner,
                workspace.id = actor.login_workspace_id AS current
            FROM mesh.workspace_membership AS membership
            JOIN mesh.workspace AS workspace
              ON workspace.deployment_id = membership.deployment_id AND workspace.id = membership.workspace_id
            JOIN mesh.workspace_identity_provider AS routing
              ON routing.deployment_id = workspace.deployment_id AND routing.workspace_id = workspace.id
             AND routing.identity_provider_id = actor.identity_provider_id
             AND routing.identity_provider_client_id = actor.identity_provider_client_id
            JOIN mesh_ops.tenant_display_identity AS identity ON identity.workspace_public_id = workspace.public_id
            WHERE membership.principal_id = actor.principal_id
              AND membership.state = 'active' AND membership.valid_from <= evaluated
              AND (membership.expires_at IS NULL OR membership.expires_at > evaluated)
              AND workspace.state = 'active' AND workspace.deleted_at IS NULL
              AND routing.state = 'active' AND routing.deleted_at IS NULL
              AND routing.organization_digest_algorithm IS NULL
              AND routing.organization_digest_key_id IS NULL AND routing.organization_digest IS NULL
            ORDER BY workspace.name_key, workspace.public_id
            LIMIT 100
        ) AS candidate;
    EXCEPTION WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', '', TRUE);
        RAISE;
    END;
    PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', '', TRUE);
    RETURN result;
END;
$function$;

-- Rebinds the Session to another Workspace the Account may enter (same rules
-- as login). The Session version increments, so every request still bound to
-- the previous version fails its exact-version check. Switching to the
-- current Workspace is a replay. The caller appends one audit/outbox record
-- unless replayed. Errors: 42501 inactive Session; P0002 Workspace unavailable
-- to this Account; 40001 the Session changed concurrently.
CREATE FUNCTION mesh_ops.switch_account_session_workspace_v1(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID,
    p_change_public_id UUID
)
RETURNS TABLE (session_version BIGINT, workspace_public_id UUID, replayed BOOLEAN)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
#variable_conflict use_column
DECLARE
    actor RECORD;
    evaluated TIMESTAMPTZ := pg_catalog.clock_timestamp();
    target_workspace_id BIGINT;
    new_version BIGINT;
BEGIN
    IF p_workspace_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Workspace switch input';
    END IF;
    SELECT * INTO actor FROM mesh_ops.resolve_account_session_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, evaluated);
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Account Session is not active';
    END IF;

    -- Candidate Workspaces are read exactly as login reads them (migration 101).
    PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', actor.principal_id::TEXT, TRUE);
    BEGIN
        SELECT workspace.id INTO target_workspace_id
        FROM mesh.workspace AS workspace
        JOIN mesh.workspace_membership AS membership
          ON membership.deployment_id = workspace.deployment_id AND membership.workspace_id = workspace.id
         AND membership.principal_id = actor.principal_id
        JOIN mesh.workspace_identity_provider AS routing
          ON routing.deployment_id = workspace.deployment_id AND routing.workspace_id = workspace.id
         AND routing.identity_provider_id = actor.identity_provider_id
         AND routing.identity_provider_client_id = actor.identity_provider_client_id
        WHERE workspace.public_id = p_workspace_public_id
          AND workspace.deployment_id = actor.deployment_id
          AND workspace.state = 'active' AND workspace.deleted_at IS NULL
          AND membership.state = 'active' AND membership.valid_from <= evaluated
          AND (membership.expires_at IS NULL OR membership.expires_at > evaluated)
          AND routing.state = 'active' AND routing.deleted_at IS NULL
          AND routing.organization_digest_algorithm IS NULL
          AND routing.organization_digest_key_id IS NULL AND routing.organization_digest IS NULL;
        -- No row lock: the candidate policy is SELECT-only, and every later
        -- request rechecks membership and routing when it resolves authority.
    EXCEPTION WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', '', TRUE);
        RAISE;
    END;
    PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', '', TRUE);
    IF target_workspace_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Workspace is unavailable to this Account';
    END IF;
    IF target_workspace_id = actor.login_workspace_id THEN
        RETURN QUERY SELECT p_session_version, p_workspace_public_id, TRUE;
        RETURN;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.account_session_workspace_switch', p_session_public_id::TEXT, TRUE);
    BEGIN
        UPDATE mesh.account_session AS session
        SET login_workspace_id = target_workspace_id,
            version = session.version + 1,
            updated_at = GREATEST(session.updated_at, evaluated)
        WHERE session.public_id = p_session_public_id
          AND session.deployment_id = actor.deployment_id
          AND session.version = p_session_version
          AND session.state = 'active'
        RETURNING session.version INTO new_version;
    EXCEPTION WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.account_session_workspace_switch', '', TRUE);
        RAISE;
    END;
    PERFORM pg_catalog.set_config('mesh.account_session_workspace_switch', '', TRUE);
    IF new_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Account Session changed';
    END IF;
    RETURN QUERY SELECT new_version, p_workspace_public_id, FALSE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.list_session_workspaces_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_session_workspaces_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.switch_account_session_workspace_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.switch_account_session_workspace_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) TO mesh_runtime;
