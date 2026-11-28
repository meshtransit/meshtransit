-- Schema 322 (V1-80 A2, part 2): API key tables and management operations.
--
-- Adds mesh.api_key (immutable metadata bound 1:1 to a mesh.account_session
-- row in kind/state 'api_key'), mesh.api_key_usage (throttled last-used
-- timestamp outside authority mutation tracking), and six mesh_api_rights
-- entry points: create, revoke, list, read, resolve, and touch usage.
--
-- Also updates logout_all_account_sessions_v1 and change_account_recovery_v1
-- to clamp ended_at with GREATEST(v_now, session.issued_at), matching the
-- Workspace member Session-ending functions so concurrent key creation cannot
-- violate account_session_timestamps_check.
--
-- Errors:
--   22023 invalid input
--   42501 not authorized / delegation ceiling / API key may only revoke itself
--   55000 API key metadata cannot be modified
--   P0002 unknown Workspace member or API key
--   MTM02 manager attempted to manage the owner's or their own API keys
--   MTA20 recent authentication required before creating a key
--   MTA21 per-principal (20) or per-Workspace (500) live key limit reached
--   MTA22 API key is already ended or expired

CREATE TABLE mesh.api_key (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL REFERENCES mesh.deployment (id) ON DELETE RESTRICT,
    workspace_id BIGINT NOT NULL,
    owner_kind TEXT NOT NULL DEFAULT 'principal'
        CONSTRAINT api_key_owner_kind_check CHECK (owner_kind = 'principal'),
    principal_id BIGINT NOT NULL,
    account_session_id BIGINT NOT NULL UNIQUE,
    created_by_session_id BIGINT NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CONSTRAINT api_key_version_check CHECK (version = 1),
    CONSTRAINT api_key_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT api_key_sessions_distinct_check CHECK (
        created_by_session_id <> account_session_id
    ),
    CONSTRAINT api_key_name_check CHECK (
        pg_catalog.char_length(name) BETWEEN 1 AND 64
        AND name = pg_catalog.btrim(name)
        AND name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT api_key_lifetime_check CHECK (
        pg_catalog.isfinite(created_at)
        AND pg_catalog.isfinite(expires_at)
        AND expires_at > created_at
        AND expires_at <= created_at + INTERVAL '365 days'
    ),
    CONSTRAINT api_key_workspace_scope_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT api_key_account_scope_fk FOREIGN KEY (deployment_id, principal_id)
        REFERENCES mesh.account (deployment_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT api_key_session_scope_fk FOREIGN KEY (deployment_id, principal_id, account_session_id)
        REFERENCES mesh.account_session (deployment_id, principal_id, id) ON DELETE RESTRICT,
    CONSTRAINT api_key_creator_session_scope_fk FOREIGN KEY (deployment_id, principal_id, created_by_session_id)
        REFERENCES mesh.account_session (deployment_id, principal_id, id) ON DELETE RESTRICT
);

CREATE INDEX api_key_workspace_principal_page_idx
    ON mesh.api_key (workspace_id, principal_id, created_at DESC, public_id DESC);

CREATE INDEX account_session_workspace_live_api_key_idx
    ON mesh.account_session (login_workspace_id, principal_id, absolute_expires_at)
    WHERE state = 'api_key';

CREATE TABLE mesh.api_key_usage (
    api_key_id BIGINT PRIMARY KEY REFERENCES mesh.api_key (id) ON DELETE RESTRICT,
    last_used_at TIMESTAMPTZ NOT NULL
        CONSTRAINT api_key_usage_last_used_at_check CHECK (pg_catalog.isfinite(last_used_at))
);

ALTER TABLE mesh.api_key ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.api_key FORCE ROW LEVEL SECURITY;
CREATE POLICY api_key_migrator_policy ON mesh.api_key
    FOR ALL TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);

ALTER TABLE mesh.api_key_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.api_key_usage FORCE ROW LEVEL SECURITY;
CREATE POLICY api_key_usage_migrator_policy ON mesh.api_key_usage
    FOR ALL TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);

REVOKE ALL ON TABLE mesh.api_key, mesh.api_key_usage
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer,
         mesh_share_writer, mesh_api_rights, mesh_control_rights;
REVOKE ALL ON SEQUENCE mesh.api_key_id_seq
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer,
         mesh_share_writer, mesh_api_rights, mesh_control_rights;

CREATE FUNCTION mesh_ops.guard_api_key_insert_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
SET join_collapse_limit = 1
SET from_collapse_limit = 1
SET plan_cache_mode = force_generic_plan
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM mesh.account_session AS session
        WHERE session.id = NEW.account_session_id
          AND session.deployment_id = NEW.deployment_id
          AND session.principal_id = NEW.principal_id
          AND session.kind = 'api_key'
          AND session.state = 'api_key'
          AND session.login_workspace_id = NEW.workspace_id
          AND session.issued_at = NEW.created_at
          AND session.absolute_expires_at = NEW.expires_at
    ) OR NOT EXISTS (
        SELECT 1 FROM mesh.account_session AS creator
        WHERE creator.id = NEW.created_by_session_id
          AND creator.deployment_id = NEW.deployment_id
          AND creator.principal_id = NEW.principal_id
          AND creator.kind = 'interactive'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'API key session binding is invalid';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.guard_api_key_insert_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer,
         mesh_share_writer, mesh_api_rights, mesh_control_rights;

CREATE TRIGGER api_key_insert_guard
BEFORE INSERT ON mesh.api_key
FOR EACH ROW EXECUTE FUNCTION mesh_ops.guard_api_key_insert_v1();

CREATE FUNCTION mesh_ops.reject_api_key_mutation_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'API key metadata cannot be modified';
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.reject_api_key_mutation_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer,
         mesh_share_writer, mesh_api_rights, mesh_control_rights;

CREATE TRIGGER api_key_immutable
BEFORE UPDATE OR DELETE ON mesh.api_key
FOR EACH ROW EXECUTE FUNCTION mesh_ops.reject_api_key_mutation_v1();

CREATE TRIGGER api_key_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.api_key
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('api_key', 'public_id');

CREATE FUNCTION mesh_ops.is_uuid_v7_internal_v1(p_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_id IS NOT NULL AND pg_catalog.get_byte(pg_catalog.uuid_send(p_id), 6) >> 4 = 7;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.is_uuid_v7_internal_v1(UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer,
         mesh_share_writer, mesh_api_rights, mesh_control_rights;

CREATE FUNCTION mesh_ops.api_key_document_internal_v1(
    p_key mesh.api_key,
    p_session mesh.account_session,
    p_workspace_public_id UUID,
    p_principal_public_id UUID,
    p_last_used_at TIMESTAMPTZ,
    p_now TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'id', p_key.public_id,
        'session_id', p_session.public_id,
        'workspace_id', p_workspace_public_id,
        'principal_id', p_principal_public_id,
        'name', p_key.name,
        'created_at', p_key.created_at,
        'last_used_at', p_last_used_at,
        'expires_at', p_key.expires_at,
        'ended_at', p_session.ended_at,
        'end_reason', p_session.end_reason,
        'state', CASE
            WHEN p_session.state = 'revoked' THEN 'revoked'
            WHEN p_session.state = 'expired'
                OR (p_session.state = 'api_key' AND p_session.absolute_expires_at <= p_now) THEN 'expired'
            WHEN p_session.state = 'api_key' AND p_session.absolute_expires_at > p_now THEN 'active'
            ELSE 'revoked'
        END
    );
$function$;
REVOKE ALL ON FUNCTION mesh_ops.api_key_document_internal_v1(
    mesh.api_key, mesh.account_session, UUID, UUID, TIMESTAMPTZ, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer,
       mesh_share_writer, mesh_api_rights, mesh_control_rights;

CREATE FUNCTION mesh_ops.create_api_key_v1(
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
    p_key_public_id UUID,
    p_key_session_public_id UUID,
    p_name TEXT,
    p_expires_at TIMESTAMPTZ,
    p_digest_algorithm TEXT,
    p_digest_key_id TEXT,
    p_digest BYTEA,
    p_change_public_id UUID
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
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_workspace BIGINT;
    v_actor_session mesh.account_session%ROWTYPE;
    v_actor RECORD;
    v_workspace_count BIGINT;
    v_principal_count BIGINT;
    v_key_session mesh.account_session%ROWTYPE;
    v_key mesh.api_key%ROWTYPE;
BEGIN
    IF NOT mesh_ops.is_uuid_v7_internal_v1(p_session_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_deployment_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_principal_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_identity_subject_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_workspace_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_key_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_key_session_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_change_public_id)
        OR p_key_public_id = p_key_session_public_id
        OR p_key_session_public_id = p_session_public_id
        OR p_session_version IS NULL OR p_session_version <= 0
        OR p_principal_authority_generation IS NULL OR p_principal_authority_generation <= 0
        OR p_account_session_generation IS NULL OR p_account_session_generation <= 0
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0
        OR p_name IS NULL OR pg_catalog.char_length(p_name) NOT BETWEEN 1 AND 64
        OR p_name <> pg_catalog.btrim(p_name) OR p_name ~ '[[:cntrl:]]'
        OR p_expires_at IS NULL OR NOT pg_catalog.isfinite(p_expires_at)
        OR p_expires_at < v_now + INTERVAL '7 days'
        OR p_expires_at > v_now + INTERVAL '365 days'
        OR p_digest_algorithm IS DISTINCT FROM 'hmac-sha256-v1'
        OR p_digest_key_id IS NULL OR pg_catalog.char_length(p_digest_key_id) NOT BETWEEN 1 AND 128
        OR p_digest_key_id <> pg_catalog.btrim(p_digest_key_id)
        OR p_digest_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR p_digest IS NULL OR pg_catalog.octet_length(p_digest) <> 32
        OR p_digest = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid API key creation input';
    END IF;

    v_workspace := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF v_workspace IS NULL OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, v_workspace) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key creation is not authorized';
    END IF;

    -- Lock order matches resolve_workspace_permission_v1 and logout_all:
    -- workspace -> creator session -> account -> route -> membership -> advisory lock.
    PERFORM 1 FROM mesh.workspace AS workspace
    WHERE workspace.id = v_workspace AND workspace.state = 'active' AND workspace.deleted_at IS NULL
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key creation is not authorized';
    END IF;

    SELECT session.* INTO v_actor_session
    FROM mesh.account_session AS session
    WHERE session.public_id = p_session_public_id
      AND session.kind = 'interactive'
      AND session.state = 'active'
      AND session.version = p_session_version
      AND session.login_workspace_id = v_workspace
    FOR SHARE;
    IF v_actor_session.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key creation is not authorized';
    END IF;

    PERFORM 1 FROM mesh.account AS account
    WHERE account.deployment_id = v_actor_session.deployment_id
      AND account.principal_id = v_actor_session.principal_id
      AND account.recovery_state = 'verified'
      AND account.session_generation = p_account_session_generation
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key creation is not authorized';
    END IF;

    SELECT * INTO v_actor FROM mesh_ops.resolve_account_session_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch, v_now
    );
    IF NOT FOUND OR v_actor.deployment_id <> v_actor_session.deployment_id
        OR v_actor.principal_id <> v_actor_session.principal_id THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key creation is not authorized';
    END IF;

    PERFORM 1 FROM mesh.workspace_identity_provider AS route
    WHERE route.deployment_id = v_actor_session.deployment_id
      AND route.workspace_id = v_workspace
      AND route.identity_provider_id = v_actor_session.identity_provider_id
      AND route.identity_provider_client_id = v_actor_session.identity_provider_client_id
      AND route.state = 'active'
      AND route.deleted_at IS NULL
      AND route.organization_digest_algorithm IS NULL
      AND route.organization_digest_key_id IS NULL
      AND route.organization_digest IS NULL
      AND (route.minimum_assurance IS NULL OR route.minimum_assurance = v_actor_session.acr)
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key creation is not authorized';
    END IF;

    PERFORM 1 FROM mesh.workspace_membership AS membership
    WHERE membership.deployment_id = v_actor_session.deployment_id
      AND membership.workspace_id = v_workspace
      AND membership.principal_id = v_actor_session.principal_id
      AND membership.state = 'active'
      AND membership.valid_from <= v_now
      AND (membership.expires_at IS NULL OR membership.expires_at > v_now)
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key creation is not authorized';
    END IF;

    -- Interim re-auth guard until step-up authentication replaces it.
    IF v_actor_session.authentication_time < v_now - INTERVAL '15 minutes' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTA20', MESSAGE = 'API key creation requires recent authentication';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('mesh.api_key.quota', v_workspace)
    );

    SELECT
        pg_catalog.count(*),
        pg_catalog.count(*) FILTER (WHERE session.principal_id = v_actor_session.principal_id)
    INTO v_workspace_count, v_principal_count
    FROM mesh.account_session AS session
    WHERE session.login_workspace_id = v_workspace
      AND session.state = 'api_key'
      AND session.absolute_expires_at > v_now;

    IF v_principal_count >= 20 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTA21', MESSAGE = 'principal API key limit reached';
    END IF;
    IF v_workspace_count >= 500 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTA21', MESSAGE = 'Workspace API key limit reached';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    INSERT INTO mesh.account_session (
        public_id, deployment_id, principal_id, identity_provider_id, identity_subject_id,
        identity_provider_client_id, login_workspace_id, token_digest_algorithm,
        token_digest_key_id, token_digest, provider_generation, authentication_time,
        acr, amr, principal_authority_generation, account_session_generation,
        deployment_recovery_epoch, issued_at, last_used_at, idle_expires_at,
        absolute_expires_at, state, kind, created_at, updated_at
    ) VALUES (
        p_key_session_public_id, v_actor_session.deployment_id, v_actor_session.principal_id,
        v_actor_session.identity_provider_id, v_actor_session.identity_subject_id,
        v_actor_session.identity_provider_client_id, v_workspace, p_digest_algorithm,
        p_digest_key_id, p_digest, v_actor_session.provider_generation,
        v_actor_session.authentication_time, v_actor_session.acr, v_actor_session.amr,
        v_actor_session.principal_authority_generation, v_actor_session.account_session_generation,
        v_actor_session.deployment_recovery_epoch, v_now, v_now, p_expires_at,
        p_expires_at, 'api_key', 'api_key', v_now, v_now
    )
    RETURNING * INTO v_key_session;

    INSERT INTO mesh.api_key (
        public_id, deployment_id, workspace_id, owner_kind, principal_id,
        account_session_id, created_by_session_id, name, created_at, expires_at
    ) VALUES (
        p_key_public_id, v_actor_session.deployment_id, v_workspace, 'principal',
        v_actor_session.principal_id, v_key_session.id, v_actor_session.id,
        p_name, v_now, p_expires_at
    )
    RETURNING * INTO v_key;

    RETURN pg_catalog.jsonb_build_object(
        'key', mesh_ops.api_key_document_internal_v1(
            v_key, v_key_session, p_workspace_public_id, p_principal_public_id, NULL, v_now
        )
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.create_api_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, TEXT, TIMESTAMPTZ, TEXT, TEXT, BYTEA, UUID
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer,
       mesh_share_writer, mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.create_api_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, TEXT, TIMESTAMPTZ, TEXT, TEXT, BYTEA, UUID
) TO mesh_api_rights;

CREATE FUNCTION mesh_ops.revoke_api_key_v1(
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
    p_member_public_id UUID,
    p_key_public_id UUID,
    p_change_public_id UUID
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
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_workspace BIGINT;
    v_owner BIGINT;
    v_caller_kind TEXT;
    v_actor RECORD;
    v_actor_acr TEXT;
    v_grant RECORD;
    v_member BIGINT;
    v_membership mesh.workspace_membership%ROWTYPE;
    v_key mesh.api_key%ROWTYPE;
    v_key_session mesh.account_session%ROWTYPE;
    v_last_used TIMESTAMPTZ;
    v_target_principal_public_id UUID;
    v_revoked_by TEXT;
    v_authority JSONB;
BEGIN
    IF NOT mesh_ops.is_uuid_v7_internal_v1(p_session_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_deployment_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_principal_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_identity_subject_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_workspace_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_key_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_change_public_id)
        OR (p_member_public_id IS NOT NULL AND NOT mesh_ops.is_uuid_v7_internal_v1(p_member_public_id))
        OR p_session_version IS NULL OR p_session_version <= 0
        OR p_principal_authority_generation IS NULL OR p_principal_authority_generation <= 0
        OR p_account_session_generation IS NULL OR p_account_session_generation <= 0
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid API key revocation input';
    END IF;

    v_workspace := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF v_workspace IS NULL OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, v_workspace) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key revocation is not authorized';
    END IF;

    IF p_member_public_id IS NOT NULL THEN
        -- Path 3: manager revoking a member's key (always human-only).
        SELECT workspace.owner_principal_id INTO v_owner FROM mesh.workspace AS workspace
        WHERE workspace.id = v_workspace AND workspace.state = 'active' AND workspace.deleted_at IS NULL
        FOR NO KEY UPDATE;
        IF v_owner IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key revocation is not authorized';
        END IF;

        SELECT * INTO v_actor FROM mesh_ops.resolve_account_session_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch, v_now
        );
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key revocation is not authorized';
        END IF;

        SELECT * INTO v_grant FROM mesh_ops.resolve_workspace_permission_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, 'member.manage', v_now
        ) LIMIT 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key revocation is not authorized';
        END IF;

        SELECT principal.id INTO v_member FROM mesh.principal AS principal
        WHERE principal.deployment_id = v_actor.deployment_id
          AND principal.public_id = p_member_public_id
          AND principal.kind = 'account' AND principal.deleted_at IS NULL;
        SELECT membership.* INTO v_membership FROM mesh.workspace_membership AS membership
        WHERE membership.workspace_id = v_workspace AND membership.principal_id = v_member
          AND membership.state <> 'revoked'
        FOR SHARE;
        IF v_membership.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Workspace member is unavailable';
        END IF;
        IF v_member = v_owner OR v_member = v_actor.principal_id THEN
            RAISE EXCEPTION USING ERRCODE = 'MTM02', MESSAGE = 'nobody manages the API keys of the owner or themselves';
        END IF;
        IF EXISTS (
            SELECT 1 FROM mesh.workspace_role_assignment AS assignment
            JOIN mesh.builtin_role AS role ON role.role_key = assignment.role_key
            WHERE assignment.workspace_id = v_workspace AND assignment.workspace_membership_id = v_membership.id
              AND assignment.state = 'active'
              AND NOT (role.assignable_by && mesh_ops.workspace_role_assigners_v1(v_workspace, v_actor.principal_id, v_now))
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'the member holds a role beyond the delegation ceiling';
        END IF;

        SELECT key_row.* INTO v_key FROM mesh.api_key AS key_row
        WHERE key_row.workspace_id = v_workspace
          AND key_row.principal_id = v_member
          AND key_row.public_id = p_key_public_id;
        IF v_key.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'API key is unavailable';
        END IF;
        SELECT session.* INTO STRICT v_key_session FROM mesh.account_session AS session
        WHERE session.id = v_key.account_session_id
        FOR UPDATE;

        v_target_principal_public_id := p_member_public_id;
        v_revoked_by := 'manager';
        v_authority := pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
            'binding_id', v_grant.role_binding_public_id,
            'role_id', v_grant.role_definition_public_id,
            'binding_generation', COALESCE(v_grant.binding_authority_generation, 0),
            'membership_generation', COALESCE(v_grant.membership_authority_generation, 0),
            'owner_generation', COALESCE(v_grant.workspace_owner_authority_generation, 0)
        ));
    ELSE
        SELECT session.kind INTO v_caller_kind FROM mesh.account_session AS session
        WHERE session.public_id = p_session_public_id;
        IF v_caller_kind IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key revocation is not authorized';
        END IF;

        PERFORM 1 FROM mesh.workspace AS workspace
        WHERE workspace.id = v_workspace AND workspace.state = 'active' AND workspace.deleted_at IS NULL
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key revocation is not authorized';
        END IF;

        IF v_caller_kind = 'interactive' THEN
            -- Path 1: key owner revoking from an interactive Session.
            -- Do not lock the actor's Session so we never lock two Sessions out of id order.
            SELECT * INTO v_actor FROM mesh_ops.resolve_account_session_v1(
                p_session_public_id, p_deployment_public_id, p_principal_public_id,
                p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
                p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch, v_now
            );
            IF NOT FOUND THEN
                RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key revocation is not authorized';
            END IF;

            SELECT session.acr INTO v_actor_acr FROM mesh.account_session AS session
            WHERE session.public_id = p_session_public_id;
            IF NOT EXISTS (
                SELECT 1 FROM mesh.workspace_identity_provider AS route
                WHERE route.deployment_id = v_actor.deployment_id
                  AND route.workspace_id = v_workspace
                  AND route.identity_provider_id = v_actor.identity_provider_id
                  AND route.identity_provider_client_id = v_actor.identity_provider_client_id
                  AND route.state = 'active' AND route.deleted_at IS NULL
                  AND route.organization_digest_algorithm IS NULL
                  AND route.organization_digest_key_id IS NULL
                  AND route.organization_digest IS NULL
                  AND (route.minimum_assurance IS NULL OR route.minimum_assurance = v_actor_acr)
            ) OR NOT EXISTS (
                SELECT 1 FROM mesh.workspace_membership AS membership
                WHERE membership.deployment_id = v_actor.deployment_id
                  AND membership.workspace_id = v_workspace
                  AND membership.principal_id = v_actor.principal_id
                  AND membership.state = 'active'
                  AND membership.valid_from <= v_now
                  AND (membership.expires_at IS NULL OR membership.expires_at > v_now)
            ) THEN
                RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key revocation is not authorized';
            END IF;

            SELECT key_row.* INTO v_key FROM mesh.api_key AS key_row
            WHERE key_row.workspace_id = v_workspace
              AND key_row.principal_id = v_actor.principal_id
              AND key_row.public_id = p_key_public_id;
            IF v_key.id IS NULL THEN
                RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'API key is unavailable';
            END IF;
            SELECT session.* INTO STRICT v_key_session FROM mesh.account_session AS session
            WHERE session.id = v_key.account_session_id
            FOR UPDATE;

            v_target_principal_public_id := p_principal_public_id;
            v_revoked_by := 'owner';
        ELSIF v_caller_kind = 'api_key' THEN
            -- Path 2: API key self-revocation. Lock caller's Session FOR UPDATE first
            -- (no SHARE -> UPDATE upgrade, matches session -> account lock order).
            SELECT session.* INTO v_key_session FROM mesh.account_session AS session
            WHERE session.public_id = p_session_public_id
            FOR UPDATE;

            IF v_key_session.id IS NULL
                OR v_key_session.kind <> 'api_key'
                OR v_key_session.state <> 'api_key'
                OR v_key_session.login_workspace_id <> v_workspace
                OR v_key_session.version <> p_session_version
                OR v_key_session.principal_authority_generation <> p_principal_authority_generation
                OR v_key_session.account_session_generation <> p_account_session_generation
                OR v_key_session.provider_generation <> p_provider_generation
                OR v_key_session.deployment_recovery_epoch <> p_deployment_recovery_epoch
                OR v_key_session.authentication_time > v_now
                OR v_key_session.idle_expires_at <= v_now
                OR v_key_session.absolute_expires_at <= v_now THEN
                RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key revocation is not authorized';
            END IF;

            IF NOT EXISTS (
                SELECT 1
                FROM mesh.deployment AS deployment
                JOIN mesh.principal AS principal
                  ON principal.deployment_id = deployment.id AND principal.id = v_key_session.principal_id
                JOIN mesh.account AS account
                  ON account.deployment_id = deployment.id AND account.principal_id = principal.id
                JOIN mesh.identity_subject AS subject
                  ON subject.deployment_id = deployment.id
                 AND subject.identity_provider_id = v_key_session.identity_provider_id
                 AND subject.principal_id = principal.id
                 AND subject.id = v_key_session.identity_subject_id
                JOIN mesh.identity_provider AS provider
                  ON provider.deployment_id = deployment.id AND provider.id = v_key_session.identity_provider_id
                JOIN mesh.identity_provider_client AS client
                  ON client.deployment_id = deployment.id
                 AND client.identity_provider_id = provider.id
                 AND client.id = v_key_session.identity_provider_client_id
                JOIN mesh.workspace_identity_provider AS route
                  ON route.deployment_id = deployment.id AND route.workspace_id = v_workspace
                 AND route.identity_provider_id = provider.id
                 AND route.identity_provider_client_id = client.id
                JOIN mesh.workspace_membership AS membership
                  ON membership.deployment_id = deployment.id AND membership.workspace_id = v_workspace
                 AND membership.principal_id = principal.id
                WHERE deployment.id = v_key_session.deployment_id
                  AND deployment.installation_public_id = p_deployment_public_id
                  AND deployment.state = 'active' AND deployment.recovery_state = 'verified'
                  AND deployment.recovery_epoch = p_deployment_recovery_epoch AND deployment.deleted_at IS NULL
                  AND principal.public_id = p_principal_public_id
                  AND principal.kind = 'account' AND principal.state = 'active'
                  AND principal.authority_generation = p_principal_authority_generation
                  AND principal.deleted_at IS NULL
                  AND account.recovery_state = 'verified'
                  AND account.session_generation = p_account_session_generation
                  AND subject.public_id = p_identity_subject_public_id
                  AND subject.state = 'active' AND subject.deleted_at IS NULL
                  AND provider.state = 'active' AND provider.recovery_state = 'verified'
                  AND provider.current_generation = p_provider_generation AND provider.deleted_at IS NULL
                  AND client.state = 'active' AND client.deleted_at IS NULL
                  AND route.state = 'active' AND route.deleted_at IS NULL
                  AND route.organization_digest_algorithm IS NULL
                  AND route.organization_digest_key_id IS NULL AND route.organization_digest IS NULL
                  AND (route.minimum_assurance IS NULL OR route.minimum_assurance = v_key_session.acr)
                  AND membership.state = 'active' AND membership.valid_from <= v_now
                  AND (membership.expires_at IS NULL OR membership.expires_at > v_now)
            ) THEN
                RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key revocation is not authorized';
            END IF;

            -- Resolve only the caller's own key; never probe p_key_public_id first (no IDOR oracle).
            SELECT key_row.* INTO v_key FROM mesh.api_key AS key_row
            WHERE key_row.account_session_id = v_key_session.id
              AND key_row.workspace_id = v_workspace
              AND key_row.principal_id = v_key_session.principal_id;
            IF v_key.id IS NULL THEN
                RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key revocation is not authorized';
            END IF;
            IF v_key.public_id <> p_key_public_id THEN
                RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key may only revoke itself';
            END IF;

            v_target_principal_public_id := p_principal_public_id;
            v_revoked_by := 'self_key';
        ELSE
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key revocation is not authorized';
        END IF;
    END IF;

    IF v_key_session.state <> 'api_key' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTA22', MESSAGE = 'API key is already ended';
    END IF;
    IF v_key_session.absolute_expires_at <= v_now THEN
        RAISE EXCEPTION USING ERRCODE = 'MTA22', MESSAGE = 'API key has expired';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    UPDATE mesh.account_session AS session
    SET state = 'revoked',
        ended_at = GREATEST(v_now, session.issued_at),
        end_reason = 'api_key_revoked',
        version = session.version + 1,
        updated_at = GREATEST(v_now, session.updated_at)
    WHERE session.id = v_key_session.id
    RETURNING * INTO v_key_session;

    SELECT usage.last_used_at INTO v_last_used FROM mesh.api_key_usage AS usage
    WHERE usage.api_key_id = v_key.id;

    RETURN pg_catalog.jsonb_build_object(
        'key', mesh_ops.api_key_document_internal_v1(
            v_key, v_key_session, p_workspace_public_id, v_target_principal_public_id, v_last_used, v_now
        ),
        'session_id', v_key_session.public_id,
        'session_version', v_key_session.version,
        'revoked_by', v_revoked_by
    ) || CASE
        WHEN v_authority IS NOT NULL THEN pg_catalog.jsonb_build_object('authority', v_authority)
        ELSE '{}'::JSONB
    END;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.revoke_api_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer,
       mesh_share_writer, mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.revoke_api_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) TO mesh_api_rights;

CREATE FUNCTION mesh_ops.list_api_keys_v1(
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
    p_member_public_id UUID,
    p_after_created_at TIMESTAMPTZ,
    p_after_public_id UUID,
    p_limit INTEGER
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
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_workspace BIGINT;
    v_owner BIGINT;
    v_actor RECORD;
    v_actor_acr TEXT;
    v_target_principal_id BIGINT;
    v_target_principal_public_id UUID;
    v_membership mesh.workspace_membership%ROWTYPE;
    v_keys JSONB;
    v_has_more BOOLEAN;
BEGIN
    IF NOT mesh_ops.is_uuid_v7_internal_v1(p_session_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_deployment_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_principal_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_identity_subject_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_workspace_public_id)
        OR (p_member_public_id IS NOT NULL AND NOT mesh_ops.is_uuid_v7_internal_v1(p_member_public_id))
        OR (p_after_created_at IS NULL) <> (p_after_public_id IS NULL)
        OR (p_after_created_at IS NOT NULL AND NOT pg_catalog.isfinite(p_after_created_at))
        OR (p_after_public_id IS NOT NULL AND NOT mesh_ops.is_uuid_v7_internal_v1(p_after_public_id))
        OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 10
        OR p_session_version IS NULL OR p_session_version <= 0
        OR p_principal_authority_generation IS NULL OR p_principal_authority_generation <= 0
        OR p_account_session_generation IS NULL OR p_account_session_generation <= 0
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid API key list input';
    END IF;

    v_workspace := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF v_workspace IS NULL OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, v_workspace) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key listing is not authorized';
    END IF;

    SELECT workspace.owner_principal_id INTO v_owner FROM mesh.workspace AS workspace
    WHERE workspace.id = v_workspace AND workspace.state = 'active' AND workspace.deleted_at IS NULL;
    IF v_owner IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key listing is not authorized';
    END IF;

    SELECT * INTO v_actor FROM mesh_ops.resolve_account_session_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch, v_now
    );
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key listing is not authorized';
    END IF;

    IF p_member_public_id IS NULL THEN
        SELECT session.acr INTO v_actor_acr FROM mesh.account_session AS session
        WHERE session.public_id = p_session_public_id;
        IF NOT EXISTS (
            SELECT 1 FROM mesh.workspace_identity_provider AS route
            WHERE route.deployment_id = v_actor.deployment_id
              AND route.workspace_id = v_workspace
              AND route.identity_provider_id = v_actor.identity_provider_id
              AND route.identity_provider_client_id = v_actor.identity_provider_client_id
              AND route.state = 'active' AND route.deleted_at IS NULL
              AND route.organization_digest_algorithm IS NULL
              AND route.organization_digest_key_id IS NULL
              AND route.organization_digest IS NULL
              AND (route.minimum_assurance IS NULL OR route.minimum_assurance = v_actor_acr)
        ) OR NOT EXISTS (
            SELECT 1 FROM mesh.workspace_membership AS membership
            WHERE membership.deployment_id = v_actor.deployment_id
              AND membership.workspace_id = v_workspace
              AND membership.principal_id = v_actor.principal_id
              AND membership.state = 'active'
              AND membership.valid_from <= v_now
              AND (membership.expires_at IS NULL OR membership.expires_at > v_now)
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key listing is not authorized';
        END IF;
        v_target_principal_id := v_actor.principal_id;
        v_target_principal_public_id := p_principal_public_id;
    ELSE
        PERFORM 1 FROM mesh_ops.resolve_workspace_permission_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, 'member.manage', v_now
        ) LIMIT 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key listing is not authorized';
        END IF;

        SELECT principal.id INTO v_target_principal_id FROM mesh.principal AS principal
        WHERE principal.deployment_id = v_actor.deployment_id
          AND principal.public_id = p_member_public_id
          AND principal.kind = 'account' AND principal.deleted_at IS NULL;
        SELECT membership.* INTO v_membership FROM mesh.workspace_membership AS membership
        WHERE membership.workspace_id = v_workspace AND membership.principal_id = v_target_principal_id
          AND membership.state <> 'revoked';
        IF v_membership.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Workspace member is unavailable';
        END IF;
        IF v_target_principal_id = v_owner OR v_target_principal_id = v_actor.principal_id THEN
            RAISE EXCEPTION USING ERRCODE = 'MTM02', MESSAGE = 'nobody manages the API keys of the owner or themselves';
        END IF;
        IF EXISTS (
            SELECT 1 FROM mesh.workspace_role_assignment AS assignment
            JOIN mesh.builtin_role AS role ON role.role_key = assignment.role_key
            WHERE assignment.workspace_id = v_workspace AND assignment.workspace_membership_id = v_membership.id
              AND assignment.state = 'active'
              AND NOT (role.assignable_by && mesh_ops.workspace_role_assigners_v1(v_workspace, v_actor.principal_id, v_now))
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'the member holds a role beyond the delegation ceiling';
        END IF;
        v_target_principal_public_id := p_member_public_id;
    END IF;

    WITH page AS (
        SELECT
            pg_catalog.row_number() OVER (ORDER BY key_row.created_at DESC, key_row.public_id DESC) AS row_num,
            mesh_ops.api_key_document_internal_v1(
                key_row, session, p_workspace_public_id, v_target_principal_public_id,
                usage.last_used_at, v_now
            ) AS document
        FROM mesh.api_key AS key_row
        JOIN mesh.account_session AS session
          ON session.deployment_id = key_row.deployment_id
         AND session.principal_id = key_row.principal_id
         AND session.id = key_row.account_session_id
        LEFT JOIN mesh.api_key_usage AS usage
          ON usage.api_key_id = key_row.id
        WHERE key_row.workspace_id = v_workspace
          AND key_row.principal_id = v_target_principal_id
          AND (
              p_after_created_at IS NULL
              OR (key_row.created_at, key_row.public_id) < (p_after_created_at, p_after_public_id)
          )
        ORDER BY key_row.created_at DESC, key_row.public_id DESC
        LIMIT p_limit + 1
    )
    SELECT
        COALESCE(pg_catalog.jsonb_agg(page.document ORDER BY page.row_num) FILTER (WHERE page.row_num <= p_limit), '[]'::JSONB),
        pg_catalog.count(*) > p_limit
    INTO v_keys, v_has_more
    FROM page;

    RETURN pg_catalog.jsonb_build_object(
        'workspace_id', p_workspace_public_id,
        'principal_id', v_target_principal_public_id,
        'keys', v_keys,
        'has_more', v_has_more
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_api_keys_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer,
       mesh_share_writer, mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.list_api_keys_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) TO mesh_api_rights;

CREATE FUNCTION mesh_ops.read_api_key_v1(
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
    p_key_public_id UUID
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
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_workspace BIGINT;
    v_actor RECORD;
    v_actor_acr TEXT;
    v_key mesh.api_key%ROWTYPE;
    v_key_session mesh.account_session%ROWTYPE;
    v_last_used TIMESTAMPTZ;
BEGIN
    IF NOT mesh_ops.is_uuid_v7_internal_v1(p_session_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_deployment_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_principal_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_identity_subject_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_workspace_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_key_public_id)
        OR p_session_version IS NULL OR p_session_version <= 0
        OR p_principal_authority_generation IS NULL OR p_principal_authority_generation <= 0
        OR p_account_session_generation IS NULL OR p_account_session_generation <= 0
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid API key read input';
    END IF;

    v_workspace := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF v_workspace IS NULL OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, v_workspace) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key read is not authorized';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM mesh.workspace AS workspace
        WHERE workspace.id = v_workspace AND workspace.state = 'active' AND workspace.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key read is not authorized';
    END IF;

    SELECT * INTO v_actor FROM mesh_ops.resolve_account_session_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch, v_now
    );
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key read is not authorized';
    END IF;

    SELECT session.acr INTO v_actor_acr FROM mesh.account_session AS session
    WHERE session.public_id = p_session_public_id;
    IF NOT EXISTS (
        SELECT 1 FROM mesh.workspace_identity_provider AS route
        WHERE route.deployment_id = v_actor.deployment_id
          AND route.workspace_id = v_workspace
          AND route.identity_provider_id = v_actor.identity_provider_id
          AND route.identity_provider_client_id = v_actor.identity_provider_client_id
          AND route.state = 'active' AND route.deleted_at IS NULL
          AND route.organization_digest_algorithm IS NULL
          AND route.organization_digest_key_id IS NULL
          AND route.organization_digest IS NULL
          AND (route.minimum_assurance IS NULL OR route.minimum_assurance = v_actor_acr)
    ) OR NOT EXISTS (
        SELECT 1 FROM mesh.workspace_membership AS membership
        WHERE membership.deployment_id = v_actor.deployment_id
          AND membership.workspace_id = v_workspace
          AND membership.principal_id = v_actor.principal_id
          AND membership.state = 'active'
          AND membership.valid_from <= v_now
          AND (membership.expires_at IS NULL OR membership.expires_at > v_now)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'API key read is not authorized';
    END IF;

    SELECT key_row.* INTO v_key FROM mesh.api_key AS key_row
    WHERE key_row.workspace_id = v_workspace
      AND key_row.principal_id = v_actor.principal_id
      AND key_row.public_id = p_key_public_id;
    IF v_key.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'API key is unavailable';
    END IF;

    SELECT session.* INTO STRICT v_key_session FROM mesh.account_session AS session
    WHERE session.id = v_key.account_session_id;
    SELECT usage.last_used_at INTO v_last_used FROM mesh.api_key_usage AS usage
    WHERE usage.api_key_id = v_key.id;

    RETURN pg_catalog.jsonb_build_object(
        'key', mesh_ops.api_key_document_internal_v1(
            v_key, v_key_session, p_workspace_public_id, p_principal_public_id, v_last_used, v_now
        )
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_api_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer,
       mesh_share_writer, mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.read_api_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) TO mesh_api_rights;

CREATE FUNCTION mesh_ops.resolve_api_key_v1(
    p_expected_deployment_public_id UUID,
    p_expected_recovery_epoch BIGINT,
    p_key_public_id UUID
)
RETURNS TABLE (
    session_public_id UUID,
    deployment_public_id UUID,
    principal_public_id UUID,
    identity_subject_public_id UUID,
    login_workspace_public_id UUID,
    authentication_time TIMESTAMPTZ,
    acr TEXT,
    amr TEXT[],
    session_version BIGINT,
    principal_authority_generation BIGINT,
    account_session_generation BIGINT,
    provider_generation BIGINT,
    deployment_recovery_epoch BIGINT,
    idle_expires_at TIMESTAMPTZ,
    absolute_expires_at TIMESTAMPTZ,
    api_key_public_id UUID,
    token_digest_algorithm TEXT,
    token_digest_key_id TEXT,
    token_digest BYTEA,
    last_used_at TIMESTAMPTZ
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
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_workspace_id BIGINT;
    v_previous_workspace_id TEXT;
BEGIN
    IF NOT mesh_ops.is_uuid_v7_internal_v1(p_expected_deployment_public_id)
        OR p_expected_recovery_epoch IS NULL OR p_expected_recovery_epoch <= 0
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_key_public_id) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid API key resolution input';
    END IF;

    SELECT key_row.workspace_id INTO v_workspace_id
    FROM mesh.api_key AS key_row
    WHERE key_row.public_id = p_key_public_id;
    IF v_workspace_id IS NULL THEN
        RETURN;
    END IF;

    v_previous_workspace_id := pg_catalog.current_setting('mesh.workspace_id', TRUE);
    PERFORM pg_catalog.set_config('mesh.workspace_id', v_workspace_id::TEXT, TRUE);

    BEGIN
        RETURN QUERY
        SELECT
            session.public_id,
            deployment.installation_public_id,
            principal.public_id,
            subject.public_id,
            workspace.public_id,
            session.authentication_time,
            session.acr,
            session.amr,
            session.version,
            session.principal_authority_generation,
            session.account_session_generation,
            session.provider_generation,
            session.deployment_recovery_epoch,
            session.idle_expires_at,
            session.absolute_expires_at,
            key_row.public_id,
            session.token_digest_algorithm,
            session.token_digest_key_id,
            session.token_digest,
            usage.last_used_at
        FROM mesh.api_key AS key_row
        JOIN mesh.account_session AS session
          ON session.deployment_id = key_row.deployment_id
         AND session.principal_id = key_row.principal_id
         AND session.id = key_row.account_session_id
        JOIN mesh.deployment AS deployment
          ON deployment.id = session.deployment_id
        JOIN mesh.principal AS principal
          ON principal.deployment_id = session.deployment_id
         AND principal.id = session.principal_id
        JOIN mesh.account AS account
          ON account.deployment_id = session.deployment_id
         AND account.principal_id = session.principal_id
        JOIN mesh.identity_subject AS subject
          ON subject.deployment_id = session.deployment_id
         AND subject.identity_provider_id = session.identity_provider_id
         AND subject.principal_id = session.principal_id
         AND subject.id = session.identity_subject_id
        JOIN mesh.identity_provider AS provider
          ON provider.deployment_id = session.deployment_id
         AND provider.id = session.identity_provider_id
        JOIN mesh.identity_provider_client AS client
          ON client.deployment_id = session.deployment_id
         AND client.identity_provider_id = session.identity_provider_id
         AND client.id = session.identity_provider_client_id
        JOIN mesh.workspace AS workspace
          ON workspace.deployment_id = session.deployment_id
         AND workspace.id = key_row.workspace_id
        JOIN mesh.workspace_identity_provider AS route
          ON route.deployment_id = session.deployment_id
         AND route.workspace_id = workspace.id
         AND route.identity_provider_id = session.identity_provider_id
         AND route.identity_provider_client_id = session.identity_provider_client_id
        JOIN mesh.workspace_membership AS membership
          ON membership.deployment_id = session.deployment_id
         AND membership.workspace_id = workspace.id
         AND membership.principal_id = session.principal_id
        LEFT JOIN mesh.api_key_usage AS usage
          ON usage.api_key_id = key_row.id
        WHERE key_row.public_id = p_key_public_id
          AND session.kind = 'api_key'
          AND session.state = 'api_key'
          AND session.login_workspace_id = key_row.workspace_id
          AND session.authentication_time <= v_now
          AND session.idle_expires_at > v_now
          AND session.absolute_expires_at > v_now
          AND key_row.expires_at > v_now
          AND deployment.installation_public_id = p_expected_deployment_public_id
          AND deployment.recovery_epoch = p_expected_recovery_epoch
          AND session.deployment_recovery_epoch = p_expected_recovery_epoch
          AND deployment.state = 'active' AND deployment.recovery_state = 'verified'
          AND deployment.deleted_at IS NULL
          AND principal.kind = 'account' AND principal.state = 'active'
          AND principal.authority_generation = session.principal_authority_generation
          AND principal.deleted_at IS NULL
          AND account.recovery_state = 'verified'
          AND account.session_generation = session.account_session_generation
          AND subject.state = 'active' AND subject.deleted_at IS NULL
          AND provider.state = 'active' AND provider.recovery_state = 'verified'
          AND provider.current_generation = session.provider_generation
          AND provider.deleted_at IS NULL
          AND client.state = 'active' AND client.deleted_at IS NULL
          AND workspace.state = 'active' AND workspace.deleted_at IS NULL
          AND route.state = 'active' AND route.deleted_at IS NULL
          AND route.organization_digest_algorithm IS NULL
          AND route.organization_digest_key_id IS NULL
          AND route.organization_digest IS NULL
          AND (route.minimum_assurance IS NULL OR route.minimum_assurance = session.acr)
          AND membership.state = 'active'
          AND membership.valid_from <= v_now
          AND (membership.expires_at IS NULL OR membership.expires_at > v_now)
        LIMIT 1;
    EXCEPTION
        WHEN OTHERS THEN
            PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(v_previous_workspace_id, ''), TRUE);
            RAISE;
    END;

    PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(v_previous_workspace_id, ''), TRUE);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.resolve_api_key_v1(UUID, BIGINT, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer,
         mesh_share_writer, mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.resolve_api_key_v1(UUID, BIGINT, UUID)
    TO mesh_api_rights;

CREATE FUNCTION mesh_ops.touch_api_key_usage_v1(
    p_expected_deployment_public_id UUID,
    p_key_public_id UUID
)
RETURNS BOOLEAN
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
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_key_id BIGINT;
BEGIN
    IF NOT mesh_ops.is_uuid_v7_internal_v1(p_expected_deployment_public_id)
        OR NOT mesh_ops.is_uuid_v7_internal_v1(p_key_public_id) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid API key usage input';
    END IF;

    SELECT key_row.id INTO v_key_id
    FROM mesh.api_key AS key_row
    JOIN mesh.account_session AS session
      ON session.deployment_id = key_row.deployment_id
     AND session.principal_id = key_row.principal_id
     AND session.id = key_row.account_session_id
    JOIN mesh.deployment AS deployment
      ON deployment.id = key_row.deployment_id
    WHERE key_row.public_id = p_key_public_id
      AND deployment.installation_public_id = p_expected_deployment_public_id
      AND deployment.state = 'active'
      AND deployment.deleted_at IS NULL
      AND session.kind = 'api_key'
      AND session.state = 'api_key'
      AND session.absolute_expires_at > v_now
      AND key_row.expires_at > v_now;

    IF v_key_id IS NULL THEN
        RETURN FALSE;
    END IF;

    INSERT INTO mesh.api_key_usage (api_key_id, last_used_at)
    VALUES (v_key_id, v_now)
    ON CONFLICT (api_key_id) DO UPDATE
        SET last_used_at = EXCLUDED.last_used_at
        WHERE mesh.api_key_usage.last_used_at <= EXCLUDED.last_used_at - INTERVAL '5 minutes';

    RETURN FOUND;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.touch_api_key_usage_v1(UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer,
         mesh_share_writer, mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.touch_api_key_usage_v1(UUID, UUID)
    TO mesh_api_rights;

-- Clamp ended_at with GREATEST(v_now, session.issued_at) on account-wide
-- Session-ending functions so a concurrent create_api_key_v1 cannot trigger
-- account_session_timestamps_check (23514).
CREATE OR REPLACE FUNCTION mesh_ops.change_account_recovery_v1(p_principal_public_id uuid, p_action text, p_change_public_id uuid)
 RETURNS TABLE(deployment_public_id uuid, account_public_id uuid, account_version bigint, session_generation bigint, recovery_state text, sessions_ended integer, changed_at timestamp with time zone)
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog'
 SET join_collapse_limit TO '1'
 SET from_collapse_limit TO '1'
 SET plan_cache_mode TO 'force_generic_plan'
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
      AND session.state IN ('active', 'api_key')
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
        SET state = 'revoked', ended_at = GREATEST(v_now, session.issued_at),
            end_reason = CASE WHEN p_action = 'quarantine' THEN 'account_suspended' ELSE 'administrative' END,
            version = session.version + 1, updated_at = GREATEST(v_now, session.updated_at)
        WHERE session.deployment_id = v_account.deployment_id AND session.principal_id = v_account.principal_id
          AND session.state IN ('active', 'api_key');
        GET DIAGNOSTICS v_count = ROW_COUNT;
    END IF;
    RETURN QUERY SELECT v_deployment, v_account.public_id, v_account.version, v_account.session_generation,
        v_account.recovery_state, v_count, v_now;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.logout_all_account_sessions_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_change_public_id uuid)
 RETURNS TABLE(account_public_id uuid, account_version bigint, session_generation bigint, sessions_ended integer, ended_at timestamp with time zone)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
 SET join_collapse_limit TO '1'
 SET from_collapse_limit TO '1'
 SET plan_cache_mode TO 'force_generic_plan'
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
    SELECT session.deployment_id, session.principal_id INTO v_deployment, v_principal
    FROM mesh.account_session AS session WHERE session.public_id = p_session_public_id;
    PERFORM 1 FROM mesh.account_session AS session
    WHERE session.deployment_id = v_deployment AND session.principal_id = v_principal
      AND session.state IN ('active', 'api_key')
    ORDER BY session.id
    FOR UPDATE;
    SELECT * INTO v_account FROM mesh.account AS account
    WHERE account.deployment_id = v_deployment AND account.principal_id = v_principal
    FOR UPDATE;
    IF v_account.id IS NULL OR v_account.session_generation <> p_account_session_generation
        OR v_account.recovery_state <> 'verified' THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Account Session is not active';
    END IF;
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
    SET state = 'revoked', ended_at = GREATEST(v_now, session.issued_at), end_reason = 'logout_all',
        version = session.version + 1, updated_at = GREATEST(v_now, session.updated_at)
    WHERE session.deployment_id = v_deployment AND session.principal_id = v_principal
      AND session.state IN ('active', 'api_key');
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN QUERY SELECT v_account.public_id, v_account.version, v_account.session_generation, v_count, v_now;
END;
$function$;
