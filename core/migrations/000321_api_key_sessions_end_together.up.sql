-- Schema 321 (V1-80 A2, part 1): API keys end with their person's Sessions.
--
-- A key is a mesh.account_session row in the state 'api_key' (schema 320).
-- Every operation that ends a person's Sessions now locks their live rows
-- ('active' and 'api_key') in session.id order FOR UPDATE before updating
-- them in one UPDATE:
--
-- * revoke_workspace_member_sessions_v1, change_workspace_member_v1
--   (suspend) and remove_workspace_member_v1 end the keys bound to that
--   Workspace (locking Workspace -> membership -> sessions in id order; a
--   concurrent path that locks a Session before membership can still 40P01);
-- * logout_all_account_sessions_v1 and change_account_recovery_v1 end the
--   person's keys in every Workspace (locking sessions in id order ->
--   Account).
--
-- The count each returns (sessions_ended) includes ended key rows, so the
-- caller records the change whenever any row ended. The checks on the
-- caller's own Session still admit only 'active' rows: a key cannot sign
-- out everything or manage members, and recovery runs only as the migrator.
-- Reinstating a member never revives a key: api_key -> revoked is final
-- (schema 320 trigger).
--
-- No key can be created before this schema: the table that creates them
-- comes with A2, part 2.


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
        SET state = 'revoked', ended_at = v_now,
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
      AND session.state IN ('active', 'api_key');
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN QUERY SELECT v_account.public_id, v_account.version, v_account.session_generation, v_count, v_now;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.revoke_workspace_member_sessions_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_member_public_id uuid, p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
 SET join_collapse_limit TO '1'
 SET from_collapse_limit TO '1'
 SET plan_cache_mode TO 'force_generic_plan'
AS $function$
DECLARE
    v_workspace BIGINT;
    v_owner BIGINT;
    v_grant RECORD;
    v_actor BIGINT;
    v_member BIGINT;
    v_membership mesh.workspace_membership%ROWTYPE;
    v_sessions INTEGER := 0;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
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
    FOR NO KEY UPDATE;
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
      AND session.login_workspace_id = v_workspace AND session.state IN ('active', 'api_key')
    ORDER BY session.id
    FOR UPDATE;
    UPDATE mesh.account_session AS session
    SET state = 'revoked', ended_at = GREATEST(v_now, session.issued_at), end_reason = 'administrative',
        version = session.version + 1, updated_at = GREATEST(v_now, session.updated_at)
    WHERE session.deployment_id = v_membership.deployment_id AND session.principal_id = v_member
      AND session.login_workspace_id = v_workspace
      AND session.state IN ('active', 'api_key');
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

CREATE OR REPLACE FUNCTION mesh_ops.change_workspace_member_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_member_public_id uuid, p_action text, p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
 SET join_collapse_limit TO '1'
 SET from_collapse_limit TO '1'
 SET plan_cache_mode TO 'force_generic_plan'
AS $function$
DECLARE
    v_workspace BIGINT;
    v_owner BIGINT;
    v_grant RECORD;
    v_actor BIGINT;
    v_member BIGINT;
    v_membership mesh.workspace_membership%ROWTYPE;
    v_before JSONB;
    v_devices JSONB := '[]'::JSONB;
    v_networks BIGINT[];
    v_advanced JSONB := '[]'::JSONB;
    v_sessions INTEGER := 0;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_action NOT IN ('suspend', 'resume') OR p_member_public_id IS NULL
        OR p_change_public_id IS NULL OR p_evaluated_at IS NULL
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
    FOR NO KEY UPDATE;
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
        RAISE EXCEPTION USING ERRCODE = 'MTM02', MESSAGE = 'nobody suspends the owner or themselves';
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
    IF (p_action = 'suspend' AND v_membership.state <> 'active')
        OR (p_action = 'resume' AND v_membership.state <> 'suspended') THEN
        RAISE EXCEPTION USING ERRCODE = 'MTM01', MESSAGE = 'Workspace member is not in that state';
    END IF;
    v_before := mesh_ops.workspace_member_document_internal_v1(v_membership);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    UPDATE mesh.workspace_membership
    SET state = CASE WHEN p_action = 'suspend' THEN 'suspended' ELSE 'active' END,
        authority_generation = authority_generation + 1, version = version + 1,
        updated_at = GREATEST(v_now, updated_at)
    WHERE id = v_membership.id
    RETURNING * INTO v_membership;

    -- The member's own Devices here; Workspace Devices are never touched.
    WITH changed AS (
        UPDATE mesh.device AS device
        SET state = CASE WHEN p_action = 'suspend' THEN 'suspended' ELSE 'active' END,
            suspended_reason = CASE WHEN p_action = 'suspend' THEN 'member' END,
            session_generation = device.session_generation + CASE WHEN p_action = 'suspend' THEN 1 ELSE 0 END,
            version = device.version + 1, updated_at = GREATEST(v_now, device.updated_at)
        WHERE device.workspace_id = v_workspace AND device.owner_principal_id = v_member
          AND device.ownership = 'member' AND device.deleted_at IS NULL
          AND ((p_action = 'suspend' AND device.state = 'active')
               OR (p_action = 'resume' AND device.state = 'suspended' AND device.suspended_reason = 'member'))
        RETURNING device.network_id, device.public_id, device.hostname, device.state
    )
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'device_id', changed.public_id, 'network_id', network.public_id,
               'hostname', changed.hostname, 'state', changed.state
           ) ORDER BY network.public_id::TEXT, changed.public_id::TEXT), '[]'::JSONB),
           pg_catalog.array_agg(DISTINCT changed.network_id ORDER BY changed.network_id)
    INTO v_devices, v_networks
    FROM changed JOIN mesh.network AS network ON network.id = changed.network_id;
    v_advanced := mesh_ops.advance_member_networks_internal_v1(v_workspace, v_networks);

    IF p_action = 'suspend' THEN
        PERFORM 1 FROM mesh.account_session AS session
        WHERE session.deployment_id = v_membership.deployment_id AND session.principal_id = v_member
          AND session.login_workspace_id = v_workspace AND session.state IN ('active', 'api_key')
        ORDER BY session.id
        FOR UPDATE;
        UPDATE mesh.account_session AS session
        SET state = 'revoked', ended_at = GREATEST(v_now, session.issued_at), end_reason = 'administrative',
            version = session.version + 1, updated_at = GREATEST(v_now, session.updated_at)
        WHERE session.deployment_id = v_membership.deployment_id AND session.principal_id = v_member
          AND session.login_workspace_id = v_workspace
          AND session.state IN ('active', 'api_key');
        GET DIAGNOSTICS v_sessions = ROW_COUNT;
    END IF;

    RETURN pg_catalog.jsonb_build_object(
        'before', v_before,
        'after', mesh_ops.workspace_member_document_internal_v1(v_membership),
        'devices', v_devices,
        'sessions_ended', v_sessions,
        'networks', v_advanced,
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

CREATE OR REPLACE FUNCTION mesh_ops.remove_workspace_member_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_member_public_id uuid, p_plan jsonb, p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
 SET join_collapse_limit TO '1'
 SET from_collapse_limit TO '1'
 SET plan_cache_mode TO 'force_generic_plan'
AS $function$
DECLARE
    v_workspace BIGINT;
    v_owner BIGINT;
    v_workspace_device_owner BIGINT;
    v_grant RECORD;
    v_actor BIGINT;
    v_member BIGINT;
    v_membership mesh.workspace_membership%ROWTYPE;
    v_before JSONB;
    v_item RECORD;
    v_device mesh.device%ROWTYPE;
    v_target BIGINT;
    v_action TEXT;
    v_devices JSONB := '[]'::JSONB;
    v_networks BIGINT[] := ARRAY[]::BIGINT[];
    v_advanced JSONB := '[]'::JSONB;
    v_handovers INTEGER := 0;
    v_keys INTEGER := 0;
    v_groups INTEGER := 0;
    v_roles INTEGER := 0;
    v_sessions INTEGER := 0;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_member_public_id IS NULL OR p_plan IS NULL OR pg_catalog.jsonb_typeof(p_plan) <> 'array'
        OR pg_catalog.jsonb_array_length(p_plan) > 250
        OR p_change_public_id IS NULL OR p_evaluated_at IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Workspace member removal is invalid';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_array_elements(p_plan) AS item(value)
        WHERE pg_catalog.jsonb_typeof(item.value) <> 'object'
           OR NOT (item.value ?& ARRAY['device_id', 'action'])
           OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(item.value) AS key(name)
                      WHERE key.name NOT IN ('device_id', 'action', 'new_owner_id'))
           OR item.value ->> 'action' NOT IN ('transfer_workspace', 'transfer_member', 'revoke')
           OR (item.value ->> 'action' = 'transfer_member') <> (item.value ? 'new_owner_id')
           OR (item.value ->> 'device_id') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
           OR ((item.value ? 'new_owner_id') AND (item.value ->> 'new_owner_id')
               !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
    ) OR (
        SELECT pg_catalog.count(DISTINCT item.value ->> 'device_id') <> pg_catalog.count(*)
        FROM pg_catalog.jsonb_array_elements(p_plan) AS item(value)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Workspace member removal plan is invalid';
    END IF;

    v_workspace := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF v_workspace IS NULL OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, v_workspace) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Workspace member removal is not authorized';
    END IF;
    -- Member changes in one Workspace are serialized by its row lock.
    SELECT workspace.owner_principal_id INTO v_owner FROM mesh.workspace AS workspace
    WHERE workspace.id = v_workspace AND workspace.state = 'active' AND workspace.deleted_at IS NULL
    FOR NO KEY UPDATE;
    IF v_owner IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Workspace member removal is not authorized';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'member.manage', v_now
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Workspace member removal is not authorized';
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
        RAISE EXCEPTION USING ERRCODE = 'MTM02', MESSAGE = 'nobody removes the owner or themselves';
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
    IF EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_array_elements(p_plan) AS item(value)
        WHERE NOT EXISTS (
            SELECT 1 FROM mesh.device AS device
            WHERE device.workspace_id = v_workspace AND device.public_id = (item.value ->> 'device_id')::UUID
              AND device.ownership = 'member' AND device.owner_principal_id = v_member
              AND device.state IN ('active', 'suspended', 'expired') AND device.deleted_at IS NULL
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTM03', MESSAGE = 'the plan names a Device the member does not own here';
    END IF;
    v_before := mesh_ops.workspace_member_document_internal_v1(v_membership);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    -- Lock order: the Network revisions of every Network the removal touches,
    -- in Network order, then their rows. The member's Network memberships
    -- cover every Network they could hold a Device, key or role in.
    SELECT COALESCE(pg_catalog.array_agg(DISTINCT touched.network_id ORDER BY touched.network_id),
                    ARRAY[]::BIGINT[])
    INTO v_networks
    FROM (
        SELECT network_member.network_id FROM mesh.network_membership AS network_member
        WHERE network_member.workspace_id = v_workspace AND network_member.principal_id = v_member
          AND network_member.workspace_membership_id = v_membership.id AND network_member.state <> 'revoked'
        UNION
        SELECT device.network_id FROM mesh.device AS device
        WHERE device.workspace_id = v_workspace AND device.deleted_at IS NULL
          AND ((device.ownership = 'member' AND device.owner_principal_id = v_member
                AND device.state IN ('active', 'suspended', 'expired'))
               OR device.handover_principal_id = v_member)
        UNION
        SELECT credential.network_id FROM mesh.enrollment_credential AS credential
        WHERE credential.workspace_id = v_workspace AND credential.issuer_principal_id = v_member
          AND credential.state = 'active'
    ) AS touched;
    PERFORM pg_catalog.set_config('mesh.identity_catalog_fanout', 'on', TRUE);
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_workspace AND revision.network_id = ANY (v_networks)
    ORDER BY revision.network_id
    FOR UPDATE;

    -- Devices, in a stable order: the plan's choice or, unnamed, revocation.
    v_workspace_device_owner := mesh_ops.workspace_device_principal_internal_v1(v_workspace);
    FOR v_item IN
        SELECT device.id, plan.value AS choice
        FROM mesh.device AS device
        LEFT JOIN pg_catalog.jsonb_array_elements(p_plan) AS plan(value)
          ON (plan.value ->> 'device_id')::UUID = device.public_id
        WHERE device.workspace_id = v_workspace AND device.ownership = 'member'
          AND device.owner_principal_id = v_member
          AND device.state IN ('active', 'suspended', 'expired') AND device.deleted_at IS NULL
        ORDER BY device.network_id, device.id
    LOOP
        SELECT * INTO STRICT v_device FROM mesh.device AS device WHERE device.id = v_item.id FOR UPDATE;
        v_action := COALESCE(v_item.choice ->> 'action', 'revoke');
        CASE v_action
        WHEN 'transfer_workspace' THEN
            -- An administrator's suspension stays; the member's and a
            -- pending handover end with the member's ownership.
            UPDATE mesh.device SET ownership = 'workspace',
                owner_principal_id = v_workspace_device_owner, custodian_principal_id = v_workspace_device_owner,
                expires_at = mesh_ops.device_never_expires_v1(),
                state = CASE WHEN state = 'expired' OR suspended_reason IN ('handover', 'member') THEN 'active'
                             ELSE state END,
                suspended_reason = CASE WHEN suspended_reason IN ('handover', 'member') THEN NULL
                                        ELSE suspended_reason END,
                handover_principal_id = NULL,
                session_generation = session_generation + 1, version = version + 1,
                updated_at = GREATEST(v_now, updated_at)
            WHERE id = v_device.id RETURNING * INTO v_device;
        WHEN 'transfer_member' THEN
            IF v_device.state = 'expired' OR v_device.suspended_reason = 'admin' THEN
                RAISE EXCEPTION USING ERRCODE = 'MTM03', MESSAGE = 'this Device cannot be handed over';
            END IF;
            SELECT principal.id INTO v_target
            FROM mesh.principal AS principal
            JOIN mesh.workspace_membership AS membership
              ON membership.workspace_id = v_workspace AND membership.principal_id = principal.id
             AND membership.state = 'active'
             AND (membership.expires_at IS NULL OR membership.expires_at > v_now)
            JOIN mesh.network_membership AS network_member
              ON network_member.workspace_id = v_workspace AND network_member.network_id = v_device.network_id
             AND network_member.principal_id = principal.id AND network_member.state = 'active'
             AND (network_member.expires_at IS NULL OR network_member.expires_at > v_now)
            WHERE principal.public_id = (v_item.choice ->> 'new_owner_id')::UUID
              AND principal.id <> v_member AND principal.state = 'active' AND principal.deleted_at IS NULL;
            IF v_target IS NULL THEN
                RAISE EXCEPTION USING ERRCODE = 'MTM04',
                    MESSAGE = 'new owner is not an active member of the Device''s Network';
            END IF;
            UPDATE mesh.device SET state = 'suspended', suspended_reason = 'handover',
                handover_principal_id = v_target,
                session_generation = session_generation + 1, version = version + 1,
                updated_at = GREATEST(v_now, updated_at)
            WHERE id = v_device.id RETURNING * INTO v_device;
        ELSE
            PERFORM mesh_ops.revoke_member_device_internal_v1(v_device.id, 'member removed', v_now);
            SELECT * INTO STRICT v_device FROM mesh.device AS device WHERE device.id = v_item.id;
        END CASE;
        v_devices := v_devices || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
            'device_id', v_device.public_id,
            'network_id', (SELECT network.public_id FROM mesh.network AS network
                           WHERE network.id = v_device.network_id),
            'hostname', v_device.hostname, 'action', v_action, 'state', v_device.state
        ));
    END LOOP;

    -- A Device waiting to be handed to the member stays suspended for an
    -- administrator to decide.
    UPDATE mesh.device AS device
    SET suspended_reason = 'admin', handover_principal_id = NULL,
        version = device.version + 1, updated_at = GREATEST(v_now, device.updated_at)
    WHERE device.workspace_id = v_workspace AND device.handover_principal_id = v_member
      AND device.deleted_at IS NULL;
    GET DIAGNOSTICS v_handovers = ROW_COUNT;

    UPDATE mesh.enrollment_credential AS credential
    SET state = 'revoked', revoked_at = GREATEST(v_now, credential.valid_from),
        version = credential.version + 1, updated_at = GREATEST(v_now, credential.updated_at)
    WHERE credential.workspace_id = v_workspace AND credential.issuer_principal_id = v_member
      AND credential.state = 'active';
    GET DIAGNOSTICS v_keys = ROW_COUNT;

    WITH removed AS (
        DELETE FROM mesh.identity_group_member AS member
        WHERE member.workspace_id = v_workspace AND member.principal_id = v_member
        RETURNING member.identity_group_id
    ), counted AS (
        UPDATE mesh.identity_group AS identity_group
        SET member_count = identity_group.member_count - changed.removed,
            version = identity_group.version + 1, updated_at = GREATEST(v_now, identity_group.updated_at)
        FROM (SELECT removed.identity_group_id, pg_catalog.count(*)::INTEGER AS removed
              FROM removed GROUP BY removed.identity_group_id) AS changed
        WHERE identity_group.id = changed.identity_group_id
        RETURNING identity_group.id
    )
    SELECT pg_catalog.count(*)::INTEGER INTO v_groups FROM counted;

    UPDATE mesh.workspace_role_assignment AS assignment
    SET state = 'revoked', revoked_at = GREATEST(v_now, assignment.created_at),
        authority_generation = assignment.authority_generation + 1, version = assignment.version + 1,
        updated_at = GREATEST(v_now, assignment.updated_at)
    WHERE assignment.workspace_id = v_workspace AND assignment.workspace_membership_id = v_membership.id
      AND assignment.state = 'active';
    GET DIAGNOSTICS v_roles = ROW_COUNT;
    UPDATE mesh.role_binding AS binding
    SET state = 'revoked', authority_generation = binding.authority_generation + 1,
        version = binding.version + 1, updated_at = GREATEST(v_now, binding.updated_at)
    WHERE binding.workspace_id = v_workspace AND binding.workspace_membership_id = v_membership.id
      AND binding.state <> 'revoked';
    UPDATE mesh.network_membership AS network_member
    SET state = 'revoked', authority_generation = network_member.authority_generation + 1,
        version = network_member.version + 1, updated_at = GREATEST(v_now, network_member.updated_at)
    WHERE network_member.workspace_id = v_workspace AND network_member.workspace_membership_id = v_membership.id
      AND network_member.state <> 'revoked';
    UPDATE mesh.workspace_membership
    SET state = 'revoked', authority_generation = authority_generation + 1, version = version + 1,
        updated_at = GREATEST(v_now, updated_at)
    WHERE id = v_membership.id
    RETURNING * INTO v_membership;

    PERFORM 1 FROM mesh.account_session AS session
    WHERE session.deployment_id = v_membership.deployment_id AND session.principal_id = v_member
      AND session.login_workspace_id = v_workspace AND session.state IN ('active', 'api_key')
    ORDER BY session.id
    FOR UPDATE;
    UPDATE mesh.account_session AS session
    SET state = 'revoked', ended_at = GREATEST(v_now, session.issued_at), end_reason = 'administrative',
        version = session.version + 1, updated_at = GREATEST(v_now, session.updated_at)
    WHERE session.deployment_id = v_membership.deployment_id AND session.principal_id = v_member
      AND session.login_workspace_id = v_workspace
      AND session.state IN ('active', 'api_key');
    GET DIAGNOSTICS v_sessions = ROW_COUNT;

    PERFORM pg_catalog.set_config('mesh.identity_catalog_fanout', '', TRUE);
    v_advanced := mesh_ops.advance_member_networks_internal_v1(v_workspace, v_networks);

    RETURN pg_catalog.jsonb_build_object(
        'before', v_before,
        'after', mesh_ops.workspace_member_document_internal_v1(v_membership),
        'devices', v_devices,
        'handovers_cancelled', v_handovers,
        'keys_revoked', v_keys,
        'groups_left', v_groups,
        'roles_revoked', v_roles,
        'sessions_ended', v_sessions,
        'networks', v_advanced,
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
