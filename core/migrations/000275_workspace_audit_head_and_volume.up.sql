-- TD-CORE-134 slice 1 (docs/audit-deployment-stream-design.md).
--
-- 1. Renaming a Workspace and assigning or revoking a Workspace role append
--    their evidence to the Workspace stream (since schema 116), yet still
--    locked the Deployment stream: every Workspace's management queued on
--    the one row all sign-ins and sessions lock. They now lock the head of
--    the Workspace stream they write, still before the expiry decision.
--    Bodies are schema 182's with that one line changed.
-- 2. The worker reads how many events the Deployment streams hold, so their
--    write rate can be watched (meshtransit_audit_deployment_events_total).

CREATE OR REPLACE FUNCTION mesh_ops.rename_owned_workspace_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_expected_version bigint, p_display_name text, p_change_public_id uuid)
 RETURNS TABLE(renamed_workspace_public_id uuid, previous_display_name text, renamed_display_name text, renamed_display_code text, renamed_version bigint, workspace_owner_authority_generation bigint, membership_authority_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
 SET join_collapse_limit TO '1'
 SET from_collapse_limit TO '1'
 SET plan_cache_mode TO 'force_generic_plan'
AS $function$
DECLARE
    selected RECORD;
    identifier UUID;
    scoped_workspace_id BIGINT;
    previous_workspace TEXT;
    evaluated_at TIMESTAMPTZ:=pg_catalog.transaction_timestamp();
BEGIN
    FOREACH identifier IN ARRAY ARRAY[p_session_public_id,p_deployment_public_id,
      p_principal_public_id,p_identity_subject_public_id,p_workspace_public_id,p_change_public_id] LOOP
      IF identifier IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(identifier),6)>>4<>7 THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid Workspace rename input';
      END IF;
    END LOOP;
    IF p_expected_version IS NULL OR p_expected_version<=0 OR p_expected_version=9223372036854775807
      OR p_session_version IS NULL OR p_session_version<=0
      OR p_principal_authority_generation IS NULL OR p_principal_authority_generation<=0
      OR p_account_session_generation IS NULL OR p_account_session_generation<=0
      OR p_provider_generation IS NULL OR p_provider_generation<=0
      OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch<=0
      OR p_display_name IS NULL OR pg_catalog.octet_length(p_display_name) NOT BETWEEN 1 AND 128
      OR p_display_name<>pg_catalog.btrim(p_display_name) OR p_display_name ~ '[[:cntrl:]]' THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid Workspace rename input';
    END IF;
    previous_workspace:=pg_catalog.current_setting('mesh.requested_workspace_public_id',TRUE);
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id',p_workspace_public_id::TEXT,TRUE);
    -- This exact-ID selection establishes RLS scope, not authority.
    SELECT workspace.id INTO scoped_workspace_id FROM mesh.workspace AS workspace
      WHERE workspace.public_id=p_workspace_public_id;
    IF scoped_workspace_id IS NULL THEN
      PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id',COALESCE(previous_workspace,''),TRUE);
      RETURN;
    END IF;
    IF COALESCE(pg_catalog.current_setting('mesh.workspace_id',TRUE),'')<>''
      AND mesh_ops.current_workspace_id()<>scoped_workspace_id THEN
      RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Workspace scope cannot be replaced';
    END IF;
    PERFORM pg_catalog.set_config('mesh.workspace_id',scoped_workspace_id::TEXT,TRUE);
    PERFORM workspace.id FROM mesh.workspace AS workspace
      WHERE workspace.id=scoped_workspace_id FOR NO KEY UPDATE;
    SELECT workspace.id,workspace.version,workspace.display_name,
      workspace.authority_generation AS owner_generation,
      membership.authority_generation AS membership_generation,
      session.authentication_time,session.idle_expires_at,session.absolute_expires_at,
      membership.valid_from,membership.expires_at,workspace.updated_at
    INTO selected
    FROM mesh.account_session AS session
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
     AND workspace.public_id = p_workspace_public_id
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = session.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = session.principal_id
    JOIN mesh.permission AS permission
      ON permission.permission_key = 'workspace.update'
     AND 'workspace' = ANY(permission.allowed_scope_kinds)
    WHERE session.public_id = p_session_public_id
      AND deployment.installation_public_id = p_deployment_public_id
      AND principal.public_id = p_principal_public_id
      AND subject.public_id = p_identity_subject_public_id
      AND session.version = p_session_version
      AND session.principal_authority_generation = p_principal_authority_generation
      AND session.account_session_generation = p_account_session_generation
      AND session.provider_generation = p_provider_generation
      AND session.deployment_recovery_epoch = p_deployment_recovery_epoch
      AND session.state = 'active'
      AND session.authentication_time <= evaluated_at
      AND session.idle_expires_at > evaluated_at
      AND session.absolute_expires_at > evaluated_at
      AND deployment.state = 'active'
      AND deployment.deleted_at IS NULL
      AND deployment.recovery_state = 'verified'
      AND deployment.recovery_epoch = p_deployment_recovery_epoch
      AND principal.state = 'active'
      AND principal.deleted_at IS NULL
      AND principal.kind = 'account'
      AND session.login_workspace_id = workspace.id
      AND workspace.owner_principal_id = principal.id
      AND principal.authority_generation = p_principal_authority_generation
      AND account.recovery_state = 'verified'
      AND account.session_generation = p_account_session_generation
      AND subject.state = 'active'
      AND provider.state = 'active'
      AND provider.recovery_state = 'verified'
      AND provider.current_generation = p_provider_generation
      AND client.state = 'active'
      AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL
      AND membership.state = 'active'
      AND membership.valid_from <= evaluated_at
      AND (membership.expires_at IS NULL OR membership.expires_at > evaluated_at)
    LIMIT 1
    FOR UPDATE OF workspace
    FOR SHARE OF session, deployment, principal, account, subject, provider, client, membership, permission;

    IF selected.id IS NULL THEN
      PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id',COALESCE(previous_workspace,''),TRUE);
      RETURN;
    END IF;
    IF selected.version<>p_expected_version THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Workspace version changed';
    END IF;
    IF COALESCE(pg_catalog.current_setting('mesh.workspace_id',TRUE),'')<>''
      AND mesh_ops.current_workspace_id()<>selected.id THEN
      RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Workspace scope cannot be replaced';
    END IF;
    PERFORM pg_catalog.set_config('mesh.workspace_id',selected.id::TEXT,TRUE);
    -- All authority and audit-head locks precede the final expiry decision.
    PERFORM head.stream_internal_id FROM mesh_audit.lock_workspace_stream_head(p_deployment_public_id, p_workspace_public_id) AS head;
    evaluated_at:=pg_catalog.clock_timestamp();
    IF selected.authentication_time>evaluated_at OR selected.idle_expires_at<=evaluated_at
      OR selected.absolute_expires_at<=evaluated_at OR selected.valid_from>evaluated_at
      OR (selected.expires_at IS NOT NULL AND selected.expires_at<=evaluated_at) THEN
      RETURN;
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id',p_change_public_id::TEXT,TRUE);
    UPDATE mesh.workspace AS workspace SET display_name=p_display_name,
      name_key=pg_catalog.lower(p_display_name),version=version+1,updated_at=GREATEST(selected.updated_at,evaluated_at)
    WHERE workspace.id=selected.id AND workspace.version=p_expected_version;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Workspace version changed'; END IF;
    SELECT identity.display_code INTO STRICT renamed_display_code
      FROM mesh_ops.tenant_display_identity AS identity WHERE identity.workspace_public_id=p_workspace_public_id;
    renamed_workspace_public_id:=p_workspace_public_id;
    previous_display_name:=selected.display_name;
    renamed_display_name:=p_display_name;
    renamed_version:=p_expected_version+1;
    workspace_owner_authority_generation:=selected.owner_generation;
    membership_authority_generation:=selected.membership_generation;
    RETURN NEXT;
END;
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.assign_workspace_role_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_assignment_public_id uuid, p_target_principal_public_id uuid, p_role_key text, p_network_public_id uuid, p_expires_at timestamp with time zone, p_change_public_id uuid)
 RETURNS TABLE(assignment_public_id uuid, assignment_version bigint, assignment_valid_from timestamp with time zone, assignment_created_at timestamp with time zone, replayed boolean, actor_binding_public_id uuid, actor_role_public_id uuid, actor_binding_generation bigint, actor_membership_generation bigint, actor_owner_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
AS $function$
DECLARE
    identifier UUID;
    scoped_workspace_id BIGINT;
    actor RECORD;
    actor_principal_id BIGINT;
    target RECORD;
    role RECORD;
    target_network_id BIGINT;
    existing mesh.workspace_role_assignment%ROWTYPE;
    evaluated_at TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    FOREACH identifier IN ARRAY ARRAY[p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_workspace_public_id, p_assignment_public_id,
        p_target_principal_public_id, p_change_public_id] LOOP
        IF identifier IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(identifier), 6) >> 4 <> 7 THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Workspace role assignment input';
        END IF;
    END LOOP;
    IF p_role_key IS NULL OR (p_expires_at IS NOT NULL AND NOT pg_catalog.isfinite(p_expires_at))
        OR (p_network_public_id IS NOT NULL
            AND pg_catalog.get_byte(pg_catalog.uuid_send(p_network_public_id), 6) >> 4 <> 7) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Workspace role assignment input';
    END IF;
    SELECT * INTO role FROM mesh.builtin_role WHERE builtin_role.role_key = p_role_key;
    IF role.role_key IS NULL OR (p_network_public_id IS NOT NULL AND NOT role.network_scope_allowed) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Workspace role or scope';
    END IF;

    scoped_workspace_id := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF scoped_workspace_id IS NULL
        OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, scoped_workspace_id) THEN
        RETURN;
    END IF;
    -- Role changes in one Workspace are serialized by its row lock.
    PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = scoped_workspace_id FOR NO KEY UPDATE;
    PERFORM head.stream_internal_id FROM mesh_audit.lock_workspace_stream_head(p_deployment_public_id, p_workspace_public_id) AS head;
    evaluated_at := pg_catalog.clock_timestamp();
    SELECT * INTO actor FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'role_binding.manage', evaluated_at
    );
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT principal.id INTO STRICT actor_principal_id
    FROM mesh.principal AS principal WHERE principal.public_id = p_principal_public_id;
    IF NOT (role.assignable_by && mesh_ops.workspace_role_assigners_v1(
        scoped_workspace_id, actor_principal_id, evaluated_at)) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'role exceeds the delegation ceiling';
    END IF;

    SELECT principal.id AS principal_id, principal.deployment_id, membership.id AS membership_id,
        workspace.owner_principal_id = principal.id AS is_owner
    INTO target
    FROM mesh.principal AS principal
    JOIN mesh.workspace AS workspace ON workspace.id = scoped_workspace_id
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = principal.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = principal.id
    WHERE principal.public_id = p_target_principal_public_id
      AND principal.state = 'active'
      AND principal.kind = 'account'
      AND principal.deleted_at IS NULL
      AND membership.state = 'active'
      AND membership.valid_from <= evaluated_at
      AND (membership.expires_at IS NULL OR membership.expires_at > evaluated_at)
    FOR SHARE OF principal, membership;
    IF target.principal_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Workspace member is unavailable';
    END IF;
    IF target.principal_id = actor_principal_id THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'members cannot change their own roles';
    END IF;
    IF target.is_owner THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'the owner holds every Workspace permission';
    END IF;
    IF p_network_public_id IS NOT NULL THEN
        -- Resolve the exact Network, then enter its scope so the row lock is
        -- permitted; a scope already set to another Network is never replaced.
        PERFORM pg_catalog.set_config('mesh.requested_network_public_id', p_network_public_id::TEXT, TRUE);
        SELECT network.id INTO target_network_id
        FROM mesh.network AS network
        WHERE network.workspace_id = scoped_workspace_id
          AND network.public_id = p_network_public_id;
        IF target_network_id IS NOT NULL THEN
            IF COALESCE(pg_catalog.current_setting('mesh.network_id', TRUE), '') <> ''
                AND mesh_ops.current_network_id() <> target_network_id THEN
                RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network scope cannot be replaced';
            END IF;
            PERFORM pg_catalog.set_config('mesh.network_id', target_network_id::TEXT, TRUE);
            SELECT network.id INTO target_network_id
            FROM mesh.network AS network
            WHERE network.id = target_network_id AND network.state = 'active'
            FOR SHARE;
        END IF;
        IF target_network_id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Network is unavailable';
        END IF;
    END IF;
    IF p_expires_at IS NOT NULL AND p_expires_at <= evaluated_at THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'role assignment expiry is in the past';
    END IF;

    actor_binding_public_id := actor.role_binding_public_id;
    actor_role_public_id := actor.role_definition_public_id;
    actor_binding_generation := actor.binding_authority_generation;
    actor_membership_generation := actor.membership_authority_generation;
    actor_owner_generation := actor.workspace_owner_authority_generation;

    -- The client-chosen ID makes a retried request converge on one assignment.
    SELECT * INTO existing FROM mesh.workspace_role_assignment AS assignment
    WHERE assignment.public_id = p_assignment_public_id;
    IF existing.id IS NOT NULL THEN
        IF existing.workspace_id <> scoped_workspace_id OR existing.principal_id <> target.principal_id
            OR existing.role_key <> p_role_key OR existing.network_id IS DISTINCT FROM target_network_id
            OR existing.expires_at IS DISTINCT FROM p_expires_at THEN
            RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'role assignment ID was used for another request';
        END IF;
        assignment_public_id := existing.public_id;
        assignment_version := existing.version;
        assignment_valid_from := existing.valid_from;
        assignment_created_at := existing.created_at;
        replayed := TRUE;
        RETURN NEXT;
        RETURN;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh.workspace_role_assignment (
        public_id, deployment_id, workspace_id, network_id, principal_id, workspace_membership_id,
        role_key, state, valid_from, expires_at, created_at, updated_at
    ) VALUES (
        p_assignment_public_id, target.deployment_id, scoped_workspace_id, target_network_id,
        target.principal_id, target.membership_id, p_role_key, 'active', evaluated_at, p_expires_at,
        evaluated_at, evaluated_at
    )
    RETURNING public_id, version, valid_from, created_at
    INTO assignment_public_id, assignment_version, assignment_valid_from, assignment_created_at;
    replayed := FALSE;
    RETURN NEXT;
END;
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.revoke_workspace_role_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_assignment_public_id uuid, p_expected_version bigint, p_change_public_id uuid)
 RETURNS TABLE(assignment_public_id uuid, assignment_version bigint, assignment_role_key text, target_principal_public_id uuid, revoked_at timestamp with time zone, replayed boolean, actor_binding_public_id uuid, actor_role_public_id uuid, actor_binding_generation bigint, actor_membership_generation bigint, actor_owner_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
AS $function$
DECLARE
    identifier UUID;
    scoped_workspace_id BIGINT;
    actor RECORD;
    actor_principal_id BIGINT;
    existing mesh.workspace_role_assignment%ROWTYPE;
    role RECORD;
    evaluated_at TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    FOREACH identifier IN ARRAY ARRAY[p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_workspace_public_id, p_assignment_public_id, p_change_public_id] LOOP
        IF identifier IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(identifier), 6) >> 4 <> 7 THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Workspace role revocation input';
        END IF;
    END LOOP;
    IF p_expected_version IS NULL OR p_expected_version <= 0 OR p_expected_version = 9223372036854775807 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Workspace role revocation input';
    END IF;

    scoped_workspace_id := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF scoped_workspace_id IS NULL
        OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, scoped_workspace_id) THEN
        RETURN;
    END IF;
    PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = scoped_workspace_id FOR NO KEY UPDATE;
    PERFORM head.stream_internal_id FROM mesh_audit.lock_workspace_stream_head(p_deployment_public_id, p_workspace_public_id) AS head;
    evaluated_at := pg_catalog.clock_timestamp();
    SELECT * INTO actor FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'role_binding.manage', evaluated_at
    );
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT principal.id INTO STRICT actor_principal_id
    FROM mesh.principal AS principal WHERE principal.public_id = p_principal_public_id;

    SELECT * INTO existing FROM mesh.workspace_role_assignment AS assignment
    WHERE assignment.public_id = p_assignment_public_id
      AND assignment.workspace_id = scoped_workspace_id
    FOR UPDATE;
    IF existing.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'role assignment is unavailable';
    END IF;
    SELECT * INTO role FROM mesh.builtin_role WHERE builtin_role.role_key = existing.role_key;
    IF NOT (role.assignable_by && mesh_ops.workspace_role_assigners_v1(
        scoped_workspace_id, actor_principal_id, evaluated_at)) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'role exceeds the delegation ceiling';
    END IF;
    IF existing.principal_id = actor_principal_id THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'members cannot change their own roles';
    END IF;

    actor_binding_public_id := actor.role_binding_public_id;
    actor_role_public_id := actor.role_definition_public_id;
    actor_binding_generation := actor.binding_authority_generation;
    actor_membership_generation := actor.membership_authority_generation;
    actor_owner_generation := actor.workspace_owner_authority_generation;
    assignment_public_id := existing.public_id;
    assignment_role_key := existing.role_key;
    SELECT principal.public_id INTO STRICT target_principal_public_id
    FROM mesh.principal AS principal WHERE principal.id = existing.principal_id;

    -- A retried revocation of the reviewed version converges on its result.
    IF existing.state = 'revoked' THEN
        IF existing.version <> p_expected_version + 1 THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'role assignment changed';
        END IF;
        assignment_version := existing.version;
        revoked_at := existing.revoked_at;
        replayed := TRUE;
        RETURN NEXT;
        RETURN;
    END IF;
    IF existing.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'role assignment changed';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.workspace_role_assignment AS assignment
    SET state = 'revoked', revoked_at = evaluated_at,
        updated_at = GREATEST(existing.updated_at, evaluated_at),
        version = assignment.version + 1, authority_generation = assignment.authority_generation + 1
    WHERE assignment.id = existing.id
    RETURNING assignment.version, assignment.revoked_at INTO assignment_version, revoked_at;
    replayed := FALSE;
    RETURN NEXT;
END;
$function$
;

CREATE FUNCTION mesh_ops.deployment_audit_events_v1()
RETURNS BIGINT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT COALESCE(pg_catalog.sum(stream.next_sequence - 1), 0)::BIGINT
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.scope_kind = 'deployment'
$function$;
REVOKE ALL ON FUNCTION mesh_ops.deployment_audit_events_v1() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mesh_ops.deployment_audit_events_v1() TO mesh_worker;
