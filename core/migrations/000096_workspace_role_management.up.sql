-- Schema 96 adds the Workspace member and role management entry points for
-- ADR-050 D6. Every call is bound to the Session's login Workspace, resolves
-- Workspace authority through resolve_workspace_permission_v1, and enforces the
-- delegation ceiling: an assigner is the owner or a holder of a Workspace-scope
-- admin/it_admin assignment named in builtin_role.assignable_by. Nobody changes
-- their own roles and the owner is never assigned a role. Writes lock the
-- Workspace first and the deployment audit stream before the final decision;
-- the application appends the audit and outbox evidence in the same commit.

-- Internal: the assigner identities a Principal holds in a Workspace now.
CREATE FUNCTION mesh_ops.workspace_role_assigners_v1(
    p_workspace_id BIGINT,
    p_principal_id BIGINT,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS TEXT[]
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
    SELECT COALESCE(pg_catalog.array_agg(assigner ORDER BY assigner), ARRAY[]::TEXT[])
    FROM (
        SELECT 'owner' AS assigner
        FROM mesh.workspace AS workspace
        WHERE workspace.id = p_workspace_id AND workspace.owner_principal_id = p_principal_id
        UNION
        SELECT assignment.role_key
        FROM mesh.workspace_role_assignment AS assignment
        JOIN mesh.workspace_membership AS membership
          ON membership.id = assignment.workspace_membership_id
         AND membership.state = 'active'
         AND membership.valid_from <= p_evaluated_at
         AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
        WHERE assignment.workspace_id = p_workspace_id
          AND assignment.principal_id = p_principal_id
          AND assignment.network_id IS NULL
          AND assignment.role_key IN ('admin', 'it_admin')
          AND assignment.state = 'active'
          AND assignment.valid_from <= p_evaluated_at
          AND (assignment.expires_at IS NULL OR assignment.expires_at > p_evaluated_at)
    ) AS assigners;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.workspace_role_assigners_v1(BIGINT, BIGINT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Internal: establish the exact Workspace RLS scope for one call, or report the
-- Workspace as unavailable. A different scope already set in the transaction
-- is never replaced.
CREATE FUNCTION mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id UUID)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
BEGIN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', p_workspace_public_id::TEXT, TRUE);
    SELECT workspace.id INTO scoped_workspace_id
    FROM mesh.workspace AS workspace
    WHERE workspace.public_id = p_workspace_public_id;
    IF scoped_workspace_id IS NULL THEN
        RETURN NULL;
    END IF;
    IF COALESCE(pg_catalog.current_setting('mesh.workspace_id', TRUE), '') <> ''
        AND mesh_ops.current_workspace_id() <> scoped_workspace_id THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Workspace scope cannot be replaced';
    END IF;
    PERFORM pg_catalog.set_config('mesh.workspace_id', scoped_workspace_id::TEXT, TRUE);
    RETURN scoped_workspace_id;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enter_workspace_management_scope_v1(UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Internal: the Session must be bound to the Workspace it manages.
CREATE FUNCTION mesh_ops.session_bound_to_workspace_v1(p_session_public_id UUID, p_workspace_id BIGINT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
    SELECT EXISTS (
        SELECT 1 FROM mesh.account_session AS session
        WHERE session.public_id = p_session_public_id
          AND session.login_workspace_id = p_workspace_id
    );
$function$;
REVOKE ALL ON FUNCTION mesh_ops.session_bound_to_workspace_v1(UUID, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.list_workspace_members_v1(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    evaluated_at TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    scoped_workspace_id BIGINT;
    result JSONB;
BEGIN
    scoped_workspace_id := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF scoped_workspace_id IS NULL
        OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, scoped_workspace_id) THEN
        RETURN NULL;
    END IF;
    PERFORM 1 FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'member.read', evaluated_at
    );
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT pg_catalog.jsonb_build_object(
        'workspace_id', workspace.public_id,
        'workspace_version', workspace.version,
        'truncated', (SELECT pg_catalog.count(*) > 1000 FROM mesh.workspace_membership AS counted
            WHERE counted.workspace_id = workspace.id AND counted.state <> 'revoked'),
        'members', COALESCE((
            SELECT pg_catalog.jsonb_agg(member.payload ORDER BY member.sort_name, member.principal_public_id)
            FROM (
                SELECT
                    pg_catalog.lower(account.display_name) AS sort_name,
                    principal.public_id AS principal_public_id,
                    pg_catalog.jsonb_build_object(
                        'principal_id', principal.public_id,
                        'display_name', account.display_name,
                        'membership_state', membership.state,
                        'membership_expires_at', membership.expires_at,
                        'owner', workspace.owner_principal_id = principal.id,
                        'role_assignments', COALESCE((
                            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                                'assignment_id', assignment.public_id,
                                'role', assignment.role_key,
                                'network_id', network.public_id,
                                'expires_at', assignment.expires_at,
                                'version', assignment.version,
                                'created_at', assignment.created_at
                            ) ORDER BY assignment.role_key, network.public_id NULLS FIRST, assignment.public_id)
                            FROM mesh.workspace_role_assignment AS assignment
                            LEFT JOIN mesh.network AS network
                              ON network.workspace_id = assignment.workspace_id
                             AND network.id = assignment.network_id
                            WHERE assignment.workspace_id = workspace.id
                              AND assignment.workspace_membership_id = membership.id
                              AND assignment.state = 'active'
                        ), '[]'::JSONB)
                    ) AS payload
                FROM mesh.workspace_membership AS membership
                JOIN mesh.principal AS principal
                  ON principal.deployment_id = membership.deployment_id
                 AND principal.id = membership.principal_id
                JOIN mesh.account AS account
                  ON account.deployment_id = principal.deployment_id
                 AND account.principal_id = principal.id
                WHERE membership.workspace_id = workspace.id
                  AND membership.state <> 'revoked'
                  AND principal.deleted_at IS NULL
                ORDER BY pg_catalog.lower(account.display_name), principal.public_id
                LIMIT 1000
            ) AS member
        ), '[]'::JSONB)
    ) INTO result
    FROM mesh.workspace AS workspace
    WHERE workspace.id = scoped_workspace_id;
    RETURN result;
END;
$function$;

CREATE FUNCTION mesh_ops.assign_workspace_role_v1(
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
    p_assignment_public_id UUID,
    p_target_principal_public_id UUID,
    p_role_key TEXT,
    p_network_public_id UUID,
    p_expires_at TIMESTAMPTZ,
    p_change_public_id UUID
)
RETURNS TABLE (
    assignment_public_id UUID,
    assignment_version BIGINT,
    assignment_valid_from TIMESTAMPTZ,
    assignment_created_at TIMESTAMPTZ,
    replayed BOOLEAN,
    actor_binding_public_id UUID,
    actor_role_public_id UUID,
    actor_binding_generation BIGINT,
    actor_membership_generation BIGINT,
    actor_owner_generation BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
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
    PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = scoped_workspace_id FOR UPDATE;
    PERFORM head.stream_internal_id FROM mesh_audit.lock_deployment_stream_head(p_deployment_public_id) AS head;
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
$function$;

CREATE FUNCTION mesh_ops.revoke_workspace_role_v1(
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
    p_assignment_public_id UUID,
    p_expected_version BIGINT,
    p_change_public_id UUID
)
RETURNS TABLE (
    assignment_public_id UUID,
    assignment_version BIGINT,
    assignment_role_key TEXT,
    target_principal_public_id UUID,
    revoked_at TIMESTAMPTZ,
    replayed BOOLEAN,
    actor_binding_public_id UUID,
    actor_role_public_id UUID,
    actor_binding_generation BIGINT,
    actor_membership_generation BIGINT,
    actor_owner_generation BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
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
    PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = scoped_workspace_id FOR UPDATE;
    PERFORM head.stream_internal_id FROM mesh_audit.lock_deployment_stream_head(p_deployment_public_id) AS head;
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
$function$;

REVOKE ALL ON FUNCTION mesh_ops.list_workspace_members_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.assign_workspace_role_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, TEXT, UUID, TIMESTAMPTZ, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.revoke_workspace_role_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_workspace_members_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.assign_workspace_role_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, TEXT, UUID, TIMESTAMPTZ, UUID
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.revoke_workspace_role_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT, UUID
) TO mesh_runtime;
