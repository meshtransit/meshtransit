-- The Workspace row is locked FOR NO KEY UPDATE, not FOR UPDATE.
--
-- These functions lock their Workspace row to serialize Workspace changes
-- (members, roles, invitations, Networks, groups, tags, relays). FOR UPDATE
-- also blocks every foreign key check on the row, and every audit event,
-- outbox event, session and Network row references its Workspace. A
-- function holding the Workspace that then waits for a Network revision
-- (removing a member from a Workspace or a Network) deadlocks with a share
-- or registration that holds that revision and inserts its audit event:
-- 40P01, as schema 167 found for guardrail changes.
--
-- FOR NO KEY UPDATE still conflicts with itself, FOR UPDATE and FOR SHARE,
-- so these functions stay serialized with each other and with the readers
-- that take the Workspace FOR SHARE (sign-in, resources, approvals). Only
-- FOR KEY SHARE, which foreign key checks take, no longer waits. No function
-- here changes a Workspace key. Bodies are otherwise unchanged; CREATE OR
-- REPLACE keeps owners and grants.

CREATE OR REPLACE FUNCTION mesh_ops.accept_workspace_invitation_v1(p_deployment_public_id uuid, p_provider_public_id uuid, p_client_public_id uuid, p_provider_generation bigint, p_recovery_epoch bigint, p_transaction_public_id uuid, p_transaction_version bigint, p_binding_hash bytea, p_consumed_at timestamp with time zone, p_subject_algorithm text, p_active_key_id text, p_active_digest bytea, p_previous_key_id text, p_previous_digest bytea, p_token_digest bytea, p_change_public_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
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
    FOR NO KEY UPDATE OF workspace;
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
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.add_network_members_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_member_public_ids uuid[], p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
 SET join_collapse_limit TO '1'
 SET from_collapse_limit TO '1'
 SET plan_cache_mode TO 'force_generic_plan'
AS $function$
DECLARE
    v_scope RECORD;
    v_grant RECORD;
    v_added JSONB;
    v_unchanged JSONB;
    v_revision BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_member_public_ids IS NULL OR pg_catalog.array_ndims(p_member_public_ids) IS DISTINCT FROM 1
        OR pg_catalog.cardinality(p_member_public_ids) NOT BETWEEN 1 AND 150
        OR pg_catalog.array_position(p_member_public_ids, NULL) IS NOT NULL
        OR (SELECT pg_catalog.count(DISTINCT member.id) FROM pg_catalog.unnest(p_member_public_ids) AS member(id))
           <> pg_catalog.cardinality(p_member_public_ids)
        OR p_change_public_id IS NULL OR p_evaluated_at IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network member addition is invalid';
    END IF;
    SELECT * INTO v_scope FROM mesh_ops.network_member_scope_internal_v1(
        p_session_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network member addition is not authorized';
    END IF;
    -- Member changes in one Workspace are serialized by its row lock, taken
    -- before any Network revision.
    PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = v_scope.workspace_id FOR NO KEY UPDATE;
    SELECT * INTO v_grant FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.member.manage', v_now
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network member addition is not authorized';
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_catalog.unnest(p_member_public_ids) AS requested(id)
        WHERE NOT EXISTS (
            SELECT 1 FROM mesh.principal AS principal
            JOIN mesh.workspace_membership AS membership
              ON membership.workspace_id = v_scope.workspace_id AND membership.principal_id = principal.id
             AND membership.state <> 'revoked'
            WHERE principal.deployment_id = v_scope.deployment_id AND principal.public_id = requested.id
              AND principal.kind = 'account' AND principal.deleted_at IS NULL
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Workspace member is unavailable';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.unnest(p_member_public_ids) AS requested(id)
        JOIN mesh.principal AS principal
          ON principal.deployment_id = v_scope.deployment_id AND principal.public_id = requested.id
        JOIN mesh.workspace_membership AS membership
          ON membership.workspace_id = v_scope.workspace_id AND membership.principal_id = principal.id
         AND membership.state <> 'revoked'
        WHERE membership.state <> 'active' OR principal.state <> 'active'
           OR (membership.expires_at IS NOT NULL AND membership.expires_at <= v_now)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTM01', MESSAGE = 'a suspended Workspace member cannot join a Network';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    WITH inserted AS (
        INSERT INTO mesh.network_membership (
            public_id, deployment_id, workspace_id, network_id, principal_id, workspace_membership_id,
            state, valid_from, created_at, updated_at
        )
        SELECT pg_catalog.uuidv7(), v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id,
            principal.id, membership.id, 'active', v_now, v_now, v_now
        FROM pg_catalog.unnest(p_member_public_ids) WITH ORDINALITY AS requested(id, position)
        JOIN mesh.principal AS principal
          ON principal.deployment_id = v_scope.deployment_id AND principal.public_id = requested.id
        JOIN mesh.workspace_membership AS membership
          ON membership.workspace_id = v_scope.workspace_id AND membership.principal_id = principal.id
         AND membership.state = 'active'
        WHERE NOT EXISTS (
            SELECT 1 FROM mesh.network_membership AS existing
            WHERE existing.workspace_id = v_scope.workspace_id AND existing.network_id = v_scope.network_id
              AND existing.principal_id = principal.id AND existing.state <> 'revoked'
        )
        ORDER BY requested.position
        RETURNING public_id, principal_id, state, version, valid_from
    )
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'membership_id', inserted.public_id, 'principal_id', principal.public_id,
               'state', inserted.state, 'version', inserted.version, 'added_at', inserted.valid_from
           ) ORDER BY principal.public_id)
    INTO v_added
    FROM inserted
    JOIN mesh.principal AS principal ON principal.id = inserted.principal_id;
    SELECT pg_catalog.jsonb_agg(requested.id ORDER BY requested.id)
    INTO v_unchanged
    FROM pg_catalog.unnest(p_member_public_ids) AS requested(id)
    WHERE NOT EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_array_elements(COALESCE(v_added, '[]'::JSONB)) AS added(value)
        WHERE (added.value ->> 'principal_id')::UUID = requested.id
    );
    SELECT revision.network_revision INTO STRICT v_revision FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id;

    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', v_revision,
        'added', COALESCE(v_added, '[]'::JSONB),
        'unchanged', COALESCE(v_unchanged, '[]'::JSONB),
        'authority', pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
            'binding_id', v_grant.role_binding_public_id,
            'role_id', v_grant.role_definition_public_id,
            'binding_generation', COALESCE(v_grant.binding_authority_generation, 0),
            'membership_generation', COALESCE(v_grant.membership_authority_generation, 0),
            'owner_generation', COALESCE(v_grant.workspace_owner_authority_generation, 0)
        ))
    );
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
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.change_device_tag_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_operation text, p_tag_public_id uuid, p_expected_version bigint, p_name text, p_description text, p_owner_group_ids uuid[], p_owner_roles text[], p_owner_row_ids uuid[], p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    v_scope RECORD;
    v_tag mesh.device_tag%ROWTYPE;
    v_before JSONB;
    v_networks BIGINT[];
    v_advanced JSONB := '[]'::JSONB;
    v_owner_count INTEGER;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_operation NOT IN ('create', 'update', 'delete') OR p_tag_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_tag_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version < 1))
        OR (p_operation <> 'delete' AND (
            p_name IS NULL OR p_description IS NULL OR p_owner_group_ids IS NULL OR p_owner_roles IS NULL
            OR p_owner_row_ids IS NULL
            OR pg_catalog.cardinality(p_owner_group_ids) + pg_catalog.cardinality(p_owner_roles) > 32
            OR pg_catalog.cardinality(p_owner_row_ids)
               <> pg_catalog.cardinality(p_owner_group_ids) + pg_catalog.cardinality(p_owner_roles)
            OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p_owner_row_ids) AS row_id(id)
                       WHERE row_id.id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(row_id.id), 6) >> 4 <> 7)
            OR (SELECT pg_catalog.count(DISTINCT owner_group.id) FROM pg_catalog.unnest(p_owner_group_ids) AS owner_group(id))
               <> pg_catalog.cardinality(p_owner_group_ids)
            OR (SELECT pg_catalog.count(DISTINCT owner_role.key) FROM pg_catalog.unnest(p_owner_roles) AS owner_role(key))
               <> pg_catalog.cardinality(p_owner_roles)
        )) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'device tag change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_identity_catalog_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'device_tag.manage', pg_catalog.transaction_timestamp()
    );
    IF p_operation <> 'delete' THEN
        SELECT pg_catalog.count(*)::INTEGER INTO v_owner_count
        FROM pg_catalog.unnest(p_owner_group_ids) AS owner_group(id)
        JOIN mesh.identity_group AS identity_group
          ON identity_group.workspace_id = v_scope.workspace_id AND identity_group.public_id = owner_group.id
         AND identity_group.state = 'active';
        IF v_owner_count <> pg_catalog.cardinality(p_owner_group_ids)
            OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p_owner_roles) AS owner_role(key)
                       WHERE NOT EXISTS (SELECT 1 FROM mesh.builtin_role AS role
                                         WHERE role.role_key = owner_role.key)) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTT03', MESSAGE = 'a tag owner is not in this Workspace';
        END IF;
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    IF p_operation = 'create' THEN
        PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = v_scope.workspace_id FOR NO KEY UPDATE;
        IF (SELECT pg_catalog.count(*) FROM mesh.device_tag AS tag
            WHERE tag.workspace_id = v_scope.workspace_id AND tag.state = 'active') >= 200 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTT02', MESSAGE = 'Workspace already has the maximum device tags';
        END IF;
        BEGIN
            INSERT INTO mesh.device_tag (public_id, deployment_id, workspace_id, name, description, created_at, updated_at)
            VALUES (p_tag_public_id, v_scope.deployment_id, v_scope.workspace_id, p_name, p_description, v_now, v_now)
            RETURNING * INTO v_tag;
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION USING ERRCODE = 'MTT04', MESSAGE = 'device tag name is taken';
        END;
    ELSE
        SELECT * INTO v_tag FROM mesh.device_tag AS tag
        WHERE tag.workspace_id = v_scope.workspace_id AND tag.public_id = p_tag_public_id AND tag.state = 'active'
        FOR UPDATE;
        IF v_tag.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'device tag is unavailable';
        END IF;
        IF v_tag.version <> p_expected_version THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'device tag version changed';
        END IF;
        v_before := mesh_ops.device_tag_document_internal_v1(v_tag);
        DELETE FROM mesh.device_tag_owner WHERE device_tag_id = v_tag.id;
        IF p_operation = 'update' THEN
            BEGIN
                UPDATE mesh.device_tag
                SET name = p_name, description = p_description, version = version + 1,
                    updated_at = GREATEST(v_now, updated_at)
                WHERE id = v_tag.id
                RETURNING * INTO v_tag;
            EXCEPTION WHEN unique_violation THEN
                RAISE EXCEPTION USING ERRCODE = 'MTT04', MESSAGE = 'device tag name is taken';
            END;
        ELSE
            IF mesh_ops.device_tag_rule_count_internal_v1(v_tag.id) > 0 THEN
                RAISE EXCEPTION USING ERRCODE = 'MTT05', MESSAGE = 'device tag is selected by active rules';
            END IF;
            SELECT pg_catalog.array_agg(DISTINCT assignment.network_id ORDER BY assignment.network_id)
            INTO v_networks
            FROM mesh.device_tag_assignment AS assignment WHERE assignment.device_tag_id = v_tag.id;
            DELETE FROM mesh.device_tag_assignment WHERE device_tag_id = v_tag.id;
            IF v_networks IS NOT NULL THEN
                v_advanced := mesh_ops.advance_identity_networks_internal_v1(v_scope.workspace_id, v_networks);
            END IF;
            UPDATE mesh.device_tag
            SET state = 'deleted', deleted_at = GREATEST(v_now, updated_at), version = version + 1,
                updated_at = GREATEST(v_now, updated_at)
            WHERE id = v_tag.id
            RETURNING * INTO v_tag;
        END IF;
    END IF;
    IF p_operation <> 'delete' THEN
        INSERT INTO mesh.device_tag_owner (public_id, workspace_id, device_tag_id, identity_group_id, role_key, created_at)
        SELECT owner.row_id, v_scope.workspace_id, v_tag.id, owner.group_id, owner.role_key, v_now
        FROM (
            SELECT row_ids.id AS row_id, owners.group_id, owners.role_key
            FROM (
                SELECT identity_group.id AS group_id, NULL::TEXT AS role_key,
                       pg_catalog.row_number() OVER (ORDER BY identity_group.public_id::TEXT) AS ordinal
                FROM pg_catalog.unnest(p_owner_group_ids) AS owner_group(id)
                JOIN mesh.identity_group AS identity_group
                  ON identity_group.workspace_id = v_scope.workspace_id AND identity_group.public_id = owner_group.id
                UNION ALL
                SELECT NULL::BIGINT, owner_role.key,
                       pg_catalog.cardinality(p_owner_group_ids) + pg_catalog.row_number() OVER (ORDER BY owner_role.key)
                FROM pg_catalog.unnest(p_owner_roles) AS owner_role(key)
            ) AS owners
            JOIN pg_catalog.unnest(p_owner_row_ids) WITH ORDINALITY AS row_ids(id, ordinal)
              ON row_ids.ordinal = owners.ordinal
        ) AS owner;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'tag', mesh_ops.device_tag_document_internal_v1(v_tag),
        'previous', v_before,
        'networks', v_advanced,
        'authority', v_scope.authority);
END;
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.change_identity_group_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_operation text, p_group_public_id uuid, p_expected_version bigint, p_name text, p_description text, p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    v_scope RECORD;
    v_group mesh.identity_group%ROWTYPE;
    v_before JSONB;
    v_hash_before BYTEA;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_operation NOT IN ('create', 'update', 'delete') OR p_group_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version < 1))
        OR (p_operation <> 'delete' AND (p_name IS NULL OR p_description IS NULL)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Identity Group change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_identity_catalog_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'identity_group.manage', pg_catalog.transaction_timestamp()
    );
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    IF p_operation = 'create' THEN
        -- Serializes creations in one Workspace so the limit holds.
        PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = v_scope.workspace_id FOR NO KEY UPDATE;
        IF (SELECT pg_catalog.count(*) FROM mesh.identity_group AS identity_group
            WHERE identity_group.workspace_id = v_scope.workspace_id AND identity_group.state = 'active') >= 500 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTI02', MESSAGE = 'Workspace already has the maximum Identity Groups';
        END IF;
        BEGIN
            INSERT INTO mesh.identity_group (
                public_id, deployment_id, workspace_id, name, name_key, description, created_at, updated_at
            ) VALUES (
                p_group_public_id, v_scope.deployment_id, v_scope.workspace_id, p_name, pg_catalog.lower(p_name),
                p_description, v_now, v_now
            ) RETURNING * INTO v_group;
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION USING ERRCODE = 'MTI04', MESSAGE = 'Identity Group name is taken';
        END;
        RETURN pg_catalog.jsonb_build_object(
            'group', mesh_ops.identity_group_document_internal_v1(v_group),
            'previous', NULL,
            'member_hash_before', NULL,
            'member_hash_after', pg_catalog.encode(mesh_ops.identity_group_member_hash_internal_v1(v_group.id), 'hex'),
            'authority', v_scope.authority);
    END IF;

    SELECT * INTO v_group FROM mesh.identity_group AS identity_group
    WHERE identity_group.workspace_id = v_scope.workspace_id AND identity_group.public_id = p_group_public_id
      AND identity_group.state = 'active'
    FOR UPDATE;
    IF v_group.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Identity Group is unavailable';
    END IF;
    IF v_group.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Identity Group version changed';
    END IF;
    v_before := mesh_ops.identity_group_document_internal_v1(v_group);
    v_hash_before := mesh_ops.identity_group_member_hash_internal_v1(v_group.id);

    IF p_operation = 'update' THEN
        BEGIN
            UPDATE mesh.identity_group
            SET name = p_name, name_key = pg_catalog.lower(p_name), description = p_description,
                version = version + 1, updated_at = GREATEST(v_now, updated_at)
            WHERE id = v_group.id
            RETURNING * INTO v_group;
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION USING ERRCODE = 'MTI04', MESSAGE = 'Identity Group name is taken';
        END;
    ELSE
        IF mesh_ops.identity_group_rule_count_internal_v1(v_group.id) > 0
            OR EXISTS (SELECT 1 FROM mesh.device_tag_owner AS owner
                       JOIN mesh.device_tag AS tag ON tag.id = owner.device_tag_id AND tag.state = 'active'
                       WHERE owner.identity_group_id = v_group.id) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTI05', MESSAGE = 'Identity Group is selected by rules or owns tags';
        END IF;
        DELETE FROM mesh.identity_group_member WHERE identity_group_id = v_group.id;
        UPDATE mesh.identity_group
        SET state = 'deleted', member_count = 0, deleted_at = GREATEST(v_now, updated_at),
            version = version + 1, updated_at = GREATEST(v_now, updated_at)
        WHERE id = v_group.id
        RETURNING * INTO v_group;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'group', mesh_ops.identity_group_document_internal_v1(v_group),
        'previous', v_before,
        'member_hash_before', pg_catalog.encode(v_hash_before, 'hex'),
        'member_hash_after', pg_catalog.encode(mesh_ops.identity_group_member_hash_internal_v1(v_group.id), 'hex'),
        'authority', v_scope.authority);
END;
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.change_workspace_guardrail_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_operation text, p_guardrail_public_id uuid, p_expected_version bigint, p_kind text, p_name text, p_description text, p_mode text, p_params jsonb, p_semantic_hash bytea, p_network_public_ids uuid[], p_permission text, p_change_public_id uuid)
 RETURNS TABLE(guardrail jsonb, previous_semantic_hash bytea, actor_binding_public_id uuid, actor_role_public_id uuid, actor_binding_generation bigint, actor_membership_generation bigint, actor_owner_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
AS $function$
DECLARE
    identifier UUID;
    scoped_workspace_id BIGINT;
    deployment_internal_id BIGINT;
    actor RECORD;
    existing mesh.guardrail%ROWTYPE;
    saved mesh.guardrail%ROWTYPE;
    evaluated_at TIMESTAMPTZ;
BEGIN
    FOREACH identifier IN ARRAY ARRAY[p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_workspace_public_id, p_guardrail_public_id, p_change_public_id] LOOP
        IF identifier IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(identifier), 6) >> 4 <> 7 THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid guardrail change input';
        END IF;
    END LOOP;
    IF p_operation IS NULL OR p_operation NOT IN ('create', 'update', 'delete')
        OR p_permission IS NULL OR p_permission NOT IN ('guardrail.manage', 'guardrail.weaken')
        OR (p_operation = 'delete' AND p_permission <> 'guardrail.weaken')
        OR (p_operation = 'create' AND p_expected_version IS NOT NULL)
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version <= 0))
        OR (p_operation <> 'delete' AND (p_kind IS NULL OR p_name IS NULL OR p_description IS NULL
            OR p_mode IS NULL OR p_params IS NULL OR p_semantic_hash IS NULL
            OR p_network_public_ids IS NULL OR pg_catalog.cardinality(p_network_public_ids) > 256)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid guardrail change input';
    END IF;

    scoped_workspace_id := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF scoped_workspace_id IS NULL
        OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, scoped_workspace_id) THEN
        RETURN;
    END IF;
    -- The guardrail state row first, then the Workspace row: share and
    -- publication transactions hold the state row FOR SHARE and may then need
    -- the Workspace row (schema 163).
    PERFORM 1 FROM mesh.workspace_guardrail_state AS state
    WHERE state.workspace_id = scoped_workspace_id FOR UPDATE;
    SELECT workspace.deployment_id INTO deployment_internal_id
    FROM mesh.workspace AS workspace WHERE workspace.id = scoped_workspace_id FOR NO KEY UPDATE;
    evaluated_at := pg_catalog.clock_timestamp();
    SELECT * INTO actor FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_permission, evaluated_at
    );
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF p_operation <> 'delete' AND EXISTS (
        SELECT 1 FROM pg_catalog.unnest(p_network_public_ids) AS referenced(public_id)
        WHERE NOT EXISTS (
            SELECT 1 FROM mesh.network AS network
            WHERE network.workspace_id = scoped_workspace_id
              AND network.public_id = referenced.public_id
              AND network.deleted_at IS NULL
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTG01', MESSAGE = 'guardrail Network is not in the Workspace';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    IF p_operation = 'create' THEN
        IF (SELECT pg_catalog.count(*) FROM mesh.guardrail AS counted
            WHERE counted.workspace_id = scoped_workspace_id AND counted.state = 'active') >= 100 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTG02', MESSAGE = 'guardrail limit reached';
        END IF;
        INSERT INTO mesh.guardrail (
            public_id, deployment_id, workspace_id, kind, name, description, mode, params,
            semantic_hash, state, created_at, updated_at
        ) VALUES (
            p_guardrail_public_id, deployment_internal_id, scoped_workspace_id, p_kind, p_name,
            p_description, p_mode, p_params, p_semantic_hash, 'active', evaluated_at, evaluated_at
        ) RETURNING * INTO saved;
    ELSE
        SELECT * INTO existing FROM mesh.guardrail AS current
        WHERE current.public_id = p_guardrail_public_id
          AND current.workspace_id = scoped_workspace_id
          AND current.state = 'active'
        FOR UPDATE;
        IF existing.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'guardrail is unavailable';
        END IF;
        IF existing.version <> p_expected_version THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'guardrail changed';
        END IF;
        IF p_operation = 'update' AND existing.kind <> p_kind THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'guardrail kind cannot change';
        END IF;
        previous_semantic_hash := existing.semantic_hash;
        IF p_operation = 'delete' THEN
            UPDATE mesh.guardrail AS current
            SET state = 'deleted', deleted_at = evaluated_at,
                updated_at = GREATEST(existing.updated_at, evaluated_at), version = current.version + 1
            WHERE current.id = existing.id
            RETURNING * INTO saved;
        ELSE
            UPDATE mesh.guardrail AS current
            SET name = p_name, description = p_description, mode = p_mode, params = p_params,
                semantic_hash = p_semantic_hash,
                updated_at = GREATEST(existing.updated_at, evaluated_at), version = current.version + 1
            WHERE current.id = existing.id
            RETURNING * INTO saved;
        END IF;
    END IF;

    guardrail := mesh_ops.guardrail_document_internal_v1(saved)
        || pg_catalog.jsonb_build_object('state', saved.state);
    actor_binding_public_id := actor.role_binding_public_id;
    actor_role_public_id := actor.role_definition_public_id;
    actor_binding_generation := actor.binding_authority_generation;
    actor_membership_generation := actor.membership_authority_generation;
    actor_owner_generation := actor.workspace_owner_authority_generation;
    RETURN NEXT;
END;
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.change_workspace_invitation_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_invitation_public_id uuid, p_action text, p_email text, p_role_key text, p_token_digest bytea, p_expires_at timestamp with time zone, p_expected_version bigint, p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
 SET join_collapse_limit TO '1'
 SET from_collapse_limit TO '1'
 SET plan_cache_mode TO 'force_generic_plan'
AS $function$
DECLARE
    v_scope RECORD;
    v_invitation mesh.workspace_invitation%ROWTYPE;
    v_before JSONB;
    v_role RECORD;
    v_workspace_name TEXT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
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
    WHERE workspace.id = v_scope.workspace_id FOR NO KEY UPDATE;

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
        SET state = 'revoked', revoked_at = GREATEST(v_now, invitation.updated_at),
            version = invitation.version + 1, updated_at = GREATEST(v_now, invitation.updated_at)
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
            version = invitation.version + 1, updated_at = GREATEST(v_now, invitation.updated_at)
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
$function$
;

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
        UPDATE mesh.account_session AS session
        SET state = 'revoked', ended_at = GREATEST(v_now, session.issued_at), end_reason = 'administrative',
            version = session.version + 1, updated_at = GREATEST(v_now, session.updated_at)
        WHERE session.principal_id = v_member AND session.login_workspace_id = v_workspace
          AND session.state = 'active';
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
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.change_workspace_private_interchange_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_operation text, p_interchange_public_id uuid, p_expected_version bigint, p_name text, p_region_code text, p_host_name text, p_ipv4 inet, p_ipv6 inet, p_relay_key bytea, p_udp_port integer, p_tls_port integer, p_stun_port integer, p_network_public_ids uuid[], p_change_public_id uuid)
 RETURNS TABLE(interchange jsonb, previous_interchange jsonb, advanced_networks jsonb, actor_binding_public_id uuid, actor_role_public_id uuid, actor_binding_generation bigint, actor_membership_generation bigint, actor_owner_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
AS $function$
DECLARE
    identifier UUID;
    scoped_workspace_id BIGINT;
    deployment_internal_id BIGINT;
    actor RECORD;
    existing mesh.private_interchange%ROWTYPE;
    saved mesh.private_interchange%ROWTYPE;
    evaluated_at TIMESTAMPTZ;
    previous_networks BIGINT[] := ARRAY[]::BIGINT[];
    granted_networks BIGINT[] := ARRAY[]::BIGINT[];
    affected BIGINT[];
    free_region INTEGER;
BEGIN
    FOREACH identifier IN ARRAY ARRAY[p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_workspace_public_id, p_interchange_public_id, p_change_public_id] LOOP
        IF identifier IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(identifier), 6) >> 4 <> 7 THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid private interchange change input';
        END IF;
    END LOOP;
    IF p_operation IS NULL OR p_operation NOT IN ('create', 'update', 'delete')
        OR (p_operation = 'create' AND p_expected_version IS NOT NULL)
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version <= 0))
        OR (p_operation <> 'delete' AND (p_name IS NULL OR p_region_code IS NULL OR p_host_name IS NULL
            OR p_relay_key IS NULL OR p_udp_port IS NULL OR p_tls_port IS NULL OR p_stun_port IS NULL
            OR p_network_public_ids IS NULL OR pg_catalog.cardinality(p_network_public_ids) > 256)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid private interchange change input';
    END IF;

    scoped_workspace_id := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF scoped_workspace_id IS NULL
        OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, scoped_workspace_id) THEN
        RETURN;
    END IF;
    SELECT workspace.deployment_id INTO deployment_internal_id
    FROM mesh.workspace AS workspace WHERE workspace.id = scoped_workspace_id FOR NO KEY UPDATE;
    evaluated_at := pg_catalog.clock_timestamp();
    SELECT * INTO actor FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'interchange.manage', evaluated_at
    );
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF p_operation <> 'delete' THEN
        SELECT COALESCE(pg_catalog.array_agg(DISTINCT network.id), ARRAY[]::BIGINT[]) INTO granted_networks
        FROM mesh.network AS network
        WHERE network.workspace_id = scoped_workspace_id
          AND network.public_id = ANY (p_network_public_ids)
          AND network.deleted_at IS NULL;
        IF pg_catalog.cardinality(granted_networks) <> (
            SELECT pg_catalog.count(DISTINCT requested) FROM pg_catalog.unnest(p_network_public_ids) AS requested
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTP01', MESSAGE = 'private interchange Network is not in the Workspace';
        END IF;
        -- Serialise changes of this deployment's relay keys and region codes.
        PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('mesh.private_interchange'),
            deployment_internal_id::INTEGER);
        IF EXISTS (
            SELECT 1 FROM mesh.private_interchange AS other
            WHERE other.deployment_id = deployment_internal_id AND other.state = 'active'
              AND other.public_id <> p_interchange_public_id
              AND (other.relay_key = p_relay_key OR other.region_code = p_region_code)
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTP03', MESSAGE = 'relay key or region code already in use';
        END IF;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    IF p_operation = 'create' THEN
        IF (SELECT pg_catalog.count(*) FROM mesh.private_interchange AS counted
            WHERE counted.workspace_id = scoped_workspace_id AND counted.state = 'active') >= 16 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTP02', MESSAGE = 'private interchange limit reached';
        END IF;
        SELECT candidate INTO free_region
        FROM pg_catalog.generate_series(1000, 64999) AS candidate
        WHERE NOT EXISTS (
            SELECT 1 FROM mesh.private_interchange AS used
            WHERE used.deployment_id = deployment_internal_id AND used.state = 'active'
              AND used.region_id = candidate
        )
        ORDER BY candidate
        LIMIT 1;
        IF free_region IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'MTP04', MESSAGE = 'no private interchange region is free';
        END IF;
        INSERT INTO mesh.private_interchange (
            public_id, deployment_id, workspace_id, name, region_id, region_code, host_name, ipv4, ipv6,
            relay_key, udp_port, tls_port, stun_port, state, created_at, updated_at
        ) VALUES (
            p_interchange_public_id, deployment_internal_id, scoped_workspace_id, p_name, free_region,
            p_region_code, p_host_name, p_ipv4, p_ipv6, p_relay_key, p_udp_port, p_tls_port, p_stun_port,
            'active', evaluated_at, evaluated_at
        ) RETURNING * INTO saved;
    ELSE
        SELECT * INTO existing FROM mesh.private_interchange AS current
        WHERE current.public_id = p_interchange_public_id
          AND current.workspace_id = scoped_workspace_id
          AND current.state = 'active'
        FOR UPDATE;
        IF existing.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'private interchange is unavailable';
        END IF;
        IF existing.version <> p_expected_version THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'private interchange changed';
        END IF;
        SELECT COALESCE(pg_catalog.array_agg(granted.network_id), ARRAY[]::BIGINT[]) INTO previous_networks
        FROM mesh.private_interchange_network AS granted WHERE granted.interchange_id = existing.id;
        previous_interchange := mesh_ops.private_interchange_document_internal_v1(existing);
        IF p_operation = 'delete' THEN
            UPDATE mesh.private_interchange AS current
            SET state = 'deleted', deleted_at = evaluated_at,
                updated_at = GREATEST(existing.updated_at, evaluated_at), version = current.version + 1
            WHERE current.id = existing.id
            RETURNING * INTO saved;
        ELSE
            UPDATE mesh.private_interchange AS current
            SET name = p_name, region_code = p_region_code, host_name = p_host_name, ipv4 = p_ipv4,
                ipv6 = p_ipv6, relay_key = p_relay_key, udp_port = p_udp_port, tls_port = p_tls_port,
                stun_port = p_stun_port,
                updated_at = GREATEST(existing.updated_at, evaluated_at), version = current.version + 1
            WHERE current.id = existing.id
            RETURNING * INTO saved;
        END IF;
        DELETE FROM mesh.private_interchange_network AS granted WHERE granted.interchange_id = existing.id;
    END IF;
    INSERT INTO mesh.private_interchange_network (interchange_id, workspace_id, network_id, network_public_id)
    SELECT saved.id, scoped_workspace_id, network.id, network.public_id
    FROM mesh.network AS network
    WHERE network.workspace_id = scoped_workspace_id AND network.id = ANY (granted_networks);

    SELECT COALESCE(pg_catalog.array_agg(DISTINCT changed ORDER BY changed), ARRAY[]::BIGINT[]) INTO affected
    FROM pg_catalog.unnest(previous_networks || granted_networks) AS changed;
    advanced_networks := '[]'::JSONB;
    IF pg_catalog.cardinality(affected) > 0 THEN
        advanced_networks := mesh_ops.advance_identity_networks_internal_v1(scoped_workspace_id, affected);
    END IF;

    interchange := mesh_ops.private_interchange_document_internal_v1(saved)
        || pg_catalog.jsonb_build_object('state', saved.state);
    actor_binding_public_id := actor.role_binding_public_id;
    actor_role_public_id := actor.role_definition_public_id;
    actor_binding_generation := actor.binding_authority_generation;
    actor_membership_generation := actor.membership_authority_generation;
    actor_owner_generation := actor.workspace_owner_authority_generation;
    RETURN NEXT;
END;
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.create_network_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_display_name text, p_ipv4_prefix cidr, p_ipv6_prefix cidr, p_ipv4_prefix_public_id uuid, p_ipv6_prefix_public_id uuid, p_membership_public_id uuid, p_enrollment_profile_public_id uuid, p_change_public_id uuid)
 RETURNS TABLE(network_public_id uuid, network_display_code text, network_version bigint, network_created_at timestamp with time zone, replayed boolean, actor_binding_public_id uuid, actor_role_public_id uuid, actor_binding_generation bigint, actor_membership_generation bigint, actor_owner_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
AS $function$
DECLARE
    identifier UUID;
    scoped_workspace_id BIGINT;
    actor RECORD;
    actor_principal_id BIGINT;
    actor_membership_id BIGINT;
    deployment_internal_id BIGINT;
    existing mesh.network%ROWTYPE;
    pool_v4 mesh.address_pool%ROWTYPE;
    pool_v6 mesh.address_pool%ROWTYPE;
    created_network_id BIGINT;
    evaluated_at TIMESTAMPTZ;
BEGIN
    FOREACH identifier IN ARRAY ARRAY[p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_workspace_public_id, p_network_public_id, p_ipv4_prefix_public_id,
        p_ipv6_prefix_public_id, p_membership_public_id, p_enrollment_profile_public_id, p_change_public_id] LOOP
        IF identifier IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(identifier), 6) >> 4 <> 7 THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Network creation input';
        END IF;
    END LOOP;
    IF p_display_name IS NULL OR pg_catalog.char_length(p_display_name) NOT BETWEEN 1 AND 128
        OR pg_catalog.btrim(p_display_name) <> p_display_name
        OR p_ipv4_prefix IS NULL OR pg_catalog.family(p_ipv4_prefix) <> 4
        OR pg_catalog.masklen(p_ipv4_prefix) NOT BETWEEN 16 AND 28
        OR NOT (p_ipv4_prefix <<= '100.64.0.0/10'::CIDR)
        OR p_ipv6_prefix IS NULL OR pg_catalog.family(p_ipv6_prefix) <> 6
        OR pg_catalog.masklen(p_ipv6_prefix) NOT BETWEEN 56 AND 112 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Network creation input';
    END IF;

    scoped_workspace_id := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF scoped_workspace_id IS NULL
        OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, scoped_workspace_id) THEN
        RETURN;
    END IF;
    -- Network creation in one Workspace is serialized by its row lock.
    SELECT workspace.deployment_id INTO deployment_internal_id
    FROM mesh.workspace AS workspace WHERE workspace.id = scoped_workspace_id FOR NO KEY UPDATE;
    evaluated_at := pg_catalog.clock_timestamp();
    SELECT * INTO actor FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'network.create', evaluated_at
    );
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT principal.id, membership.id INTO STRICT actor_principal_id, actor_membership_id
    FROM mesh.principal AS principal
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = principal.deployment_id
     AND membership.workspace_id = scoped_workspace_id
     AND membership.principal_id = principal.id
     AND membership.state = 'active'
    WHERE principal.public_id = p_principal_public_id;

    SELECT * INTO existing FROM mesh.network AS network
    WHERE network.workspace_id = scoped_workspace_id AND network.public_id = p_network_public_id;
    IF FOUND THEN
        IF existing.display_name <> p_display_name OR NOT EXISTS (
            SELECT 1 FROM mesh.network_prefix AS prefix
            WHERE prefix.network_id = existing.id AND prefix.prefix = p_ipv4_prefix AND prefix.state = 'active'
        ) OR NOT EXISTS (
            SELECT 1 FROM mesh.network_prefix AS prefix
            WHERE prefix.network_id = existing.id AND prefix.prefix = p_ipv6_prefix AND prefix.state = 'active'
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'Network ID was used for another request';
        END IF;
        PERFORM pg_catalog.set_config('mesh.network_id', existing.id::TEXT, TRUE);
        RETURN QUERY
        SELECT existing.public_id, identity.display_code, existing.version, existing.created_at, TRUE,
            actor.role_binding_public_id, actor.role_definition_public_id, actor.binding_authority_generation,
            actor.membership_authority_generation, actor.workspace_owner_authority_generation
        FROM mesh_ops.tenant_display_identity AS identity
        WHERE identity.network_public_id = existing.public_id;
        RETURN;
    END IF;

    SELECT pool.* INTO pool_v4 FROM mesh.address_pool AS pool
    JOIN mesh.address_realm AS realm ON realm.id = pool.address_realm_id
    WHERE pool.workspace_id = scoped_workspace_id AND pool.purpose = 'node_overlay' AND pool.family = 4
      AND pool.state = 'active' AND realm.state = 'active' AND realm.kind = 'workspace_overlay'
      AND p_ipv4_prefix <<= pool.prefix;
    SELECT pool.* INTO pool_v6 FROM mesh.address_pool AS pool
    JOIN mesh.address_realm AS realm ON realm.id = pool.address_realm_id
    WHERE pool.workspace_id = scoped_workspace_id AND pool.purpose = 'node_overlay' AND pool.family = 6
      AND pool.state = 'active' AND realm.state = 'active' AND realm.kind = 'workspace_overlay'
      AND p_ipv6_prefix <<= pool.prefix;
    IF pool_v4.id IS NULL OR pool_v6.id IS NULL OR pool_v4.address_realm_id <> pool_v6.address_realm_id THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network prefix is outside the Workspace address pools';
    END IF;
    IF EXISTS (
        SELECT 1 FROM mesh.network_prefix AS prefix
        WHERE prefix.address_realm_id = pool_v4.address_realm_id
          AND prefix.state IN ('reserved', 'active', 'quarantined')
          AND (prefix.prefix && p_ipv4_prefix OR prefix.prefix && p_ipv6_prefix)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23P01', MESSAGE = 'network_prefix_overlap';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    SELECT pg_catalog.nextval(pg_catalog.pg_get_serial_sequence('mesh.network', 'id')) INTO created_network_id;
    PERFORM pg_catalog.set_config('mesh.network_id', created_network_id::TEXT, TRUE);
    INSERT INTO mesh.network (id, public_id, workspace_id, display_name, name_key, node_limit, state)
    OVERRIDING SYSTEM VALUE
    VALUES (created_network_id, p_network_public_id, scoped_workspace_id, p_display_name,
        pg_catalog.lower(p_display_name), 1000, 'active');
    INSERT INTO mesh_ops.network_revision (workspace_id, network_id) VALUES (scoped_workspace_id, created_network_id);
    INSERT INTO mesh.network_prefix (
        public_id, workspace_id, network_id, address_realm_id, address_pool_id, prefix, family, state
    ) VALUES
        (p_ipv4_prefix_public_id, scoped_workspace_id, created_network_id, pool_v4.address_realm_id, pool_v4.id,
            p_ipv4_prefix, 4, 'active'),
        (p_ipv6_prefix_public_id, scoped_workspace_id, created_network_id, pool_v6.address_realm_id, pool_v6.id,
            p_ipv6_prefix, 6, 'active');
    INSERT INTO mesh.network_membership (
        public_id, deployment_id, workspace_id, network_id, principal_id, workspace_membership_id, state, valid_from
    ) VALUES (
        p_membership_public_id, deployment_internal_id, scoped_workspace_id, created_network_id,
        actor_principal_id, actor_membership_id, 'active', evaluated_at
    );
    INSERT INTO mesh.enrollment_profile (
        public_id, workspace_id, network_id, created_by_principal_id, display_name, name_key,
        node_lifetime_seconds, ephemeral_mode, credential_use_policy, state, interactive_authorization_enabled
    ) VALUES (
        p_enrollment_profile_public_id, scoped_workspace_id, created_network_id, actor_principal_id,
        'Interactive login', 'interactive-login', 2592000, 'persistent', 'unlimited', 'active', TRUE
    );
    INSERT INTO mesh_audit.audit_stream (deployment_id, workspace_id, network_id, scope_kind)
    VALUES (deployment_internal_id, scoped_workspace_id, created_network_id, 'network');

    RETURN QUERY
    SELECT network.public_id, identity.display_code, network.version, network.created_at, FALSE,
        actor.role_binding_public_id, actor.role_definition_public_id, actor.binding_authority_generation,
        actor.membership_authority_generation, actor.workspace_owner_authority_generation
    FROM mesh.network AS network
    JOIN mesh_ops.tenant_display_identity AS identity ON identity.network_public_id = network.public_id
    WHERE network.id = created_network_id;
END;
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.create_network_v2(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_display_name text, p_ipv4_prefix cidr, p_ipv6_prefix cidr, p_ipv4_prefix_public_id uuid, p_ipv6_prefix_public_id uuid, p_membership_public_id uuid, p_enrollment_profile_public_id uuid, p_change_public_id uuid)
 RETURNS TABLE(network_public_id uuid, network_display_code text, network_version bigint, network_created_at timestamp with time zone, network_ipv4_prefix cidr, network_ipv6_prefix cidr, replayed boolean, actor_binding_public_id uuid, actor_role_public_id uuid, actor_binding_generation bigint, actor_membership_generation bigint, actor_owner_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
AS $function$
DECLARE
    identifier UUID;
    scoped_workspace_id BIGINT;
    actor RECORD;
    actor_principal_id BIGINT;
    actor_membership_id BIGINT;
    deployment_internal_id BIGINT;
    existing mesh.network%ROWTYPE;
    pool_v4 mesh.address_pool%ROWTYPE;
    pool_v6 mesh.address_pool%ROWTYPE;
    created_network_id BIGINT;
    evaluated_at TIMESTAMPTZ;
    assigned_ipv6 CIDR;
    existing_ipv6 CIDR;
    pool_hex TEXT;
BEGIN
    FOREACH identifier IN ARRAY ARRAY[p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_workspace_public_id, p_network_public_id, p_ipv4_prefix_public_id,
        p_ipv6_prefix_public_id, p_membership_public_id, p_enrollment_profile_public_id, p_change_public_id] LOOP
        IF identifier IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(identifier), 6) >> 4 <> 7 THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Network creation input';
        END IF;
    END LOOP;
    IF p_display_name IS NULL OR pg_catalog.char_length(p_display_name) NOT BETWEEN 1 AND 128
        OR pg_catalog.btrim(p_display_name) <> p_display_name
        OR p_ipv4_prefix IS NULL OR pg_catalog.family(p_ipv4_prefix) <> 4
        OR pg_catalog.masklen(p_ipv4_prefix) NOT BETWEEN 16 AND 28
        OR NOT (p_ipv4_prefix <<= '100.64.0.0/10'::CIDR)
        OR (p_ipv6_prefix IS NOT NULL AND (pg_catalog.family(p_ipv6_prefix) <> 6
            OR pg_catalog.masklen(p_ipv6_prefix) NOT BETWEEN 56 AND 112)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Network creation input';
    END IF;

    scoped_workspace_id := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF scoped_workspace_id IS NULL
        OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, scoped_workspace_id) THEN
        RETURN;
    END IF;
    -- Network creation in one Workspace is serialized by its row lock.
    SELECT workspace.deployment_id INTO deployment_internal_id
    FROM mesh.workspace AS workspace WHERE workspace.id = scoped_workspace_id FOR NO KEY UPDATE;
    evaluated_at := pg_catalog.clock_timestamp();
    SELECT * INTO actor FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'network.create', evaluated_at
    );
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT principal.id, membership.id INTO STRICT actor_principal_id, actor_membership_id
    FROM mesh.principal AS principal
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = principal.deployment_id
     AND membership.workspace_id = scoped_workspace_id
     AND membership.principal_id = principal.id
     AND membership.state = 'active'
    WHERE principal.public_id = p_principal_public_id;

    SELECT * INTO existing FROM mesh.network AS network
    WHERE network.workspace_id = scoped_workspace_id AND network.public_id = p_network_public_id;
    IF FOUND THEN
        SELECT prefix.prefix INTO existing_ipv6 FROM mesh.network_prefix AS prefix
        WHERE prefix.network_id = existing.id AND prefix.family = 6 AND prefix.state = 'active';
        IF existing.display_name <> p_display_name OR NOT EXISTS (
            SELECT 1 FROM mesh.network_prefix AS prefix
            WHERE prefix.network_id = existing.id AND prefix.prefix = p_ipv4_prefix AND prefix.state = 'active'
        ) OR (p_ipv6_prefix IS NOT NULL AND existing_ipv6 IS DISTINCT FROM p_ipv6_prefix) THEN
            RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'Network ID was used for another request';
        END IF;
        PERFORM pg_catalog.set_config('mesh.network_id', existing.id::TEXT, TRUE);
        RETURN QUERY
        SELECT existing.public_id, identity.display_code, existing.version, existing.created_at,
            p_ipv4_prefix, existing_ipv6, TRUE,
            actor.role_binding_public_id, actor.role_definition_public_id, actor.binding_authority_generation,
            actor.membership_authority_generation, actor.workspace_owner_authority_generation
        FROM mesh_ops.tenant_display_identity AS identity
        WHERE identity.network_public_id = existing.public_id;
        RETURN;
    END IF;

    SELECT pool.* INTO pool_v4 FROM mesh.address_pool AS pool
    JOIN mesh.address_realm AS realm ON realm.id = pool.address_realm_id
    WHERE pool.workspace_id = scoped_workspace_id AND pool.purpose = 'node_overlay' AND pool.family = 4
      AND pool.state = 'active' AND realm.state = 'active' AND realm.kind = 'workspace_overlay'
      AND p_ipv4_prefix <<= pool.prefix;
    SELECT pool.* INTO pool_v6 FROM mesh.address_pool AS pool
    JOIN mesh.address_realm AS realm ON realm.id = pool.address_realm_id
    WHERE pool.workspace_id = scoped_workspace_id AND pool.purpose = 'node_overlay' AND pool.family = 6
      AND pool.state = 'active' AND realm.state = 'active' AND realm.kind = 'workspace_overlay'
      AND (p_ipv6_prefix IS NULL OR p_ipv6_prefix <<= pool.prefix)
    ORDER BY pool.id
    LIMIT 1;
    IF pool_v4.id IS NULL OR pool_v6.id IS NULL OR pool_v4.address_realm_id <> pool_v6.address_realm_id THEN
        RAISE EXCEPTION USING ERRCODE = 'MTN01', MESSAGE = 'Network prefix is outside the Workspace address pools';
    END IF;
    assigned_ipv6 := p_ipv6_prefix;
    IF assigned_ipv6 IS NULL THEN
        -- First free /64 of the /48 pool: the pool's 48-bit routing prefix
        -- plus a 16-bit subnet ID, skipping any overlap in the realm.
        IF pg_catalog.masklen(pool_v6.prefix) <> 48 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTN01', MESSAGE = 'Workspace IPv6 pool cannot assign /64 ranges';
        END IF;
        pool_hex := pg_catalog.encode(pg_catalog.substr(
            pg_catalog.inet_send(pg_catalog.network(pool_v6.prefix)), 5, 6), 'hex');
        SELECT candidate.prefix INTO assigned_ipv6
        FROM pg_catalog.generate_series(0, 65535) AS subnet(id)
        CROSS JOIN LATERAL (
            SELECT (pg_catalog.substr(pool_hex, 1, 4) || ':' || pg_catalog.substr(pool_hex, 5, 4)
                || ':' || pg_catalog.substr(pool_hex, 9, 4) || ':'
                || pg_catalog.lpad(pg_catalog.to_hex(subnet.id), 4, '0') || '::/64')::CIDR AS prefix
        ) AS candidate
        WHERE NOT EXISTS (
            SELECT 1 FROM mesh.network_prefix AS used
            WHERE used.address_realm_id = pool_v6.address_realm_id
              AND used.state IN ('reserved', 'active', 'quarantined')
              AND used.prefix && candidate.prefix
        )
        ORDER BY subnet.id
        LIMIT 1;
        IF assigned_ipv6 IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'MTN01', MESSAGE = 'Workspace IPv6 pool is exhausted';
        END IF;
    END IF;
    IF EXISTS (
        SELECT 1 FROM mesh.network_prefix AS prefix
        WHERE prefix.address_realm_id = pool_v4.address_realm_id
          AND prefix.state IN ('reserved', 'active', 'quarantined')
          AND (prefix.prefix && p_ipv4_prefix OR prefix.prefix && assigned_ipv6)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23P01', MESSAGE = 'network_prefix_overlap';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    SELECT pg_catalog.nextval(pg_catalog.pg_get_serial_sequence('mesh.network', 'id')) INTO created_network_id;
    PERFORM pg_catalog.set_config('mesh.network_id', created_network_id::TEXT, TRUE);
    INSERT INTO mesh.network (id, public_id, workspace_id, display_name, name_key, node_limit, state)
    OVERRIDING SYSTEM VALUE
    VALUES (created_network_id, p_network_public_id, scoped_workspace_id, p_display_name,
        pg_catalog.lower(p_display_name), 1000, 'active');
    INSERT INTO mesh_ops.network_revision (workspace_id, network_id) VALUES (scoped_workspace_id, created_network_id);
    INSERT INTO mesh.network_prefix (
        public_id, workspace_id, network_id, address_realm_id, address_pool_id, prefix, family, state
    ) VALUES
        (p_ipv4_prefix_public_id, scoped_workspace_id, created_network_id, pool_v4.address_realm_id, pool_v4.id,
            p_ipv4_prefix, 4, 'active'),
        (p_ipv6_prefix_public_id, scoped_workspace_id, created_network_id, pool_v6.address_realm_id, pool_v6.id,
            assigned_ipv6, 6, 'active');
    INSERT INTO mesh.network_membership (
        public_id, deployment_id, workspace_id, network_id, principal_id, workspace_membership_id, state, valid_from
    ) VALUES (
        p_membership_public_id, deployment_internal_id, scoped_workspace_id, created_network_id,
        actor_principal_id, actor_membership_id, 'active', evaluated_at
    );
    INSERT INTO mesh.enrollment_profile (
        public_id, workspace_id, network_id, created_by_principal_id, display_name, name_key,
        node_lifetime_seconds, ephemeral_mode, credential_use_policy, state, interactive_authorization_enabled
    ) VALUES (
        p_enrollment_profile_public_id, scoped_workspace_id, created_network_id, actor_principal_id,
        'Interactive login', 'interactive-login', 2592000, 'persistent', 'unlimited', 'active', TRUE
    );
    INSERT INTO mesh_audit.audit_stream (deployment_id, workspace_id, network_id, scope_kind)
    VALUES (deployment_internal_id, scoped_workspace_id, created_network_id, 'network');

    RETURN QUERY
    SELECT network.public_id, identity.display_code, network.version, network.created_at,
        p_ipv4_prefix, assigned_ipv6, FALSE,
        actor.role_binding_public_id, actor.role_definition_public_id, actor.binding_authority_generation,
        actor.membership_authority_generation, actor.workspace_owner_authority_generation
    FROM mesh.network AS network
    JOIN mesh_ops.tenant_display_identity AS identity ON identity.network_public_id = network.public_id
    WHERE network.id = created_network_id;
END;
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.remove_network_member_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_member_public_id uuid, p_plan jsonb, p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
 SET join_collapse_limit TO '1'
 SET from_collapse_limit TO '1'
 SET plan_cache_mode TO 'force_generic_plan'
AS $function$
DECLARE
    v_scope RECORD;
    v_owner BIGINT;
    v_workspace_device_owner BIGINT;
    v_grant RECORD;
    v_actor BIGINT;
    v_member BIGINT;
    v_membership mesh.network_membership%ROWTYPE;
    v_before JSONB;
    v_item RECORD;
    v_device mesh.device%ROWTYPE;
    v_target BIGINT;
    v_action TEXT;
    v_devices JSONB := '[]'::JSONB;
    v_advanced JSONB;
    v_handovers INTEGER := 0;
    v_keys INTEGER := 0;
    v_roles INTEGER := 0;
    v_bindings INTEGER := 0;
    v_assigners TEXT[];
    v_network_assigners TEXT[];
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_member_public_id IS NULL OR p_plan IS NULL OR pg_catalog.jsonb_typeof(p_plan) <> 'array'
        OR pg_catalog.jsonb_array_length(p_plan) > 250
        OR p_change_public_id IS NULL OR p_evaluated_at IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network member removal is invalid';
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
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network member removal plan is invalid';
    END IF;

    SELECT * INTO v_scope FROM mesh_ops.network_member_scope_internal_v1(
        p_session_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network member removal is not authorized';
    END IF;
    -- Member changes in one Workspace are serialized by its row lock, taken
    -- before the Network revision.
    SELECT workspace.owner_principal_id INTO v_owner FROM mesh.workspace AS workspace
    WHERE workspace.id = v_scope.workspace_id
    FOR NO KEY UPDATE;
    SELECT * INTO v_grant FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.member.manage', v_now
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network member removal is not authorized';
    END IF;
    SELECT principal.id INTO STRICT v_actor FROM mesh.principal AS principal
    WHERE principal.public_id = p_principal_public_id;

    SELECT principal.id INTO v_member FROM mesh.principal AS principal
    WHERE principal.public_id = p_member_public_id AND principal.kind = 'account' AND principal.deleted_at IS NULL;
    SELECT * INTO v_membership FROM mesh.network_membership AS network_member
    WHERE network_member.workspace_id = v_scope.workspace_id AND network_member.network_id = v_scope.network_id
      AND network_member.principal_id = v_member AND network_member.state <> 'revoked'
    FOR UPDATE;
    IF v_membership.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Network member is unavailable';
    END IF;
    IF v_member = v_owner OR v_member = v_actor THEN
        RAISE EXCEPTION USING ERRCODE = 'MTM02', MESSAGE = 'nobody removes the owner or themselves';
    END IF;
    -- The actor's assigners: from the Workspace, and for roles bound to this
    -- Network also their own admin/it_admin role bound to this Network.
    v_assigners := mesh_ops.workspace_role_assigners_v1(v_scope.workspace_id, v_actor, v_now);
    SELECT v_assigners || COALESCE(pg_catalog.array_agg(DISTINCT assignment.role_key), ARRAY[]::TEXT[])
    INTO v_network_assigners
    FROM mesh.workspace_role_assignment AS assignment
    JOIN mesh.workspace_membership AS actor_membership
      ON actor_membership.id = assignment.workspace_membership_id AND actor_membership.state = 'active'
     AND actor_membership.valid_from <= v_now
     AND (actor_membership.expires_at IS NULL OR actor_membership.expires_at > v_now)
    WHERE assignment.workspace_id = v_scope.workspace_id AND assignment.principal_id = v_actor
      AND assignment.network_id = v_scope.network_id AND assignment.role_key IN ('admin', 'it_admin')
      AND assignment.state = 'active' AND assignment.valid_from <= v_now
      AND (assignment.expires_at IS NULL OR assignment.expires_at > v_now);
    IF EXISTS (
        SELECT 1 FROM mesh.workspace_role_assignment AS assignment
        JOIN mesh.builtin_role AS role ON role.role_key = assignment.role_key
        WHERE assignment.workspace_id = v_scope.workspace_id
          AND assignment.workspace_membership_id = v_membership.workspace_membership_id
          AND assignment.state = 'active'
          AND ((assignment.network_id IS NULL AND NOT (role.assignable_by && v_assigners))
               OR (assignment.network_id = v_scope.network_id
                   AND NOT (role.assignable_by && v_network_assigners)))
    ) OR (pg_catalog.cardinality(v_assigners) = 0 AND EXISTS (
        SELECT 1 FROM mesh.role_binding AS binding
        WHERE binding.workspace_id = v_scope.workspace_id AND binding.network_id = v_scope.network_id
          AND binding.workspace_membership_id = v_membership.workspace_membership_id
          AND binding.state <> 'revoked'
    )) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'the member holds a role beyond the delegation ceiling';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_array_elements(p_plan) AS item(value)
        WHERE NOT EXISTS (
            SELECT 1 FROM mesh.device AS device
            WHERE device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
              AND device.public_id = (item.value ->> 'device_id')::UUID
              AND device.ownership = 'member' AND device.owner_principal_id = v_member
              AND device.state IN ('active', 'suspended', 'expired') AND device.deleted_at IS NULL
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTM03', MESSAGE = 'the plan names a Device the member does not own here';
    END IF;
    v_before := mesh_ops.network_member_document_internal_v1(v_membership);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    FOR UPDATE;

    -- Devices, in a stable order: the plan's choice or, unnamed, revocation.
    v_workspace_device_owner := mesh_ops.workspace_device_principal_internal_v1(v_scope.workspace_id);
    FOR v_item IN
        SELECT device.id, plan.value AS choice
        FROM mesh.device AS device
        LEFT JOIN pg_catalog.jsonb_array_elements(p_plan) AS plan(value)
          ON (plan.value ->> 'device_id')::UUID = device.public_id
        WHERE device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
          AND device.ownership = 'member' AND device.owner_principal_id = v_member
          AND device.state IN ('active', 'suspended', 'expired') AND device.deleted_at IS NULL
        ORDER BY device.id
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
              ON membership.workspace_id = v_scope.workspace_id AND membership.principal_id = principal.id
             AND membership.state = 'active'
             AND (membership.expires_at IS NULL OR membership.expires_at > v_now)
            JOIN mesh.network_membership AS network_member
              ON network_member.workspace_id = v_scope.workspace_id AND network_member.network_id = v_scope.network_id
             AND network_member.principal_id = principal.id AND network_member.state = 'active'
             AND (network_member.expires_at IS NULL OR network_member.expires_at > v_now)
            WHERE principal.public_id = (v_item.choice ->> 'new_owner_id')::UUID
              AND principal.id <> v_member AND principal.state = 'active' AND principal.deleted_at IS NULL;
            IF v_target IS NULL THEN
                RAISE EXCEPTION USING ERRCODE = 'MTM04',
                    MESSAGE = 'new owner is not an active member of this Network';
            END IF;
            UPDATE mesh.device SET state = 'suspended', suspended_reason = 'handover',
                handover_principal_id = v_target,
                session_generation = session_generation + 1, version = version + 1,
                updated_at = GREATEST(v_now, updated_at)
            WHERE id = v_device.id RETURNING * INTO v_device;
        ELSE
            PERFORM mesh_ops.revoke_member_device_internal_v1(v_device.id, 'network member removed', v_now);
            SELECT * INTO STRICT v_device FROM mesh.device AS device WHERE device.id = v_item.id;
        END CASE;
        v_devices := v_devices || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
            'device_id', v_device.public_id,
            'hostname', v_device.hostname, 'action', v_action, 'state', v_device.state
        ));
    END LOOP;

    -- A Device of this Network waiting to be handed to the member stays
    -- suspended for an administrator to decide.
    UPDATE mesh.device AS device
    SET suspended_reason = 'admin', handover_principal_id = NULL,
        version = device.version + 1, updated_at = GREATEST(v_now, device.updated_at)
    WHERE device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
      AND device.handover_principal_id = v_member AND device.deleted_at IS NULL;
    GET DIAGNOSTICS v_handovers = ROW_COUNT;

    UPDATE mesh.enrollment_credential AS credential
    SET state = 'revoked', revoked_at = GREATEST(v_now, credential.valid_from),
        version = credential.version + 1, updated_at = GREATEST(v_now, credential.updated_at)
    WHERE credential.workspace_id = v_scope.workspace_id AND credential.network_id = v_scope.network_id
      AND credential.issuer_principal_id = v_member AND credential.state = 'active';
    GET DIAGNOSTICS v_keys = ROW_COUNT;

    UPDATE mesh.workspace_role_assignment AS assignment
    SET state = 'revoked', revoked_at = GREATEST(v_now, assignment.created_at),
        authority_generation = assignment.authority_generation + 1, version = assignment.version + 1,
        updated_at = GREATEST(v_now, assignment.updated_at)
    WHERE assignment.workspace_id = v_scope.workspace_id
      AND assignment.workspace_membership_id = v_membership.workspace_membership_id
      AND assignment.network_id = v_scope.network_id AND assignment.state = 'active';
    GET DIAGNOSTICS v_roles = ROW_COUNT;
    UPDATE mesh.role_binding AS binding
    SET state = 'revoked', authority_generation = binding.authority_generation + 1,
        version = binding.version + 1, updated_at = GREATEST(v_now, binding.updated_at)
    WHERE binding.workspace_id = v_scope.workspace_id AND binding.network_id = v_scope.network_id
      AND binding.workspace_membership_id = v_membership.workspace_membership_id AND binding.state <> 'revoked';
    GET DIAGNOSTICS v_bindings = ROW_COUNT;
    UPDATE mesh.network_membership
    SET state = 'revoked', authority_generation = authority_generation + 1, version = version + 1,
        updated_at = GREATEST(v_now, updated_at)
    WHERE id = v_membership.id
    RETURNING * INTO v_membership;

    v_advanced := mesh_ops.advance_member_networks_internal_v1(v_scope.workspace_id, ARRAY[v_scope.network_id]);

    RETURN pg_catalog.jsonb_build_object(
        'before', v_before,
        'after', mesh_ops.network_member_document_internal_v1(v_membership),
        'devices', v_devices,
        'handovers_cancelled', v_handovers,
        'keys_revoked', v_keys,
        'roles_revoked', v_roles + v_bindings,
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
$function$
;

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

    UPDATE mesh.account_session AS session
    SET state = 'revoked', ended_at = GREATEST(v_now, session.issued_at), end_reason = 'administrative',
        version = session.version + 1, updated_at = GREATEST(v_now, session.updated_at)
    WHERE session.principal_id = v_member AND session.login_workspace_id = v_workspace
      AND session.state = 'active';
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
$function$
;

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
    PERFORM head.stream_internal_id FROM mesh_audit.lock_deployment_stream_head(p_deployment_public_id) AS head;
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
      AND session.login_workspace_id = v_workspace AND session.state = 'active'
    ORDER BY session.id
    FOR UPDATE;
    UPDATE mesh.account_session AS session
    SET state = 'revoked', ended_at = GREATEST(v_now, session.issued_at), end_reason = 'administrative',
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
$function$
;
