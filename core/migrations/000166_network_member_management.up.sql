-- Schema 166: add and remove the members of one Network.
--
-- Until now a Network membership was written only when a Network was created
-- (its creator) or when someone first joined the Workspace (every active
-- Network), so a Network created later held only its creator and nobody else
-- could enroll a Device into it. network.member.manage, granted to admin and
-- it_admin (the owner holds it through the resolver's owner branch), lets a
-- Network's members be listed, added and removed. A Network-scope it_admin
-- manages only that Network.
--
-- list_network_members_v1 (network.read) pages the Workspace's members with
-- their membership of the Network, keyed by principal ID. Members of the
-- Network are always listed; the rest of the Workspace only to a caller who
-- can add them (network.member.manage) or read the Workspace's members
-- (member.read). can_manage reports network.member.manage.
--
-- add_network_members_v1 adds up to 150 active Workspace members at once and
-- skips those already in the Network. Maps do not read Network membership, so
-- adding advances no revision; enrollment choices and browser approval read
-- it live.
--
-- remove_network_member_v1 removes one member from one Network as schema 130
-- removes a member from the Workspace, limited to that Network: each Device
-- the member owns in the Network is moved to the Workspace, handed to another
-- member of the Network, or revoked (a Device the plan does not name is
-- revoked); a Device waiting to be handed to them in the Network stays
-- suspended for an administrator; the enrollment keys they issued for the
-- Network are revoked; their Network-scope roles for it end; and the
-- membership becomes revoked. The Workspace membership, Identity Groups,
-- other Networks and Console sessions are untouched. Nobody removes the owner
-- or themselves, and the actor must be allowed to assign every Workspace or
-- this Network's role the member holds. The Network is advanced once.
--
-- Every entry point runs in the transaction's exact Network scope
-- (set_network_scope) and the session's login Workspace. Writes lock the
-- Workspace row first, then the Network revision. The caller appends the
-- evidence on the Network stream. Errors: 22023 invalid input, 42501 not
-- authorized, P0002 unknown member, MTM01 a member who is suspended in the
-- Workspace cannot be added, MTM02 the member is the owner or the actor,
-- MTM03 the plan names a Device that is not the member's in this Network or
-- cannot take that action, MTM04 the new owner is not an active member of
-- this Network.

INSERT INTO mesh.permission (permission_key, description, risk_class, allowed_scope_kinds, catalog_version)
VALUES ('network.member.manage', 'Add and remove the members of a Network', 'mutation', ARRAY['network'], 1);

INSERT INTO mesh.builtin_role_permission (role_key, permission_id)
SELECT grant_row.role_key, permission.id
FROM (VALUES
    ('admin', 'network.member.manage'),
    ('it_admin', 'network.member.manage')
) AS grant_row(role_key, permission_key)
JOIN mesh.permission AS permission ON permission.permission_key = grant_row.permission_key
ON CONFLICT DO NOTHING;

-- The exact Network the transaction is scoped to, when it is the named one,
-- active, in the session's login Workspace. Returns NULL otherwise.
CREATE FUNCTION mesh_ops.network_member_scope_internal_v1(
    p_session_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID
)
RETURNS TABLE (deployment_id BIGINT, workspace_id BIGINT, network_id BIGINT)
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT workspace.deployment_id, workspace.id, network.id
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network ON network.workspace_id = workspace.id
    WHERE workspace.id = mesh_ops.current_workspace_id() AND network.id = mesh_ops.current_network_id()
      AND workspace.public_id = p_workspace_public_id AND network.public_id = p_network_public_id
      AND workspace.state = 'active' AND workspace.deleted_at IS NULL
      AND network.state = 'active' AND network.deleted_at IS NULL
      AND mesh_ops.session_bound_to_workspace_v1(p_session_public_id, workspace.id)
$function$;
REVOKE ALL ON FUNCTION mesh_ops.network_member_scope_internal_v1(UUID, UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The membership document of one Network member.
CREATE FUNCTION mesh_ops.network_member_document_internal_v1(p_membership mesh.network_membership)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'membership_id', p_membership.public_id,
        'principal_id', (SELECT principal.public_id FROM mesh.principal AS principal
                         WHERE principal.id = p_membership.principal_id),
        'state', p_membership.state,
        'version', p_membership.version,
        'added_at', p_membership.valid_from
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.network_member_document_internal_v1(mesh.network_membership)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.list_network_members_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_after_principal_public_id UUID,
    p_limit INTEGER, p_evaluated_at TIMESTAMPTZ
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
    v_can_manage BOOLEAN;
    v_directory BOOLEAN;
    v_members JSONB;
    v_count INTEGER;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 200 OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network member page input is invalid';
    END IF;
    SELECT * INTO v_scope FROM mesh_ops.network_member_scope_internal_v1(
        p_session_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network members are not available';
    END IF;
    PERFORM 1 FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.read', p_evaluated_at
    );
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network members are not available';
    END IF;
    PERFORM 1 FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.member.manage', p_evaluated_at
    );
    v_can_manage := FOUND;
    v_directory := v_can_manage;
    IF NOT v_directory THEN
        PERFORM 1 FROM mesh_ops.resolve_workspace_permission_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, 'member.read', p_evaluated_at
        );
        v_directory := FOUND;
    END IF;

    WITH page AS (
        SELECT principal.public_id, account.display_name, membership.state AS workspace_state,
            workspace.owner_principal_id = principal.id AS owner, network_member.public_id AS membership_public_id,
            network_member.state AS network_state, network_member.version AS network_version,
            network_member.valid_from AS added_at
        FROM mesh.workspace_membership AS membership
        JOIN mesh.workspace AS workspace ON workspace.id = membership.workspace_id
        JOIN mesh.principal AS principal
          ON principal.deployment_id = membership.deployment_id AND principal.id = membership.principal_id
        JOIN mesh.account AS account
          ON account.deployment_id = principal.deployment_id AND account.principal_id = principal.id
        LEFT JOIN mesh.network_membership AS network_member
          ON network_member.workspace_id = membership.workspace_id AND network_member.network_id = v_scope.network_id
         AND network_member.principal_id = principal.id AND network_member.workspace_membership_id = membership.id
         AND network_member.state <> 'revoked'
        WHERE membership.workspace_id = v_scope.workspace_id AND membership.state <> 'revoked'
          AND principal.deleted_at IS NULL
          AND (v_directory OR network_member.id IS NOT NULL)
          AND (p_after_principal_public_id IS NULL OR principal.public_id > p_after_principal_public_id)
        ORDER BY principal.public_id
        LIMIT p_limit + 1
    )
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'principal_id', page.public_id,
               'display_name', page.display_name,
               'workspace_membership_state', page.workspace_state,
               'owner', page.owner,
               'network_membership', CASE WHEN page.membership_public_id IS NULL THEN NULL
                   ELSE pg_catalog.jsonb_build_object(
                       'membership_id', page.membership_public_id, 'principal_id', page.public_id,
                       'state', page.network_state, 'version', page.network_version, 'added_at', page.added_at)
                   END
           ) ORDER BY page.public_id),
           pg_catalog.count(*)::INTEGER
    INTO v_members, v_count
    FROM page;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'can_manage', v_can_manage,
        'members', CASE WHEN v_count > p_limit
            THEN (SELECT pg_catalog.jsonb_agg(item.value ORDER BY item.ordinal)
                  FROM pg_catalog.jsonb_array_elements(v_members) WITH ORDINALITY AS item(value, ordinal)
                  WHERE item.ordinal <= p_limit)
            ELSE COALESCE(v_members, '[]'::JSONB) END,
        'has_more', COALESCE(v_count, 0) > p_limit
    );
END;
$function$;

CREATE FUNCTION mesh_ops.add_network_members_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_member_public_ids UUID[],
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
    v_scope RECORD;
    v_grant RECORD;
    v_added JSONB;
    v_unchanged JSONB;
    v_revision BIGINT;
    v_now TIMESTAMPTZ := GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at);
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
    PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = v_scope.workspace_id FOR UPDATE;
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
$function$;

CREATE FUNCTION mesh_ops.remove_network_member_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_member_public_id UUID, p_plan JSONB,
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
    v_now TIMESTAMPTZ := GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at);
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
    FOR UPDATE;
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
    IF EXISTS (
        SELECT 1 FROM mesh.workspace_role_assignment AS assignment
        JOIN mesh.builtin_role AS role ON role.role_key = assignment.role_key
        WHERE assignment.workspace_id = v_scope.workspace_id
          AND assignment.workspace_membership_id = v_membership.workspace_membership_id
          AND (assignment.network_id IS NULL OR assignment.network_id = v_scope.network_id)
          AND assignment.state = 'active'
          AND NOT (role.assignable_by && mesh_ops.workspace_role_assigners_v1(v_scope.workspace_id, v_actor, v_now))
    ) THEN
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
$function$;

REVOKE ALL ON FUNCTION mesh_ops.list_network_members_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.add_network_members_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID[], UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.remove_network_member_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, JSONB, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_network_members_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER, TIMESTAMPTZ
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.add_network_members_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID[], UUID, TIMESTAMPTZ
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.remove_network_member_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, JSONB, UUID, TIMESTAMPTZ
) TO mesh_runtime;
