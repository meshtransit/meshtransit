-- Schema 130: remove a Workspace member (L2b of docs/device-lifecycle.md).
--
-- Removing a member (member.manage) ends everything the person holds in this
-- Workspace in one transaction:
--   - each Device they own here is handled as the plan says: moved to the
--     Workspace, handed to another member (suspended until that member signs
--     in on it), or revoked. A Device the plan does not name is revoked, so
--     nothing they own survives by omission;
--   - a Device waiting to be handed to them loses the handover and stays
--     suspended (reason 'admin') for an administrator to decide;
--   - the enrollment keys they issued here are revoked;
--   - they leave every Identity Group of the Workspace;
--   - their Workspace roles, Network roles and Network memberships end;
--   - their Console sessions logged in to this Workspace end;
--   - the membership becomes revoked. Audit history keeps their identity, and
--     an invitation may bring them back later as a new membership.
--
-- Delegation and protection follow schema 127: nobody removes themselves or
-- the owner, and the actor must be allowed to assign every role the member
-- holds. A suspended member can be removed.
--
-- The plan is a JSON array of at most 250 objects
--   {"device_id": UUID, "action": "transfer_workspace"|"transfer_member"|"revoke",
--    "new_owner_id": UUID (transfer_member only)}.
-- Every named Device must be the member's own here, named once. A handover
-- needs an active member of the Device's Network other than the removed one,
-- and a Device an administrator suspended is not handed over (as in schema
-- 125). An expired Device can only move to the Workspace or be revoked.
--
-- remove_workspace_member_v1 authorizes, applies and returns the documents;
-- the caller appends evidence on the Workspace stream and on the stream of
-- each Network it advanced. Errors: 22023 invalid input, 42501 not
-- authorized, P0002 unknown member, MTM02 the member is the owner or the
-- actor, MTM03 the plan names a Device that is not the member's or cannot
-- take that action, MTM04 the new owner is not an active member of the
-- Device's Network.

-- Revokes one Device and its current keys. The caller holds the Device's
-- Network revision and sets mesh.change_public_id.
CREATE FUNCTION mesh_ops.revoke_member_device_internal_v1(
    p_device_id BIGINT, p_reason TEXT, p_now TIMESTAMPTZ
)
RETURNS VOID
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_device mesh.device%ROWTYPE;
BEGIN
    UPDATE mesh.device AS device
    SET state = 'revoked', suspended_reason = NULL, handover_principal_id = NULL,
        session_generation = device.session_generation + 1, version = device.version + 1,
        updated_at = GREATEST(p_now, device.updated_at)
    WHERE device.id = p_device_id AND device.state IN ('active', 'suspended', 'expired')
      AND device.deleted_at IS NULL
    RETURNING * INTO v_device;
    IF v_device.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MTM03', MESSAGE = 'Device cannot be revoked';
    END IF;
    UPDATE mesh.device_machine_key_epoch AS key_epoch
    SET state = 'revoked', valid_until = GREATEST(p_now, key_epoch.valid_from), revocation_reason = p_reason,
        version = key_epoch.version + 1, updated_at = GREATEST(p_now, key_epoch.updated_at)
    WHERE key_epoch.workspace_id = v_device.workspace_id AND key_epoch.network_id = v_device.network_id
      AND key_epoch.device_id = v_device.id AND key_epoch.state = 'active';
    UPDATE mesh.device_node_key_epoch AS key_epoch
    SET state = 'revoked', valid_until = GREATEST(p_now, key_epoch.valid_from), revocation_reason = p_reason,
        version = key_epoch.version + 1, updated_at = GREATEST(p_now, key_epoch.updated_at)
    WHERE key_epoch.workspace_id = v_device.workspace_id AND key_epoch.network_id = v_device.network_id
      AND key_epoch.device_id = v_device.id AND key_epoch.state = 'active';
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.revoke_member_device_internal_v1(BIGINT, TEXT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.remove_workspace_member_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_member_public_id UUID, p_plan JSONB,
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
    v_now TIMESTAMPTZ := GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at);
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
    FOR UPDATE;
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
    SET state = 'revoked', ended_at = v_now, end_reason = 'administrative',
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
$function$;

REVOKE ALL ON FUNCTION mesh_ops.remove_workspace_member_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, JSONB, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.remove_workspace_member_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, JSONB, UUID, TIMESTAMPTZ
) TO mesh_runtime;
