-- Schema 127: suspend and resume a Workspace member (L2 of
-- docs/device-lifecycle.md).
--
-- Suspending a member (member.manage) cuts them off in this Workspace at once:
-- the membership becomes suspended, so every permission resolver refuses
-- them; each Device they own here that is active becomes suspended with the
-- reason 'member' and a new session generation, so it leaves every map and
-- its open sessions end; and their Console sessions logged in to this
-- Workspace end. Workspace Devices are untouched.
--
-- Resuming the member restores the membership and resumes exactly the
-- Devices suspended for the member. A Device an administrator suspended on
-- its own stays suspended. While the member is suspended, their Devices
-- cannot be resumed one by one, but they can be moved to the Workspace (the
-- suspension ends with the member's ownership) or handed to another member.
--
-- Delegation: nobody suspends themselves or the owner, and the actor must be
-- allowed to assign every role the member holds (builtin_role.assignable_by),
-- so an IT admin cannot suspend an admin.
--
-- change_workspace_member_v1 authorizes, applies and returns the documents;
-- the caller appends evidence on the Workspace stream and on the stream of
-- each Network it advanced. Errors: 22023 invalid input, 42501 not
-- authorized, P0002 unknown member, MTM01 the member is in a state the action
-- does not accept, MTM02 the member is the owner or the actor.

ALTER TABLE mesh.device DROP CONSTRAINT device_suspension_check;
ALTER TABLE mesh.device
    ADD CONSTRAINT device_suspension_check CHECK (
        (state = 'suspended') = (suspended_reason IS NOT NULL)
        AND (suspended_reason IS NULL OR suspended_reason IN ('admin', 'handover', 'member'))
        AND (handover_principal_id IS NOT NULL) = (suspended_reason IS NOT DISTINCT FROM 'handover')
    );

CREATE INDEX device_workspace_owner_state_idx ON mesh.device (workspace_id, owner_principal_id, state)
    WHERE deleted_at IS NULL;

CREATE OR REPLACE FUNCTION mesh_ops.change_device_lifecycle_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_device_public_id UUID,
    p_action TEXT, p_expected_version BIGINT, p_target_principal_public_id UUID, p_hostname TEXT,
    p_change_public_id UUID, p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_permission TEXT;
    v_grant RECORD;
    v_device mesh.device%ROWTYPE;
    v_before JSONB;
    v_target BIGINT;
    v_workspace_owner BIGINT;
    v_hostname TEXT;
    v_network_revision BIGINT;
    v_inventory_revision BIGINT;
    v_group_revision BIGINT;
    v_dns_revision BIGINT;
    v_owner_changes BOOLEAN := FALSE;
    v_now TIMESTAMPTZ := GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at);
BEGIN
    v_permission := CASE p_action
        WHEN 'suspend' THEN 'device.quarantine'
        WHEN 'resume' THEN 'device.quarantine'
        WHEN 'transfer_workspace' THEN 'device.transfer'
        WHEN 'transfer_member' THEN 'device.transfer'
        WHEN 'rename' THEN 'device.manage'
    END;
    IF v_workspace IS NULL OR v_network IS NULL OR v_permission IS NULL
        OR p_device_public_id IS NULL OR p_expected_version IS NULL OR p_expected_version < 1
        OR p_change_public_id IS NULL OR p_evaluated_at IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_action = 'transfer_member') <> (p_target_principal_public_id IS NOT NULL)
        OR (p_action = 'rename') <> (p_hostname IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device lifecycle change is invalid';
    END IF;
    IF p_action = 'rename' THEN
        v_hostname := pg_catalog.lower(p_hostname);
        IF pg_catalog.octet_length(p_hostname) NOT BETWEEN 1 AND 253
            OR v_hostname !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$' THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device hostname is invalid';
        END IF;
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, v_permission, p_evaluated_at
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Device lifecycle change is not authorized';
    END IF;

    -- Serializes with registration, publication and other map inputs.
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
    FOR UPDATE;
    SELECT * INTO v_device FROM mesh.device AS device
    WHERE device.workspace_id = v_workspace AND device.network_id = v_network
      AND device.public_id = p_device_public_id AND device.deleted_at IS NULL
    FOR UPDATE;
    IF v_device.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device is unavailable';
    END IF;
    IF v_device.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device changed';
    END IF;
    IF v_device.state NOT IN ('active', 'suspended') THEN
        RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'Device is not active or suspended';
    END IF;
    v_before := mesh_ops.device_lifecycle_document_internal_v1(v_device);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    CASE p_action
    WHEN 'suspend' THEN
        IF v_device.state <> 'active' THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'Device is not active';
        END IF;
        UPDATE mesh.device SET state = 'suspended', suspended_reason = 'admin',
            session_generation = session_generation + 1, version = version + 1, updated_at = v_now
        WHERE id = v_device.id RETURNING * INTO v_device;
    WHEN 'resume' THEN
        -- Resuming a Device that waits for handover cancels the handover.
        IF v_device.state <> 'suspended' THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'Device is not suspended';
        END IF;
        IF v_device.suspended_reason = 'member' THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'resume the member to resume this Device';
        END IF;
        UPDATE mesh.device SET state = 'active', suspended_reason = NULL, handover_principal_id = NULL,
            version = version + 1, updated_at = v_now
        WHERE id = v_device.id RETURNING * INTO v_device;
    WHEN 'transfer_workspace' THEN
        IF v_device.ownership = 'workspace' AND v_device.handover_principal_id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'Device is already owned by the Workspace';
        END IF;
        v_workspace_owner := mesh_ops.workspace_device_principal_internal_v1(v_workspace);
        -- An administrator's suspension stays; a pending handover ends, and so
        -- does the suspension of a suspended member, who no longer owns it.
        UPDATE mesh.device SET ownership = 'workspace',
            owner_principal_id = v_workspace_owner, custodian_principal_id = v_workspace_owner,
            expires_at = mesh_ops.device_never_expires_v1(),
            state = CASE WHEN suspended_reason IN ('handover', 'member') THEN 'active' ELSE state END,
            suspended_reason = CASE WHEN suspended_reason IN ('handover', 'member') THEN NULL
                                    ELSE suspended_reason END,
            handover_principal_id = NULL,
            session_generation = session_generation + 1, version = version + 1, updated_at = v_now
        WHERE id = v_device.id RETURNING * INTO v_device;
        v_owner_changes := TRUE;
    WHEN 'transfer_member' THEN
        SELECT principal.id INTO v_target
        FROM mesh.principal AS principal
        JOIN mesh.workspace_membership AS membership
          ON membership.workspace_id = v_workspace AND membership.principal_id = principal.id
         AND membership.state = 'active'
         AND (membership.expires_at IS NULL OR membership.expires_at > v_now)
        JOIN mesh.network_membership AS network_member
          ON network_member.workspace_id = v_workspace AND network_member.network_id = v_network
         AND network_member.principal_id = principal.id AND network_member.state = 'active'
         AND (network_member.expires_at IS NULL OR network_member.expires_at > v_now)
        WHERE principal.public_id = p_target_principal_public_id
          AND principal.state = 'active' AND principal.deleted_at IS NULL;
        IF v_target IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL02', MESSAGE = 'new owner is not an active member of this Network';
        END IF;
        IF v_device.ownership = 'member' AND v_device.owner_principal_id = v_target THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'Device already belongs to this member';
        END IF;
        IF v_device.suspended_reason = 'admin' THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'resume the suspended Device before transferring it';
        END IF;
        UPDATE mesh.device SET state = 'suspended', suspended_reason = 'handover',
            handover_principal_id = v_target,
            session_generation = session_generation + 1, version = version + 1, updated_at = v_now
        WHERE id = v_device.id RETURNING * INTO v_device;
    WHEN 'rename' THEN
        IF v_hostname = v_device.hostname THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'Device already has this hostname';
        END IF;
        IF EXISTS (
            SELECT 1 FROM mesh.device AS other
            WHERE other.workspace_id = v_workspace AND other.network_id = v_network
              AND other.hostname_key = v_hostname AND other.deleted_at IS NULL AND other.id <> v_device.id
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL03', MESSAGE = 'another Device has this hostname';
        END IF;
        UPDATE mesh.device SET hostname = v_hostname, hostname_key = v_hostname, hostname_locked = TRUE,
            version = version + 1, updated_at = v_now
        WHERE id = v_device.id RETURNING * INTO v_device;
    END CASE;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        inventory_revision = revision.inventory_revision + 1,
        group_revision = revision.group_revision + CASE WHEN v_owner_changes THEN 1 ELSE 0 END,
        dns_revision = revision.dns_revision + CASE WHEN p_action = 'rename' THEN 1 ELSE 0 END,
        updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
    RETURNING revision.network_revision, revision.inventory_revision, revision.group_revision,
        revision.dns_revision
    INTO v_network_revision, v_inventory_revision, v_group_revision, v_dns_revision;

    RETURN pg_catalog.jsonb_build_object(
        'before', v_before,
        'after', mesh_ops.device_lifecycle_document_internal_v1(v_device),
        'network_revision', v_network_revision,
        'inventory_revision', v_inventory_revision,
        'group_revision', v_group_revision,
        'role_binding_id', v_grant.role_binding_public_id,
        'permission', v_permission
    );
END;
$function$;


-- Advances, once each and in Network order, the Networks whose Devices a
-- member change suspended or resumed: their maps (network), inventories and
-- owner-derived group edges change.
CREATE FUNCTION mesh_ops.advance_member_networks_internal_v1(p_workspace_id BIGINT, p_network_ids BIGINT[])
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_result JSONB := '[]'::JSONB;
    v_row RECORD;
BEGIN
    IF p_workspace_id IS NULL OR p_workspace_id <> mesh_ops.current_workspace_id() THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Workspace scope is unavailable';
    END IF;
    IF pg_catalog.cardinality(p_network_ids) IS NULL OR pg_catalog.cardinality(p_network_ids) = 0 THEN
        RETURN v_result;
    END IF;
    -- Schema 121's fan-out policies admit the bound Workspace's revisions
    -- while this setting is on.
    PERFORM pg_catalog.set_config('mesh.identity_catalog_fanout', 'on', TRUE);
    FOR v_row IN
        SELECT revision.network_id FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = p_workspace_id AND revision.network_id = ANY (p_network_ids)
        ORDER BY revision.network_id
        FOR UPDATE
    LOOP
        NULL;
    END LOOP;
    WITH advanced AS (
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            inventory_revision = revision.inventory_revision + 1,
            group_revision = revision.group_revision + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = p_workspace_id AND revision.network_id = ANY (p_network_ids)
        RETURNING revision.network_id, revision.network_revision, revision.group_revision
    )
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'network_id', network.public_id,
               'network_revision', advanced.network_revision,
               'group_revision', advanced.group_revision
           ) ORDER BY network.public_id::TEXT), '[]'::JSONB)
    INTO v_result
    FROM advanced JOIN mesh.network AS network ON network.id = advanced.network_id;
    PERFORM pg_catalog.set_config('mesh.identity_catalog_fanout', '', TRUE);
    IF pg_catalog.jsonb_array_length(v_result) <> pg_catalog.cardinality(p_network_ids) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'a Network revision is unavailable';
    END IF;
    RETURN v_result;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.advance_member_networks_internal_v1(BIGINT, BIGINT[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The membership document of one member.
CREATE FUNCTION mesh_ops.workspace_member_document_internal_v1(p_membership mesh.workspace_membership)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'principal_id', (SELECT principal.public_id FROM mesh.principal AS principal
                         WHERE principal.id = p_membership.principal_id),
        'state', p_membership.state,
        'expires_at', p_membership.expires_at,
        'version', p_membership.version
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.workspace_member_document_internal_v1(mesh.workspace_membership)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.change_workspace_member_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_member_public_id UUID, p_action TEXT,
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
    v_before JSONB;
    v_devices JSONB := '[]'::JSONB;
    v_networks BIGINT[];
    v_advanced JSONB := '[]'::JSONB;
    v_sessions INTEGER := 0;
    v_now TIMESTAMPTZ := GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at);
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
        SET state = 'revoked', ended_at = v_now, end_reason = 'administrative',
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
$function$;

REVOKE ALL ON FUNCTION mesh_ops.change_workspace_member_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_workspace_member_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT, UUID, TIMESTAMPTZ
) TO mesh_runtime;
