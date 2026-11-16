-- Schema 295: role review 2026-11-15 (techdebt security.md TD-SEC-87), what it_admin still did beyond its job.
--
-- * interchange.manage leaves it_admin for network_admin: a Private Interchange relay goes into the signed relay map of
--   the Workspace's Networks as a preferred region, so whoever adds one sees relay traffic metadata and can drop it.
--   That is network infrastructure. admin keeps it; it_admin and the others keep interchange.read.
-- * Acting on a Device (suspend, resume, hand over, move to the Workspace, rename in change_device_lifecycle_v1, and
--   revocation, which the Go store performs) needed only the permission. Now, through
--   mesh_ops.device_actor_within_ceiling_v1: a Workspace Device or one's own always; the Workspace owner's Devices only
--   by the owner; any other member's only when the actor's Workspace-scope assigners reach every active role the owner
--   holds in the Workspace or this Network (and, with no assigners at all, no custom role binding there), the rule
--   member suspension and removal use. So an it_admin no longer suspends, revokes or takes the laptop of the owner, an
--   admin, a network_admin or an auditor. extend_device_v1 only lengthens a Device's life and stays as it is.
-- * remove_network_member_v1 let a Network-bound it_admin revoke roles bound to its Network, which
--   assign_workspace_role_v1 and revoke_workspace_role_v1 never let it grant or revoke: the two ceilings now agree, from
--   Workspace-scope roles only. Body otherwise as in 000228.
--
-- An it_admin still revokes, suspends and removes another it_admin: they hold the same permissions, so neither gains
-- anything; the owner or an admin restores what one undoes (accepted, TD-SEC-87).
--
-- change_device_lifecycle_v1 (body as in 000181) and remove_network_member_v1 are replaced in place; CREATE OR REPLACE
-- keeps their owners and grants. The helper is read only and answers only for the transaction's own Network scope;
-- the runtime may call it because Device revocation runs in the api's own transaction.
--
-- Not covered, recorded in techdebt: Workspace-owned Devices (servers, subnet routers, exit nodes) stay manageable by
-- anyone with the permission; change_device_tags_v2 needs tag ownership, not this ceiling; extend_device_v1 only
-- lengthens a Device's life.

ALTER TABLE mesh.builtin_role_permission DISABLE TRIGGER builtin_role_permission_immutable;
DELETE FROM mesh.builtin_role_permission AS grant_row
USING mesh.permission AS permission
WHERE permission.id = grant_row.permission_id AND grant_row.role_key = 'it_admin'
  AND permission.permission_key = 'interchange.manage';
ALTER TABLE mesh.builtin_role_permission ENABLE TRIGGER builtin_role_permission_immutable;
INSERT INTO mesh.builtin_role_permission (role_key, permission_id)
SELECT 'network_admin', permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'interchange.manage'
ON CONFLICT DO NOTHING;

-- Whether an actor may act on one Device of a Network, by who owns it.
CREATE FUNCTION mesh_ops.device_actor_within_ceiling_v1(
    p_workspace_id BIGINT,
    p_network_id BIGINT,
    p_device_id BIGINT,
    p_actor_public_id UUID,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_ownership TEXT;
    v_owner BIGINT;
    v_actor BIGINT;
    v_assigners TEXT[];
BEGIN
    IF p_workspace_id IS NULL OR p_network_id IS NULL OR p_device_id IS NULL OR p_actor_public_id IS NULL
        OR p_evaluated_at IS NULL
        -- Only about the transaction's own Network: the runtime may call this,
        -- so it never answers about another tenant.
        OR p_workspace_id IS DISTINCT FROM mesh_ops.current_workspace_id()
        OR p_network_id IS DISTINCT FROM mesh_ops.current_network_id() THEN
        RETURN FALSE;
    END IF;
    SELECT device.ownership, device.owner_principal_id INTO v_ownership, v_owner
    FROM mesh.device AS device
    WHERE device.id = p_device_id AND device.workspace_id = p_workspace_id AND device.network_id = p_network_id;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    IF v_ownership = 'workspace' THEN
        RETURN TRUE;
    END IF;
    SELECT principal.id INTO v_actor FROM mesh.principal AS principal WHERE principal.public_id = p_actor_public_id;
    IF v_actor IS NULL THEN
        RETURN FALSE;
    END IF;
    IF v_owner = v_actor THEN
        RETURN TRUE;
    END IF;
    IF EXISTS (
        SELECT 1 FROM mesh.workspace AS workspace
        WHERE workspace.id = p_workspace_id AND workspace.owner_principal_id = v_owner
    ) THEN
        RETURN FALSE;
    END IF;
    v_assigners := mesh_ops.workspace_role_assigners_v1(p_workspace_id, v_actor, p_evaluated_at);
    IF pg_catalog.cardinality(v_assigners) = 0 AND EXISTS (
        SELECT 1 FROM mesh.role_binding AS binding
        JOIN mesh.workspace_membership AS membership ON membership.id = binding.workspace_membership_id
        WHERE binding.workspace_id = p_workspace_id AND membership.principal_id = v_owner
          AND (binding.network_id IS NULL OR binding.network_id = p_network_id)
          AND binding.state <> 'revoked'
    ) THEN
        RETURN FALSE;
    END IF;
    RETURN NOT EXISTS (
        SELECT 1
        FROM mesh.workspace_role_assignment AS assignment
        JOIN mesh.builtin_role AS role ON role.role_key = assignment.role_key
        WHERE assignment.workspace_id = p_workspace_id AND assignment.principal_id = v_owner
          AND (assignment.network_id IS NULL OR assignment.network_id = p_network_id)
          AND assignment.state = 'active'
          AND (assignment.expires_at IS NULL OR assignment.expires_at > p_evaluated_at)
          AND NOT (role.assignable_by && v_assigners)
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.device_actor_within_ceiling_v1(BIGINT, BIGINT, BIGINT, UUID, TIMESTAMPTZ)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.device_actor_within_ceiling_v1(BIGINT, BIGINT, BIGINT, UUID, TIMESTAMPTZ)
    TO mesh_runtime;

CREATE OR REPLACE FUNCTION mesh_ops.change_device_lifecycle_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_device_public_id uuid, p_action text, p_expected_version bigint, p_target_principal_public_id uuid, p_hostname text, p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
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
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
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
        p_workspace_public_id, p_network_public_id, v_permission, pg_catalog.transaction_timestamp()
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
    -- TD-SEC-87: a member's Device only within the ceiling over its owner's
    -- roles; the owner's Devices only by the owner.
    IF NOT mesh_ops.device_actor_within_ceiling_v1(
            v_workspace, v_network, v_device.id, p_principal_public_id, v_now) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'the Device owner holds a role beyond the delegation ceiling';
    END IF;
    v_before := mesh_ops.device_lifecycle_document_internal_v1(v_device);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    CASE p_action
    WHEN 'suspend' THEN
        IF v_device.state <> 'active' THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'Device is not active';
        END IF;
        UPDATE mesh.device SET state = 'suspended', suspended_reason = 'admin',
            session_generation = session_generation + 1, version = version + 1, updated_at = GREATEST(v_now, updated_at)
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
            version = version + 1, updated_at = GREATEST(v_now, updated_at)
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
            session_generation = session_generation + 1, version = version + 1, updated_at = GREATEST(v_now, updated_at)
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
            session_generation = session_generation + 1, version = version + 1, updated_at = GREATEST(v_now, updated_at)
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
        IF EXISTS (
            SELECT 1 FROM mesh.device_dns_label AS other
            WHERE other.workspace_id = v_workspace AND other.network_id = v_network
              AND other.dns_label = mesh_ops.derive_device_dns_label_v1(v_hostname)
              AND other.device_id <> v_device.id
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL03', MESSAGE = 'another Device has this DNS name';
        END IF;
        UPDATE mesh.device SET hostname = v_hostname, hostname_key = v_hostname, hostname_locked = TRUE,
            version = version + 1, updated_at = GREATEST(v_now, updated_at)
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
    -- The actor's assigners come from Workspace-scope roles only, for roles of
    -- either scope, exactly as assign_workspace_role_v1 and
    -- revoke_workspace_role_v1 decide (TD-SEC-87): a role bound to this Network
    -- gives its holder no ceiling over other members' roles.
    v_assigners := mesh_ops.workspace_role_assigners_v1(v_scope.workspace_id, v_actor, v_now);
    v_network_assigners := v_assigners;
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
    -- Schema 228: the member leaves the Network's user groups with it.
    WITH removed AS (
        DELETE FROM mesh.identity_group_member AS member
        USING mesh.identity_group AS identity_group
        WHERE identity_group.id = member.identity_group_id
          AND identity_group.workspace_id = v_scope.workspace_id
          AND identity_group.network_id = v_scope.network_id AND member.principal_id = v_member
        RETURNING member.identity_group_id
    )
    UPDATE mesh.identity_group AS identity_group
    SET member_count = identity_group.member_count - changed.removed,
        version = identity_group.version + 1, updated_at = GREATEST(v_now, identity_group.updated_at)
    FROM (SELECT removed.identity_group_id, pg_catalog.count(*)::INTEGER AS removed
          FROM removed GROUP BY removed.identity_group_id) AS changed
    WHERE identity_group.id = changed.identity_group_id;
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
