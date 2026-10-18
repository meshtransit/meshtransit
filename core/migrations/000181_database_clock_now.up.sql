-- The database clock is the only "now" (see the dbclock package). These
-- functions took GREATEST(clock_timestamp(), p_evaluated_at) as now and
-- passed p_evaluated_at to the permission resolvers, so a caller's clock
-- could move validity checks and stamps (valid_from, ended_at, revoked_at)
-- forward. Each now uses transaction_timestamp(), the same instant MeshCore
-- reads at the start of the unit of work and sends as p_evaluated_at, for
-- both. p_evaluated_at stays in the signature, still required, so MeshCore
-- binaries on either side of this migration keep calling them unchanged.
--
-- The transaction's start can precede a row a concurrent transaction wrote
-- after it, so a stamp written onto an existing row never goes below that
-- row's own times: ended_at no earlier than a session's issued_at, and
-- revoked_at and updated_at no earlier than the row's updated_at (the
-- timestamp checks require ended_at >= issued_at and updated_at >=
-- created_at). Bodies are otherwise unchanged; CREATE OR REPLACE keeps
-- owners and grants.

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
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.change_device_group_members_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_group_public_id uuid, p_expected_version bigint, p_add jsonb, p_remove uuid[], p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    v_scope RECORD;
    v_group mesh.device_group%ROWTYPE;
    v_before JSONB;
    v_hash_before BYTEA;
    v_hash_after BYTEA;
    v_requested INTEGER;
    v_eligible INTEGER;
    v_added INTEGER := 0;
    v_removed INTEGER := 0;
    v_count INTEGER;
    v_network_revision BIGINT;
    v_group_revision BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_group_public_id IS NULL OR p_expected_version IS NULL OR p_expected_version < 1
        OR p_add IS NULL OR pg_catalog.jsonb_typeof(p_add) <> 'array'
        OR pg_catalog.jsonb_array_length(p_add) > 150
        OR p_remove IS NULL OR pg_catalog.cardinality(p_remove) > 150
        OR pg_catalog.jsonb_array_length(p_add) + pg_catalog.cardinality(p_remove) = 0
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_array_elements(p_add) AS entry(value)
            WHERE pg_catalog.jsonb_typeof(entry.value) <> 'object'
               OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(entry.value)) <> 2
               OR NOT entry.value ? 'device_id' OR NOT entry.value ? 'member_id'
        ) OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_add) AS item(device_id UUID, member_id UUID)
            WHERE item.device_id IS NULL OR item.member_id IS NULL
               OR pg_catalog.get_byte(pg_catalog.uuid_send(item.member_id), 6) >> 4 <> 7
        ) OR (
            SELECT pg_catalog.count(DISTINCT item.device_id) <> pg_catalog.jsonb_array_length(p_add)
            FROM pg_catalog.jsonb_to_recordset(p_add) AS item(device_id UUID, member_id UUID)
        ) OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p_remove) AS removed(id) WHERE removed.id IS NULL)
        OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_add) AS item(device_id UUID, member_id UUID)
            WHERE item.device_id = ANY (p_remove)
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device Group membership change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_device_group_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device_group.members.manage', pg_catalog.transaction_timestamp()
    );
    SELECT revision.network_revision, revision.group_revision
    INTO v_network_revision, v_group_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    FOR UPDATE;
    IF v_network_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Device Group scope is unavailable';
    END IF;
    SELECT * INTO v_group FROM mesh.device_group AS device_group
    WHERE device_group.workspace_id = v_scope.workspace_id AND device_group.network_id = v_scope.network_id
      AND device_group.public_id = p_group_public_id AND device_group.state = 'active'
    FOR UPDATE;
    IF v_group.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device Group is unavailable';
    END IF;
    IF v_group.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device Group version changed';
    END IF;
    v_before := mesh_ops.device_group_document_internal_v1(v_group);
    v_hash_before := mesh_ops.device_group_member_hash_internal_v1(v_group.id);

    v_requested := pg_catalog.jsonb_array_length(p_add);
    IF v_requested > 0 THEN
        SELECT pg_catalog.count(*)::INTEGER INTO v_eligible
        FROM pg_catalog.jsonb_to_recordset(p_add) AS item(device_id UUID, member_id UUID)
        JOIN mesh.device AS device
          ON device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
         AND device.public_id = item.device_id
         AND device.state = 'active' AND device.deleted_at IS NULL;
        IF v_eligible <> v_requested THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD01', MESSAGE = 'a Device is not an active Device of this Network';
        END IF;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    IF pg_catalog.cardinality(p_remove) > 0 THEN
        DELETE FROM mesh.device_group_member AS member
        USING mesh.device AS device
        WHERE member.device_group_id = v_group.id AND device.id = member.device_id
          AND device.public_id = ANY (p_remove);
        GET DIAGNOSTICS v_removed = ROW_COUNT;
    END IF;
    IF v_requested > 0 THEN
        INSERT INTO mesh.device_group_member (
            public_id, workspace_id, network_id, device_group_id, device_id, created_at
        )
        SELECT item.member_id, v_scope.workspace_id, v_scope.network_id, v_group.id, device.id, v_now
        FROM pg_catalog.jsonb_to_recordset(p_add) AS item(device_id UUID, member_id UUID)
        JOIN mesh.device AS device
          ON device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
         AND device.public_id = item.device_id
        ORDER BY device.id
        ON CONFLICT (device_group_id, device_id) DO NOTHING;
        GET DIAGNOSTICS v_added = ROW_COUNT;
    END IF;

    IF v_added + v_removed > 0 THEN
        SELECT pg_catalog.count(*)::INTEGER INTO v_count
        FROM mesh.device_group_member AS member WHERE member.device_group_id = v_group.id;
        IF v_count > 5000 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD03', MESSAGE = 'Device Group would exceed 5000 members';
        END IF;
        UPDATE mesh.device_group
        SET member_count = v_count, version = version + 1, updated_at = GREATEST(v_now, updated_at)
        WHERE id = v_group.id
        RETURNING * INTO v_group;
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            group_revision = revision.group_revision + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
        RETURNING revision.network_revision, revision.group_revision
        INTO v_network_revision, v_group_revision;
        IF v_added > 0 AND mesh_ops.device_group_rule_count_internal_v1(v_group.id) > 0
            AND mesh_ops.max_device_policy_edges_internal_v1(v_scope.workspace_id, v_scope.network_id) > 10000 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD06',
                MESSAGE = 'a Device would load more than 10000 rule edges';
        END IF;
    END IF;
    v_hash_after := mesh_ops.device_group_member_hash_internal_v1(v_group.id);
    RETURN pg_catalog.jsonb_build_object(
        'group', mesh_ops.device_group_document_internal_v1(v_group),
        'previous', v_before,
        'added', v_added,
        'removed', v_removed,
        'changed', v_added + v_removed > 0,
        'member_hash_before', pg_catalog.encode(v_hash_before, 'hex'),
        'member_hash_after', pg_catalog.encode(v_hash_after, 'hex'),
        'network_revision', v_network_revision,
        'group_revision', v_group_revision,
        'role_binding_id', v_scope.role_binding_public_id
    );
END;
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.change_device_group_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_operation text, p_group_public_id uuid, p_expected_version bigint, p_name text, p_description text, p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    v_scope RECORD;
    v_group mesh.device_group%ROWTYPE;
    v_before JSONB;
    v_hash_before BYTEA;
    v_network_revision BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_operation NOT IN ('create', 'update', 'delete') OR p_group_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version < 1))
        OR (p_operation <> 'delete' AND (p_name IS NULL OR p_description IS NULL)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device Group change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_device_group_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device_group.manage', pg_catalog.transaction_timestamp()
    );
    -- Serializes group changes with publication and membership changes.
    SELECT revision.network_revision INTO v_network_revision FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    FOR UPDATE;
    IF v_network_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Device Group scope is unavailable';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    IF p_operation = 'create' THEN
        IF (SELECT pg_catalog.count(*) FROM mesh.device_group AS device_group
            WHERE device_group.workspace_id = v_scope.workspace_id
              AND device_group.network_id = v_scope.network_id
              AND device_group.state = 'active') >= 200 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD02', MESSAGE = 'Network already has the maximum Device Groups';
        END IF;
        BEGIN
            INSERT INTO mesh.device_group (
                public_id, deployment_id, workspace_id, network_id, name, name_key, description,
                created_at, updated_at
            ) VALUES (
                p_group_public_id, v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id,
                p_name, pg_catalog.lower(p_name), p_description, v_now, v_now
            ) RETURNING * INTO v_group;
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD04', MESSAGE = 'Device Group name is taken';
        END;
        RETURN pg_catalog.jsonb_build_object(
            'group', mesh_ops.device_group_document_internal_v1(v_group),
            'previous', NULL,
            'member_hash_before', NULL,
            'member_hash_after', pg_catalog.encode(mesh_ops.device_group_member_hash_internal_v1(v_group.id), 'hex'),
            'network_revision', v_network_revision,
            'role_binding_id', v_scope.role_binding_public_id);
    END IF;

    SELECT * INTO v_group FROM mesh.device_group AS device_group
    WHERE device_group.workspace_id = v_scope.workspace_id AND device_group.network_id = v_scope.network_id
      AND device_group.public_id = p_group_public_id AND device_group.state = 'active'
    FOR UPDATE;
    IF v_group.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device Group is unavailable';
    END IF;
    IF v_group.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device Group version changed';
    END IF;
    v_before := mesh_ops.device_group_document_internal_v1(v_group);
    v_hash_before := mesh_ops.device_group_member_hash_internal_v1(v_group.id);

    IF p_operation = 'update' THEN
        BEGIN
            UPDATE mesh.device_group
            SET name = p_name, name_key = pg_catalog.lower(p_name), description = p_description,
                version = version + 1, updated_at = GREATEST(v_now, updated_at)
            WHERE id = v_group.id
            RETURNING * INTO v_group;
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD04', MESSAGE = 'Device Group name is taken';
        END;
    ELSE
        IF mesh_ops.device_group_rule_count_internal_v1(v_group.id) > 0 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD05', MESSAGE = 'Device Group is selected by active rules';
        END IF;
        DELETE FROM mesh.device_group_member WHERE device_group_id = v_group.id;
        UPDATE mesh.device_group
        SET state = 'deleted', member_count = 0, deleted_at = GREATEST(v_now, updated_at),
            version = version + 1, updated_at = GREATEST(v_now, updated_at)
        WHERE id = v_group.id
        RETURNING * INTO v_group;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'group', mesh_ops.device_group_document_internal_v1(v_group),
        'previous', v_before,
        'member_hash_before', pg_catalog.encode(v_hash_before, 'hex'),
        'member_hash_after', pg_catalog.encode(mesh_ops.device_group_member_hash_internal_v1(v_group.id), 'hex'),
        'network_revision', v_network_revision,
        'role_binding_id', v_scope.role_binding_public_id);
END;
$function$
;

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
        PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = v_scope.workspace_id FOR UPDATE;
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

CREATE OR REPLACE FUNCTION mesh_ops.change_device_tags_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_device_public_id uuid, p_add jsonb, p_remove uuid[], p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_device mesh.device%ROWTYPE;
    v_grant RECORD;
    v_principal BIGINT;
    v_manage_any BOOLEAN;
    v_manage_devices BOOLEAN;
    v_requested UUID[];
    v_known INTEGER;
    v_hash_before BYTEA;
    v_added INTEGER := 0;
    v_removed INTEGER := 0;
    v_network_revision BIGINT;
    v_group_revision BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL OR p_device_public_id IS NULL
        OR p_add IS NULL OR pg_catalog.jsonb_typeof(p_add) <> 'array'
        OR pg_catalog.jsonb_array_length(p_add) > 32
        OR p_remove IS NULL OR pg_catalog.cardinality(p_remove) > 32
        OR pg_catalog.jsonb_array_length(p_add) + pg_catalog.cardinality(p_remove) = 0
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_array_elements(p_add) AS entry(value)
            WHERE pg_catalog.jsonb_typeof(entry.value) <> 'object'
               OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(entry.value)) <> 2
               OR NOT entry.value ? 'tag_id' OR NOT entry.value ? 'assignment_id'
        ) OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_add) AS item(tag_id UUID, assignment_id UUID)
            WHERE item.tag_id IS NULL OR item.assignment_id IS NULL
               OR pg_catalog.get_byte(pg_catalog.uuid_send(item.assignment_id), 6) >> 4 <> 7
        ) OR (
            SELECT pg_catalog.count(DISTINCT item.tag_id) <> pg_catalog.jsonb_array_length(p_add)
            FROM pg_catalog.jsonb_to_recordset(p_add) AS item(tag_id UUID, assignment_id UUID)
        ) OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p_remove) AS removed(id) WHERE removed.id IS NULL)
        OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_add) AS item(tag_id UUID, assignment_id UUID)
            WHERE item.tag_id = ANY (p_remove)
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'device tag assignment change is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device.read', pg_catalog.transaction_timestamp()
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'device tag assignment is not authorized';
    END IF;
    SELECT principal.id INTO v_principal FROM mesh.principal AS principal
    WHERE principal.public_id = p_principal_public_id AND principal.state = 'active';
    v_manage_any := mesh_ops.holds_workspace_permission_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'device_tag.manage', pg_catalog.transaction_timestamp());
    v_manage_devices := mesh_ops.holds_device_group_permission_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device.manage', pg_catalog.transaction_timestamp());

    -- Serializes tag changes with publication and other map inputs.
    SELECT revision.network_revision INTO v_network_revision FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
    FOR UPDATE;
    SELECT * INTO v_device FROM mesh.device AS device
    WHERE device.workspace_id = v_workspace AND device.network_id = v_network
      AND device.public_id = p_device_public_id AND device.state = 'active' AND device.deleted_at IS NULL
    FOR UPDATE;
    IF v_device.id IS NULL OR v_network_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device is unavailable';
    END IF;
    v_requested := ARRAY(
        SELECT item.tag_id FROM pg_catalog.jsonb_to_recordset(p_add) AS item(tag_id UUID, assignment_id UUID)
        UNION ALL SELECT removed.id FROM pg_catalog.unnest(p_remove) AS removed(id)
    );
    SELECT pg_catalog.count(*)::INTEGER INTO v_known
    FROM pg_catalog.unnest(v_requested) AS requested(id)
    JOIN mesh.device_tag AS tag
      ON tag.workspace_id = v_workspace AND tag.public_id = requested.id AND tag.state = 'active';
    IF v_known <> pg_catalog.cardinality(v_requested) THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'device tag is unavailable';
    END IF;
    IF NOT v_manage_any AND (
        v_principal IS NULL
        OR (v_device.owner_principal_id <> v_principal AND NOT v_manage_devices)
        OR EXISTS (
            SELECT 1 FROM pg_catalog.unnest(v_requested) AS requested(id)
            JOIN mesh.device_tag AS tag ON tag.workspace_id = v_workspace AND tag.public_id = requested.id
            WHERE NOT mesh_ops.device_tag_owned_by_internal_v1(tag.id, v_workspace, v_network, v_principal, v_now)
        )) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'device tag assignment is not authorized';
    END IF;

    v_hash_before := mesh_ops.device_tag_set_hash_internal_v1(v_device.id);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    IF pg_catalog.cardinality(p_remove) > 0 THEN
        DELETE FROM mesh.device_tag_assignment AS assignment
        USING mesh.device_tag AS tag
        WHERE assignment.device_id = v_device.id AND tag.id = assignment.device_tag_id
          AND tag.public_id = ANY (p_remove);
        GET DIAGNOSTICS v_removed = ROW_COUNT;
    END IF;
    IF pg_catalog.jsonb_array_length(p_add) > 0 THEN
        INSERT INTO mesh.device_tag_assignment (
            public_id, workspace_id, network_id, device_id, device_tag_id, created_at
        )
        SELECT item.assignment_id, v_workspace, v_network, v_device.id, tag.id, v_now
        FROM pg_catalog.jsonb_to_recordset(p_add) AS item(tag_id UUID, assignment_id UUID)
        JOIN mesh.device_tag AS tag ON tag.workspace_id = v_workspace AND tag.public_id = item.tag_id
        ORDER BY tag.id
        ON CONFLICT (device_id, device_tag_id) DO NOTHING;
        GET DIAGNOSTICS v_added = ROW_COUNT;
    END IF;
    IF v_added + v_removed > 0 THEN
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            group_revision = revision.group_revision + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
        RETURNING revision.network_revision, revision.group_revision
        INTO v_network_revision, v_group_revision;
        IF v_added > 0 AND mesh_ops.max_device_policy_edges_internal_v1(v_workspace, v_network) > 10000 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD06', MESSAGE = 'a Device would load more than 10000 rule edges';
        END IF;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'device_id', v_device.public_id,
        'device_name', v_device.hostname,
        'tag_ids', COALESCE((
            SELECT pg_catalog.jsonb_agg(tag.public_id ORDER BY tag.public_id::TEXT)
            FROM mesh.device_tag_assignment AS assignment
            JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id
            WHERE assignment.device_id = v_device.id
        ), '[]'::JSONB),
        'added', v_added,
        'removed', v_removed,
        'changed', v_added + v_removed > 0,
        'tag_set_hash_before', pg_catalog.encode(v_hash_before, 'hex'),
        'tag_set_hash_after', pg_catalog.encode(mesh_ops.device_tag_set_hash_internal_v1(v_device.id), 'hex'),
        'network_revision', v_network_revision,
        'group_revision', v_group_revision,
        'role_binding_id', v_grant.role_binding_public_id,
        'manage_any', v_manage_any
    );
END;
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.change_identity_group_members_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_group_public_id uuid, p_expected_version bigint, p_add jsonb, p_remove uuid[], p_change_public_id uuid, p_evaluated_at timestamp with time zone)
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
    v_requested INTEGER;
    v_eligible INTEGER;
    v_added INTEGER := 0;
    v_removed INTEGER := 0;
    v_count INTEGER;
    v_networks BIGINT[];
    v_advanced JSONB := '[]'::JSONB;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_group_public_id IS NULL OR p_expected_version IS NULL OR p_expected_version < 1
        OR p_add IS NULL OR pg_catalog.jsonb_typeof(p_add) <> 'array'
        OR pg_catalog.jsonb_array_length(p_add) > 150
        OR p_remove IS NULL OR pg_catalog.cardinality(p_remove) > 150
        OR pg_catalog.jsonb_array_length(p_add) + pg_catalog.cardinality(p_remove) = 0
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_array_elements(p_add) AS entry(value)
            WHERE pg_catalog.jsonb_typeof(entry.value) <> 'object'
               OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(entry.value)) <> 2
               OR NOT entry.value ? 'principal_id' OR NOT entry.value ? 'member_id'
        ) OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_add) AS item(principal_id UUID, member_id UUID)
            WHERE item.principal_id IS NULL OR item.member_id IS NULL
               OR pg_catalog.get_byte(pg_catalog.uuid_send(item.member_id), 6) >> 4 <> 7
        ) OR (
            SELECT pg_catalog.count(DISTINCT item.principal_id) <> pg_catalog.jsonb_array_length(p_add)
            FROM pg_catalog.jsonb_to_recordset(p_add) AS item(principal_id UUID, member_id UUID)
        ) OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p_remove) AS removed(id) WHERE removed.id IS NULL)
        OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_add) AS item(principal_id UUID, member_id UUID)
            WHERE item.principal_id = ANY (p_remove)
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Identity Group membership change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_identity_catalog_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'identity_group.manage', pg_catalog.transaction_timestamp()
    );
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

    v_requested := pg_catalog.jsonb_array_length(p_add);
    IF v_requested > 0 THEN
        SELECT pg_catalog.count(*)::INTEGER INTO v_eligible
        FROM pg_catalog.jsonb_to_recordset(p_add) AS item(principal_id UUID, member_id UUID)
        JOIN mesh.principal AS principal
          ON principal.deployment_id = v_scope.deployment_id AND principal.public_id = item.principal_id
         AND principal.state = 'active' AND principal.deleted_at IS NULL
        JOIN mesh.workspace_membership AS membership
          ON membership.workspace_id = v_scope.workspace_id AND membership.principal_id = principal.id
         AND membership.state = 'active'
         AND (membership.expires_at IS NULL OR membership.expires_at > v_now);
        IF v_eligible <> v_requested THEN
            RAISE EXCEPTION USING ERRCODE = 'MTI01', MESSAGE = 'a principal is not an active member of this Workspace';
        END IF;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    IF pg_catalog.cardinality(p_remove) > 0 THEN
        DELETE FROM mesh.identity_group_member AS member
        USING mesh.principal AS principal
        WHERE member.identity_group_id = v_group.id AND principal.id = member.principal_id
          AND principal.public_id = ANY (p_remove);
        GET DIAGNOSTICS v_removed = ROW_COUNT;
    END IF;
    IF v_requested > 0 THEN
        INSERT INTO mesh.identity_group_member (public_id, workspace_id, identity_group_id, principal_id, created_at)
        SELECT item.member_id, v_scope.workspace_id, v_group.id, principal.id, v_now
        FROM pg_catalog.jsonb_to_recordset(p_add) AS item(principal_id UUID, member_id UUID)
        JOIN mesh.principal AS principal
          ON principal.deployment_id = v_scope.deployment_id AND principal.public_id = item.principal_id
        ORDER BY principal.id
        ON CONFLICT (identity_group_id, principal_id) DO NOTHING;
        GET DIAGNOSTICS v_added = ROW_COUNT;
    END IF;

    IF v_added + v_removed > 0 THEN
        SELECT pg_catalog.count(*)::INTEGER INTO v_count
        FROM mesh.identity_group_member AS member WHERE member.identity_group_id = v_group.id;
        IF v_count > 10000 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTI03', MESSAGE = 'Identity Group would exceed 10000 members';
        END IF;
        UPDATE mesh.identity_group
        SET member_count = v_count, version = version + 1, updated_at = GREATEST(v_now, updated_at)
        WHERE id = v_group.id
        RETURNING * INTO v_group;
        SELECT pg_catalog.array_agg(DISTINCT rule.network_id ORDER BY rule.network_id) INTO v_networks
        FROM mesh.compiled_policy_group_rule AS rule
        JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id AND release.state = 'active'
        WHERE rule.workspace_id = v_scope.workspace_id AND rule.source_identity_group_id = v_group.id;
        IF v_networks IS NOT NULL THEN
            v_advanced := mesh_ops.advance_identity_networks_internal_v1(v_scope.workspace_id, v_networks);
            IF v_added > 0 AND mesh_ops.identity_networks_over_edge_budget_internal_v1(
                    v_scope.workspace_id, v_networks) THEN
                RAISE EXCEPTION USING ERRCODE = 'MTD06', MESSAGE = 'a Device would load more than 10000 rule edges';
            END IF;
        END IF;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'group', mesh_ops.identity_group_document_internal_v1(v_group),
        'previous', v_before,
        'added', v_added,
        'removed', v_removed,
        'changed', v_added + v_removed > 0,
        'member_hash_before', pg_catalog.encode(v_hash_before, 'hex'),
        'member_hash_after', pg_catalog.encode(mesh_ops.identity_group_member_hash_internal_v1(v_group.id), 'hex'),
        'networks', v_advanced,
        'authority', v_scope.authority
    );
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
        PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = v_scope.workspace_id FOR UPDATE;
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
    WHERE workspace.id = v_scope.workspace_id FOR UPDATE;

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

CREATE OR REPLACE FUNCTION mesh_ops.list_workspace_invitations_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_evaluated_at timestamp with time zone)
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
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    SELECT * INTO v_scope FROM mesh_ops.authorize_workspace_people_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'member.invite', v_now
    );
    RETURN pg_catalog.jsonb_build_object(
        'invitations', COALESCE((
            SELECT pg_catalog.jsonb_agg(
                mesh_ops.workspace_invitation_document_internal_v1(listed, v_now)
                ORDER BY listed.created_at DESC, listed.public_id DESC)
            FROM (
                SELECT invitation.* FROM mesh.workspace_invitation AS invitation
                WHERE invitation.workspace_id = v_scope.workspace_id
                  AND (invitation.state = 'pending' OR invitation.updated_at > v_now - INTERVAL '30 days')
                ORDER BY invitation.created_at DESC, invitation.public_id DESC
                LIMIT 500
            ) AS listed
        ), '[]'::JSONB)
    );
END;
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.logout_device_v1(p_machine_fingerprint bytea, p_node_key bytea, p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_device mesh.device%ROWTYPE;
    v_before JSONB;
    v_actor UUID;
    v_network_revision BIGINT;
    v_inventory_revision BIGINT;
    v_group_revision BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_change_public_id IS NULL OR p_evaluated_at IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device logout is invalid';
    END IF;
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;

    -- Serializes with registration, publication and other map inputs.
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
    FOR UPDATE;
    SELECT device.* INTO v_device
    FROM mesh.device AS device
    JOIN mesh.device_machine_key_epoch AS machine
      ON machine.workspace_id = device.workspace_id AND machine.network_id = device.network_id
     AND machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch
     AND machine.state = 'active' AND machine.fingerprint = p_machine_fingerprint
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.workspace_id = device.workspace_id AND node_key.network_id = device.network_id
     AND node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
     AND node_key.state = 'active' AND node_key.public_key = p_node_key
    WHERE device.workspace_id = v_workspace AND device.network_id = v_network
      AND device.state = 'active' AND device.deleted_at IS NULL
    FOR UPDATE OF device;
    IF v_device.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device is unavailable';
    END IF;
    SELECT principal.public_id INTO STRICT v_actor
    FROM mesh.principal AS principal WHERE principal.id = v_device.owner_principal_id;
    v_before := mesh_ops.device_lifecycle_document_internal_v1(v_device);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    PERFORM mesh_ops.revoke_member_device_internal_v1(v_device.id, 'logged out', v_now);
    SELECT * INTO STRICT v_device FROM mesh.device AS device WHERE device.id = v_device.id;

    -- Peers lose the Device and groups their member: every projection moves.
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        inventory_revision = revision.inventory_revision + 1,
        group_revision = revision.group_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
    RETURNING revision.network_revision, revision.inventory_revision, revision.group_revision
    INTO v_network_revision, v_inventory_revision, v_group_revision;

    RETURN pg_catalog.jsonb_build_object(
        'before', v_before,
        'after', mesh_ops.device_lifecycle_document_internal_v1(v_device),
        'actor_principal_id', v_actor,
        'network_revision', v_network_revision,
        'inventory_revision', v_inventory_revision,
        'group_revision', v_group_revision
    );
END;
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.preview_workspace_invitation_v1(p_token_digest bytea, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    v_invitation mesh.workspace_invitation%ROWTYPE;
    v_result JSONB;
BEGIN
    IF p_token_digest IS NULL OR pg_catalog.octet_length(p_token_digest) <> 32 THEN
        RETURN NULL;
    END IF;
    SELECT * INTO v_invitation FROM mesh.workspace_invitation AS invitation
    WHERE invitation.token_digest = p_token_digest AND invitation.state = 'pending'
      AND invitation.expires_at > pg_catalog.transaction_timestamp();
    IF v_invitation.id IS NULL THEN
        RETURN NULL;
    END IF;
    -- Schema 16's scope policy admits exactly this Workspace for the read.
    PERFORM pg_catalog.set_config('mesh.workspace_id', v_invitation.workspace_id::TEXT, TRUE);
    SELECT pg_catalog.jsonb_build_object(
        'workspace_name', workspace.display_name,
        'inviter_name', COALESCE(account.display_name, ''),
        'email', v_invitation.email,
        'role', v_invitation.role_key,
        'expires_at', v_invitation.expires_at
    ) INTO v_result
    FROM mesh.workspace AS workspace
    LEFT JOIN mesh.account AS account ON account.principal_id = v_invitation.invited_by_principal_id
    WHERE workspace.id = v_invitation.workspace_id AND workspace.state = 'active' AND workspace.deleted_at IS NULL;
    PERFORM pg_catalog.set_config('mesh.workspace_id', '', TRUE);
    RETURN v_result;
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

CREATE OR REPLACE FUNCTION mesh_ops.set_network_alias_ranges_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_expected_version bigint, p_set_ipv4 boolean, p_ipv4_prefix cidr, p_ipv4_row_public_id uuid, p_set_ipv6 boolean, p_ipv6_prefix cidr, p_ipv6_row_public_id uuid, p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    v_prior TEXT := pg_catalog.current_setting('mesh.device_alias_deployment_id', TRUE);
    v_scope RECORD;
    v_before JSONB;
    v_after JSONB;
    v_network_revision BIGINT;
    v_current BIGINT;
    v_request RECORD;
    v_frame CIDR;
    v_existing mesh.network_alias_range%ROWTYPE;
    v_changed BOOLEAN := FALSE;
    v_now TIMESTAMPTZ;
BEGIN
    IF p_expected_version IS NULL OR p_expected_version < 1
        OR p_set_ipv4 IS NULL OR p_set_ipv6 IS NULL OR NOT (p_set_ipv4 OR p_set_ipv6)
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_set_ipv4 AND (p_ipv4_row_public_id IS NULL
            OR pg_catalog.get_byte(pg_catalog.uuid_send(p_ipv4_row_public_id), 6) >> 4 <> 7))
        OR (p_set_ipv6 AND (p_ipv6_row_public_id IS NULL
            OR pg_catalog.get_byte(pg_catalog.uuid_send(p_ipv6_row_public_id), 6) >> 4 <> 7)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network alias range request is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_network_alias_range_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.update', pg_catalog.transaction_timestamp()
    );
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', v_scope.deployment_id::TEXT, TRUE);
    -- Alias allocation holds this lock too, so no alias appears mid-check.
    SELECT revision.network_revision INTO v_network_revision FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    FOR UPDATE;
    IF v_network_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network alias range scope is unavailable';
    END IF;
    PERFORM range.id FROM mesh.network_alias_range AS range
    WHERE range.network_id = v_scope.network_id ORDER BY range.family FOR UPDATE;
    v_before := mesh_ops.network_alias_range_state_internal_v1(v_scope.deployment_id, v_scope.network_id);
    v_current := (v_before ->> 'version')::BIGINT;
    IF v_current <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MTR03', MESSAGE = 'Network alias range version changed';
    END IF;
    v_now := pg_catalog.transaction_timestamp();
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    FOR v_request IN
        SELECT * FROM (VALUES
            (4, p_set_ipv4, p_ipv4_prefix, p_ipv4_row_public_id),
            (6, p_set_ipv6, p_ipv6_prefix, p_ipv6_row_public_id)
        ) AS request(family, requested, prefix, row_public_id)
        WHERE request.requested
        ORDER BY request.family
    LOOP
        IF v_request.prefix IS NOT NULL THEN
            IF pg_catalog.family(v_request.prefix) <> v_request.family THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network alias range family is invalid';
            END IF;
            SELECT pool.prefix INTO v_frame FROM mesh.address_pool AS pool
            WHERE pool.deployment_id = v_scope.deployment_id AND pool.workspace_id IS NULL
              AND pool.purpose = 'federation_resource_alias' AND pool.family = v_request.family
              AND pool.state = 'active' AND pool.deleted_at IS NULL
              AND v_request.prefix <<= pool.prefix
            ORDER BY pool.id LIMIT 1;
            IF v_frame IS NULL THEN
                RAISE EXCEPTION USING ERRCODE = 'MTR01', MESSAGE = 'Network alias range is outside the frame';
            END IF;
            IF EXISTS (
                SELECT 1 FROM mesh.device_alias_lease AS lease
                WHERE lease.consumer_network_id = v_scope.network_id AND lease.alias_role = 'resource'
                  AND lease.family = v_request.family AND lease.state IN ('reserved', 'quarantined')
                  AND NOT lease.address <<= v_request.prefix
            ) OR EXISTS (
                SELECT 1 FROM mesh.federation_alias_lease AS lease
                WHERE lease.consumer_network_id = v_scope.network_id AND lease.family = v_request.family
                  AND lease.state IN ('reserved', 'active')
                  AND NOT lease.resource_alias <<= v_request.prefix
            ) THEN
                RAISE EXCEPTION USING ERRCODE = 'MTR02', MESSAGE = 'Network alias range would exclude a retained alias';
            END IF;
        END IF;
        SELECT * INTO v_existing FROM mesh.network_alias_range AS range
        WHERE range.network_id = v_scope.network_id AND range.family = v_request.family;
        IF v_existing.id IS NULL THEN
            IF v_request.prefix IS NOT NULL THEN
                INSERT INTO mesh.network_alias_range (
                    public_id, deployment_id, workspace_id, network_id, family, prefix,
                    version, created_at, updated_at
                ) VALUES (
                    v_request.row_public_id, v_scope.deployment_id, v_scope.workspace_id,
                    v_scope.network_id, v_request.family, v_request.prefix, 1, v_now, v_now
                );
                v_changed := TRUE;
            END IF;
        ELSIF v_existing.prefix IS DISTINCT FROM v_request.prefix THEN
            UPDATE mesh.network_alias_range
            SET prefix = v_request.prefix, version = version + 1,
                updated_at = GREATEST(v_now, v_existing.updated_at)
            WHERE id = v_existing.id;
            v_changed := TRUE;
        END IF;
    END LOOP;

    v_after := mesh_ops.network_alias_range_state_internal_v1(v_scope.deployment_id, v_scope.network_id);
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', COALESCE(v_prior, ''), TRUE);
    RETURN pg_catalog.jsonb_build_object(
        'changed', v_changed,
        'role_binding_id', v_scope.role_binding_public_id,
        'network_revision', v_network_revision,
        'before', v_before,
        'after', v_after
    );
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', COALESCE(v_prior, ''), TRUE);
    RAISE;
END;
$function$
;
