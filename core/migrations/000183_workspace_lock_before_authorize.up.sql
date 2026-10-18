-- Three Workspace changes no longer take their Workspace row FOR SHARE
-- before FOR NO KEY UPDATE.
--
-- Creating a user group or a tag, and every invitation change, checked the
-- caller's permission first. The permission resolver reads the Workspace
-- row FOR SHARE; the function then asked for FOR NO KEY UPDATE on the same
-- row to serialize the change. Two such changes in one Workspace, or one
-- and any other change past its own permission check, each held SHARE and
-- waited for the other to release it: a deadlock (40P01).
--
-- Each now enters the Workspace scope, checks that the session is bound to
-- it, and locks the row FOR NO KEY UPDATE before the permission check, as
-- the member changes already do; the resolver's FOR SHARE then adds
-- nothing. A tag or group update or deletion locks no Workspace row, as
-- before. A session bound to the Workspace but without the permission now
-- holds the row until its call fails, one statement under the caller's lock
-- and statement timeouts, as with member changes. Bodies are otherwise
-- unchanged; CREATE OR REPLACE keeps owners and grants.

CREATE OR REPLACE FUNCTION mesh_ops.change_device_tag_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_operation text, p_tag_public_id uuid, p_expected_version bigint, p_name text, p_description text, p_owner_group_ids uuid[], p_owner_roles text[], p_owner_row_ids uuid[], p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    v_scope RECORD;
    v_locked BIGINT;
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
    -- The Workspace row lock comes before the permission check, which reads
    -- the row FOR SHARE: two changes that each took SHARE and then asked
    -- for NO KEY UPDATE would wait for each other.
    IF p_operation = 'create' THEN
        v_locked := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
        IF v_locked IS NULL OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, v_locked) THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'identity catalog scope is unavailable';
        END IF;
        PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = v_locked FOR NO KEY UPDATE;
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
    v_locked BIGINT;
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
    -- The Workspace row lock comes before the permission check, which reads
    -- the row FOR SHARE: two changes that each took SHARE and then asked
    -- for NO KEY UPDATE would wait for each other.
    IF p_operation = 'create' THEN
        v_locked := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
        IF v_locked IS NULL OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, v_locked) THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'identity catalog scope is unavailable';
        END IF;
        PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = v_locked FOR NO KEY UPDATE;
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
    v_locked BIGINT;
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
    -- The Workspace row lock comes before the permission check, which reads
    -- the row FOR SHARE: two changes that each took SHARE and then asked
    -- for NO KEY UPDATE would wait for each other.
    v_locked := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF v_locked IS NULL OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, v_locked) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Workspace people scope is unavailable';
    END IF;
    PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = v_locked FOR NO KEY UPDATE;
    SELECT * INTO v_scope FROM mesh_ops.authorize_workspace_people_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'member.invite', v_now
    );
    -- Invitations of one Workspace are serialized by its row lock, taken above.
    SELECT workspace.display_name INTO v_workspace_name FROM mesh.workspace AS workspace
    WHERE workspace.id = v_scope.workspace_id;

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
