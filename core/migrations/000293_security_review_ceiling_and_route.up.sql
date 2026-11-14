-- Schema 293: security review 2026-11-14 (techdebt security.md).
--
-- TD-SEC-79: change_workspace_invitation_v1 checks the delegation ceiling only when an invitation is created; resend
-- and revoke needed only member.invite, so an it_admin could rotate or revoke an admin invitation the owner sent.
-- Both now need the same ceiling as create. Body otherwise as in 000183.
--
-- TD-SEC-78: the per-request permission resolvers (resolve_network_permission_v1/v2, resolve_workspace_permission_v1)
-- checked membership and role but not the Workspace's sign-in route: the identity provider and client it accepts,
-- an organization requirement and minimum_assurance. A member of Workspaces A and B signed in through a route only A
-- accepts could act on B's Networks without B's sign-in rules. Each resolver now joins the route exactly as browser
-- registration approval does (000070), in every branch. Bodies otherwise as in 000184; CREATE OR REPLACE keeps owners
-- and grants. Every Workspace has an active route for the deployment's one client today (checked on POC), so no
-- request changes outcome until Workspaces get their own sign-in rules.
--
-- Switching Workspace (and listing the ones a session may switch to) checked the route's provider, client and
-- organization but not minimum_assurance, so a session could switch into a Workspace whose route asks a stronger acr
-- and reach the reads bound to the login Workspace. Both now compare minimum_assurance with the session's acr. Bodies
-- otherwise as in 000103; the planner settings 000107 gave the switch are set again, and the listing gets them too.

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
        -- TD-SEC-79: resending or revoking an invitation that carries a role
        -- needs the same delegation ceiling as creating it.
        IF p_action IN ('resend', 'revoke') AND v_invitation.role_key IS NOT NULL THEN
            SELECT * INTO v_role FROM mesh.builtin_role AS role WHERE role.role_key = v_invitation.role_key;
            IF v_role.role_key IS NULL OR NOT (v_role.assignable_by && mesh_ops.workspace_role_assigners_v1(
                    v_scope.workspace_id, v_scope.actor_id, v_now)) THEN
                RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'role exceeds the delegation ceiling';
            END IF;
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

CREATE OR REPLACE FUNCTION mesh_ops.resolve_network_permission_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_permission_key text, p_evaluated_at timestamp with time zone)
 RETURNS TABLE(role_binding_public_id uuid, role_definition_public_id uuid, scope_authority_generation bigint, membership_authority_generation bigint, binding_authority_generation bigint, role_authority_generation bigint, binding_expires_at timestamp with time zone)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
 SET join_collapse_limit TO '1'
 SET from_collapse_limit TO '1'
 SET plan_cache_mode TO 'force_generic_plan'
AS $function$
BEGIN
    IF p_session_public_id IS NULL
        OR p_deployment_public_id IS NULL
        OR p_principal_public_id IS NULL
        OR p_identity_subject_public_id IS NULL
        OR p_workspace_public_id IS NULL
        OR p_network_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_session_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_identity_subject_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_network_public_id), 6) >> 4 <> 7
        OR p_session_version IS NULL OR p_session_version <= 0
        OR p_principal_authority_generation IS NULL
        OR p_principal_authority_generation <= 0
        OR p_account_session_generation IS NULL OR p_account_session_generation <= 0
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0
        OR p_permission_key IS NULL
        OR pg_catalog.char_length(p_permission_key) NOT BETWEEN 3 AND 128
        OR p_permission_key <> pg_catalog.btrim(p_permission_key)
        OR p_permission_key !~ '^[a-z][a-z0-9_]*[.][a-z][a-z0-9_.]*$'
        OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid Network permission resolution input';
    END IF;

    -- The Workspace row first. A member change holds it and then writes this
    -- session and membership, so locking those before waiting for the
    -- Workspace would deadlock with it.
    PERFORM 1 FROM mesh.workspace AS workspace
    WHERE workspace.public_id = p_workspace_public_id
    FOR SHARE;

    RETURN QUERY
    SELECT
        binding.public_id,
        role_definition.public_id,
        network.authority_generation,
        membership.authority_generation,
        binding.authority_generation,
        role_definition.authority_generation,
        binding.expires_at
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
    JOIN mesh.workspace_identity_provider AS route
      ON route.deployment_id = session.deployment_id
     AND route.workspace_id = workspace.id
     AND route.identity_provider_id = session.identity_provider_id
     AND route.identity_provider_client_id = session.identity_provider_client_id
     AND route.state = 'active' AND route.deleted_at IS NULL
     AND route.organization_digest_algorithm IS NULL
     AND route.organization_digest_key_id IS NULL AND route.organization_digest IS NULL
     AND (route.minimum_assurance IS NULL OR route.minimum_assurance = session.acr)
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.public_id = p_network_public_id
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = session.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = session.principal_id
    JOIN mesh.role_binding AS binding
      ON binding.deployment_id = session.deployment_id
     AND binding.workspace_id = workspace.id
     AND binding.network_id = network.id
     AND binding.principal_id = session.principal_id
     AND binding.workspace_membership_id = membership.id
    JOIN mesh.role_definition AS role_definition
      ON role_definition.deployment_id = session.deployment_id
     AND role_definition.workspace_id = workspace.id
     AND role_definition.id = binding.role_definition_id
    JOIN mesh.role_permission AS role_permission
      ON role_permission.deployment_id = session.deployment_id
     AND role_permission.workspace_id = workspace.id
     AND role_permission.role_definition_id = role_definition.id
    JOIN mesh.permission AS permission
      ON permission.id = role_permission.permission_id
     AND permission.permission_key = p_permission_key
     AND 'network' = ANY(permission.allowed_scope_kinds)
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
      AND session.authentication_time <= p_evaluated_at
      AND session.idle_expires_at > p_evaluated_at
      AND session.absolute_expires_at > p_evaluated_at
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.recovery_epoch = p_deployment_recovery_epoch
      AND principal.state = 'active'
      AND principal.authority_generation = p_principal_authority_generation
      AND account.recovery_state = 'verified'
      AND account.session_generation = p_account_session_generation
      AND subject.state = 'active'
      AND provider.state = 'active'
      AND provider.recovery_state = 'verified'
      AND provider.current_generation = p_provider_generation
      AND client.state = 'active'
      AND workspace.state = 'active'
      AND network.state = 'active'
      AND membership.state = 'active'
      AND membership.valid_from <= p_evaluated_at
      AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
      AND binding.state = 'active'
      AND binding.valid_from <= p_evaluated_at
      AND (binding.expires_at IS NULL OR binding.expires_at > p_evaluated_at)
      AND role_definition.state = 'active'
      AND role_permission.state = 'active'
    ORDER BY binding.id
    LIMIT 256
    FOR SHARE OF session, deployment, principal, account, subject, provider, client,
        workspace, network, membership, binding, role_definition, role_permission, permission;
END;
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.resolve_network_permission_v2(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_permission_key text, p_evaluated_at timestamp with time zone)
 RETURNS TABLE(role_binding_public_id uuid, role_definition_public_id uuid, scope_authority_generation bigint, membership_authority_generation bigint, binding_authority_generation bigint, role_authority_generation bigint, binding_expires_at timestamp with time zone, workspace_owner_authority_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
 SET join_collapse_limit TO '1'
 SET from_collapse_limit TO '1'
 SET plan_cache_mode TO 'force_generic_plan'
AS $function$
BEGIN
    IF p_session_public_id IS NULL
        OR p_deployment_public_id IS NULL
        OR p_principal_public_id IS NULL
        OR p_identity_subject_public_id IS NULL
        OR p_workspace_public_id IS NULL
        OR p_network_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_session_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_identity_subject_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_network_public_id), 6) >> 4 <> 7
        OR p_session_version IS NULL OR p_session_version <= 0
        OR p_principal_authority_generation IS NULL
        OR p_principal_authority_generation <= 0
        OR p_account_session_generation IS NULL OR p_account_session_generation <= 0
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0
        OR p_permission_key IS NULL
        OR pg_catalog.char_length(p_permission_key) NOT BETWEEN 3 AND 128
        OR p_permission_key <> pg_catalog.btrim(p_permission_key)
        OR p_permission_key !~ '^[a-z][a-z0-9_]*[.][a-z][a-z0-9_.]*$'
        OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid Network permission resolution input';
    END IF;

    -- The Workspace row first. A member change holds it and then writes this
    -- session and membership, so locking those before waiting for the
    -- Workspace would deadlock with it.
    PERFORM 1 FROM mesh.workspace AS workspace
    WHERE workspace.public_id = p_workspace_public_id
    FOR SHARE;

    RETURN QUERY
    SELECT
        NULL::UUID,
        NULL::UUID,
        network.authority_generation,
        membership.authority_generation,
        0::BIGINT,
        0::BIGINT,
        NULL::TIMESTAMPTZ,
        workspace.authority_generation
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
    JOIN mesh.workspace_identity_provider AS route
      ON route.deployment_id = session.deployment_id
     AND route.workspace_id = workspace.id
     AND route.identity_provider_id = session.identity_provider_id
     AND route.identity_provider_client_id = session.identity_provider_client_id
     AND route.state = 'active' AND route.deleted_at IS NULL
     AND route.organization_digest_algorithm IS NULL
     AND route.organization_digest_key_id IS NULL AND route.organization_digest IS NULL
     AND (route.minimum_assurance IS NULL OR route.minimum_assurance = session.acr)
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.public_id = p_network_public_id
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = session.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = session.principal_id
    JOIN mesh.permission AS permission
      ON permission.permission_key = p_permission_key
     AND 'network' = ANY(permission.allowed_scope_kinds)
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
      AND session.authentication_time <= p_evaluated_at
      AND session.idle_expires_at > p_evaluated_at
      AND session.absolute_expires_at > p_evaluated_at
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.recovery_epoch = p_deployment_recovery_epoch
      AND principal.state = 'active'
      AND principal.kind = 'account'
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
      AND network.state = 'active'
      AND membership.state = 'active'
      AND membership.valid_from <= p_evaluated_at
      AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
    LIMIT 1
    FOR SHARE OF session, deployment, principal, account, subject, provider, client,
        workspace, network, membership, permission;
    IF FOUND THEN RETURN; END IF;

    -- Built-in roles: a Workspace-scope assignment covers every Network of the
    -- Workspace; a Network-scope one only its Network. The exact Network
    -- assignment is preferred so evidence names the narrowest grant.
    RETURN QUERY
    SELECT
        assignment.public_id,
        role.public_id,
        network.authority_generation,
        membership.authority_generation,
        assignment.authority_generation,
        role.catalog_version::BIGINT,
        assignment.expires_at,
        0::BIGINT
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
    JOIN mesh.workspace_identity_provider AS route
      ON route.deployment_id = session.deployment_id
     AND route.workspace_id = workspace.id
     AND route.identity_provider_id = session.identity_provider_id
     AND route.identity_provider_client_id = session.identity_provider_client_id
     AND route.state = 'active' AND route.deleted_at IS NULL
     AND route.organization_digest_algorithm IS NULL
     AND route.organization_digest_key_id IS NULL AND route.organization_digest IS NULL
     AND (route.minimum_assurance IS NULL OR route.minimum_assurance = session.acr)
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.public_id = p_network_public_id
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = session.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = session.principal_id
    JOIN mesh.permission AS permission
      ON permission.permission_key = p_permission_key
     AND 'network' = ANY(permission.allowed_scope_kinds)
    JOIN mesh.workspace_role_assignment AS assignment
      ON assignment.deployment_id = session.deployment_id
     AND assignment.workspace_id = workspace.id
     AND assignment.principal_id = principal.id
     AND assignment.workspace_membership_id = membership.id
     AND (assignment.network_id IS NULL OR assignment.network_id = network.id)
    JOIN mesh.builtin_role AS role
      ON role.role_key = assignment.role_key
    JOIN mesh.builtin_role_permission AS role_permission
      ON role_permission.role_key = role.role_key
     AND role_permission.permission_id = permission.id
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
      AND session.authentication_time <= p_evaluated_at
      AND session.idle_expires_at > p_evaluated_at
      AND session.absolute_expires_at > p_evaluated_at
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.recovery_epoch = p_deployment_recovery_epoch
      AND principal.state = 'active'
      AND principal.kind = 'account'
      AND principal.authority_generation = p_principal_authority_generation
      AND account.recovery_state = 'verified'
      AND account.session_generation = p_account_session_generation
      AND subject.state = 'active'
      AND provider.state = 'active'
      AND provider.recovery_state = 'verified'
      AND provider.current_generation = p_provider_generation
      AND client.state = 'active'
      AND workspace.state = 'active'
      AND network.state = 'active'
      AND membership.state = 'active'
      AND membership.valid_from <= p_evaluated_at
      AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
      AND assignment.state = 'active'
      AND assignment.valid_from <= p_evaluated_at
      AND (assignment.expires_at IS NULL OR assignment.expires_at > p_evaluated_at)
    ORDER BY assignment.network_id IS NULL, assignment.id
    LIMIT 1
    FOR SHARE OF session, deployment, principal, account, subject, provider, client,
        workspace, network, membership, permission, assignment;
    IF FOUND THEN RETURN; END IF;

    -- Members retain the existing exact-Network role resolver and its locks.
    RETURN QUERY
    SELECT resolved.role_binding_public_id, resolved.role_definition_public_id,
        resolved.scope_authority_generation, resolved.membership_authority_generation,
        resolved.binding_authority_generation, resolved.role_authority_generation,
        resolved.binding_expires_at, 0::BIGINT
    FROM mesh_ops.resolve_network_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_permission_key, p_evaluated_at
    ) AS resolved;

END;
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.resolve_workspace_permission_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_permission_key text, p_evaluated_at timestamp with time zone)
 RETURNS TABLE(role_binding_public_id uuid, role_definition_public_id uuid, scope_authority_generation bigint, membership_authority_generation bigint, binding_authority_generation bigint, role_authority_generation bigint, binding_expires_at timestamp with time zone, workspace_owner_authority_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
 SET join_collapse_limit TO '1'
 SET from_collapse_limit TO '1'
 SET plan_cache_mode TO 'force_generic_plan'
AS $function$
DECLARE
    resolved RECORD;
BEGIN
    IF p_session_public_id IS NULL
        OR p_deployment_public_id IS NULL
        OR p_principal_public_id IS NULL
        OR p_identity_subject_public_id IS NULL
        OR p_workspace_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_session_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_identity_subject_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR p_session_version IS NULL OR p_session_version <= 0
        OR p_principal_authority_generation IS NULL
        OR p_principal_authority_generation <= 0
        OR p_account_session_generation IS NULL OR p_account_session_generation <= 0
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0
        OR p_permission_key IS NULL
        OR pg_catalog.char_length(p_permission_key) NOT BETWEEN 3 AND 128
        OR p_permission_key <> pg_catalog.btrim(p_permission_key)
        OR p_permission_key !~ '^[a-z][a-z0-9_]*[.][a-z][a-z0-9_.]*$'
        OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid Workspace permission resolution input';
    END IF;

    -- The Workspace row first. A member change holds it and then writes this
    -- session and membership, so locking those before waiting for the
    -- Workspace would deadlock with it.
    PERFORM 1 FROM mesh.workspace AS workspace
    WHERE workspace.public_id = p_workspace_public_id
    FOR SHARE;

    SELECT
        workspace.owner_principal_id = principal.id AS is_owner,
        assignment.id AS assignment_id,
        assignment.public_id AS assignment_public_id,
        role.public_id AS role_public_id,
        role.catalog_version AS role_generation,
        assignment.authority_generation AS assignment_generation,
        assignment.expires_at AS assignment_expires_at,
        workspace.authority_generation AS workspace_generation,
        membership.authority_generation AS membership_generation
    INTO resolved
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
    JOIN mesh.workspace_identity_provider AS route
      ON route.deployment_id = session.deployment_id
     AND route.workspace_id = workspace.id
     AND route.identity_provider_id = session.identity_provider_id
     AND route.identity_provider_client_id = session.identity_provider_client_id
     AND route.state = 'active' AND route.deleted_at IS NULL
     AND route.organization_digest_algorithm IS NULL
     AND route.organization_digest_key_id IS NULL AND route.organization_digest IS NULL
     AND (route.minimum_assurance IS NULL OR route.minimum_assurance = session.acr)
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = session.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = session.principal_id
    JOIN mesh.permission AS permission
      ON permission.permission_key = p_permission_key
     AND 'workspace' = ANY(permission.allowed_scope_kinds)
    LEFT JOIN mesh.workspace_role_assignment AS assignment
      ON assignment.deployment_id = session.deployment_id
     AND assignment.workspace_id = workspace.id
     AND assignment.principal_id = principal.id
     AND assignment.workspace_membership_id = membership.id
     AND assignment.network_id IS NULL
     AND assignment.state = 'active'
     AND assignment.valid_from <= p_evaluated_at
     AND (assignment.expires_at IS NULL OR assignment.expires_at > p_evaluated_at)
     AND EXISTS (
        SELECT 1 FROM mesh.builtin_role_permission AS role_permission
        WHERE role_permission.role_key = assignment.role_key
          AND role_permission.permission_id = permission.id
     )
    LEFT JOIN mesh.builtin_role AS role
      ON role.role_key = assignment.role_key
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
      AND session.authentication_time <= p_evaluated_at
      AND session.idle_expires_at > p_evaluated_at
      AND session.absolute_expires_at > p_evaluated_at
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.recovery_epoch = p_deployment_recovery_epoch
      AND principal.state = 'active'
      AND principal.kind = 'account'
      AND principal.authority_generation = p_principal_authority_generation
      AND account.recovery_state = 'verified'
      AND account.session_generation = p_account_session_generation
      AND subject.state = 'active'
      AND provider.state = 'active'
      AND provider.recovery_state = 'verified'
      AND provider.current_generation = p_provider_generation
      AND client.state = 'active'
      AND workspace.state = 'active'
      AND membership.state = 'active'
      AND membership.valid_from <= p_evaluated_at
      AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
      AND (workspace.owner_principal_id = principal.id OR assignment.id IS NOT NULL)
    ORDER BY workspace.owner_principal_id = principal.id DESC, assignment.id
    LIMIT 1
    FOR SHARE OF session, deployment, principal, account, subject, provider, client,
        workspace, membership, permission;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    scope_authority_generation := resolved.workspace_generation;
    membership_authority_generation := resolved.membership_generation;
    IF resolved.is_owner THEN
        role_binding_public_id := NULL;
        role_definition_public_id := NULL;
        binding_authority_generation := 0;
        role_authority_generation := 0;
        binding_expires_at := NULL;
        workspace_owner_authority_generation := resolved.workspace_generation;
        RETURN NEXT;
        RETURN;
    END IF;
    -- The outer join cannot lock the assignment, so lock it now and recheck it:
    -- a concurrent revocation that committed first denies this operation.
    PERFORM 1 FROM mesh.workspace_role_assignment AS assignment
    WHERE assignment.id = resolved.assignment_id
      AND assignment.state = 'active'
      AND assignment.authority_generation = resolved.assignment_generation
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    role_binding_public_id := resolved.assignment_public_id;
    role_definition_public_id := resolved.role_public_id;
    binding_authority_generation := resolved.assignment_generation;
    role_authority_generation := resolved.role_generation;
    binding_expires_at := resolved.assignment_expires_at;
    workspace_owner_authority_generation := 0;
    RETURN NEXT;
END;
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.list_session_workspaces_v1(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    actor RECORD;
    evaluated TIMESTAMPTZ := pg_catalog.clock_timestamp();
    result JSONB;
BEGIN
    SELECT * INTO actor FROM mesh_ops.resolve_account_session_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, evaluated);
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', actor.principal_id::TEXT, TRUE);
    BEGIN
        SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'workspace_id', candidate.public_id,
            'display_name', candidate.display_name,
            'display_code', candidate.display_code,
            'owner', candidate.owner,
            'current', candidate.current
        ) ORDER BY candidate.name_key, candidate.public_id), '[]'::JSONB)
        INTO result
        FROM (
            SELECT workspace.public_id, workspace.display_name, workspace.name_key,
                identity.display_code,
                workspace.owner_principal_id = actor.principal_id AS owner,
                workspace.id = actor.login_workspace_id AS current
            FROM mesh.workspace_membership AS membership
            JOIN mesh.workspace AS workspace
              ON workspace.deployment_id = membership.deployment_id AND workspace.id = membership.workspace_id
            JOIN mesh.workspace_identity_provider AS routing
              ON routing.deployment_id = workspace.deployment_id AND routing.workspace_id = workspace.id
             AND routing.identity_provider_id = actor.identity_provider_id
             AND routing.identity_provider_client_id = actor.identity_provider_client_id
            JOIN mesh_ops.tenant_display_identity AS identity ON identity.workspace_public_id = workspace.public_id
            WHERE membership.principal_id = actor.principal_id
              AND membership.state = 'active' AND membership.valid_from <= evaluated
              AND (membership.expires_at IS NULL OR membership.expires_at > evaluated)
              AND workspace.state = 'active' AND workspace.deleted_at IS NULL
              AND routing.state = 'active' AND routing.deleted_at IS NULL
              AND routing.organization_digest_algorithm IS NULL
              AND routing.organization_digest_key_id IS NULL AND routing.organization_digest IS NULL
              AND (routing.minimum_assurance IS NULL OR routing.minimum_assurance = (
                  SELECT session.acr FROM mesh.account_session AS session
                  WHERE session.public_id = p_session_public_id))
            ORDER BY workspace.name_key, workspace.public_id
            LIMIT 100
        ) AS candidate;
    EXCEPTION WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', '', TRUE);
        RAISE;
    END;
    PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', '', TRUE);
    RETURN result;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.switch_account_session_workspace_v1(
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
    p_change_public_id UUID
)
RETURNS TABLE (session_version BIGINT, workspace_public_id UUID, replayed BOOLEAN)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
#variable_conflict use_column
DECLARE
    actor RECORD;
    evaluated TIMESTAMPTZ := pg_catalog.clock_timestamp();
    target_workspace_id BIGINT;
    new_version BIGINT;
BEGIN
    IF p_workspace_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Workspace switch input';
    END IF;
    SELECT * INTO actor FROM mesh_ops.resolve_account_session_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, evaluated);
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Account Session is not active';
    END IF;

    -- Candidate Workspaces are read exactly as login reads them (migration 101).
    PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', actor.principal_id::TEXT, TRUE);
    BEGIN
        SELECT workspace.id INTO target_workspace_id
        FROM mesh.workspace AS workspace
        JOIN mesh.workspace_membership AS membership
          ON membership.deployment_id = workspace.deployment_id AND membership.workspace_id = workspace.id
         AND membership.principal_id = actor.principal_id
        JOIN mesh.workspace_identity_provider AS routing
          ON routing.deployment_id = workspace.deployment_id AND routing.workspace_id = workspace.id
         AND routing.identity_provider_id = actor.identity_provider_id
         AND routing.identity_provider_client_id = actor.identity_provider_client_id
        WHERE workspace.public_id = p_workspace_public_id
          AND workspace.deployment_id = actor.deployment_id
          AND workspace.state = 'active' AND workspace.deleted_at IS NULL
          AND membership.state = 'active' AND membership.valid_from <= evaluated
          AND (membership.expires_at IS NULL OR membership.expires_at > evaluated)
          AND routing.state = 'active' AND routing.deleted_at IS NULL
          AND routing.organization_digest_algorithm IS NULL
          AND routing.organization_digest_key_id IS NULL AND routing.organization_digest IS NULL
          AND (routing.minimum_assurance IS NULL OR routing.minimum_assurance = (
              SELECT session.acr FROM mesh.account_session AS session
              WHERE session.public_id = p_session_public_id));
        -- No row lock: the candidate policy is SELECT-only, and every later
        -- request rechecks membership and routing when it resolves authority.
    EXCEPTION WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', '', TRUE);
        RAISE;
    END;
    PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', '', TRUE);
    IF target_workspace_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Workspace is unavailable to this Account';
    END IF;
    IF target_workspace_id = actor.login_workspace_id THEN
        RETURN QUERY SELECT p_session_version, p_workspace_public_id, TRUE;
        RETURN;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.account_session_workspace_switch', p_session_public_id::TEXT, TRUE);
    BEGIN
        UPDATE mesh.account_session AS session
        SET login_workspace_id = target_workspace_id,
            version = session.version + 1,
            updated_at = GREATEST(session.updated_at, evaluated)
        WHERE session.public_id = p_session_public_id
          AND session.deployment_id = actor.deployment_id
          AND session.version = p_session_version
          AND session.state = 'active'
        RETURNING session.version INTO new_version;
    EXCEPTION WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.account_session_workspace_switch', '', TRUE);
        RAISE;
    END;
    PERFORM pg_catalog.set_config('mesh.account_session_workspace_switch', '', TRUE);
    IF new_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Account Session changed';
    END IF;
    RETURN QUERY SELECT new_version, p_workspace_public_id, FALSE;
END;
$function$;

ALTER FUNCTION mesh_ops.switch_account_session_workspace_v1(uuid, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint, uuid, uuid)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
-- The listing now reads the session's acr: like every session-anchored function (000107) it plans in written order.
ALTER FUNCTION mesh_ops.list_session_workspaces_v1(uuid, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
