-- The permission resolvers lock the Workspace row before the caller's
-- session.
--
-- resolve_network_permission_v1/v2 and resolve_workspace_permission_v1
-- lock, in one statement, the session, deployment, principal, account,
-- identity rows, then the Workspace and the membership, FOR SHARE, in that
-- order. A member change (removal, suspension, ending sessions) holds the
-- Workspace FOR NO KEY UPDATE and then writes the member's sessions. A
-- request of that member arriving in between held its session row and
-- waited for the Workspace, while the change waited for the session: a
-- deadlock (40P01).
--
-- Each resolver now takes the Workspace FOR SHARE first, so such a request
-- waits for the change without holding its session, and then finds the
-- session ended. The same transaction holding the Workspace more strongly
-- already is unaffected. Bodies are otherwise unchanged; CREATE OR REPLACE
-- keeps owners and grants.

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
