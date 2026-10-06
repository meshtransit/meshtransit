-- ADR-050 D3: any authenticated Account may create a Workspace within the
-- verified entitlement quotas. Creation is an Account action, so the Session
-- is validated without a Workspace scope. The Deployment row is locked so the
-- active-Workspace and per-Account counts cannot race. A client-chosen
-- Workspace ID makes a retried request converge on one Workspace.

-- The quota guard counts every Workspace of the Deployment. The policy only
-- applies while create_workspace_v1 holds the guard setting.
CREATE POLICY workspace_migrator_limit_guard_read ON mesh.workspace
    FOR SELECT TO mesh_migrator
    USING (pg_catalog.current_setting('mesh.workspace_limit_guard', TRUE) = 'on');

-- Validates one exact, fresh Account Session without any Workspace scope and
-- returns its principal and login provider binding.
CREATE FUNCTION mesh_ops.resolve_account_session_v1(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (
    deployment_id BIGINT,
    principal_id BIGINT,
    identity_provider_id BIGINT,
    identity_provider_client_id BIGINT,
    login_workspace_id BIGINT
)
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
    SELECT session.deployment_id, session.principal_id, session.identity_provider_id,
        session.identity_provider_client_id, session.login_workspace_id
    FROM mesh.account_session AS session
    JOIN mesh.deployment AS deployment ON deployment.id = session.deployment_id
    JOIN mesh.principal AS principal
      ON principal.deployment_id = session.deployment_id AND principal.id = session.principal_id
    JOIN mesh.account AS account
      ON account.deployment_id = session.deployment_id AND account.principal_id = session.principal_id
    JOIN mesh.identity_subject AS subject
      ON subject.deployment_id = session.deployment_id
     AND subject.identity_provider_id = session.identity_provider_id
     AND subject.principal_id = session.principal_id
     AND subject.id = session.identity_subject_id
    JOIN mesh.identity_provider AS provider
      ON provider.deployment_id = session.deployment_id AND provider.id = session.identity_provider_id
    JOIN mesh.identity_provider_client AS client
      ON client.deployment_id = session.deployment_id
     AND client.identity_provider_id = session.identity_provider_id
     AND client.id = session.identity_provider_client_id
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
      AND principal.kind = 'account'
      AND principal.state = 'active'
      AND principal.authority_generation = p_principal_authority_generation
      AND account.recovery_state = 'verified'
      AND account.session_generation = p_account_session_generation
      AND subject.state = 'active'
      AND provider.state = 'active'
      AND provider.recovery_state = 'verified'
      AND provider.current_generation = p_provider_generation
      AND client.state = 'active'
    LIMIT 1
$function$;
REVOKE ALL ON FUNCTION mesh_ops.resolve_account_session_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Errors: 42501 inactive Session; 55000 'deployment_entitlement_missing' or
-- 'deployment_entitlement_expired'; 53400 'deployment_workspace_limit' or
-- 'account_workspace_limit'; 23505 reused Workspace ID or a name the Account
-- already owns. The caller appends one audit/outbox record unless replayed.
CREATE FUNCTION mesh_ops.create_workspace_v1(
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
    p_display_name TEXT,
    p_membership_public_id UUID,
    p_routing_public_id UUID,
    p_realm_public_id UUID,
    p_ipv4_pool_public_id UUID,
    p_ipv6_pool_public_id UUID,
    p_ipv6_prefix CIDR,
    p_change_public_id UUID
)
RETURNS TABLE (
    workspace_public_id UUID,
    workspace_display_code TEXT,
    workspace_version BIGINT,
    workspace_created_at TIMESTAMPTZ,
    replayed BOOLEAN
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
DECLARE
    actor RECORD;
    evaluated TIMESTAMPTZ;
    locked_deployment mesh.deployment%ROWTYPE;
    entitlement mesh.deployment_entitlement%ROWTYPE;
    existing mesh.workspace%ROWTYPE;
    active_count BIGINT;
    owned_count BIGINT;
    login_assurance TEXT;
    created_id BIGINT;
BEGIN
    IF p_workspace_public_id IS NULL OR p_change_public_id IS NULL OR p_display_name IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR pg_catalog.char_length(p_display_name) NOT BETWEEN 1 AND 128
        OR pg_catalog.btrim(p_display_name) <> p_display_name THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Workspace creation input';
    END IF;
    evaluated := pg_catalog.clock_timestamp();
    SELECT * INTO actor FROM mesh_ops.resolve_account_session_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, evaluated);
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Account Session is not active';
    END IF;

    SELECT * INTO locked_deployment FROM mesh.deployment WHERE id = actor.deployment_id FOR UPDATE;

    PERFORM pg_catalog.set_config('mesh.workspace_limit_guard', 'on', TRUE);
    SELECT * INTO existing FROM mesh.workspace
    WHERE deployment_id = actor.deployment_id AND public_id = p_workspace_public_id;
    IF FOUND THEN
        PERFORM pg_catalog.set_config('mesh.workspace_limit_guard', '', TRUE);
        IF existing.owner_principal_id <> actor.principal_id OR existing.display_name <> p_display_name THEN
            RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'Workspace ID was used for another request';
        END IF;
        RETURN QUERY
        SELECT existing.public_id, identity.display_code, existing.version, existing.created_at, TRUE
        FROM mesh_ops.tenant_display_identity AS identity
        WHERE identity.workspace_public_id = existing.public_id;
        RETURN;
    END IF;

    SELECT * INTO entitlement FROM mesh.deployment_entitlement AS candidate
    WHERE candidate.deployment_id = actor.deployment_id AND candidate.profile = locked_deployment.profile
    ORDER BY candidate.generation DESC LIMIT 1
    FOR SHARE;
    IF NOT FOUND OR evaluated < entitlement.not_before THEN
        PERFORM pg_catalog.set_config('mesh.workspace_limit_guard', '', TRUE);
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'deployment_entitlement_missing';
    END IF;
    IF evaluated >= entitlement.expires_at + pg_catalog.make_interval(secs => entitlement.grace_seconds) THEN
        PERFORM pg_catalog.set_config('mesh.workspace_limit_guard', '', TRUE);
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'deployment_entitlement_expired';
    END IF;

    SELECT pg_catalog.count(*),
        pg_catalog.count(*) FILTER (WHERE workspace.owner_principal_id = actor.principal_id)
    INTO active_count, owned_count
    FROM mesh.workspace AS workspace
    WHERE workspace.deployment_id = actor.deployment_id
      AND workspace.state = 'active' AND workspace.deleted_at IS NULL;
    PERFORM pg_catalog.set_config('mesh.workspace_limit_guard', '', TRUE);
    IF active_count >= entitlement.max_active_workspaces THEN
        RAISE EXCEPTION USING ERRCODE = '53400', MESSAGE = 'deployment_workspace_limit';
    END IF;
    IF owned_count >= entitlement.max_owned_workspaces_per_account THEN
        RAISE EXCEPTION USING ERRCODE = '53400', MESSAGE = 'account_workspace_limit';
    END IF;

    -- New Workspaces require the same assurance as the Workspace the
    -- creator signed in to; a Session without one requires none.
    SELECT routing.minimum_assurance INTO login_assurance
    FROM mesh.workspace_identity_provider AS routing
    WHERE routing.workspace_id = actor.login_workspace_id
      AND routing.identity_provider_id = actor.identity_provider_id
      AND routing.identity_provider_client_id = actor.identity_provider_client_id
      AND routing.state = 'active'
    LIMIT 1;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    created_id := mesh_ops.provision_workspace_v1(
        actor.deployment_id, actor.principal_id, p_workspace_public_id, p_display_name,
        p_membership_public_id, p_routing_public_id, actor.identity_provider_id,
        actor.identity_provider_client_id, login_assurance, p_realm_public_id,
        p_ipv4_pool_public_id, p_ipv6_pool_public_id, p_ipv6_prefix, evaluated);

    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', p_workspace_public_id::TEXT, TRUE);
    RETURN QUERY
    SELECT workspace.public_id, identity.display_code, workspace.version, workspace.created_at, FALSE
    FROM mesh.workspace AS workspace
    JOIN mesh_ops.tenant_display_identity AS identity ON identity.workspace_public_id = workspace.public_id
    WHERE workspace.id = created_id;
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.create_workspace_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, TEXT, UUID, UUID, UUID, UUID, UUID, CIDR, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.create_workspace_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, TEXT, UUID, UUID, UUID, UUID, UUID, CIDR, UUID
) TO mesh_runtime;
