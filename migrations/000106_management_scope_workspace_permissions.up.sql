-- The Console shows Workspace actions only to people who may take them:
-- read_console_management_scopes_v4 adds the Workspace-level permissions the
-- Session holds from a fixed presentation set. Presentation only: every
-- mutation still reauthorizes its exact permission.

CREATE FUNCTION mesh_ops.read_console_management_scopes_v4(
    p_session_public_id UUID,p_deployment_public_id UUID,p_principal_public_id UUID,
    p_identity_subject_public_id UUID,p_session_version BIGINT,
    p_principal_authority_generation BIGINT,p_account_session_generation BIGINT,
    p_provider_generation BIGINT,p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID,p_evaluated_at TIMESTAMPTZ,p_after_network_public_id UUID,p_limit INTEGER
) RETURNS JSONB LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,mesh,mesh_ops
AS $function$
DECLARE
    result JSONB;
    held TEXT[];
    authority RECORD;
    presentation TEXT[] := ARRAY['network.create','member.read','role_binding.manage','audit.read','billing.read'];
    previous_requested TEXT := pg_catalog.current_setting('mesh.requested_workspace_public_id',TRUE);
    previous_projection TEXT := pg_catalog.current_setting('mesh.console_management_scope_workspace_public_id',TRUE);
BEGIN
    -- v3 validates the Session, membership and Workspace and returns NULL otherwise.
    result:=mesh_ops.read_console_management_scopes_v3(
      p_session_public_id,p_deployment_public_id,p_principal_public_id,p_identity_subject_public_id,
      p_session_version,p_principal_authority_generation,p_account_session_generation,
      p_provider_generation,p_deployment_recovery_epoch,p_workspace_public_id,p_evaluated_at,
      p_after_network_public_id,p_limit);
    IF result IS NULL THEN RETURN NULL; END IF;
    -- Read-only like the Network projection: the scope read runs in a
    -- read-only transaction, so no row locks.
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id',p_workspace_public_id::TEXT,TRUE);
    PERFORM pg_catalog.set_config('mesh.console_management_scope_workspace_public_id',p_workspace_public_id::TEXT,TRUE);
    SELECT workspace.id AS workspace_id, workspace.deployment_id, principal.id AS principal_id,
        membership.id AS membership_id, workspace.owner_principal_id = principal.id AS is_owner
    INTO authority
    FROM mesh.workspace AS workspace
    JOIN mesh.principal AS principal
      ON principal.deployment_id = workspace.deployment_id AND principal.public_id = p_principal_public_id
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = workspace.deployment_id AND membership.workspace_id = workspace.id
     AND membership.principal_id = principal.id AND membership.state = 'active'
    WHERE workspace.public_id = p_workspace_public_id;
    IF authority.workspace_id IS NULL THEN
        held := ARRAY[]::TEXT[];
    ELSIF authority.is_owner THEN
        held := presentation;
    ELSE
        held := ARRAY(
            SELECT DISTINCT permission.permission_key
            FROM mesh.workspace_role_assignment AS assignment
            JOIN mesh.builtin_role_permission AS role_permission ON role_permission.role_key = assignment.role_key
            JOIN mesh.permission AS permission
              ON permission.id = role_permission.permission_id AND permission.permission_key = ANY(presentation)
            WHERE assignment.deployment_id = authority.deployment_id
              AND assignment.workspace_id = authority.workspace_id
              AND assignment.network_id IS NULL
              AND assignment.principal_id = authority.principal_id
              AND assignment.workspace_membership_id = authority.membership_id
              AND assignment.state = 'active'
              AND assignment.valid_from <= p_evaluated_at
              AND (assignment.expires_at IS NULL OR assignment.expires_at > p_evaluated_at)
            ORDER BY permission.permission_key);
    END IF;
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id',COALESCE(previous_requested,''),TRUE);
    PERFORM pg_catalog.set_config('mesh.console_management_scope_workspace_public_id',COALESCE(previous_projection,''),TRUE);
    RETURN result || pg_catalog.jsonb_build_object('workspace_permissions',pg_catalog.to_jsonb(held));
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_console_management_scopes_v4(
 UUID,UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,UUID,TIMESTAMPTZ,UUID,INTEGER
) FROM PUBLIC,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_console_management_scopes_v4(
 UUID,UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,UUID,TIMESTAMPTZ,UUID,INTEGER
) TO mesh_runtime;
