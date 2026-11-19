-- Schema 304: the Workspace member directory names each person's email and when they joined.
--
-- The Console's People page lists Name, Email, Roles, Status and Joined (owner request 2026-11-19; it overrides the
-- S4c Q3 deferral in docs/device-logout-s4c-account-email.md). list_workspace_members_v2 is v1 (schema 96) plus:
--
-- * email: the verified email Core last stored for the person's Account (schema 288), or null when it has none. It
--   stays display data: it never identifies, links or authorizes anyone. Only callers who already pass member.read
--   for the Workspace read it, the same people who see the directory now;
-- * joined_at: when the person's membership of the Workspace was created.
--
-- v1 stays for rollback: an older Core keeps calling it. Expand step: only new code calls v2.

CREATE FUNCTION mesh_ops.list_workspace_members_v2(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    evaluated_at TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    scoped_workspace_id BIGINT;
    result JSONB;
BEGIN
    scoped_workspace_id := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF scoped_workspace_id IS NULL
        OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, scoped_workspace_id) THEN
        RETURN NULL;
    END IF;
    PERFORM 1 FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'member.read', evaluated_at
    );
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT pg_catalog.jsonb_build_object(
        'workspace_id', workspace.public_id,
        'workspace_version', workspace.version,
        'truncated', (SELECT pg_catalog.count(*) > 1000 FROM mesh.workspace_membership AS counted
            WHERE counted.workspace_id = workspace.id AND counted.state <> 'revoked'),
        'members', COALESCE((
            SELECT pg_catalog.jsonb_agg(member.payload ORDER BY member.sort_name, member.principal_public_id)
            FROM (
                SELECT
                    pg_catalog.lower(account.display_name) AS sort_name,
                    principal.public_id AS principal_public_id,
                    pg_catalog.jsonb_build_object(
                        'principal_id', principal.public_id,
                        'display_name', account.display_name,
                        'membership_state', membership.state,
                        'membership_expires_at', membership.expires_at,
                        'email', account_email.email,
                        'joined_at', membership.created_at,
                        'owner', workspace.owner_principal_id = principal.id,
                        'role_assignments', COALESCE((
                            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                                'assignment_id', assignment.public_id,
                                'role', assignment.role_key,
                                'network_id', network.public_id,
                                'expires_at', assignment.expires_at,
                                'version', assignment.version,
                                'created_at', assignment.created_at
                            ) ORDER BY assignment.role_key, network.public_id NULLS FIRST, assignment.public_id)
                            FROM mesh.workspace_role_assignment AS assignment
                            LEFT JOIN mesh.network AS network
                              ON network.workspace_id = assignment.workspace_id
                             AND network.id = assignment.network_id
                            WHERE assignment.workspace_id = workspace.id
                              AND assignment.workspace_membership_id = membership.id
                              AND assignment.state = 'active'
                        ), '[]'::JSONB)
                    ) AS payload
                FROM mesh.workspace_membership AS membership
                JOIN mesh.principal AS principal
                  ON principal.deployment_id = membership.deployment_id
                 AND principal.id = membership.principal_id
                JOIN mesh.account AS account
                  ON account.deployment_id = principal.deployment_id
                 AND account.principal_id = principal.id
                LEFT JOIN mesh.account_email AS account_email
                  ON account_email.deployment_id = account.deployment_id
                 AND account_email.account_id = account.id
                WHERE membership.workspace_id = workspace.id
                  AND membership.state <> 'revoked'
                  AND principal.deleted_at IS NULL
                ORDER BY pg_catalog.lower(account.display_name), principal.public_id
                LIMIT 1000
            ) AS member
        ), '[]'::JSONB)
    ) INTO result
    FROM mesh.workspace AS workspace
    WHERE workspace.id = scoped_workspace_id;
    RETURN result;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.list_workspace_members_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mesh_ops.list_workspace_members_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID
) TO mesh_api_rights;
