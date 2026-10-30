-- Schema 255 (K1d d4a, docs/k8s-k1d-console-design.md Q150, Q177): readers of
-- a cluster see when someone was given the right to approve its replicas in
-- the last 24 hours (K1a1 plan §14.7: an admin could grant network_admin to
-- two accounts and approve with them a day later).
--
-- The right comes from a role assignment in force: a built-in role whose
-- permissions hold kubernetes_cluster.approve, or a custom role binding
-- holding it, over the whole Workspace or the cluster's Network, given
-- directly or through an invitation. Audit payloads do not name roles, so the
-- assignments themselves are read. Never names who: the time and how many
-- people. Not caught (Q177, TD-SEC-60): a member resumed with an old
-- assignment, a Workspace owner transfer, a binding reactivated, a custom
-- role given the permission later.

CREATE FUNCTION mesh_ops.read_kubernetes_cluster_approver_additions_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_latest TIMESTAMPTZ;
    v_count INTEGER;
BEGIN
    v_cluster := mesh_ops.kubernetes_cluster_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    -- The newest grants of each kind, then how many people they reached.
    SELECT pg_catalog.max(granted.at), pg_catalog.count(DISTINCT granted.principal_id) INTO v_latest, v_count
    FROM (
        (SELECT GREATEST(assignment.created_at, assignment.valid_from) AS at, assignment.principal_id
         FROM mesh.workspace_role_assignment AS assignment
         JOIN mesh.builtin_role_permission AS role_permission ON role_permission.role_key = assignment.role_key
         JOIN mesh.permission AS permission
           ON permission.id = role_permission.permission_id
          AND permission.permission_key = 'kubernetes_cluster.approve'
         WHERE assignment.workspace_id = v_cluster.workspace_id
           AND (assignment.network_id IS NULL OR assignment.network_id = v_cluster.network_id)
           AND assignment.state = 'active' AND assignment.valid_from <= v_now
           AND (assignment.expires_at IS NULL OR assignment.expires_at > v_now)
           AND GREATEST(assignment.created_at, assignment.valid_from) > v_now - INTERVAL '24 hours'
         ORDER BY at DESC
         LIMIT 10)
        UNION ALL
        (SELECT GREATEST(binding.created_at, binding.valid_from) AS at, binding.principal_id
         FROM mesh.role_binding AS binding
         JOIN mesh.role_permission AS role_permission
           ON role_permission.role_definition_id = binding.role_definition_id AND role_permission.state = 'active'
         JOIN mesh.permission AS permission
           ON permission.id = role_permission.permission_id
          AND permission.permission_key = 'kubernetes_cluster.approve'
         WHERE binding.workspace_id = v_cluster.workspace_id
           AND (binding.network_id IS NULL OR binding.network_id = v_cluster.network_id)
           AND binding.state = 'active' AND binding.valid_from <= v_now
           AND (binding.expires_at IS NULL OR binding.expires_at > v_now)
           AND GREATEST(binding.created_at, binding.valid_from) > v_now - INTERVAL '24 hours'
         ORDER BY at DESC
         LIMIT 10)
    ) AS granted;
    RETURN pg_catalog.jsonb_build_object(
        'cluster_id', p_cluster_public_id,
        'latest_at', v_latest,
        'count', LEAST(v_count, 10)
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_cluster_approver_additions_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_cluster_approver_additions_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) TO mesh_runtime;
