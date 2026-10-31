-- K2f f4: the latest profile denials of a cluster with their samples, for the
-- Console's Recent denials and Would deny panels. Readers as the cluster's
-- other operation reads (audit.read on the Network, any cluster state).
-- Rows carry the scope hash of the grant that refused; the Console names the
-- profile from the release's rules (GET …/policy/kubernetes-access).
-- Profile denials without a sample are left out: they name no grant.

-- The read walks only rows of a profile with a sample, so RBAC noise never
-- makes it scan a whole month (review f4 H1). The predicate matches the
-- read's exactly.
CREATE INDEX kubernetes_operation_denial_profile_idx
    ON mesh_audit.kubernetes_operation_denial
        (kubernetes_cluster_id, recorded_at DESC, first_at DESC, peer_device_id)
    WHERE reason IN ('profile_denied', 'profile_would_deny') AND sample_scope IS NOT NULL;

CREATE FUNCTION mesh_ops.kubernetes_profile_denials_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_since TIMESTAMPTZ
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
BEGIN
    IF p_since IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes operation request is invalid';
    END IF;
    v_cluster := mesh_ops.kubernetes_operation_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    RETURN pg_catalog.jsonb_build_object('denials', COALESCE((
        SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'recorded_at', latest.recorded_at,
            'reason', latest.reason,
            'count', latest.count,
            'first_at', latest.first_at,
            'last_at', latest.last_at,
            'device_id', (SELECT device.public_id FROM mesh.device AS device
                          WHERE device.id = latest.peer_device_id
                            AND device.workspace_id = latest.workspace_id),
            'device_name', (SELECT device.hostname FROM mesh.device AS device
                            WHERE device.id = latest.peer_device_id
                              AND device.workspace_id = latest.workspace_id),
            'verb', latest.sample_verb,
            'api_group', latest.sample_api_group,
            'resource', latest.sample_resource,
            'subresource', latest.sample_subresource,
            'namespace', latest.sample_namespace,
            'scope_hash', pg_catalog.encode(latest.sample_scope, 'hex')
        ) ORDER BY latest.recorded_at DESC, latest.first_at DESC, latest.peer_device_id)
        FROM (
            SELECT denial.*
            FROM mesh_audit.kubernetes_operation_denial AS denial
            WHERE denial.kubernetes_cluster_id = v_cluster.id
              AND denial.workspace_id = v_cluster.workspace_id AND denial.network_id = v_cluster.network_id
              AND denial.recorded_at >= GREATEST(p_since, pg_catalog.statement_timestamp() - INTERVAL '31 days')
              AND denial.reason IN ('profile_denied', 'profile_would_deny')
              AND denial.sample_scope IS NOT NULL
            ORDER BY denial.recorded_at DESC, denial.first_at DESC, denial.peer_device_id
            LIMIT 50
        ) AS latest
    ), '[]'::JSONB));
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.kubernetes_profile_denials_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.kubernetes_profile_denials_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ
) TO mesh_runtime;
