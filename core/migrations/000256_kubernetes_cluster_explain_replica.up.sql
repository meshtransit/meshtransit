-- Schema 256 (K1d d4c, docs/k8s-k1d-console-design.md §8, Q179): Explain
-- asks about a Kubernetes cluster through one of its replicas. Every rule to
-- a cluster reaches all its replicas alike, so the answer comes through the
-- active replica with the lowest ordinal: the same one each time while it
-- stays. Read as the cluster's reader (network.read); NULL device_id when no
-- replica is active. Bounded by device_kubernetes_ordinal_uidx: a cluster's
-- replicas not deleted, in ordinal order.

CREATE FUNCTION mesh_ops.read_kubernetes_cluster_explain_replica_v1(
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
    v_device UUID;
BEGIN
    v_cluster := mesh_ops.kubernetes_cluster_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    SELECT device.public_id INTO v_device
    FROM mesh.device AS device
    WHERE device.kubernetes_cluster_id = v_cluster.id AND device.deleted_at IS NULL
      AND device.workspace_id = v_cluster.workspace_id AND device.network_id = v_cluster.network_id
      AND device.state = 'active'
    ORDER BY device.kubernetes_ordinal
    LIMIT 1;
    RETURN pg_catalog.jsonb_build_object('cluster_id', p_cluster_public_id, 'device_id', v_device);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_cluster_explain_replica_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_cluster_explain_replica_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) TO mesh_runtime;
