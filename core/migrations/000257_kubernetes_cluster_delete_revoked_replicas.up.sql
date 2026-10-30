-- Schema 257 (TD-CORE-108, found in K1f): a cluster whose replicas were all
-- revoked can be deleted. Removing a gateway Device in the Console revokes
-- it (state revoked, deleted_at unset) and nothing ever sets its deleted_at,
-- so the check that every replica is gone refused every cluster that once
-- had a replica. A revoked replica holds no keys, is never in a map and can
-- never become active again (enforce_kubernetes_gateway_device_v1); only an
-- active one still blocks the deletion (a gateway is never suspended or
-- expired), as do requests waiting or approved. Only the device predicate
-- changes.

CREATE OR REPLACE FUNCTION mesh_ops.delete_kubernetes_cluster_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_expected_version BIGINT, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_before mesh.kubernetes_cluster%ROWTYPE;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
BEGIN
    IF p_cluster_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.manage');
    SELECT * INTO v_before FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    IF p_expected_version IS NOT NULL AND p_expected_version <> v_before.version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'the Kubernetes cluster changed';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    -- Lock order: cluster (above), then keys, then requests.
    PERFORM 1 FROM mesh.enrollment_credential AS credential
    JOIN mesh.enrollment_profile AS profile ON profile.id = credential.enrollment_profile_id
    WHERE profile.kubernetes_cluster_id = v_before.id
    ORDER BY credential.id
    FOR UPDATE OF credential;
    PERFORM mesh_ops.expire_kubernetes_replica_requests_internal_v1(NULL, v_before.id, NULL, NULL);
    IF EXISTS (
        SELECT 1 FROM mesh.device AS device
        WHERE device.workspace_id = v_grant.workspace_id AND device.network_id = v_grant.network_id
          AND device.kubernetes_cluster_id = v_before.id AND device.deleted_at IS NULL
          AND device.state <> 'revoked'
    ) OR EXISTS (
        SELECT 1 FROM mesh.kubernetes_replica_request AS request
        WHERE request.kubernetes_cluster_id = v_before.id AND request.state IN ('pending', 'approved')
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK05', MESSAGE = 'the Kubernetes cluster still has replicas or requests';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.enrollment_credential AS credential
    SET state = 'revoked', revoked_at = v_now, version = credential.version + 1,
        updated_at = GREATEST(v_now, credential.updated_at)
    FROM mesh.enrollment_profile AS profile
    WHERE profile.kubernetes_cluster_id = v_before.id AND credential.enrollment_profile_id = profile.id
      AND credential.state = 'active';
    UPDATE mesh.enrollment_profile AS profile
    SET state = 'deleted', deleted_at = v_now, version = profile.version + 1,
        updated_at = GREATEST(v_now, profile.updated_at)
    WHERE profile.kubernetes_cluster_id = v_before.id AND profile.deleted_at IS NULL;
    UPDATE mesh.kubernetes_cluster AS cluster
    SET state = 'deleted', deleted_at = v_now, version = cluster.version + 1,
        updated_at = GREATEST(v_now, cluster.updated_at)
    WHERE cluster.id = v_before.id
    RETURNING * INTO v_cluster;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_grant.workspace_id, v_grant.network_id),
        'before', mesh_ops.kubernetes_cluster_document_internal_v1(v_before),
        'cluster', mesh_ops.kubernetes_cluster_document_internal_v1(v_cluster),
        'authority', v_grant.authority
    );
END;
$function$;
