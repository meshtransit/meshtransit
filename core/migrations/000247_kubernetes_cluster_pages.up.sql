-- Schema 247 (K1d d1a, docs/k8s-k1d-console-design.md §3): join keys and
-- replica requests of a cluster read a page at a time, newest first, by a
-- cursor on (time, public ID), and one at a time by ID (TD-API-60). The
-- cluster read keeps its 50 newest rows for older Consoles.
--
-- Only kubernetes_cluster.manage or .approve holders read either; a reader
-- of the Network alone gets 42501, an ID outside the cluster P0002.

CREATE INDEX enrollment_credential_profile_page_idx
    ON mesh.enrollment_credential (enrollment_profile_id, valid_from DESC, public_id DESC);

-- The cluster a manager or approver reads, or the error the caller maps.
CREATE FUNCTION mesh_ops.kubernetes_cluster_manager_read_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID
)
RETURNS BIGINT
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_cluster_id BIGINT;
BEGIN
    IF p_cluster_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'network.read');
    IF NOT EXISTS (SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'kubernetes_cluster.manage',
            pg_catalog.transaction_timestamp()))
        AND NOT EXISTS (SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'kubernetes_cluster.approve',
            pg_catalog.transaction_timestamp())) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Kubernetes cluster permission required';
    END IF;
    SELECT cluster.id INTO v_cluster_id FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    RETURN v_cluster_id;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_cluster_manager_read_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A page of join keys, newest first, after (p_after_at, p_after_id) when
-- given: up to p_limit + 1 rows, so the caller knows whether more follow.
CREATE FUNCTION mesh_ops.list_kubernetes_join_keys_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_after_at TIMESTAMPTZ, p_after_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_cluster_id BIGINT;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 OR (p_after_at IS NULL) <> (p_after_id IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    v_cluster_id := mesh_ops.kubernetes_cluster_manager_read_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    RETURN COALESCE((
        SELECT pg_catalog.jsonb_agg(mesh_ops.kubernetes_join_key_document_internal_v1(listed)
            ORDER BY listed.valid_from DESC, listed.public_id DESC)
        FROM (
            SELECT credential.* FROM mesh.enrollment_profile AS profile
            JOIN mesh.enrollment_credential AS credential ON credential.enrollment_profile_id = profile.id
            WHERE profile.kubernetes_cluster_id = v_cluster_id
              AND (p_after_at IS NULL OR (credential.valid_from, credential.public_id) < (p_after_at, p_after_id))
            ORDER BY credential.valid_from DESC, credential.public_id DESC
            LIMIT p_limit + 1
        ) AS listed
    ), '[]'::JSONB);
END;
$function$;

CREATE FUNCTION mesh_ops.read_kubernetes_join_key_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID, p_key_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_cluster_id BIGINT;
    v_document JSONB;
BEGIN
    IF p_key_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    v_cluster_id := mesh_ops.kubernetes_cluster_manager_read_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    SELECT mesh_ops.kubernetes_join_key_document_internal_v1(credential) INTO v_document
    FROM mesh.enrollment_profile AS profile
    JOIN mesh.enrollment_credential AS credential ON credential.enrollment_profile_id = profile.id
    WHERE profile.kubernetes_cluster_id = v_cluster_id AND credential.public_id = p_key_public_id;
    IF v_document IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes join key';
    END IF;
    RETURN v_document;
END;
$function$;

-- A page of replica requests, newest first; as list_kubernetes_join_keys_v1.
CREATE FUNCTION mesh_ops.list_kubernetes_replica_requests_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_after_at TIMESTAMPTZ, p_after_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_cluster_id BIGINT;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 OR (p_after_at IS NULL) <> (p_after_id IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    v_cluster_id := mesh_ops.kubernetes_cluster_manager_read_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    RETURN COALESCE((
        SELECT pg_catalog.jsonb_agg(mesh_ops.kubernetes_replica_request_document_internal_v1(listed)
            ORDER BY listed.created_at DESC, listed.public_id DESC)
        FROM (
            SELECT request.* FROM mesh.kubernetes_replica_request AS request
            WHERE request.kubernetes_cluster_id = v_cluster_id
              AND (p_after_at IS NULL OR (request.created_at, request.public_id) < (p_after_at, p_after_id))
            ORDER BY request.created_at DESC, request.public_id DESC
            LIMIT p_limit + 1
        ) AS listed
    ), '[]'::JSONB);
END;
$function$;

CREATE FUNCTION mesh_ops.read_kubernetes_replica_request_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID, p_request_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_cluster_id BIGINT;
    v_document JSONB;
BEGIN
    IF p_request_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    v_cluster_id := mesh_ops.kubernetes_cluster_manager_read_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    SELECT mesh_ops.kubernetes_replica_request_document_internal_v1(request) INTO v_document
    FROM mesh.kubernetes_replica_request AS request
    WHERE request.kubernetes_cluster_id = v_cluster_id AND request.public_id = p_request_public_id;
    IF v_document IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes replica request';
    END IF;
    RETURN v_document;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.list_kubernetes_join_keys_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_kubernetes_join_keys_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_join_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_join_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.list_kubernetes_replica_requests_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_kubernetes_replica_requests_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_replica_request_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_replica_request_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) TO mesh_runtime;
