-- Schema 251 (K1d d1d-b, docs/k8s-k1d-console-design.md §3.2, Q132): holders
-- of audit.export in the Workspace or the Network export a cluster's
-- operations for meshctl kube audit-check. Core streams the file a page at
-- a time: a begin read gives the header (gateway namespace, the audit
-- settings and their version) and a bounded count, so a range over 200000
-- records is refused before anything is written; pages of at most 1000
-- records follow, oldest first, by a (received_at, audit_id) cursor.

-- The cluster (any state) an audit exporter names, or 42501 / P0002.
CREATE FUNCTION mesh_ops.kubernetes_operation_exporter_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID
)
RETURNS mesh.kubernetes_cluster
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
BEGIN
    IF p_cluster_public_id IS NULL OR p_workspace_public_id IS NULL OR p_network_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes operation export is invalid';
    END IF;
    PERFORM 1 FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, 'audit.export', v_now);
    IF NOT FOUND THEN
        PERFORM 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
            p_session_version, p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
            'audit.export', v_now);
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'audit.export required';
        END IF;
    END IF;
    SELECT cluster.* INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    JOIN mesh.workspace AS workspace ON workspace.id = cluster.workspace_id
    JOIN mesh.network AS network ON network.workspace_id = cluster.workspace_id AND network.id = cluster.network_id
    WHERE workspace.public_id = p_workspace_public_id AND network.public_id = p_network_public_id
      AND cluster.public_id = p_cluster_public_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    RETURN v_cluster;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_operation_exporter_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The header and a count of the records in [p_records_from, p_records_to),
-- read up to 200001 on the cluster index.
CREATE FUNCTION mesh_ops.begin_kubernetes_operation_export_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_records_from TIMESTAMPTZ, p_records_to TIMESTAMPTZ
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
    v_settings mesh.kubernetes_cluster_audit_settings%ROWTYPE;
BEGIN
    IF p_records_from IS NULL OR p_records_to IS NULL OR p_records_to <= p_records_from
        OR p_records_to - p_records_from > INTERVAL '1 day 10 minutes' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes operation export is invalid';
    END IF;
    v_cluster := mesh_ops.kubernetes_operation_exporter_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    SELECT * INTO v_settings FROM mesh.kubernetes_cluster_audit_settings AS settings
    WHERE settings.kubernetes_cluster_id = v_cluster.id;
    RETURN pg_catalog.jsonb_build_object(
        'cluster_id', v_cluster.public_id,
        'gateway_namespace', (SELECT trust.namespace FROM mesh.kubernetes_cluster_signing_trust AS trust
                              WHERE trust.kubernetes_cluster_id = v_cluster.id),
        'settings', mesh_ops.kubernetes_audit_settings_document_internal_v1(v_settings),
        'count', (SELECT pg_catalog.count(*) FROM (
            SELECT 1 FROM mesh_audit.kubernetes_operation AS operation
            WHERE operation.kubernetes_cluster_id = v_cluster.id
              AND operation.workspace_id = v_cluster.workspace_id AND operation.network_id = v_cluster.network_id
              AND operation.received_at >= p_records_from AND operation.received_at < p_records_to
            LIMIT 200001) AS counted)
    );
END;
$function$;

-- A page of export records after (p_after_at, p_after_id), oldest first.
CREATE FUNCTION mesh_ops.list_kubernetes_operation_export_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_records_from TIMESTAMPTZ, p_records_to TIMESTAMPTZ, p_after_at TIMESTAMPTZ, p_after_id UUID, p_limit INTEGER
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
    IF p_records_from IS NULL OR p_records_to IS NULL OR p_records_to <= p_records_from
        OR p_records_to - p_records_from > INTERVAL '1 day 10 minutes'
        OR (p_after_at IS NULL) <> (p_after_id IS NULL) OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes operation export is invalid';
    END IF;
    v_cluster := mesh_ops.kubernetes_operation_exporter_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    RETURN COALESCE((
        SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'audit_id', listed.audit_id, 'received_at', listed.received_at, 'class', listed.class,
            'groups', pg_catalog.to_jsonb(listed.groups), 'verb', listed.verb, 'api_group', listed.api_group,
            'resource', listed.resource, 'subresource', listed.subresource, 'namespace', listed.namespace,
            'name', listed.name, 'impersonated', listed.impersonated,
            'status', COALESCE((
                SELECT result.status FROM mesh_audit.kubernetes_operation_outcome AS result
                WHERE result.audit_id = listed.audit_id AND result.gateway_device_id = listed.gateway_device_id
                  AND result.recorded_at >= listed.received_at
                  AND result.recorded_at < listed.received_at + INTERVAL '1 day'
                ORDER BY result.recorded_at LIMIT 1), 0)
        ) ORDER BY listed.received_at, listed.audit_id)
        FROM (
            SELECT operation.* FROM mesh_audit.kubernetes_operation AS operation
            WHERE operation.kubernetes_cluster_id = v_cluster.id
              AND operation.workspace_id = v_cluster.workspace_id AND operation.network_id = v_cluster.network_id
              AND operation.received_at >= GREATEST(p_records_from, COALESCE(p_after_at, p_records_from))
              AND operation.received_at < p_records_to
              AND (p_after_at IS NULL OR (operation.received_at, operation.audit_id) > (p_after_at, p_after_id))
            ORDER BY operation.received_at, operation.audit_id
            LIMIT p_limit
        ) AS listed
    ), '[]'::JSONB);
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.begin_kubernetes_operation_export_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.begin_kubernetes_operation_export_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.list_kubernetes_operation_export_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID,
    TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_kubernetes_operation_export_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID,
    TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, UUID, INTEGER
) TO mesh_runtime;
