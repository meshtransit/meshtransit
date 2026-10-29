-- Schema 248 (K1d d1b, docs/k8s-k1d-console-design.md §3, Q139): a cluster's
-- replicas and certificate authorities read a page at a time, newest first,
-- by a (time, public ID) cursor, and one at a time by ID, for any reader of
-- the Network: replicas are already in the cluster read, CA fingerprints and
-- roots in every client's map. A CA's private key never leaves the worker.

CREATE INDEX kubernetes_cluster_ca_cluster_page_idx
    ON mesh.kubernetes_cluster_ca (kubernetes_cluster_id, created_at DESC, public_id DESC);

-- The active cluster a reader of the Network names, or the error the
-- caller maps (42501 without network.read, P0002 for an unknown cluster).
CREATE FUNCTION mesh_ops.kubernetes_cluster_reader_internal_v1(
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
    v_grant RECORD;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
BEGIN
    IF p_cluster_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'network.read');
    SELECT * INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    RETURN v_cluster;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_cluster_reader_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A replica as an administrator sees it: its Device and whether it ever
-- proved a pod token (the K1c-T ratchet).
CREATE FUNCTION mesh_ops.kubernetes_cluster_replica_document_internal_v1(p_device mesh.device)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'device_id', p_device.public_id,
        'name', p_device.hostname,
        'ordinal', p_device.kubernetes_ordinal,
        'state', p_device.state,
        'created_at', p_device.created_at,
        'token_first_proven_at', (
            SELECT proof.first_proven_at FROM mesh_ops.kubernetes_gateway_token_proof AS proof
            WHERE proof.device_id = p_device.id AND proof.workspace_id = p_device.workspace_id
              AND proof.network_id = p_device.network_id)
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_cluster_replica_document_internal_v1(mesh.device)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A CA as anyone in the Network may see it: never its private key, nor the
-- operator's name or change reference (audit.read reads those in the audit
-- trail; review d1b H1).
CREATE FUNCTION mesh_ops.kubernetes_cluster_ca_document_internal_v1(p_ca mesh.kubernetes_cluster_ca)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'ca_id', p_ca.public_id,
        'kind', p_ca.kind,
        'issuer_ca_id', (SELECT issuer.public_id FROM mesh.kubernetes_cluster_ca AS issuer
                         WHERE issuer.id = p_ca.issuer_ca_id
                           AND issuer.kubernetes_cluster_id = p_ca.kubernetes_cluster_id),
        'state', p_ca.state,
        'reason', p_ca.reason,
        'state_reason', p_ca.state_reason,
        'fingerprint', pg_catalog.encode(p_ca.fingerprint, 'hex'),
        'certificate', pg_catalog.encode(p_ca.certificate, 'base64'),
        'cluster_dns_name', p_ca.cluster_dns_name,
        'not_before', p_ca.not_before,
        'not_after', p_ca.not_after,
        'created_at', p_ca.created_at,
        'activated_at', p_ca.activated_at,
        'retiring_at', p_ca.retiring_at,
        'retired_at', p_ca.retired_at,
        'changed_by_operator', p_ca.changed_by IS NOT NULL,
        'version', p_ca.version
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_cluster_ca_document_internal_v1(mesh.kubernetes_cluster_ca)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A page of replicas, newest first, after (p_after_at, p_after_id) when
-- given: up to p_limit + 1 rows, so the caller knows whether more follow.
CREATE FUNCTION mesh_ops.list_kubernetes_cluster_replicas_v1(
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
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 OR (p_after_at IS NULL) <> (p_after_id IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    v_cluster := mesh_ops.kubernetes_cluster_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    RETURN COALESCE((
        SELECT pg_catalog.jsonb_agg(mesh_ops.kubernetes_cluster_replica_document_internal_v1(listed)
            ORDER BY listed.created_at DESC, listed.public_id DESC)
        FROM (
            SELECT device.* FROM mesh.device AS device
            WHERE device.workspace_id = v_cluster.workspace_id AND device.network_id = v_cluster.network_id
              AND device.kubernetes_cluster_id = v_cluster.id AND device.deleted_at IS NULL
              AND (p_after_at IS NULL OR (device.created_at, device.public_id) < (p_after_at, p_after_id))
            ORDER BY device.created_at DESC, device.public_id DESC
            LIMIT p_limit + 1
        ) AS listed
    ), '[]'::JSONB);
END;
$function$;

CREATE FUNCTION mesh_ops.read_kubernetes_cluster_replica_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID, p_device_public_id UUID
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
    v_document JSONB;
BEGIN
    IF p_device_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    v_cluster := mesh_ops.kubernetes_cluster_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    SELECT mesh_ops.kubernetes_cluster_replica_document_internal_v1(device) INTO v_document
    FROM mesh.device AS device
    WHERE device.workspace_id = v_cluster.workspace_id AND device.network_id = v_cluster.network_id
      AND device.kubernetes_cluster_id = v_cluster.id AND device.deleted_at IS NULL
      AND device.public_id = p_device_public_id;
    IF v_document IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes replica';
    END IF;
    RETURN v_document;
END;
$function$;

-- A page of CAs, newest first; as list_kubernetes_cluster_replicas_v1.
CREATE FUNCTION mesh_ops.list_kubernetes_cluster_cas_v1(
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
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
BEGIN
    -- At most 50: a certificate takes up to 8 KiB (review d1b L1).
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 50 OR (p_after_at IS NULL) <> (p_after_id IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    v_cluster := mesh_ops.kubernetes_cluster_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    RETURN COALESCE((
        SELECT pg_catalog.jsonb_agg(mesh_ops.kubernetes_cluster_ca_document_internal_v1(listed)
            ORDER BY listed.created_at DESC, listed.public_id DESC)
        FROM (
            SELECT ca.* FROM mesh.kubernetes_cluster_ca AS ca
            WHERE ca.kubernetes_cluster_id = v_cluster.id
              AND (p_after_at IS NULL OR (ca.created_at, ca.public_id) < (p_after_at, p_after_id))
            ORDER BY ca.created_at DESC, ca.public_id DESC
            LIMIT p_limit + 1
        ) AS listed
    ), '[]'::JSONB);
END;
$function$;

CREATE FUNCTION mesh_ops.read_kubernetes_cluster_ca_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID, p_ca_public_id UUID
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
    v_document JSONB;
BEGIN
    IF p_ca_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    v_cluster := mesh_ops.kubernetes_cluster_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    SELECT mesh_ops.kubernetes_cluster_ca_document_internal_v1(ca) INTO v_document
    FROM mesh.kubernetes_cluster_ca AS ca
    WHERE ca.kubernetes_cluster_id = v_cluster.id AND ca.public_id = p_ca_public_id;
    IF v_document IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster CA';
    END IF;
    RETURN v_document;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.list_kubernetes_cluster_replicas_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_kubernetes_cluster_replicas_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_cluster_replica_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_cluster_replica_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.list_kubernetes_cluster_cas_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_kubernetes_cluster_cas_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_cluster_ca_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_cluster_ca_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) TO mesh_runtime;
