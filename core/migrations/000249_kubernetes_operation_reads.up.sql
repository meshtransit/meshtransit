-- Schema 249 (K1d d1c, docs/k8s-k1d-console-design.md §3.1, Q139, Q140): a
-- cluster's Kubernetes operations read a page at a time, newest first, for
-- holders of audit.read in the Workspace or the Network: who did what is
-- personal data. A page reads the cluster index in order and stops after
-- p_scan_budget rows whatever the filters keep, so a filter that matches
-- little costs a bounded scan; the caller continues from the last row
-- scanned. One operation reads by its audit ID, whose UUIDv7 time is its
-- received_at (one partition). Denials sum by reason over a range.

CREATE INDEX kubernetes_operation_denial_cluster_idx
    ON mesh_audit.kubernetes_operation_denial (kubernetes_cluster_id, recorded_at DESC);

-- The cluster (any state: a deleted cluster's history stays readable) an
-- audit reader names, or the error the caller maps (42501, P0002).
CREATE FUNCTION mesh_ops.kubernetes_operation_reader_internal_v1(
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
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes operation request is invalid';
    END IF;
    PERFORM 1 FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, 'audit.read', v_now);
    IF NOT FOUND THEN
        PERFORM 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
            p_session_version, p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
            'audit.read', v_now);
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'audit.read required';
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
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_operation_reader_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- An operation as an audit reader sees it: public IDs only, and the
-- gateway's outcome if it came within a day.
CREATE FUNCTION mesh_ops.kubernetes_operation_document_internal_v1(p_operation mesh_audit.kubernetes_operation)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'audit_id', p_operation.audit_id,
        'received_at', p_operation.received_at,
        'class', p_operation.class,
        'groups', pg_catalog.to_jsonb(p_operation.groups),
        'verb', p_operation.verb,
        'api_group', p_operation.api_group,
        'resource', p_operation.resource,
        'subresource', p_operation.subresource,
        'namespace', p_operation.namespace,
        'name', p_operation.name,
        'impersonated', p_operation.impersonated,
        'owner_kind', p_operation.owner_kind,
        'owner_ref', p_operation.owner_ref,
        'network_revision', p_operation.network_revision,
        'clock_skew', p_operation.clock_skew,
        'gateway_device_id', (SELECT device.public_id FROM mesh.device AS device
                              WHERE device.id = p_operation.gateway_device_id
                                AND device.workspace_id = p_operation.workspace_id),
        'peer_device_id', (SELECT device.public_id FROM mesh.device AS device
                           WHERE device.id = p_operation.peer_device_id
                             AND device.workspace_id = p_operation.workspace_id),
        'status', outcome.status,
        'duration_ms', outcome.duration_ms
    )
    FROM (SELECT NULL) AS anchor
    LEFT JOIN LATERAL (
        SELECT result.status, result.duration_ms FROM mesh_audit.kubernetes_operation_outcome AS result
        WHERE result.audit_id = p_operation.audit_id AND result.gateway_device_id = p_operation.gateway_device_id
          AND result.recorded_at >= p_operation.received_at
          AND result.recorded_at < p_operation.received_at + INTERVAL '1 day'
        ORDER BY result.recorded_at
        LIMIT 1
    ) AS outcome ON TRUE
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_operation_document_internal_v1(mesh_audit.kubernetes_operation)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A page of a cluster's operations in [p_from, p_to), newest first, after
-- (p_after_at, p_after_id) when given, kept by the optional filters. It
-- returns up to p_limit + 1 kept rows, and the last row scanned with
-- truncated = true when it stopped at p_scan_budget rows first. A range
-- spans at most 31 days, 1 day with a filter (Q140).
CREATE FUNCTION mesh_ops.list_kubernetes_operations_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_from TIMESTAMPTZ, p_to TIMESTAMPTZ, p_after_at TIMESTAMPTZ, p_after_id UUID,
    p_owner_ref TEXT, p_peer_device_public_id UUID, p_class TEXT, p_limit INTEGER, p_scan_budget INTEGER
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
    v_filtered BOOLEAN := p_owner_ref IS NOT NULL OR p_peer_device_public_id IS NOT NULL OR p_class IS NOT NULL;
    -- Out of the IF below: plpgsql ends its condition at the first THEN.
    v_longest INTERVAL := CASE WHEN v_filtered THEN INTERVAL '1 day' ELSE INTERVAL '31 days' END;
    v_peer BIGINT;
    v_row mesh_audit.kubernetes_operation%ROWTYPE;
    v_kept JSONB := '[]'::JSONB;
    v_kept_count INTEGER := 0;
    v_scanned INTEGER := 0;
    v_last_at TIMESTAMPTZ;
    v_last_id UUID;
BEGIN
    IF p_from IS NULL OR p_to IS NULL OR p_to <= p_from
        OR p_to - p_from > v_longest
        OR (p_after_at IS NULL) <> (p_after_id IS NULL)
        OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100
        OR p_scan_budget IS NULL OR p_scan_budget NOT BETWEEN 1 AND 50000
        OR p_owner_ref IS NOT NULL AND pg_catalog.octet_length(p_owner_ref) NOT BETWEEN 1 AND 1024
        OR p_class IS NOT NULL AND p_class NOT IN ('write', 'exec', 'proxy', 'secret_read', 'privileged', 'unparsed')
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes operation request is invalid';
    END IF;
    v_cluster := mesh_ops.kubernetes_operation_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    IF p_peer_device_public_id IS NOT NULL THEN
        SELECT device.id INTO v_peer FROM mesh.device AS device
        WHERE device.workspace_id = v_cluster.workspace_id AND device.network_id = v_cluster.network_id
          AND device.public_id = p_peer_device_public_id;
        IF NOT FOUND THEN
            RETURN pg_catalog.jsonb_build_object('operations', '[]'::JSONB, 'truncated', FALSE);
        END IF;
    END IF;
    FOR v_row IN
        SELECT operation.* FROM mesh_audit.kubernetes_operation AS operation
        WHERE operation.kubernetes_cluster_id = v_cluster.id
          AND operation.workspace_id = v_cluster.workspace_id AND operation.network_id = v_cluster.network_id
          AND operation.received_at >= p_from AND operation.received_at < p_to
          -- Indexable even in a generic plan: the cursor bounds the scan,
          -- and older partitions prune at run time (review d1c M1).
          AND operation.received_at <= COALESCE(p_after_at, 'infinity'::TIMESTAMPTZ)
          AND (p_after_at IS NULL OR (operation.received_at, operation.audit_id) < (p_after_at, p_after_id))
        ORDER BY operation.received_at DESC, operation.audit_id DESC
        LIMIT p_scan_budget
    LOOP
        v_scanned := v_scanned + 1;
        v_last_at := v_row.received_at;
        v_last_id := v_row.audit_id;
        IF (p_owner_ref IS NULL OR v_row.owner_ref = p_owner_ref)
            AND (v_peer IS NULL OR v_row.peer_device_id = v_peer)
            AND (p_class IS NULL OR v_row.class = p_class) THEN
            v_kept := v_kept || pg_catalog.jsonb_build_array(mesh_ops.kubernetes_operation_document_internal_v1(v_row));
            v_kept_count := v_kept_count + 1;
            EXIT WHEN v_kept_count > p_limit;
        END IF;
    END LOOP;
    RETURN pg_catalog.jsonb_build_object(
        'operations', v_kept,
        'truncated', v_scanned = p_scan_budget AND v_kept_count <= p_limit,
        'last_scanned_at', v_last_at,
        'last_scanned_id', v_last_id
    );
END;
$function$;

CREATE FUNCTION mesh_ops.read_kubernetes_operation_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID, p_audit_id UUID
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
    IF p_audit_id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(p_audit_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes operation request is invalid';
    END IF;
    v_cluster := mesh_ops.kubernetes_operation_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    SELECT mesh_ops.kubernetes_operation_document_internal_v1(operation) INTO v_document
    FROM mesh_audit.kubernetes_operation AS operation
    WHERE operation.received_at = pg_catalog.uuid_extract_timestamp(p_audit_id)
      AND operation.audit_id = p_audit_id AND operation.kubernetes_cluster_id = v_cluster.id
      AND operation.workspace_id = v_cluster.workspace_id AND operation.network_id = v_cluster.network_id;
    IF v_document IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes operation';
    END IF;
    RETURN v_document;
END;
$function$;

-- A cluster's denials in [p_from, p_to) by reason (at most six rows), over
-- the newest 50000 denial rows at most: a flood of denials is when an
-- auditor looks (review d1c H2, Q153). truncated says older rows were left
-- out, counted_from the oldest row summed.
CREATE FUNCTION mesh_ops.kubernetes_operation_denial_counts_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_from TIMESTAMPTZ, p_to TIMESTAMPTZ
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
    IF p_from IS NULL OR p_to IS NULL OR p_to <= p_from OR p_to - p_from > INTERVAL '31 days' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes operation request is invalid';
    END IF;
    v_cluster := mesh_ops.kubernetes_operation_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    RETURN (
        WITH newest AS (
            SELECT denial.reason, denial.count, denial.first_at, denial.last_at, denial.recorded_at
            FROM mesh_audit.kubernetes_operation_denial AS denial
            WHERE denial.kubernetes_cluster_id = v_cluster.id
              AND denial.workspace_id = v_cluster.workspace_id AND denial.network_id = v_cluster.network_id
              AND denial.recorded_at >= p_from AND denial.recorded_at < p_to
            ORDER BY denial.recorded_at DESC
            LIMIT 50001
        ), kept AS (
            SELECT * FROM newest ORDER BY newest.recorded_at DESC LIMIT 50000
        )
        SELECT pg_catalog.jsonb_build_object(
            'counts', COALESCE((
                SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                    'reason', summed.reason, 'count', summed.total, 'first_at', summed.first_at,
                    'last_at', summed.last_at) ORDER BY summed.reason)
                FROM (
                    SELECT kept.reason, pg_catalog.sum(kept.count) AS total,
                        pg_catalog.min(kept.first_at) AS first_at, pg_catalog.max(kept.last_at) AS last_at
                    FROM kept GROUP BY kept.reason
                ) AS summed
            ), '[]'::JSONB),
            'truncated', (SELECT pg_catalog.count(*) FROM newest) > 50000,
            'counted_from', (SELECT pg_catalog.min(kept.recorded_at) FROM kept)
        )
    );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.list_kubernetes_operations_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID,
    TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, UUID, TEXT, UUID, TEXT, INTEGER, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_kubernetes_operations_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID,
    TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, UUID, TEXT, UUID, TEXT, INTEGER, INTEGER
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_operation_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_operation_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_operation_denial_counts_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.kubernetes_operation_denial_counts_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, TIMESTAMPTZ
) TO mesh_runtime;
