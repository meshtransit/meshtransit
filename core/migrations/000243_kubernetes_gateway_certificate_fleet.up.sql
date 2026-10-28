-- K1a4 a4d: the gateway certificate fleet for Core's own gauges (a4 design
-- §10 M7). An operator of a SaaS installation cannot scrape meshgw in a
-- customer's cluster, so the signing worker reads, a page at a time, each
-- active gateway Device of an active cluster: when its latest certificate
-- expires (absent: none), whether it asked within the last 10 minutes (a
-- request not yet pruned), and whether that latest request went unserved.
-- The worker sums the pages in Go; the gauges carry no identifier.
--
-- Keyset by (cluster, ordinal) on device_kubernetes_ordinal_uidx; the latest
-- certificate by kubernetes_gateway_certificate_device_idx; the latest
-- recent request by the request's (device_id, request_id) key.

CREATE FUNCTION mesh_ops.read_kubernetes_gateway_certificate_fleet_v1(p_deployment_public_id UUID,
    p_after_cluster BIGINT, p_after_ordinal INTEGER, p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
    v_rows JSONB;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 OR p_after_cluster IS NULL OR p_after_ordinal IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway certificate fleet input';
    END IF;
    v_deployment_id := mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id);
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    -- The page's keys first, then the lookups for those rows only: a plan
    -- never computes them for the whole fleet (review a4d M1).
    WITH page AS MATERIALIZED (
        SELECT device.id, device.kubernetes_cluster_id AS cluster_id, device.kubernetes_ordinal AS ordinal
        FROM mesh.device AS device
        JOIN mesh.kubernetes_cluster AS cluster
          ON cluster.workspace_id = device.workspace_id AND cluster.network_id = device.network_id
         AND cluster.id = device.kubernetes_cluster_id
        JOIN mesh.workspace AS workspace ON workspace.id = device.workspace_id
        WHERE device.kubernetes_cluster_id IS NOT NULL AND device.deleted_at IS NULL
          AND (device.kubernetes_cluster_id, device.kubernetes_ordinal)
              > (p_after_cluster, p_after_ordinal::SMALLINT)
          AND device.kind = 'kubernetes_gateway' AND device.state = 'active' AND device.expires_at > v_now
          AND cluster.state = 'active' AND workspace.deployment_id = v_deployment_id
        ORDER BY device.kubernetes_cluster_id, device.kubernetes_ordinal
        LIMIT p_limit
    )
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(page.cluster_id, page.ordinal,
               (EXTRACT(EPOCH FROM latest.not_after) * 1000)::BIGINT, asked.created_at IS NOT NULL,
               -- Asked and not served: the latest recent request was refused
               -- or given up, or has waited over a minute, whatever the
               -- latest certificate (a pod that lost its key, review a4d M2).
               COALESCE(asked.state IN ('refused', 'abandoned')
                   OR asked.state IN ('pending', 'claimed') AND asked.created_at < v_now - INTERVAL '1 minute',
                   FALSE))
               ORDER BY page.cluster_id, page.ordinal), '[]'::JSONB)
    INTO v_rows
    FROM page
    LEFT JOIN LATERAL (
        SELECT issued.not_after FROM mesh.kubernetes_gateway_certificate AS issued
        WHERE issued.device_id = page.id
        ORDER BY issued.issued_at DESC
        LIMIT 1
    ) AS latest ON TRUE
    LEFT JOIN LATERAL (
        SELECT request.state, request.created_at FROM mesh_ops.kubernetes_gateway_certificate_request AS request
        WHERE request.device_id = page.id AND request.created_at > v_now - INTERVAL '10 minutes'
        ORDER BY request.created_at DESC
        LIMIT 1
    ) AS asked ON TRUE;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    RETURN pg_catalog.jsonb_build_object('rows', v_rows);
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_gateway_certificate_fleet_v1(UUID, BIGINT, INTEGER, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_gateway_certificate_fleet_v1(UUID, BIGINT, INTEGER, INTEGER)
    TO mesh_worker;
