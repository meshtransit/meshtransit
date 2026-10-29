-- Schema 244 (K1a4d, docs/k8s-k1a4d-client-ca-design.md §3.1): what a
-- client's map needs to trust its clusters' gateways (capability kube.ca1),
-- read with the Network's shared inventory, in its transaction.
--
-- v2 of the map CA reader names, for each active cluster, its public ID,
-- the TLS name its gateways' certificates carry, and the fingerprints of the
-- roots a client trusts (next, active and retiring), besides what a
-- gateway's map names (§7.10: the signing intermediate and the root it
-- chains to). The roots' DER is read apart, by fingerprint, only for those
-- the map server does not hold yet: DER never changes for a fingerprint.
--
-- While a database restore is suspected both withhold, as v1 does.

CREATE FUNCTION mesh_ops.load_map_network_kubernetes_cas_v2(p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace_id BIGINT := mesh_ops.current_workspace_id();
    v_network_id BIGINT := mesh_ops.current_network_id();
    v_clusters JSONB;
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 10001 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map Kubernetes CA request is invalid';
    END IF;
    IF v_workspace_id IS NULL OR v_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network inventory scope is unavailable';
    END IF;
    IF EXISTS (SELECT 1 FROM mesh_ops.kubernetes_ca_guard AS guard WHERE guard.restore_suspected) THEN
        RETURN pg_catalog.jsonb_build_object('withheld', TRUE, 'clusters', '[]'::JSONB);
    END IF;
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'id', listed.public_id,
        'name', listed.name,
        'signing', pg_catalog.encode(listed.signing, 'hex'),
        'signing_root', pg_catalog.encode(listed.signing_root, 'hex'),
        'tls_name', listed.tls_name,
        'trusted', listed.trusted) ORDER BY listed.id), '[]'::JSONB)
    INTO v_clusters
    FROM (
        SELECT cluster.id, cluster.public_id, cluster.name,
            signing.fingerprint AS signing,
            -- As v1's root: the root the signing intermediate chains to,
            -- else the active root.
            COALESCE(issuer.fingerprint, active.fingerprint) AS signing_root,
            COALESCE(signing.cluster_dns_name, active.cluster_dns_name) AS tls_name,
            -- Scoped by Workspace and Network so the lookup walks the
            -- (workspace_id, network_id, kubernetes_cluster_id, id) key in id
            -- order (review d1 H1).
            (SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.encode(ca.fingerprint, 'hex') ORDER BY ca.id),
                    '[]'::JSONB)
             FROM mesh.kubernetes_cluster_ca AS ca
             WHERE ca.workspace_id = v_workspace_id AND ca.network_id = v_network_id
               AND ca.kubernetes_cluster_id = cluster.id AND ca.kind = 'root'
               AND ca.state IN ('next', 'active', 'retiring')) AS trusted
        FROM mesh.kubernetes_cluster AS cluster
        LEFT JOIN LATERAL (
            SELECT ca.fingerprint, ca.issuer_ca_id, ca.cluster_dns_name FROM mesh.kubernetes_cluster_ca AS ca
            WHERE ca.kubernetes_cluster_id = cluster.id AND ca.kind = 'intermediate' AND ca.state = 'active'
            ORDER BY ca.id DESC LIMIT 1
        ) AS signing ON TRUE
        LEFT JOIN mesh.kubernetes_cluster_ca AS issuer ON issuer.id = signing.issuer_ca_id
        LEFT JOIN LATERAL (
            SELECT ca.fingerprint, ca.cluster_dns_name FROM mesh.kubernetes_cluster_ca AS ca
            WHERE ca.kubernetes_cluster_id = cluster.id AND ca.kind = 'root' AND ca.state = 'active'
            ORDER BY ca.id DESC LIMIT 1
        ) AS active ON TRUE
        WHERE cluster.workspace_id = v_workspace_id AND cluster.network_id = v_network_id
          AND cluster.state = 'active'
        ORDER BY cluster.id
        LIMIT p_limit
    ) AS listed;
    RETURN pg_catalog.jsonb_build_object('withheld', FALSE, 'clusters', v_clusters);
END;
$function$;

-- The DER of the Network's roots (never an intermediate, never a retired
-- root, never another Network's) named by fingerprint: at most 1,024 a call.
CREATE FUNCTION mesh_ops.load_map_kubernetes_ca_roots_v1(p_fingerprints BYTEA[])
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace_id BIGINT := mesh_ops.current_workspace_id();
    v_network_id BIGINT := mesh_ops.current_network_id();
    v_roots JSONB;
BEGIN
    IF p_fingerprints IS NULL OR pg_catalog.cardinality(p_fingerprints) NOT BETWEEN 1 AND 1024
       OR pg_catalog.array_position(p_fingerprints, NULL) IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map Kubernetes root request is invalid';
    END IF;
    IF v_workspace_id IS NULL OR v_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network inventory scope is unavailable';
    END IF;
    IF EXISTS (SELECT 1 FROM mesh_ops.kubernetes_ca_guard AS guard WHERE guard.restore_suspected) THEN
        RETURN pg_catalog.jsonb_build_object('withheld', TRUE, 'roots', '[]'::JSONB);
    END IF;
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.encode(ca.certificate, 'hex') ORDER BY ca.id), '[]'::JSONB)
    INTO v_roots
    FROM mesh.kubernetes_cluster_ca AS ca
    JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = ca.kubernetes_cluster_id
    WHERE ca.fingerprint = ANY (p_fingerprints) AND ca.kind = 'root' AND ca.state <> 'retired'
      AND ca.workspace_id = v_workspace_id AND ca.network_id = v_network_id
      AND cluster.workspace_id = v_workspace_id AND cluster.network_id = v_network_id
      AND cluster.state = 'active';
    RETURN pg_catalog.jsonb_build_object('withheld', FALSE, 'roots', v_roots);
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.load_map_network_kubernetes_cas_v2(INTEGER)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_kubernetes_cas_v2(INTEGER) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.load_map_kubernetes_ca_roots_v1(BYTEA[])
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_kubernetes_ca_roots_v1(BYTEA[]) TO mesh_runtime;
