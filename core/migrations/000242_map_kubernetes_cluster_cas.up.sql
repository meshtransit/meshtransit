-- Schema 242 (K1a4a a3b2, mtcp-v1 §7.10, design a3 §3 "Map của gateway",
-- §14 R-M6): a Kubernetes gateway's map names its cluster's active root and
-- the intermediate that signs now, by the SHA-256 of their DER, so the
-- gateway renews early when either changes. Read with the Network's shared
-- inventory, in its transaction: a CA change advances the Network revision
-- (schema 240), so the inventory is read again.
--
-- While a database restore is suspected the CAs are withheld: the maps
-- built from a restored database would name CAs the gateways' certificates
-- no longer chain to (review a3b H3). One installation per database
-- (TD-CORE-103): any suspected guard withholds.

CREATE FUNCTION mesh_ops.load_map_network_kubernetes_cas_v1(p_limit INTEGER)
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
        'name', listed.name,
        'root', pg_catalog.encode(listed.root, 'hex'),
        'signing', pg_catalog.encode(listed.signing, 'hex')) ORDER BY listed.id), '[]'::JSONB)
    INTO v_clusters
    FROM (
        -- The root named is the one the signing intermediate chains to, so
        -- the map never names a root no certificate Core issues chains to
        -- (review a3b2 M1); with no intermediate active, the active root.
        SELECT cluster.id, cluster.name,
            COALESCE(issuer.fingerprint, (SELECT ca.fingerprint FROM mesh.kubernetes_cluster_ca AS ca
             WHERE ca.kubernetes_cluster_id = cluster.id AND ca.kind = 'root' AND ca.state = 'active'
             ORDER BY ca.id DESC LIMIT 1)) AS root,
            signing.fingerprint AS signing
        FROM mesh.kubernetes_cluster AS cluster
        LEFT JOIN LATERAL (
            SELECT ca.fingerprint, ca.issuer_ca_id FROM mesh.kubernetes_cluster_ca AS ca
            WHERE ca.kubernetes_cluster_id = cluster.id AND ca.kind = 'intermediate' AND ca.state = 'active'
            ORDER BY ca.id DESC LIMIT 1
        ) AS signing ON TRUE
        LEFT JOIN mesh.kubernetes_cluster_ca AS issuer ON issuer.id = signing.issuer_ca_id
        WHERE cluster.workspace_id = v_workspace_id AND cluster.network_id = v_network_id
          AND cluster.state = 'active'
        ORDER BY cluster.id
        LIMIT p_limit
    ) AS listed;
    RETURN pg_catalog.jsonb_build_object('withheld', FALSE, 'clusters', v_clusters);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_kubernetes_cas_v1(INTEGER)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_kubernetes_cas_v1(INTEGER) TO mesh_runtime;
