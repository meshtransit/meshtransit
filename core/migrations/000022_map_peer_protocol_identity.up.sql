CREATE FUNCTION mesh_ops.load_map_peer_candidates_v2(
    p_machine_key_fingerprint BYTEA,
    p_node_key BYTEA,
    p_limit INTEGER
)
RETURNS TABLE (
    numeric_node_id BIGINT,
    numeric_owner_id BIGINT,
    node_public_id UUID,
    owner_public_id UUID,
    hostname TEXT,
    machine_key BYTEA,
    node_key BYTEA,
    session_generation BIGINT,
    created_at TIMESTAMPTZ,
    key_expiry TIMESTAMPTZ,
    addresses TEXT[]
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
    SELECT
        candidate.id,
        owner.id,
        projected.node_public_id,
        projected.owner_public_id,
        projected.hostname,
        projected.machine_key,
        projected.node_key,
        projected.session_generation,
        projected.created_at,
        projected.key_expiry,
        projected.addresses
    FROM mesh_ops.load_map_peer_candidates(
        p_machine_key_fingerprint,
        p_node_key,
        p_limit
    ) AS projected
    JOIN mesh.device AS candidate
      ON candidate.workspace_id = mesh_ops.current_workspace_id()
     AND candidate.network_id = mesh_ops.current_network_id()
     AND candidate.public_id = projected.node_public_id
    JOIN mesh.principal AS owner
      ON owner.id = candidate.owner_principal_id
     AND owner.public_id = projected.owner_public_id
    ORDER BY candidate.created_at DESC, candidate.id DESC;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.load_map_peer_candidates_v2(BYTEA, BYTEA, INTEGER)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_peer_candidates_v2(BYTEA, BYTEA, INTEGER)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_peer_candidates_v2(BYTEA, BYTEA, INTEGER)
    TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
