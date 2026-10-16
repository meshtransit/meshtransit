-- operator-step: rollout=after
BEGIN;
ALTER FUNCTION mesh_ops.load_direct_share_map_edges_v1(BYTEA, BYTEA, INTEGER)
    OWNER TO mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.load_direct_share_map_edges_v1(BYTEA, BYTEA, INTEGER)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_direct_share_map_edges_v1(BYTEA, BYTEA, INTEGER)
    TO mesh_runtime;
COMMIT;
