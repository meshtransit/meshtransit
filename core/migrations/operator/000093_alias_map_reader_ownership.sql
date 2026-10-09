BEGIN;
ALTER FUNCTION mesh_ops.load_device_alias_map_edges_v3(BYTEA,BYTEA,INTEGER) OWNER TO mesh_device_alias_map_reader;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v3(BYTEA,BYTEA,INTEGER) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.load_device_alias_map_edges_v3(BYTEA,BYTEA,INTEGER) FROM PUBLIC,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer,mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.load_device_alias_map_edges_v2(BYTEA,BYTEA,INTEGER) FROM mesh_runtime;
COMMIT;
