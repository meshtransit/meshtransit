BEGIN;
ALTER FUNCTION mesh_ops.load_device_sharing_dependencies_v2(BYTEA,BYTEA,INTEGER) OWNER TO mesh_device_alias_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.load_device_sharing_dependencies_v2(BYTEA,BYTEA,INTEGER) FROM PUBLIC,mesh_migrator,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer,mesh_direct_map_reader;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v2(BYTEA,BYTEA,INTEGER) TO mesh_runtime;
-- v1 stays executable so the previous image can roll back; a later contract
-- step closes it once no supported binary calls it.
COMMIT;
