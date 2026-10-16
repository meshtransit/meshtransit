BEGIN;
-- The alias worker: load v4 and prepare v5 give a resumed provider Device the
-- endpoint's own Resource aliases back (schema 171). The worker uses them only
-- once both are granted.
ALTER FUNCTION mesh_ops.load_device_alias_work_v4(UUID,UUID,UUID,INTEGER) OWNER TO mesh_device_alias_writer;
REVOKE ALL ON FUNCTION mesh_ops.load_device_alias_work_v4(UUID,UUID,UUID,INTEGER) FROM PUBLIC,mesh_migrator,mesh_runtime,mesh_observer,mesh_audit_writer,mesh_share_writer,mesh_direct_map_reader;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_work_v4(UUID,UUID,UUID,INTEGER) TO mesh_worker;
ALTER FUNCTION mesh_ops.prepare_device_alias_change_v5(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) OWNER TO mesh_device_alias_writer;
REVOKE ALL ON FUNCTION mesh_ops.prepare_device_alias_change_v5(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) FROM PUBLIC,mesh_migrator,mesh_runtime,mesh_observer,mesh_audit_writer,mesh_share_writer,mesh_direct_map_reader;
GRANT EXECUTE ON FUNCTION mesh_ops.prepare_device_alias_change_v5(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) TO mesh_worker;
-- Load v2 and v3 and prepare v2 to v4 stay executable so the previous image
-- can roll back; a later contract step closes them once no supported binary
-- calls them.
COMMIT;
