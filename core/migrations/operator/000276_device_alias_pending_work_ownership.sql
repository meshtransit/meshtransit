-- operator-step: rollout=before
BEGIN;
-- The alias worker: load v5 skips ended endpoints left with nothing to clean
-- up (schema 276). The worker uses it, with prepare v5, once it is granted.
-- It needs no rollout: v5 hands out exactly v4's work, and the previous
-- image keeps calling v4.
ALTER FUNCTION mesh_ops.load_device_alias_work_v5(UUID,UUID,UUID,INTEGER) OWNER TO mesh_device_alias_writer;
REVOKE ALL ON FUNCTION mesh_ops.load_device_alias_work_v5(UUID,UUID,UUID,INTEGER) FROM PUBLIC,mesh_migrator,mesh_runtime,mesh_observer,mesh_audit_writer,mesh_share_writer,mesh_direct_map_reader;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_work_v5(UUID,UUID,UUID,INTEGER) TO mesh_worker;
-- Load v4 stays executable so the previous image can roll back; a later
-- contract step closes it once no supported binary calls it.
COMMIT;
