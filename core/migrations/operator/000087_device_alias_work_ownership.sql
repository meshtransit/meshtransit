-- operator-step: rollout=after
BEGIN;
ALTER FUNCTION mesh_ops.load_device_alias_work_v1(UUID,UUID,UUID,INTEGER) OWNER TO mesh_device_alias_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_work_v1(UUID,UUID,UUID,INTEGER) TO mesh_worker;
ALTER FUNCTION mesh_ops.prepare_device_alias_resource_quarantine_v1(UUID,UUID,BIGINT,UUID) OWNER TO mesh_device_alias_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.prepare_device_alias_resource_quarantine_v1(UUID,UUID,BIGINT,UUID) TO mesh_worker;
COMMIT;
