-- operator-step: rollout=after
BEGIN;
ALTER FUNCTION mesh_ops.save_device_alias_worker_context_v1() OWNER TO mesh_device_alias_writer;
ALTER FUNCTION mesh_ops.restore_device_alias_worker_context_v1(JSONB) OWNER TO mesh_device_alias_writer;
ALTER FUNCTION mesh_ops.derive_device_alias_worker_scope_v1(UUID,UUID) OWNER TO mesh_device_alias_writer;
ALTER FUNCTION mesh_ops.device_alias_change_proof_internal_v1(UUID,UUID,TEXT) OWNER TO mesh_device_alias_writer;
ALTER FUNCTION mesh_ops.prepare_device_alias_change_v1(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) OWNER TO mesh_device_alias_writer;
ALTER FUNCTION mesh_ops.finalize_device_alias_change_v1(UUID,UUID,BIGINT,UUID,TEXT,JSONB) OWNER TO mesh_device_alias_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.prepare_device_alias_change_v1(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.finalize_device_alias_change_v1(UUID,UUID,BIGINT,UUID,TEXT,JSONB) TO mesh_worker;
COMMIT;
