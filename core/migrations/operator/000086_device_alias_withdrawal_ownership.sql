-- operator-step: rollout=after
BEGIN;
ALTER FUNCTION mesh_ops.device_alias_withdrawal_proof_internal_v1(UUID,UUID,TEXT) OWNER TO mesh_device_alias_writer;
ALTER FUNCTION mesh_ops.prepare_device_alias_withdrawal_v1(UUID,UUID,UUID,BIGINT,UUID,TEXT) OWNER TO mesh_device_alias_writer;
ALTER FUNCTION mesh_ops.finalize_device_alias_withdrawal_v1(UUID,UUID,BIGINT,UUID,TEXT,JSONB) OWNER TO mesh_device_alias_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.prepare_device_alias_withdrawal_v1(UUID,UUID,UUID,BIGINT,UUID,TEXT) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.finalize_device_alias_withdrawal_v1(UUID,UUID,BIGINT,UUID,TEXT,JSONB) TO mesh_worker;
COMMIT;
