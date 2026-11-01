-- operator-step: rollout=before
BEGIN;
ALTER FUNCTION mesh_ops.flowlog_directory_network_v1(UUID,UUID) OWNER TO mesh_flowlog_reader;
REVOKE ALL ON FUNCTION mesh_ops.flowlog_directory_network_v1(UUID,UUID) FROM PUBLIC,mesh_migrator,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.flowlog_directory_network_v1(UUID,UUID) TO mesh_runtime;
ALTER FUNCTION mesh_ops.flowlog_directory_devices_v1(UUID,UUID,UUID,INTEGER) OWNER TO mesh_flowlog_reader;
REVOKE ALL ON FUNCTION mesh_ops.flowlog_directory_devices_v1(UUID,UUID,UUID,INTEGER) FROM PUBLIC,mesh_migrator,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.flowlog_directory_devices_v1(UUID,UUID,UUID,INTEGER) TO mesh_runtime;
COMMIT;
