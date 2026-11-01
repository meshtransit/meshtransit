-- operator-step: rollout=before
BEGIN;
ALTER FUNCTION mesh_ops.network_connection_log_status_internal_v1(BIGINT,BIGINT,INTEGER) OWNER TO mesh_flowlog_status_writer;
REVOKE ALL ON FUNCTION mesh_ops.network_connection_log_status_internal_v1(BIGINT,BIGINT,INTEGER) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.network_connection_log_status_internal_v1(BIGINT,BIGINT,INTEGER) TO mesh_migrator;
COMMIT;
