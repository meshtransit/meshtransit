-- operator-step: rollout=before
BEGIN;
ALTER FUNCTION mesh_ops.flowlog_report_status_v2(BYTEA,INTEGER[],BYTEA[],TEXT[],TEXT[],TIMESTAMPTZ,JSONB) OWNER TO mesh_flowlog_status_writer;
REVOKE ALL ON FUNCTION mesh_ops.flowlog_report_status_v2(BYTEA,INTEGER[],BYTEA[],TEXT[],TEXT[],TIMESTAMPTZ,JSONB) FROM PUBLIC,mesh_migrator,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.flowlog_report_status_v2(BYTEA,INTEGER[],BYTEA[],TEXT[],TEXT[],TIMESTAMPTZ,JSONB) TO mesh_runtime;
ALTER FUNCTION mesh_ops.flowlog_receiver_gate_v2(INTEGER,BYTEA) OWNER TO mesh_flowlog_reader;
REVOKE ALL ON FUNCTION mesh_ops.flowlog_receiver_gate_v2(INTEGER,BYTEA) FROM PUBLIC,mesh_migrator,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.flowlog_receiver_gate_v2(INTEGER,BYTEA) TO mesh_runtime;
ALTER FUNCTION mesh_ops.flowlog_destination_v2(UUID,UUID) OWNER TO mesh_flowlog_reader;
REVOKE ALL ON FUNCTION mesh_ops.flowlog_destination_v2(UUID,UUID) FROM PUBLIC,mesh_migrator,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.flowlog_destination_v2(UUID,UUID) TO mesh_runtime;
ALTER FUNCTION mesh_ops.network_connection_log_status_internal_v2(BIGINT,BIGINT,INTEGER,TEXT) OWNER TO mesh_flowlog_status_writer;
REVOKE ALL ON FUNCTION mesh_ops.network_connection_log_status_internal_v2(BIGINT,BIGINT,INTEGER,TEXT) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.network_connection_log_status_internal_v2(BIGINT,BIGINT,INTEGER,TEXT) TO mesh_migrator;
COMMIT;
