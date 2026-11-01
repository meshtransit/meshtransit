-- operator-step: rollout=before
BEGIN;
ALTER FUNCTION mesh_ops.flowlog_report_status_v1(BYTEA,INTEGER[],BYTEA[],TEXT[],TIMESTAMPTZ,JSONB) OWNER TO mesh_flowlog_status_writer;
REVOKE ALL ON FUNCTION mesh_ops.flowlog_report_status_v1(BYTEA,INTEGER[],BYTEA[],TEXT[],TIMESTAMPTZ,JSONB) FROM PUBLIC,mesh_migrator,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.flowlog_report_status_v1(BYTEA,INTEGER[],BYTEA[],TEXT[],TIMESTAMPTZ,JSONB) TO mesh_runtime;
ALTER FUNCTION mesh_ops.flowlog_receiver_gate_v1(INTEGER,BYTEA) OWNER TO mesh_flowlog_reader;
REVOKE ALL ON FUNCTION mesh_ops.flowlog_receiver_gate_v1(INTEGER,BYTEA) FROM PUBLIC,mesh_migrator,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.flowlog_receiver_gate_v1(INTEGER,BYTEA) TO mesh_runtime;
COMMIT;
