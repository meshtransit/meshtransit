-- operator-step: rollout=before
BEGIN;
ALTER FUNCTION mesh_ops.flowlog_networks_v1(UUID,INTEGER) OWNER TO mesh_flowlog_reader;
REVOKE ALL ON FUNCTION mesh_ops.flowlog_networks_v1(UUID,INTEGER) FROM PUBLIC,mesh_migrator,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.flowlog_networks_v1(UUID,INTEGER) TO mesh_runtime;
ALTER FUNCTION mesh_ops.flowlog_destination_v1(UUID,UUID) OWNER TO mesh_flowlog_reader;
REVOKE ALL ON FUNCTION mesh_ops.flowlog_destination_v1(UUID,UUID) FROM PUBLIC,mesh_migrator,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.flowlog_destination_v1(UUID,UUID) TO mesh_runtime;
ALTER FUNCTION mesh_ops.flowlog_revocations_v1(TIMESTAMPTZ) OWNER TO mesh_flowlog_reader;
REVOKE ALL ON FUNCTION mesh_ops.flowlog_revocations_v1(TIMESTAMPTZ) FROM PUBLIC,mesh_migrator,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.flowlog_revocations_v1(TIMESTAMPTZ) TO mesh_runtime;
COMMIT;
