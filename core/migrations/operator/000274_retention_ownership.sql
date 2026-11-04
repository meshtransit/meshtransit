-- operator-step: rollout=before
BEGIN;
ALTER FUNCTION mesh_ops.prune_idempotency_records_v1(INTEGER,INTEGER) OWNER TO mesh_retention;
REVOKE ALL ON FUNCTION mesh_ops.prune_idempotency_records_v1(INTEGER,INTEGER) FROM PUBLIC,mesh_migrator,mesh_runtime,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.prune_idempotency_records_v1(INTEGER,INTEGER) TO mesh_worker;
ALTER FUNCTION mesh_ops.prune_outbox_events_v1(INTEGER,INTEGER,INTEGER) OWNER TO mesh_retention;
REVOKE ALL ON FUNCTION mesh_ops.prune_outbox_events_v1(INTEGER,INTEGER,INTEGER) FROM PUBLIC,mesh_migrator,mesh_runtime,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.prune_outbox_events_v1(INTEGER,INTEGER,INTEGER) TO mesh_worker;
ALTER FUNCTION mesh_ops.prune_audit_rows_v1(INTEGER,INTEGER) OWNER TO mesh_retention;
REVOKE ALL ON FUNCTION mesh_ops.prune_audit_rows_v1(INTEGER,INTEGER) FROM PUBLIC,mesh_migrator,mesh_runtime,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.prune_audit_rows_v1(INTEGER,INTEGER) TO mesh_worker;
COMMIT;
