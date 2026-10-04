BEGIN;
ALTER FUNCTION mesh_ops.read_compiled_imported_policy_evidence_internal_v1(BIGINT)
OWNER TO mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.read_compiled_imported_policy_evidence_internal_v1(BIGINT)
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_compiled_imported_policy_evidence_internal_v1(BIGINT)
TO mesh_migrator;
COMMIT;
