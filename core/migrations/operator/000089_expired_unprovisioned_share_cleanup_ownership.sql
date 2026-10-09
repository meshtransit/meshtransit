BEGIN;
ALTER FUNCTION mesh_ops.revoke_resource_share_v6(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) OWNER TO mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.revoke_resource_share_v5(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_migrator, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.revoke_resource_share_v6(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_migrator, mesh_worker, mesh_observer, mesh_audit_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.revoke_resource_share_v6(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) TO mesh_runtime;
COMMIT;
