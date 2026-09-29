BEGIN;

ALTER FUNCTION mesh_ops.activate_resource_share_v2(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TIMESTAMPTZ
) OWNER TO mesh_share_writer;
ALTER FUNCTION mesh_ops.revoke_resource_share_v3(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) OWNER TO mesh_share_writer;

REVOKE ALL ON FUNCTION mesh_ops.activate_resource_share_v1(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.revoke_resource_share_v2(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.activate_resource_share_v2(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_migrator, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.revoke_resource_share_v3(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_migrator, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;

GRANT EXECUTE ON FUNCTION mesh_ops.activate_resource_share_v2(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TIMESTAMPTZ
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.revoke_resource_share_v3(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) TO mesh_runtime;

COMMIT;
