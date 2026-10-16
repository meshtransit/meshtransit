-- operator-step: rollout=after
BEGIN;

ALTER FUNCTION mesh_ops.assert_private_endpoint_scope_internal_v1(
    BIGINT, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT
) OWNER TO mesh_share_writer;

REVOKE ALL ON FUNCTION mesh_ops.assert_private_endpoint_scope_internal_v1(
    BIGINT, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.assert_private_endpoint_scope_internal_v1(
    BIGINT, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT
) TO mesh_migrator;

ALTER FUNCTION mesh_ops.revoke_resource_share_v4(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) OWNER TO mesh_share_writer;

REVOKE ALL ON FUNCTION mesh_ops.revoke_resource_share_v3(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.revoke_resource_share_v4(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_migrator, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.revoke_resource_share_v4(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) TO mesh_runtime;

COMMIT;
