-- operator-step: rollout=after
BEGIN;
ALTER FUNCTION mesh_ops.activate_resource_share_v3(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) OWNER TO mesh_share_writer;
ALTER FUNCTION mesh_ops.revoke_resource_share_v5(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) OWNER TO mesh_share_writer;
ALTER FUNCTION mesh_ops.withdraw_direct_device_endpoint_on_contract_end()
    OWNER TO mesh_share_writer;
-- Preserve v2/v4 runtime entry points while the supported rollback writer needs
-- them. Contract terminal transitions withdraw direct evidence through the trigger.
REVOKE ALL ON FUNCTION mesh_ops.activate_resource_share_v3(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_migrator, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.revoke_resource_share_v5(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_migrator, mesh_worker, mesh_observer, mesh_audit_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.activate_resource_share_v3(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.revoke_resource_share_v5(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) TO mesh_runtime;
COMMIT;
