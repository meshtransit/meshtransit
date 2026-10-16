-- operator-step: rollout=before
BEGIN;
-- The worker that ends shares of removed provider Devices (schema 178). Until
-- these grants exist the worker only logs deferred discovery, so apply this
-- step before the new image rolls out.
ALTER FUNCTION mesh_ops.list_trust_contract_device_removals_v1(UUID, TIMESTAMPTZ, UUID, INTEGER)
    OWNER TO mesh_share_writer;
ALTER FUNCTION mesh_ops.prepare_trust_contract_device_removal_v1(UUID, UUID, UUID)
    OWNER TO mesh_share_writer;
ALTER FUNCTION mesh_ops.finalize_trust_contract_device_removal_v1(UUID, UUID, UUID, JSONB)
    OWNER TO mesh_share_writer;

REVOKE ALL ON FUNCTION mesh_ops.list_trust_contract_device_removals_v1(UUID, TIMESTAMPTZ, UUID, INTEGER)
    FROM PUBLIC, mesh_migrator, mesh_runtime, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.prepare_trust_contract_device_removal_v1(UUID, UUID, UUID)
    FROM PUBLIC, mesh_migrator, mesh_runtime, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.finalize_trust_contract_device_removal_v1(UUID, UUID, UUID, JSONB)
    FROM PUBLIC, mesh_migrator, mesh_runtime, mesh_observer, mesh_audit_writer;

-- Only the worker role ends shares of removed Devices.
GRANT EXECUTE ON FUNCTION mesh_ops.list_trust_contract_device_removals_v1(UUID, TIMESTAMPTZ, UUID, INTEGER)
    TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.prepare_trust_contract_device_removal_v1(UUID, UUID, UUID)
    TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.finalize_trust_contract_device_removal_v1(UUID, UUID, UUID, JSONB)
    TO mesh_worker;
COMMIT;
