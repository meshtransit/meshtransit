BEGIN;

ALTER FUNCTION mesh_ops.list_expired_trust_contracts_v1(UUID, TIMESTAMPTZ, UUID, INTEGER)
    OWNER TO mesh_share_writer;
ALTER FUNCTION mesh_ops.prepare_trust_contract_expiry_v1(UUID, UUID, UUID)
    OWNER TO mesh_share_writer;
ALTER FUNCTION mesh_ops.finalize_trust_contract_expiry_v1(UUID, UUID, UUID, JSONB)
    OWNER TO mesh_share_writer;

REVOKE ALL ON FUNCTION mesh_ops.list_expired_trust_contracts_v1(UUID, TIMESTAMPTZ, UUID, INTEGER)
    FROM PUBLIC, mesh_migrator, mesh_runtime, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.prepare_trust_contract_expiry_v1(UUID, UUID, UUID)
    FROM PUBLIC, mesh_migrator, mesh_runtime, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.finalize_trust_contract_expiry_v1(UUID, UUID, UUID, JSONB)
    FROM PUBLIC, mesh_migrator, mesh_runtime, mesh_observer, mesh_audit_writer;

-- Only the worker role finalizes expiry; runtime callers keep revoke only.
GRANT EXECUTE ON FUNCTION mesh_ops.list_expired_trust_contracts_v1(UUID, TIMESTAMPTZ, UUID, INTEGER)
    TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.prepare_trust_contract_expiry_v1(UUID, UUID, UUID)
    TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.finalize_trust_contract_expiry_v1(UUID, UUID, UUID, JSONB)
    TO mesh_worker;

COMMIT;
