BEGIN;

ALTER FUNCTION mesh_ops.resolve_imported_policy_destinations_v2(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID[], TIMESTAMPTZ
) OWNER TO mesh_share_writer;
ALTER FUNCTION mesh_ops.lock_and_resolve_policy_imported_resources_internal_v2(
    JSONB, TIMESTAMPTZ
) OWNER TO mesh_share_writer;

REVOKE ALL ON FUNCTION mesh_ops.resolve_imported_policy_destinations_v2(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID[], TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.lock_and_resolve_policy_imported_resources_internal_v2(
    JSONB, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.resolve_imported_policy_destinations_v2(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID[], TIMESTAMPTZ
) TO mesh_runtime;
-- publish_compiled_policy_v2 (owned by the migrator) calls it.
GRANT EXECUTE ON FUNCTION mesh_ops.lock_and_resolve_policy_imported_resources_internal_v2(
    JSONB, TIMESTAMPTZ
) TO mesh_migrator;
-- The v1 chain stays executable so the previous image can roll back; a later
-- contract step closes it once no supported binary calls it.

COMMIT;
