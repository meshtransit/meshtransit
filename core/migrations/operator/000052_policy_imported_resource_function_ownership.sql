-- operator-step: rollout=before
BEGIN;

ALTER FUNCTION mesh_ops.resolve_imported_policy_destinations_v1(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID[], TIMESTAMPTZ
) OWNER TO mesh_share_writer;
ALTER FUNCTION mesh_ops.lock_and_resolve_policy_imported_resources_internal_v1(
    JSONB, TIMESTAMPTZ
) OWNER TO mesh_share_writer;

REVOKE ALL ON FUNCTION mesh_ops.resolve_imported_policy_destinations_v1(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID[], TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.lock_and_resolve_policy_imported_resources_internal_v1(
    JSONB, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.resolve_imported_policy_destinations_v1(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID[], TIMESTAMPTZ
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_and_resolve_policy_imported_resources_internal_v1(
    JSONB, TIMESTAMPTZ
) TO mesh_migrator;

COMMIT;
