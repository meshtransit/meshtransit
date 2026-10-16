-- operator-step: rollout=before
BEGIN;

ALTER FUNCTION mesh_ops.create_resource_share_offer_v3(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID,
    BIGINT, BIGINT, BYTEA, UUID, UUID, JSONB, JSONB,
    BYTEA, BYTEA, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT
) OWNER TO mesh_share_writer;
ALTER FUNCTION mesh_ops.decide_resource_share_offer_v4(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, BIGINT, BYTEA, TEXT,
    UUID, UUID, TEXT, UUID, TEXT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) OWNER TO mesh_share_writer;

REVOKE ALL ON FUNCTION mesh_ops.create_resource_share_offer_v3(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID,
    BIGINT, BIGINT, BYTEA, UUID, UUID, JSONB, JSONB,
    BYTEA, BYTEA, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT
) FROM PUBLIC, mesh_migrator, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.decide_resource_share_offer_v4(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, BIGINT, BYTEA, TEXT,
    UUID, UUID, TEXT, UUID, TEXT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_migrator, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;

-- create_v2 and decide_v3 stay executable so the previous image can roll
-- back; a later contract step closes them once no supported binary needs them.
GRANT EXECUTE ON FUNCTION mesh_ops.create_resource_share_offer_v3(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID,
    BIGINT, BIGINT, BYTEA, UUID, UUID, JSONB, JSONB,
    BYTEA, BYTEA, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.decide_resource_share_offer_v4(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, BIGINT, BYTEA, TEXT,
    UUID, UUID, TEXT, UUID, TEXT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) TO mesh_runtime;

COMMIT;
