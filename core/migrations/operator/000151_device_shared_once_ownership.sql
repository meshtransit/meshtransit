BEGIN;
-- Accepting a share: decide v6 refuses a second live share of one Device into
-- one Network (MT013) after v5's checks.
ALTER FUNCTION mesh_ops.decide_resource_share_offer_v6(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, BIGINT, BYTEA, TEXT,
    UUID, UUID, TEXT, UUID, TEXT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) OWNER TO mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.decide_resource_share_offer_v6(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, BIGINT, BYTEA, TEXT,
    UUID, UUID, TEXT, UUID, TEXT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_migrator, mesh_worker, mesh_observer, mesh_audit_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.decide_resource_share_offer_v6(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, BIGINT, BYTEA, TEXT,
    UUID, UUID, TEXT, UUID, TEXT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) TO mesh_runtime;
-- decide v5 stays executable so the previous image can roll back.
COMMIT;
