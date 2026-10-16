-- operator-step: rollout=before
BEGIN;
ALTER FUNCTION mesh_ops.load_device_alias_map_edges_v5(BYTEA,BYTEA,INTEGER) OWNER TO mesh_device_alias_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.load_device_alias_map_edges_v5(BYTEA,BYTEA,INTEGER) FROM PUBLIC,mesh_migrator,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer,mesh_direct_map_reader;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v5(BYTEA,BYTEA,INTEGER) TO mesh_runtime;
ALTER FUNCTION mesh_ops.load_device_sharing_dependencies_v3(BYTEA,BYTEA,INTEGER) OWNER TO mesh_device_alias_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.load_device_sharing_dependencies_v3(BYTEA,BYTEA,INTEGER) FROM PUBLIC,mesh_migrator,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer,mesh_direct_map_reader;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v3(BYTEA,BYTEA,INTEGER) TO mesh_runtime;
-- The alias worker: prepare v3 reserves up to 10000 consumer Devices per
-- endpoint and checks readiness through the one-endpoint reader, which only
-- the alias writer (prepare v3's owner) may run.
ALTER FUNCTION mesh_ops.load_device_alias_map_endpoint_edges_v1(BYTEA,BYTEA,UUID) OWNER TO mesh_device_alias_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.load_device_alias_map_endpoint_edges_v1(BYTEA,BYTEA,UUID) FROM PUBLIC,mesh_migrator,mesh_runtime,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer,mesh_direct_map_reader;
ALTER FUNCTION mesh_ops.prepare_device_alias_change_v3(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) OWNER TO mesh_device_alias_writer;
REVOKE ALL ON FUNCTION mesh_ops.prepare_device_alias_change_v3(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) FROM PUBLIC,mesh_migrator,mesh_runtime,mesh_observer,mesh_audit_writer,mesh_share_writer,mesh_direct_map_reader;
GRANT EXECUTE ON FUNCTION mesh_ops.prepare_device_alias_change_v3(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) TO mesh_worker;
-- Accepting a share: decide v5 checks the share limits before v4.
ALTER FUNCTION mesh_ops.decide_resource_share_offer_v5(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, BIGINT, BYTEA, TEXT,
    UUID, UUID, TEXT, UUID, TEXT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) OWNER TO mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.decide_resource_share_offer_v5(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, BIGINT, BYTEA, TEXT,
    UUID, UUID, TEXT, UUID, TEXT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_migrator, mesh_worker, mesh_observer, mesh_audit_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.decide_resource_share_offer_v5(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, BIGINT, BYTEA, TEXT,
    UUID, UUID, TEXT, UUID, TEXT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) TO mesh_runtime;
-- The v4 alias reader, v2 readers, decide v4 and prepare v2 stay executable
-- so the previous image can roll back; a later contract step closes them once
-- no supported binary calls them.
COMMIT;
