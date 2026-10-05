BEGIN;

-- Activation: every Device share takes the alias endpoint. Close the earlier
-- runtime entry point, whose same-Workspace branch created direct readiness.
ALTER FUNCTION mesh_ops.activate_resource_share_v4(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) OWNER TO mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.activate_resource_share_v4(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_migrator, mesh_worker, mesh_observer, mesh_audit_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.activate_resource_share_v4(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.activate_resource_share_v3(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) FROM mesh_runtime;

-- Map reader: the Network-based local/remote selection replaces v1.
ALTER FUNCTION mesh_ops.load_device_alias_map_edges_v2(BYTEA,BYTEA,INTEGER) OWNER TO mesh_device_alias_map_reader;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v2(BYTEA,BYTEA,INTEGER) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.load_device_alias_map_edges_v2(BYTEA,BYTEA,INTEGER) FROM PUBLIC,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer,mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.load_device_alias_map_edges_v1(BYTEA,BYTEA,INTEGER) FROM mesh_runtime;

-- Worker: Network-scoped entry points replace the cross-Workspace-only ones.
ALTER FUNCTION mesh_ops.prepare_device_alias_change_v2(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) OWNER TO mesh_device_alias_writer;
ALTER FUNCTION mesh_ops.prepare_device_alias_withdrawal_v2(UUID,UUID,UUID,BIGINT,UUID,TEXT) OWNER TO mesh_device_alias_writer;
ALTER FUNCTION mesh_ops.finalize_device_alias_withdrawal_v2(UUID,UUID,BIGINT,UUID,TEXT,JSONB) OWNER TO mesh_device_alias_writer;
ALTER FUNCTION mesh_ops.prepare_device_alias_resource_quarantine_v2(UUID,UUID,BIGINT,UUID) OWNER TO mesh_device_alias_writer;
ALTER FUNCTION mesh_ops.load_device_alias_work_v2(UUID,UUID,UUID,INTEGER) OWNER TO mesh_device_alias_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.prepare_device_alias_change_v2(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.prepare_device_alias_withdrawal_v2(UUID,UUID,UUID,BIGINT,UUID,TEXT) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.finalize_device_alias_withdrawal_v2(UUID,UUID,BIGINT,UUID,TEXT,JSONB) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.prepare_device_alias_resource_quarantine_v2(UUID,UUID,BIGINT,UUID) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_work_v2(UUID,UUID,UUID,INTEGER) TO mesh_worker;
REVOKE ALL ON FUNCTION mesh_ops.prepare_device_alias_change_v1(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) FROM mesh_worker;
REVOKE ALL ON FUNCTION mesh_ops.prepare_device_alias_withdrawal_v1(UUID,UUID,UUID,BIGINT,UUID,TEXT) FROM mesh_worker;
REVOKE ALL ON FUNCTION mesh_ops.finalize_device_alias_withdrawal_v1(UUID,UUID,BIGINT,UUID,TEXT,JSONB) FROM mesh_worker;
REVOKE ALL ON FUNCTION mesh_ops.prepare_device_alias_resource_quarantine_v1(UUID,UUID,BIGINT,UUID) FROM mesh_worker;
REVOKE ALL ON FUNCTION mesh_ops.load_device_alias_work_v1(UUID,UUID,UUID,INTEGER) FROM mesh_worker;

COMMIT;
