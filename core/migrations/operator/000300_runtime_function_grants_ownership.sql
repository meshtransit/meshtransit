-- operator-step: rollout=before
BEGIN;
-- Role isolation S2.3 (docs/role-isolation-design.md §3.5): mesh_runtime, the api login, holds no function an owner
-- role holds directly any more. The api reaches the ones it calls through mesh_api_rights and control through
-- mesh_control_rights (operator step 000298); versions no role calls are left to no serving role. Rollout before is
-- safe: the previous release runs on its groups alone (role split integration run, S2.1).
REVOKE EXECUTE ON FUNCTION mesh_ops.resolve_imported_policy_destinations_v1(BIGINT,BIGINT,BIGINT,BIGINT,UUID,UUID,UUID,UUID,UUID[],TIMESTAMPTZ) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.activate_resource_share_v2(BIGINT,BIGINT,BIGINT,BIGINT,UUID,BIGINT,BIGINT,BIGINT,UUID,UUID,TIMESTAMPTZ) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.revoke_resource_share_v4(BIGINT,BIGINT,BIGINT,BIGINT,UUID,BIGINT,BIGINT,BIGINT,TIMESTAMPTZ) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.load_direct_share_map_edges_v1(BYTEA,BYTEA,INTEGER) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.observe_device_alias_version_v1(BYTEA,BYTEA,INTEGER) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v1(BYTEA,BYTEA,INTEGER) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.revoke_resource_share_v6(BIGINT,BIGINT,BIGINT,BIGINT,UUID,BIGINT,BIGINT,BIGINT,TIMESTAMPTZ) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.create_resource_share_offer_v2(BIGINT,BIGINT,BIGINT,BIGINT,UUID,UUID,UUID,UUID,UUID,BIGINT,BIGINT,BYTEA,UUID,UUID,JSONB,JSONB,BYTEA,BYTEA,BIGINT,BIGINT,BIGINT,BIGINT,TIMESTAMPTZ,TIMESTAMPTZ) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.decide_resource_share_offer_v3(BIGINT,BIGINT,BIGINT,BIGINT,UUID,UUID,UUID,UUID,UUID,BIGINT,BYTEA,TEXT,UUID,UUID,TEXT,UUID,TEXT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,TIMESTAMPTZ) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.activate_resource_share_v4(BIGINT,BIGINT,BIGINT,BIGINT,UUID,BIGINT,BIGINT,BIGINT,UUID,UUID,TIMESTAMPTZ) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v3(BYTEA,BYTEA,INTEGER) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.create_resource_share_offer_v3(BIGINT,BIGINT,BIGINT,BIGINT,UUID,UUID,UUID,UUID,UUID,BIGINT,BIGINT,BYTEA,UUID,UUID,JSONB,JSONB,BYTEA,BYTEA,BIGINT,BIGINT,BIGINT,BIGINT,TIMESTAMPTZ,TIMESTAMPTZ,TEXT) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.decide_resource_share_offer_v4(BIGINT,BIGINT,BIGINT,BIGINT,UUID,UUID,UUID,UUID,UUID,BIGINT,BYTEA,TEXT,UUID,UUID,TEXT,UUID,TEXT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,TIMESTAMPTZ) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v4(BYTEA,BYTEA,INTEGER) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v2(BYTEA,BYTEA,INTEGER) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v5(BYTEA,BYTEA,INTEGER) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v3(BYTEA,BYTEA,INTEGER) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.decide_resource_share_offer_v5(BIGINT,BIGINT,BIGINT,BIGINT,UUID,UUID,UUID,UUID,UUID,BIGINT,BYTEA,TEXT,UUID,UUID,TEXT,UUID,TEXT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,TIMESTAMPTZ) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.resolve_imported_policy_destinations_v2(BIGINT,BIGINT,BIGINT,BIGINT,UUID,UUID,UUID,UUID,UUID[],TIMESTAMPTZ) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v6(BYTEA,BYTEA,INTEGER) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v4(BYTEA,BYTEA,INTEGER) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.decide_resource_share_offer_v6(BIGINT,BIGINT,BIGINT,BIGINT,UUID,UUID,UUID,UUID,UUID,BIGINT,BYTEA,TEXT,UUID,UUID,TEXT,UUID,TEXT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,TIMESTAMPTZ) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v7(BYTEA,BYTEA,INTEGER) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v5(BYTEA,BYTEA,INTEGER) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v6(BYTEA,BYTEA,INTEGER) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.flowlog_networks_v1(UUID,INTEGER) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.flowlog_destination_v1(UUID,UUID) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.flowlog_revocations_v1(TIMESTAMPTZ) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.flowlog_directory_network_v1(UUID,UUID) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.flowlog_directory_devices_v1(UUID,UUID,UUID,INTEGER) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.flowlog_report_status_v1(BYTEA,INTEGER[],BYTEA[],TEXT[],TIMESTAMPTZ,JSONB) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.flowlog_receiver_gate_v1(INTEGER,BYTEA) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.flowlog_report_status_v2(BYTEA,INTEGER[],BYTEA[],TEXT[],TEXT[],TIMESTAMPTZ,JSONB) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.flowlog_receiver_gate_v2(INTEGER,BYTEA) FROM mesh_runtime;
REVOKE EXECUTE ON FUNCTION mesh_ops.flowlog_destination_v2(UUID,UUID) FROM mesh_runtime;
COMMIT;
