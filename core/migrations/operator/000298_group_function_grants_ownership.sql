-- operator-step: rollout=before
BEGIN;
-- Role isolation S2.2 (docs/role-isolation-design.md §3.5): the functions an owner role holds, which the migrator
-- cannot grant, reach the group roles of the roles that call them (core/migrations/role_grants.json), exactly as
-- mesh_runtime holds them today. mesh_runtime keeps its own grants until step S2.3; versions no role calls any
-- more stay with mesh_runtime only. Additive: nothing is revoked.
GRANT EXECUTE ON FUNCTION mesh_ops.resolve_imported_policy_destinations_v1(BIGINT,BIGINT,BIGINT,BIGINT,UUID,UUID,UUID,UUID,UUID[],TIMESTAMPTZ) TO mesh_api_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.load_direct_share_map_edges_v1(BYTEA,BYTEA,INTEGER) TO mesh_api_rights,mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.observe_device_alias_version_v1(BYTEA,BYTEA,INTEGER) TO mesh_api_rights,mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v1(BYTEA,BYTEA,INTEGER) TO mesh_api_rights,mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.revoke_resource_share_v6(BIGINT,BIGINT,BIGINT,BIGINT,UUID,BIGINT,BIGINT,BIGINT,TIMESTAMPTZ) TO mesh_api_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.activate_resource_share_v4(BIGINT,BIGINT,BIGINT,BIGINT,UUID,BIGINT,BIGINT,BIGINT,UUID,UUID,TIMESTAMPTZ) TO mesh_api_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v3(BYTEA,BYTEA,INTEGER) TO mesh_api_rights,mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.create_resource_share_offer_v3(BIGINT,BIGINT,BIGINT,BIGINT,UUID,UUID,UUID,UUID,UUID,BIGINT,BIGINT,BYTEA,UUID,UUID,JSONB,JSONB,BYTEA,BYTEA,BIGINT,BIGINT,BIGINT,BIGINT,TIMESTAMPTZ,TIMESTAMPTZ,TEXT) TO mesh_api_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.decide_resource_share_offer_v4(BIGINT,BIGINT,BIGINT,BIGINT,UUID,UUID,UUID,UUID,UUID,BIGINT,BYTEA,TEXT,UUID,UUID,TEXT,UUID,TEXT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,TIMESTAMPTZ) TO mesh_api_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v4(BYTEA,BYTEA,INTEGER) TO mesh_api_rights,mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v2(BYTEA,BYTEA,INTEGER) TO mesh_api_rights,mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v5(BYTEA,BYTEA,INTEGER) TO mesh_api_rights,mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v3(BYTEA,BYTEA,INTEGER) TO mesh_api_rights,mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.decide_resource_share_offer_v5(BIGINT,BIGINT,BIGINT,BIGINT,UUID,UUID,UUID,UUID,UUID,BIGINT,BYTEA,TEXT,UUID,UUID,TEXT,UUID,TEXT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,TIMESTAMPTZ) TO mesh_api_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.resolve_imported_policy_destinations_v2(BIGINT,BIGINT,BIGINT,BIGINT,UUID,UUID,UUID,UUID,UUID[],TIMESTAMPTZ) TO mesh_api_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v6(BYTEA,BYTEA,INTEGER) TO mesh_api_rights,mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v4(BYTEA,BYTEA,INTEGER) TO mesh_api_rights,mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.decide_resource_share_offer_v6(BIGINT,BIGINT,BIGINT,BIGINT,UUID,UUID,UUID,UUID,UUID,BIGINT,BYTEA,TEXT,UUID,UUID,TEXT,UUID,TEXT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,TIMESTAMPTZ) TO mesh_api_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v7(BYTEA,BYTEA,INTEGER) TO mesh_api_rights,mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v5(BYTEA,BYTEA,INTEGER) TO mesh_api_rights,mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v6(BYTEA,BYTEA,INTEGER) TO mesh_api_rights,mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.flowlog_networks_v1(UUID,INTEGER) TO mesh_api_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.flowlog_revocations_v1(TIMESTAMPTZ) TO mesh_api_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.flowlog_directory_network_v1(UUID,UUID) TO mesh_api_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.flowlog_directory_devices_v1(UUID,UUID,UUID,INTEGER) TO mesh_api_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.flowlog_report_status_v2(BYTEA,INTEGER[],BYTEA[],TEXT[],TEXT[],TIMESTAMPTZ,JSONB) TO mesh_api_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.flowlog_receiver_gate_v2(INTEGER,BYTEA) TO mesh_control_rights;
GRANT EXECUTE ON FUNCTION mesh_ops.flowlog_destination_v2(UUID,UUID) TO mesh_api_rights;
COMMIT;
