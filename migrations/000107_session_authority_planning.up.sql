-- Session-anchored authority functions join ten or more FORCE RLS tables in
-- one statement. Each call re-planned that join from scratch: about 170 ms and
-- 40 MB of planner memory for a 1 ms execution, so a policy publish, which
-- resolves authority several times, could push a 768 MB database container
-- into the OOM killer.
--
-- Every such statement is written from the Session row found by its unique
-- public ID or digest, then follows unique or narrow indexes. Keeping that
-- written join order and caching one generic plan per backend removes the
-- repeated planning without changing any result, lock or authority check.
-- Any later CREATE OR REPLACE of these functions must restate these settings;
-- the catalog test pins them.

ALTER FUNCTION mesh_ops.approve_policy_approval_request_v1(uuid, uuid, uuid, bigint, bytea, bytea, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint, bytea, text, timestamp with time zone)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.create_policy_approval_request_v1(uuid, uuid, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bytea, integer, bytea, bytea, text, timestamp with time zone, timestamp with time zone)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.issue_oidc_existing_subject_v1(uuid, uuid, uuid, uuid, bigint, bigint, text, text, text, text, text, text, text, text[], text[], text, uuid, bigint, bytea, timestamp with time zone, text, text, text, text, bytea, text, bytea, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint, bigint, timestamp with time zone, timestamp with time zone, uuid, text, text, bytea, text, text, bytea, timestamp with time zone, text, text[], timestamp with time zone, bigint, bigint)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.list_browser_enrollment_networks_v1(uuid, bigint, text, bytea, uuid, integer)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.list_browser_enrollment_networks_v2(uuid, bigint, text, bytea, uuid, uuid, integer)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.list_browser_enrollment_workspaces_v1(uuid, bigint, text, bytea, uuid, integer)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.lock_browser_registration_approval_authority_v1(uuid, bigint, text, bytea, bytea, uuid, text)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.lock_browser_registration_approval_authority_v2(uuid, bigint, text, bytea, bytea, uuid, uuid, text)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.lock_browser_registration_completion_authority_v1(uuid, bigint, bytea, bytea, bytea, bytea, text)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.lock_browser_registration_completion_authority_v2(uuid, bigint, bytea, bytea, bytea, bytea, text)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.lock_policy_approval_for_publication_v1(uuid, timestamp with time zone)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.lock_resource_authority_change_request_v1(uuid)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.logout_account_session_v1(uuid, bigint, text, text, bytea)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.logout_account_session_v2(uuid, bigint, text, text, bytea)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.read_console_deployment_capabilities_v1(uuid, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint, uuid, timestamp with time zone)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.read_console_deployment_capabilities_v2(uuid, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint, uuid, timestamp with time zone)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.read_console_management_scopes_v1(uuid, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint, uuid, timestamp with time zone, uuid, integer)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.read_console_management_scopes_v2(uuid, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint, uuid, timestamp with time zone, uuid, integer)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.read_console_management_scopes_v3(uuid, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint, uuid, timestamp with time zone, uuid, integer)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.read_console_management_scopes_v4(uuid, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint, uuid, timestamp with time zone, uuid, integer)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.rename_owned_workspace_v1(uuid, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint, uuid, bigint, text, uuid)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.require_resource_authority_step_up_v1(uuid, uuid, timestamp with time zone)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.resolve_account_session(text, text, bytea)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.resolve_account_session_v2(uuid, bigint, text, text, bytea)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.resolve_network_permission_v1(uuid, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint, uuid, uuid, text, timestamp with time zone)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.resolve_network_permission_v2(uuid, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint, uuid, uuid, text, timestamp with time zone)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.resolve_oidc_login_subject_v2(uuid, uuid, uuid, bigint, bigint, text, text, text, text, text, text, text, text[], text[], text, uuid, bigint, bytea, timestamp with time zone, text, text, text, text, bytea, text, bytea)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.resolve_workspace_permission_v1(uuid, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint, uuid, text, timestamp with time zone)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.revoke_account_session(text, text, bytea, text)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.switch_account_session_workspace_v1(uuid, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint, uuid, uuid)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
ALTER FUNCTION mesh_ops.touch_account_session_v1(uuid, bigint, uuid, bigint, text, text, bytea)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;
