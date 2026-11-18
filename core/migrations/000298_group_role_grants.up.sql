-- Schema 298: role isolation step S2.2 (docs/role-isolation-design.md §3.5, TD-SEC-90).
--
-- The group roles mesh_api_rights and mesh_control_rights (release N0) receive what their role uses, taken from
-- what mesh_runtime holds today and never more:
--   * the functions and tables of core/migrations/role_grants.json for the api and for control (as of this schema),
--     each EXECUTE, table and column privilege copied from mesh_runtime's own ACL entries (aclexplode), so overloads
--     and column grants carry over exactly and nothing mesh_runtime lacks is granted;
--   * what PostgreSQL itself needs when a group member runs those statements as itself: functions and tables named in
--     the row-level security policies of those tables, the bodies of SECURITY INVOKER functions and triggers that run
--     as the caller, column defaults (sequences and functions), CHECK constraints and security_invoker views;
--   * USAGE on the three schemas and CONNECT/TEMPORARY on the database, as mesh_runtime holds them.
-- Functions an owner role holds, or an operator step hands to one, are granted by operator step 000298 once every
-- earlier step ran; this migration only counts them. mesh_runtime keeps every grant: the logins are still members of it (S2.2 is additive), and S2.3
-- takes its direct grants away once the per-login evidence agrees.
--
-- Expand only: images before 298 do not know the groups' grants and keep working through mesh_runtime.

DO $grants$
DECLARE
    v_source OID := (SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = 'mesh_runtime');
    v_group TEXT;
    v_functions TEXT[];
    v_relations TEXT[];
    -- Work lists: functions (oid) and relation privileges ('oid:TYPE').
    v_function_queue OID[];
    v_function_seen OID[];
    v_relation_queue TEXT[];
    v_relation_seen TEXT[];
    v_function OID;
    v_entry TEXT;
    v_relation OID;
    v_type TEXT;
    v_reference RECORD;
    v_granted INTEGER;
    v_owner_held INTEGER;
    v_foreign INTEGER;
    v_missing TEXT[];
    v_overloads OID[];
    v_body TEXT;
    v_name TEXT;
    -- The function families an operator step hands to an owner role (operator_roles.go): the operator command
    -- grants them (step 000298) once every earlier step ran, since a later step may still take one away from
    -- mesh_runtime. This migration grants none of them, whoever owns them now.
    v_operator_families TEXT[] := ARRAY[
        'activate_resource_share', 'assert_private_endpoint_scope_internal', 'create_resource_share_offer',
        'decide_resource_share_offer', 'decide_resource_share_offer_base', 'derive_device_alias_worker_scope',
        'device_alias_change_proof_internal', 'device_alias_withdrawal_proof_internal',
        'finalize_device_alias_change', 'finalize_device_alias_withdrawal',
        'finalize_trust_contract_device_removal', 'finalize_trust_contract_expiry', 'flowlog_destination',
        'flowlog_directory_devices', 'flowlog_directory_network', 'flowlog_networks', 'flowlog_receiver_gate',
        'flowlog_report_status', 'flowlog_revocations', 'list_expired_trust_contracts',
        'list_trust_contract_device_removals', 'load_device_alias_map_edges',
        'load_device_alias_map_endpoint_edges', 'load_device_alias_work', 'load_device_sharing_dependencies',
        'load_direct_share_map_edges', 'lock_and_resolve_policy_imported_resources_internal',
        'network_connection_log_status_internal', 'observe_device_alias_version', 'prepare_device_alias_change',
        'prepare_device_alias_resource_quarantine', 'prepare_device_alias_withdrawal',
        'prepare_trust_contract_device_removal', 'prepare_trust_contract_expiry', 'prune_audit_rows',
        'prune_idempotency_records', 'prune_outbox_events', 'read_compiled_imported_policy_evidence_internal',
        'resolve_imported_policy_destinations', 'restore_device_alias_worker_context', 'revoke_resource_share',
        'save_device_alias_worker_context', 'set_share_scope', 'withdraw_direct_device_endpoint_on_contract_end'
    ]::TEXT[];
BEGIN
    -- Names below print schema-qualified.
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog', TRUE);
    IF v_source IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42704', MESSAGE = 'mesh_runtime is missing';
    END IF;
    FOR v_group, v_functions, v_relations IN
        SELECT 'mesh_api_rights', ARRAY[
        'mesh_audit.append_authority_evidence', 'mesh_audit.lock_deployment_stream_head',
        'mesh_audit.lock_network_stream_head', 'mesh_audit.lock_workspace_network_stream_head_v1',
        'mesh_audit.lock_workspace_stream_head', 'mesh_ops.accept_mtcp_timestamp_v2',
        'mesh_ops.accept_mtcp_timestamp_v3', 'mesh_ops.accept_mtcp_timestamp_v4',
        'mesh_ops.accept_workspace_invitation_v2', 'mesh_ops.acknowledge_browser_move_v1',
        'mesh_ops.activate_resource_share_v4', 'mesh_ops.active_release_imported_paths_v1',
        'mesh_ops.active_workspace_guardrails_v1', 'mesh_ops.active_workspace_guardrails_v2',
        'mesh_ops.add_network_members_v1', 'mesh_ops.add_share_offer_service_names_v1',
        'mesh_ops.admit_oidc_login_route_v2', 'mesh_ops.advance_network_inventory_revision',
        'mesh_ops.append_device_captive_window_evidence_v1',
        'mesh_ops.append_kubernetes_gateway_group_event_evidence_v1',
        'mesh_ops.append_kubernetes_gateway_key_event_evidence_v1',
        'mesh_ops.approve_kubernetes_replica_request_v2', 'mesh_ops.approve_policy_approval_request_v1',
        'mesh_ops.assign_workspace_role_v1', 'mesh_ops.attach_policy_exit_rules_v1',
        'mesh_ops.attach_policy_group_rules_v2', 'mesh_ops.attach_policy_group_rules_v3',
        'mesh_ops.attach_policy_group_rules_v4', 'mesh_ops.attach_policy_kubernetes_profiles_v2',
        'mesh_ops.attach_policy_resource_destinations', 'mesh_ops.attach_policy_resource_group_destinations',
        'mesh_ops.attach_policy_route_rules_v1', 'mesh_ops.begin_kubernetes_operation_export_v1',
        'mesh_ops.browser_sibling_conflict_v1', 'mesh_ops.bump_guardrail_share_networks_v2',
        'mesh_ops.change_device_group_members_v1', 'mesh_ops.change_device_group_v1',
        'mesh_ops.change_device_lifecycle_v1', 'mesh_ops.change_device_tag_v2', 'mesh_ops.change_device_tags_v2',
        'mesh_ops.change_dns_names_v2', 'mesh_ops.change_dns_setting_v1', 'mesh_ops.change_dns_zone_v2',
        'mesh_ops.change_exit_node_v3', 'mesh_ops.change_exit_pool_v3',
        'mesh_ops.change_identity_group_members_v2', 'mesh_ops.change_identity_group_v2',
        'mesh_ops.change_site_router_v1', 'mesh_ops.change_site_v1', 'mesh_ops.change_workspace_guardrail_v2',
        'mesh_ops.change_workspace_invitation_v1', 'mesh_ops.change_workspace_member_v1',
        'mesh_ops.change_workspace_private_interchange_v1', 'mesh_ops.claim_network_idempotency',
        'mesh_ops.claim_oidc_browser_v2', 'mesh_ops.commit_mtcp_gateway_timestamp_v1',
        'mesh_ops.commit_mtcp_gateway_timestamp_v2', 'mesh_ops.commit_mtcp_gateway_timestamp_v3',
        'mesh_ops.complete_network_idempotency', 'mesh_ops.confirm_resource_authority_change_v1',
        'mesh_ops.consume_policy_approval_for_publication_v1', 'mesh_ops.create_device_resource_v1',
        'mesh_ops.create_kubernetes_cluster_v1', 'mesh_ops.create_network_v2',
        'mesh_ops.create_oidc_auth_transaction_v2', 'mesh_ops.create_policy_approval_request_v1',
        'mesh_ops.create_resource_group_v1', 'mesh_ops.create_resource_share_offer_v3',
        'mesh_ops.create_workspace_v1', 'mesh_ops.current_network_id', 'mesh_ops.current_workspace_id',
        'mesh_ops.decide_resource_share_offer_v4', 'mesh_ops.decide_resource_share_offer_v5',
        'mesh_ops.decide_resource_share_offer_v6', 'mesh_ops.defer_dns_change_wakeup_v1',
        'mesh_ops.delete_kubernetes_cluster_v1', 'mesh_ops.delete_network_v1',
        'mesh_ops.delete_storage_credential_v1', 'mesh_ops.device_actor_within_ceiling_v1',
        'mesh_ops.dns_zone_receivers_v1', 'mesh_ops.ensure_kubernetes_cluster_policy_group_v1',
        'mesh_ops.explain_active_policy_v4', 'mesh_ops.explain_address_access_v1',
        'mesh_ops.export_workspace_audit_events_v1', 'mesh_ops.extend_device_v1', 'mesh_ops.fail_oidc_browser_v2',
        'mesh_ops.find_dns_zone_for_name_v1', 'mesh_ops.flowlog_destination_v2',
        'mesh_ops.flowlog_directory_devices_v1', 'mesh_ops.flowlog_directory_network_v1',
        'mesh_ops.flowlog_networks_v1', 'mesh_ops.flowlog_report_status_v2', 'mesh_ops.flowlog_revocations_v1',
        'mesh_ops.guardrail_change_share_contracts_v2', 'mesh_ops.imported_resource_provider_guardrails_v1',
        'mesh_ops.issue_browser_registration_intent_v1', 'mesh_ops.issue_enrollment_key_v1',
        'mesh_ops.issue_kubernetes_join_key_v1', 'mesh_ops.issue_oidc_existing_subject_v1',
        'mesh_ops.join_browser_existing_device_v1', 'mesh_ops.kubernetes_cluster_can_approve_v1',
        'mesh_ops.kubernetes_operation_denial_counts_v1', 'mesh_ops.kubernetes_profile_denials_v1',
        'mesh_ops.list_browser_enrollment_networks_v1', 'mesh_ops.list_browser_enrollment_networks_v2',
        'mesh_ops.list_browser_enrollment_workspaces_v1', 'mesh_ops.list_device_groups_v1',
        'mesh_ops.list_device_tags_v2', 'mesh_ops.list_dns_names_v2', 'mesh_ops.list_dns_zones_v2',
        'mesh_ops.list_enrollment_keys_v1', 'mesh_ops.list_exit_pool_primary_changes_v1',
        'mesh_ops.list_exit_pool_serving_changes_v1', 'mesh_ops.list_exit_pools_v3',
        'mesh_ops.list_guardrail_share_contracts_v2', 'mesh_ops.list_identity_groups_v2',
        'mesh_ops.list_kubernetes_ca_retire_requests_v1', 'mesh_ops.list_kubernetes_cluster_cas_v1',
        'mesh_ops.list_kubernetes_cluster_ceilings_v1', 'mesh_ops.list_kubernetes_cluster_replicas_v3',
        'mesh_ops.list_kubernetes_clusters_v1', 'mesh_ops.list_kubernetes_join_keys_v1',
        'mesh_ops.list_kubernetes_operation_export_v1', 'mesh_ops.list_kubernetes_operations_v1',
        'mesh_ops.list_kubernetes_replica_requests_v1', 'mesh_ops.list_network_members_v1',
        'mesh_ops.list_policy_approval_requests_management_v1', 'mesh_ops.list_resource_groups_v1',
        'mesh_ops.list_resources_v1', 'mesh_ops.list_session_workspaces_v1',
        'mesh_ops.list_share_offer_service_names_v1', 'mesh_ops.list_site_primary_changes_v1',
        'mesh_ops.list_sites_v1', 'mesh_ops.list_storage_credentials_v2',
        'mesh_ops.list_workspace_audit_events_v1', 'mesh_ops.list_workspace_guardrails_v1',
        'mesh_ops.list_workspace_invitations_v1', 'mesh_ops.list_workspace_members_v1',
        'mesh_ops.list_workspace_private_interchanges_v1', 'mesh_ops.load_device_alias_map_edges_v3',
        'mesh_ops.load_device_alias_map_edges_v4', 'mesh_ops.load_device_alias_map_edges_v5',
        'mesh_ops.load_device_alias_map_edges_v6', 'mesh_ops.load_device_alias_map_edges_v7',
        'mesh_ops.load_device_sharing_dependencies_v1', 'mesh_ops.load_device_sharing_dependencies_v2',
        'mesh_ops.load_device_sharing_dependencies_v3', 'mesh_ops.load_device_sharing_dependencies_v4',
        'mesh_ops.load_device_sharing_dependencies_v5', 'mesh_ops.load_device_sharing_dependencies_v6',
        'mesh_ops.load_direct_share_map_edges_v1', 'mesh_ops.load_map_kubernetes_ca_roots_v1',
        'mesh_ops.load_map_network_device_changes_v1', 'mesh_ops.load_map_network_devices_v1',
        'mesh_ops.load_map_network_dns_names_v1', 'mesh_ops.load_map_network_dns_names_v2',
        'mesh_ops.load_map_network_dns_resolvers_v1', 'mesh_ops.load_map_network_dns_unmanaged_v1',
        'mesh_ops.load_map_network_dns_zones_v1', 'mesh_ops.load_map_network_dns_zones_v2',
        'mesh_ops.load_map_network_exit_nodes_v1', 'mesh_ops.load_map_network_exit_pool_captive_v1',
        'mesh_ops.load_map_network_exit_pools_v1', 'mesh_ops.load_map_network_exit_pools_v2',
        'mesh_ops.load_map_network_exit_rules_v1', 'mesh_ops.load_map_network_header_v1',
        'mesh_ops.load_map_network_kubernetes_cas_v1', 'mesh_ops.load_map_network_kubernetes_cas_v2',
        'mesh_ops.load_map_network_kubernetes_contacts_v1', 'mesh_ops.load_map_network_kubernetes_gateways_v1',
        'mesh_ops.load_map_network_kubernetes_profiles_v1', 'mesh_ops.load_map_network_kubernetes_rule_access_v1',
        'mesh_ops.load_map_network_kubernetes_rule_groups_v1', 'mesh_ops.load_map_network_kubernetes_sources_v1',
        'mesh_ops.load_map_network_policy_devices_v1', 'mesh_ops.load_map_network_policy_rules_v1',
        'mesh_ops.load_map_network_route_rules_v1', 'mesh_ops.load_map_network_selector_members_v1',
        'mesh_ops.load_map_network_site_routers_v1', 'mesh_ops.load_map_network_sites_v1',
        'mesh_ops.load_map_network_sites_v2', 'mesh_ops.load_map_network_sites_v3',
        'mesh_ops.load_map_peer_candidates_v2', 'mesh_ops.load_network_idempotency',
        'mesh_ops.load_oidc_auth_transaction_creation_v1', 'mesh_ops.load_oidc_pending_browser_v2',
        'mesh_ops.load_policy_approval_evidence_v1', 'mesh_ops.load_policy_approval_request_v1',
        'mesh_ops.lock_active_network_revision_v1', 'mesh_ops.lock_active_policy_release',
        'mesh_ops.lock_browser_registration_approval_authority_v1',
        'mesh_ops.lock_browser_registration_approval_authority_v2', 'mesh_ops.lock_device_resource_rebind_v1',
        'mesh_ops.lock_device_revocation_target_v1', 'mesh_ops.lock_kubernetes_join_key_v1',
        'mesh_ops.lock_kubernetes_replica_request_v2', 'mesh_ops.lock_network_revision',
        'mesh_ops.lock_policy_approval_for_publication_v1', 'mesh_ops.lock_policy_approval_request_v1',
        'mesh_ops.lock_registration_credential', 'mesh_ops.lock_resource_authority_change_request_v1',
        'mesh_ops.lock_resource_authority_change_v1', 'mesh_ops.lock_resource_group_authority_change_v1',
        'mesh_ops.lock_resource_group_replace_v1', 'mesh_ops.logout_account_session_v2',
        'mesh_ops.logout_all_account_sessions_v1', 'mesh_ops.lookup_browser_move_source_v1',
        'mesh_ops.lookup_browser_sibling_devices_v1', 'mesh_ops.map_network_has_direct_endpoints_v1',
        'mesh_ops.map_network_sharing_devices_v1', 'mesh_ops.map_session_revoked_v2',
        'mesh_ops.map_session_suspended_v1', 'mesh_ops.map_share_guardrails_v2', 'mesh_ops.mark_session_proven_v1',
        'mesh_ops.minimize_browser_intent_siblings_v1', 'mesh_ops.observe_device_alias_version_v1',
        'mesh_ops.open_kubernetes_replica_request_v2', 'mesh_ops.preview_device_resource_rebind_v1',
        'mesh_ops.preview_resource_authority_change_v1', 'mesh_ops.preview_resource_group_authority_change_v1',
        'mesh_ops.preview_resource_group_replace_v1', 'mesh_ops.preview_workspace_invitation_v1',
        'mesh_ops.publish_compiled_policy', 'mesh_ops.publish_compiled_policy_v2',
        'mesh_ops.put_storage_credential_v2', 'mesh_ops.ratchet_kubernetes_gateway_token_v1',
        'mesh_ops.read_access_graph_history_v3', 'mesh_ops.read_access_graph_v4', 'mesh_ops.read_active_policy_v4',
        'mesh_ops.read_browser_registration_followup_v1', 'mesh_ops.read_browser_registration_landing_v1',
        'mesh_ops.read_connection_log_ticket_v2', 'mesh_ops.read_console_deployment_capabilities_v2',
        'mesh_ops.read_console_device_names_v1', 'mesh_ops.read_console_device_v6',
        'mesh_ops.read_console_devices_v7', 'mesh_ops.read_console_management_scopes_v4',
        'mesh_ops.read_console_network_summaries_v1', 'mesh_ops.read_console_network_summary_v1',
        'mesh_ops.read_console_workspace_overview_v1', 'mesh_ops.read_contract_service_names_v1',
        'mesh_ops.read_current_deployment_entitlement_v1', 'mesh_ops.read_device_distribution_target_v1',
        'mesh_ops.read_device_enforcement_history_v1', 'mesh_ops.read_device_group_members_v1',
        'mesh_ops.read_dns_name_v2', 'mesh_ops.read_dns_setting_v1', 'mesh_ops.read_dns_zone_v2',
        'mesh_ops.read_exit_pool_v4', 'mesh_ops.read_identity_group_members_v2',
        'mesh_ops.read_kubernetes_access_settings_v1', 'mesh_ops.read_kubernetes_audit_settings_v1',
        'mesh_ops.read_kubernetes_cluster_approver_additions_v1', 'mesh_ops.read_kubernetes_cluster_ca_v1',
        'mesh_ops.read_kubernetes_cluster_ceiling_v1', 'mesh_ops.read_kubernetes_cluster_explain_replica_v1',
        'mesh_ops.read_kubernetes_cluster_policy_groups_v1', 'mesh_ops.read_kubernetes_cluster_replica_v3',
        'mesh_ops.read_kubernetes_cluster_signing_v2', 'mesh_ops.read_kubernetes_cluster_v2',
        'mesh_ops.read_kubernetes_gateway_ratchet_suspension_v1',
        'mesh_ops.read_kubernetes_gateway_rotation_trust_v1', 'mesh_ops.read_kubernetes_join_key_v1',
        'mesh_ops.read_kubernetes_operation_v1', 'mesh_ops.read_kubernetes_replica_request_v1',
        'mesh_ops.read_map_inventory_change_head_v1', 'mesh_ops.read_map_self_identity_v1',
        'mesh_ops.read_map_self_identity_v2', 'mesh_ops.read_network_address_usage_v1',
        'mesh_ops.read_network_alias_ranges_v1', 'mesh_ops.read_network_connection_log_v3',
        'mesh_ops.read_network_device_lifetime_v1', 'mesh_ops.read_network_device_tags_v1',
        'mesh_ops.read_network_revision_v1', 'mesh_ops.read_network_tag_options_v2', 'mesh_ops.read_network_v1',
        'mesh_ops.read_policy_approval_request_management_v1', 'mesh_ops.read_policy_exit_pools_v1',
        'mesh_ops.read_policy_kubernetes_access_v2', 'mesh_ops.read_policy_release_rule_fingerprints_v1',
        'mesh_ops.read_policy_simulation_baseline_v6', 'mesh_ops.read_policy_sites_v1',
        'mesh_ops.read_resource_group_v2', 'mesh_ops.read_resource_v2', 'mesh_ops.read_scope_display_codes_v1',
        'mesh_ops.read_scope_workspace_name_v1', 'mesh_ops.read_share_offer_access_name_v1',
        'mesh_ops.read_share_offer_display_codes_v1', 'mesh_ops.read_site_v2',
        'mesh_ops.rebind_device_resource_v1', 'mesh_ops.record_account_verified_email_v1',
        'mesh_ops.record_browser_intent_siblings_v1', 'mesh_ops.record_browser_registration_approval_v1',
        'mesh_ops.record_browser_registration_approval_v2', 'mesh_ops.record_deployment_entitlement_v1',
        'mesh_ops.record_device_captive_window_v1', 'mesh_ops.record_kubernetes_gateway_ceiling_v1',
        'mesh_ops.record_kubernetes_gateway_group_report_v1', 'mesh_ops.record_kubernetes_gateway_key_event_v3',
        'mesh_ops.record_kubernetes_join_code_failure_v2', 'mesh_ops.record_policy_release_rule_fingerprints_v1',
        'mesh_ops.reject_kubernetes_replica_request_v1', 'mesh_ops.remove_network_member_v1',
        'mesh_ops.remove_workspace_member_v1', 'mesh_ops.rename_owned_workspace_v1',
        'mesh_ops.replace_contract_service_names_v1', 'mesh_ops.replace_kubernetes_access_settings_v1',
        'mesh_ops.replace_kubernetes_audit_settings_v1', 'mesh_ops.replace_kubernetes_cluster_signing_trust_v1',
        'mesh_ops.replace_network_connection_log_v2', 'mesh_ops.replace_resource_group_definition_v1',
        'mesh_ops.report_device_exit_offer_v2', 'mesh_ops.report_device_route_offer_v2',
        'mesh_ops.request_kubernetes_ca_retire_v1', 'mesh_ops.request_resource_authority_change_v1',
        'mesh_ops.resolve_account_session_v2', 'mesh_ops.resolve_group_policy_edges_v1',
        'mesh_ops.resolve_imported_policy_destinations_v1', 'mesh_ops.resolve_imported_policy_destinations_v2',
        'mesh_ops.resolve_kubernetes_join_scope_v1', 'mesh_ops.resolve_map_session_scope',
        'mesh_ops.resolve_network_permission_v2', 'mesh_ops.resolve_oidc_login_subject_v2',
        'mesh_ops.resolve_registration_intake_scope', 'mesh_ops.resolve_share_target_v1',
        'mesh_ops.resume_kubernetes_gateway_token_ratchet_v1', 'mesh_ops.revoke_device_v2',
        'mesh_ops.revoke_enrollment_key_v1', 'mesh_ops.revoke_kubernetes_join_key_v1',
        'mesh_ops.revoke_resource_share_v6', 'mesh_ops.revoke_workspace_member_sessions_v1',
        'mesh_ops.revoke_workspace_role_v1', 'mesh_ops.rotate_kubernetes_gateway_machine_key_v2',
        'mesh_ops.set_network_alias_ranges_v1', 'mesh_ops.set_network_device_lifetime_v1',
        'mesh_ops.set_network_scope', 'mesh_ops.share_offer_provider_guardrails_v1', 'mesh_ops.sign_up_account_v1',
        'mesh_ops.suspend_kubernetes_gateway_token_ratchet_v1', 'mesh_ops.switch_account_session_workspace_v1',
        'mesh_ops.touch_account_session_v1', 'mesh_ops.transition_resource_group_lifecycle_v1',
        'mesh_ops.transition_resource_lifecycle_v1', 'mesh_ops.wake_guardrail_share_networks_v1'
    ]::TEXT[],
            ARRAY[
        'mesh.compiled_policy_rule:SELECT', 'mesh.device:SELECT', 'mesh.device_dns_label:SELECT',
        'mesh.device_machine_key_epoch:SELECT', 'mesh.device_node_key_epoch:SELECT',
        'mesh.enrollment_credential:SELECT', 'mesh.enrollment_profile:SELECT', 'mesh.imported_resource:SELECT',
        'mesh.imported_resource_access_name:SELECT', 'mesh.network:SELECT', 'mesh.node_address_lease:SELECT',
        'mesh.pending_registration:SELECT', 'mesh.policy_approval_evidence:SELECT',
        'mesh.policy_approval_request:SELECT', 'mesh.policy_release:SELECT', 'mesh.resource_export:SELECT',
        'mesh.resource_export_constraint:SELECT', 'mesh.share_offer:SELECT', 'mesh.share_offer_locator:SELECT',
        'mesh.trust_contract:SELECT', 'mesh_ops.network_revision:SELECT', 'mesh_ops.schema_compatibility:SELECT',
        'mesh_ops.schema_migration:SELECT', 'mesh.pending_registration:INSERT', 'mesh.pending_registration:UPDATE',
        'mesh.enrollment_profile:UPDATE'
    ]::TEXT[]
        UNION ALL
        SELECT 'mesh_control_rights', ARRAY[
        'mesh_audit.append_authority_evidence', 'mesh_audit.lock_deployment_stream_head',
        'mesh_audit.lock_network_stream_head', 'mesh_ops.abandon_kubernetes_gateway_certificate_v1',
        'mesh_ops.accept_mtcp_timestamp_v2', 'mesh_ops.accept_mtcp_timestamp_v3',
        'mesh_ops.accept_mtcp_timestamp_v4', 'mesh_ops.admit_oidc_login_route_v2',
        'mesh_ops.advance_network_inventory_revision', 'mesh_ops.append_device_captive_window_evidence_v1',
        'mesh_ops.append_kubernetes_gateway_group_event_evidence_v1',
        'mesh_ops.append_kubernetes_gateway_key_event_evidence_v1',
        'mesh_ops.approve_kubernetes_replica_request_v2', 'mesh_ops.begin_kubernetes_operation_export_v1',
        'mesh_ops.browser_device_moved_v1', 'mesh_ops.browser_sibling_conflict_v1',
        'mesh_ops.clear_browser_intent_siblings_v1', 'mesh_ops.commit_mtcp_gateway_timestamp_v1',
        'mesh_ops.commit_mtcp_gateway_timestamp_v2', 'mesh_ops.commit_mtcp_gateway_timestamp_v3',
        'mesh_ops.complete_browser_registration_intent_v1', 'mesh_ops.complete_kubernetes_replica_request_v1',
        'mesh_ops.consume_kubernetes_gateway_rotation_token_v1', 'mesh_ops.create_kubernetes_cluster_v1',
        'mesh_ops.current_network_id', 'mesh_ops.current_workspace_id', 'mesh_ops.delete_kubernetes_cluster_v1',
        'mesh_ops.enqueue_kubernetes_gateway_certificate_v1', 'mesh_ops.ensure_kubernetes_cluster_policy_group_v1',
        'mesh_ops.finalize_browser_move_v1', 'mesh_ops.flowlog_receiver_gate_v2',
        'mesh_ops.insert_kubernetes_gateway_device_v1', 'mesh_ops.issue_browser_registration_intent_v1',
        'mesh_ops.issue_kubernetes_join_key_v1', 'mesh_ops.kubernetes_cluster_can_approve_v1',
        'mesh_ops.kubernetes_cluster_policy_group_evidence_v1', 'mesh_ops.kubernetes_operation_denial_counts_v1',
        'mesh_ops.kubernetes_profile_denials_v1', 'mesh_ops.list_kubernetes_ca_retire_requests_v1',
        'mesh_ops.list_kubernetes_cluster_cas_v1', 'mesh_ops.list_kubernetes_cluster_ceilings_v1',
        'mesh_ops.list_kubernetes_cluster_replicas_v3', 'mesh_ops.list_kubernetes_clusters_v1',
        'mesh_ops.list_kubernetes_join_keys_v1', 'mesh_ops.list_kubernetes_operation_export_v1',
        'mesh_ops.list_kubernetes_operations_v1', 'mesh_ops.list_kubernetes_replica_requests_v1',
        'mesh_ops.load_device_alias_map_edges_v3', 'mesh_ops.load_device_alias_map_edges_v4',
        'mesh_ops.load_device_alias_map_edges_v5', 'mesh_ops.load_device_alias_map_edges_v6',
        'mesh_ops.load_device_alias_map_edges_v7', 'mesh_ops.load_device_sharing_dependencies_v1',
        'mesh_ops.load_device_sharing_dependencies_v2', 'mesh_ops.load_device_sharing_dependencies_v3',
        'mesh_ops.load_device_sharing_dependencies_v4', 'mesh_ops.load_device_sharing_dependencies_v5',
        'mesh_ops.load_device_sharing_dependencies_v6', 'mesh_ops.load_direct_share_map_edges_v1',
        'mesh_ops.load_map_kubernetes_ca_roots_v1', 'mesh_ops.load_map_network_device_changes_v1',
        'mesh_ops.load_map_network_devices_v1', 'mesh_ops.load_map_network_dns_names_v1',
        'mesh_ops.load_map_network_dns_names_v2', 'mesh_ops.load_map_network_dns_resolvers_v1',
        'mesh_ops.load_map_network_dns_unmanaged_v1', 'mesh_ops.load_map_network_dns_zones_v1',
        'mesh_ops.load_map_network_dns_zones_v2', 'mesh_ops.load_map_network_exit_nodes_v1',
        'mesh_ops.load_map_network_exit_pool_captive_v1', 'mesh_ops.load_map_network_exit_pools_v1',
        'mesh_ops.load_map_network_exit_pools_v2', 'mesh_ops.load_map_network_exit_rules_v1',
        'mesh_ops.load_map_network_header_v1', 'mesh_ops.load_map_network_kubernetes_cas_v1',
        'mesh_ops.load_map_network_kubernetes_cas_v2', 'mesh_ops.load_map_network_kubernetes_contacts_v1',
        'mesh_ops.load_map_network_kubernetes_gateways_v1', 'mesh_ops.load_map_network_kubernetes_profiles_v1',
        'mesh_ops.load_map_network_kubernetes_rule_access_v1',
        'mesh_ops.load_map_network_kubernetes_rule_groups_v1', 'mesh_ops.load_map_network_kubernetes_sources_v1',
        'mesh_ops.load_map_network_policy_devices_v1', 'mesh_ops.load_map_network_policy_rules_v1',
        'mesh_ops.load_map_network_route_rules_v1', 'mesh_ops.load_map_network_selector_members_v1',
        'mesh_ops.load_map_network_site_routers_v1', 'mesh_ops.load_map_network_sites_v1',
        'mesh_ops.load_map_network_sites_v2', 'mesh_ops.load_map_network_sites_v3',
        'mesh_ops.load_map_peer_candidates_v2', 'mesh_ops.lock_active_network_revision_v1',
        'mesh_ops.lock_browser_move_revisions_v1', 'mesh_ops.lock_browser_registration_completion_authority_v2',
        'mesh_ops.lock_kubernetes_join_key_v1', 'mesh_ops.lock_kubernetes_replica_completion_v1',
        'mesh_ops.lock_kubernetes_replica_request_v2', 'mesh_ops.lock_registration_credential',
        'mesh_ops.lock_registration_credential_v2', 'mesh_ops.lock_registration_prefixes',
        'mesh_ops.logout_device_v2', 'mesh_ops.lookup_browser_joined_v1',
        'mesh_ops.map_network_has_direct_endpoints_v1', 'mesh_ops.map_network_sharing_devices_v1',
        'mesh_ops.map_session_revoked_v2', 'mesh_ops.map_session_suspended_v1', 'mesh_ops.map_share_guardrails_v2',
        'mesh_ops.mark_session_proven_v1', 'mesh_ops.move_out_browser_device_v1',
        'mesh_ops.node_address_quarantine_v1', 'mesh_ops.observe_device_alias_version_v1',
        'mesh_ops.open_kubernetes_replica_request_v2', 'mesh_ops.private_interchange_directory_v1',
        'mesh_ops.ratchet_kubernetes_gateway_token_v1', 'mesh_ops.read_browser_registration_followup_v1',
        'mesh_ops.read_browser_registration_landing_v1', 'mesh_ops.read_completed_browser_registration_v1',
        'mesh_ops.read_connection_log_ticket_v2', 'mesh_ops.read_current_deployment_entitlement_v1',
        'mesh_ops.read_kubernetes_access_settings_v1', 'mesh_ops.read_kubernetes_audit_settings_v1',
        'mesh_ops.read_kubernetes_ca_signing_state_v1', 'mesh_ops.read_kubernetes_cluster_approver_additions_v1',
        'mesh_ops.read_kubernetes_cluster_ca_v1', 'mesh_ops.read_kubernetes_cluster_ceiling_v1',
        'mesh_ops.read_kubernetes_cluster_explain_replica_v1', 'mesh_ops.read_kubernetes_cluster_policy_groups_v1',
        'mesh_ops.read_kubernetes_cluster_replica_v3', 'mesh_ops.read_kubernetes_cluster_signing_v2',
        'mesh_ops.read_kubernetes_cluster_v2', 'mesh_ops.read_kubernetes_gateway_certificate_v1',
        'mesh_ops.read_kubernetes_gateway_ratchet_suspension_v1',
        'mesh_ops.read_kubernetes_gateway_rotation_trust_v1', 'mesh_ops.read_kubernetes_join_key_v1',
        'mesh_ops.read_kubernetes_operation_v1', 'mesh_ops.read_kubernetes_replica_request_v1',
        'mesh_ops.read_map_inventory_change_head_v1', 'mesh_ops.read_map_self_identity_v1',
        'mesh_ops.read_map_self_identity_v2', 'mesh_ops.read_scope_display_codes_v1',
        'mesh_ops.read_scope_workspace_name_v1', 'mesh_ops.record_browser_intent_siblings_v1',
        'mesh_ops.record_deployment_entitlement_v1', 'mesh_ops.record_device_captive_window_v1',
        'mesh_ops.record_kubernetes_gateway_ceiling_v1', 'mesh_ops.record_kubernetes_gateway_group_report_v1',
        'mesh_ops.record_kubernetes_gateway_key_event_v3', 'mesh_ops.record_kubernetes_join_code_failure_v2',
        'mesh_ops.record_kubernetes_operation_outcomes_v2', 'mesh_ops.record_kubernetes_operations_v2',
        'mesh_ops.reject_kubernetes_replica_request_v1', 'mesh_ops.relay_revocations_v1',
        'mesh_ops.replace_kubernetes_access_settings_v1', 'mesh_ops.replace_kubernetes_audit_settings_v1',
        'mesh_ops.replace_kubernetes_cluster_signing_trust_v1', 'mesh_ops.report_device_exit_offer_v2',
        'mesh_ops.report_device_route_offer_v2', 'mesh_ops.request_kubernetes_ca_retire_v1',
        'mesh_ops.resolve_group_policy_edges_v1', 'mesh_ops.resolve_kubernetes_join_scope_v1',
        'mesh_ops.resolve_logout_scope_v1', 'mesh_ops.resolve_map_session_scope',
        'mesh_ops.resolve_node_key_rotation_scope', 'mesh_ops.resolve_registration_intake_scope',
        'mesh_ops.resume_kubernetes_gateway_token_ratchet_v1', 'mesh_ops.revoke_kubernetes_join_key_v1',
        'mesh_ops.rotate_kubernetes_gateway_machine_key_v2', 'mesh_ops.set_network_scope',
        'mesh_ops.suspend_kubernetes_gateway_token_ratchet_v1'
    ]::TEXT[],
            ARRAY[
        'mesh.compiled_policy_rule:SELECT', 'mesh.device:SELECT', 'mesh.device_dns_label:SELECT',
        'mesh.device_machine_key_epoch:SELECT', 'mesh.device_node_key_epoch:SELECT',
        'mesh.enrollment_credential:SELECT', 'mesh.enrollment_profile:SELECT', 'mesh.network:SELECT',
        'mesh.node_address_lease:SELECT', 'mesh.pending_registration:SELECT', 'mesh.policy_release:SELECT',
        'mesh_ops.network_revision:SELECT', 'mesh_ops.registration_address_floor:SELECT',
        'mesh_ops.schema_compatibility:SELECT', 'mesh_ops.schema_migration:SELECT', 'mesh.device:INSERT',
        'mesh.device_machine_key_epoch:INSERT', 'mesh.device_node_key_epoch:INSERT',
        'mesh.enrollment_credential_use:INSERT', 'mesh.enrollment_credential_use:SELECT',
        'mesh.node_address_lease:INSERT', 'mesh.pending_registration:INSERT',
        'mesh_ops.registration_address_floor:INSERT', 'mesh.device:UPDATE', 'mesh.device_node_key_epoch:UPDATE',
        'mesh.enrollment_credential:UPDATE', 'mesh.node_address_lease:UPDATE', 'mesh.pending_registration:UPDATE',
        'mesh_ops.registration_address_floor:UPDATE', 'mesh.device_machine_key_epoch:UPDATE',
        'mesh.enrollment_profile:UPDATE'
    ]::TEXT[]
    LOOP
        v_function_queue := ARRAY[]::OID[];
        v_function_seen := ARRAY[]::OID[];
        v_relation_queue := ARRAY[]::TEXT[];
        v_relation_seen := ARRAY[]::TEXT[];
        v_missing := ARRAY[]::TEXT[];
        v_granted := 0;
        v_owner_held := 0;
        v_foreign := 0;

        -- Seeds: every overload of a listed function that mesh_runtime may run directly.
        FOR v_entry IN SELECT pg_catalog.unnest(v_functions) LOOP
            SELECT pg_catalog.array_agg(routine.oid) INTO v_overloads
            FROM pg_catalog.pg_proc AS routine
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = routine.pronamespace
            WHERE namespace.nspname || '.' || routine.proname = v_entry
              AND EXISTS (SELECT 1 FROM pg_catalog.aclexplode(routine.proacl) AS acl
                  WHERE acl.grantee = v_source AND acl.privilege_type = 'EXECUTE');
            IF v_overloads IS NULL THEN
                v_missing := v_missing || v_entry;
            ELSE
                v_function_queue := v_function_queue || v_overloads;
            END IF;
        END LOOP;
        FOR v_entry IN SELECT pg_catalog.unnest(v_relations) LOOP
            v_relation := pg_catalog.to_regclass(pg_catalog.split_part(v_entry, ':', 1));
            IF v_relation IS NULL THEN
                v_missing := v_missing || v_entry;
            ELSE
                v_relation_queue := v_relation_queue || (v_relation::TEXT || ':' || pg_catalog.split_part(v_entry, ':', 2));
            END IF;
        END LOOP;

        -- The closure: what running those statements as the caller reaches.
        WHILE pg_catalog.cardinality(v_function_queue) > 0 OR pg_catalog.cardinality(v_relation_queue) > 0 LOOP
            IF pg_catalog.cardinality(v_function_queue) > 0 THEN
                v_function := v_function_queue[1];
                v_function_queue := v_function_queue[2:];
                CONTINUE WHEN v_function = ANY(v_function_seen);
                v_function_seen := v_function_seen || v_function;
                -- A SECURITY INVOKER body runs as the caller: what it names, it needs: a table read
                -- always and written as its statements write it, a sequence drawn from.
                v_body := NULL;
                SELECT routine.prosrc INTO v_body FROM pg_catalog.pg_proc AS routine
                WHERE routine.oid = v_function AND NOT routine.prosecdef;
                IF v_body IS NOT NULL THEN
                    FOR v_reference IN
                        SELECT DISTINCT referenced.schema_name, referenced.object_name
                        FROM pg_catalog.pg_proc AS routine
                        CROSS JOIN LATERAL pg_catalog.regexp_matches(routine.prosrc,
                            '(?<![a-z0-9_])(mesh|mesh_ops|mesh_audit)\.([a-z_][a-z0-9_]*)', 'g')
                            AS match_parts(parts)
                        CROSS JOIN LATERAL (SELECT match_parts.parts[1] AS schema_name,
                            match_parts.parts[2] AS object_name) AS referenced
                        WHERE routine.oid = v_function
                    LOOP
                        v_relation := pg_catalog.to_regclass(
                            pg_catalog.quote_ident(v_reference.schema_name) || '.' ||
                            pg_catalog.quote_ident(v_reference.object_name));
                        IF v_relation IS NOT NULL AND (SELECT relation.relkind FROM pg_catalog.pg_class AS relation
                            WHERE relation.oid = v_relation) = 'S' THEN
                            v_relation_queue := v_relation_queue || (v_relation::TEXT || ':USAGE');
                        ELSIF v_relation IS NOT NULL THEN
                            v_name := v_reference.schema_name || '\.' || v_reference.object_name || '(?![a-z0-9_])';
                            v_relation_queue := v_relation_queue || (v_relation::TEXT || ':SELECT');
                            IF v_body ~* ('(INSERT\s+INTO|MERGE\s+INTO)\s+' || v_name) THEN
                                v_relation_queue := v_relation_queue || (v_relation::TEXT || ':INSERT');
                            END IF;
                            -- A row lock of any strength needs UPDATE, as does an upsert or MERGE.
                            IF v_body ~* ('(UPDATE\s+(ONLY\s+)?|MERGE\s+INTO\s+)' || v_name)
                                OR v_body ~* 'FOR\s+(NO\s+KEY\s+UPDATE|UPDATE|KEY\s+SHARE|SHARE)\M'
                                OR v_body ~* 'ON\s+CONFLICT[^;]*DO\s+UPDATE' THEN
                                v_relation_queue := v_relation_queue || (v_relation::TEXT || ':UPDATE');
                            END IF;
                            IF v_body ~* ('DELETE\s+FROM\s+(ONLY\s+)?' || v_name) OR v_body ~* ('MERGE\s+INTO\s+' || v_name) THEN
                                v_relation_queue := v_relation_queue || (v_relation::TEXT || ':DELETE');
                            END IF;
                        END IF;
                        v_function_queue := v_function_queue || ARRAY(
                            SELECT routine.oid FROM pg_catalog.pg_proc AS routine
                            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = routine.pronamespace
                            WHERE namespace.nspname = v_reference.schema_name
                              AND routine.proname = v_reference.object_name);
                    END LOOP;
                    -- SQL-standard bodies record what they use.
                    v_function_queue := v_function_queue || ARRAY(
                        SELECT dependency.refobjid FROM pg_catalog.pg_depend AS dependency
                        WHERE dependency.classid = 'pg_catalog.pg_proc'::REGCLASS AND dependency.objid = v_function
                          AND dependency.refclassid = 'pg_catalog.pg_proc'::REGCLASS);
                    v_relation_queue := v_relation_queue || ARRAY(
                        SELECT dependency.refobjid::TEXT || ':SELECT' FROM pg_catalog.pg_depend AS dependency
                        WHERE dependency.classid = 'pg_catalog.pg_proc'::REGCLASS AND dependency.objid = v_function
                          AND dependency.refclassid = 'pg_catalog.pg_class'::REGCLASS);
                END IF;
                CONTINUE;
            END IF;

            v_entry := v_relation_queue[1];
            v_relation_queue := v_relation_queue[2:];
            CONTINUE WHEN v_entry = ANY(v_relation_seen);
            v_relation_seen := v_relation_seen || v_entry;
            v_relation := pg_catalog.split_part(v_entry, ':', 1)::OID;
            CONTINUE WHEN (v_relation::TEXT || ':DONE') = ANY(v_relation_seen);
            v_relation_seen := v_relation_seen || (v_relation::TEXT || ':DONE');
            -- Row-level security policies: the functions and relations their expressions use.
            -- Triggers that run as the caller, column defaults and CHECK constraints: their functions.
            -- A security_invoker view: what its query reads.
            FOR v_reference IN
                SELECT dependency.refclassid, dependency.refobjid
                FROM pg_catalog.pg_policy AS policy
                JOIN pg_catalog.pg_depend AS dependency
                  ON dependency.classid = 'pg_catalog.pg_policy'::REGCLASS AND dependency.objid = policy.oid
                WHERE policy.polrelid = v_relation
                UNION
                SELECT 'pg_catalog.pg_proc'::REGCLASS, trigger_row.tgfoid
                FROM pg_catalog.pg_trigger AS trigger_row
                WHERE trigger_row.tgrelid = v_relation AND NOT trigger_row.tgisinternal
                UNION
                SELECT dependency.refclassid, dependency.refobjid
                FROM pg_catalog.pg_attrdef AS column_default
                JOIN pg_catalog.pg_depend AS dependency
                  ON dependency.classid = 'pg_catalog.pg_attrdef'::REGCLASS AND dependency.objid = column_default.oid
                WHERE column_default.adrelid = v_relation
                UNION
                SELECT dependency.refclassid, dependency.refobjid
                FROM pg_catalog.pg_constraint AS check_constraint
                JOIN pg_catalog.pg_depend AS dependency
                  ON dependency.classid = 'pg_catalog.pg_constraint'::REGCLASS
                 AND dependency.objid = check_constraint.oid
                WHERE check_constraint.conrelid = v_relation AND check_constraint.contype = 'c'
                UNION
                SELECT dependency.refclassid, dependency.refobjid
                FROM pg_catalog.pg_class AS view_relation
                JOIN pg_catalog.pg_rewrite AS rewrite ON rewrite.ev_class = view_relation.oid
                JOIN pg_catalog.pg_depend AS dependency
                  ON dependency.classid = 'pg_catalog.pg_rewrite'::REGCLASS AND dependency.objid = rewrite.oid
                WHERE view_relation.oid = v_relation AND view_relation.relkind = 'v'
                  AND 'security_invoker=true' = ANY(COALESCE(view_relation.reloptions, ARRAY[]::TEXT[]))
            LOOP
                IF v_reference.refclassid = 'pg_catalog.pg_proc'::REGCLASS THEN
                    v_function_queue := v_function_queue || v_reference.refobjid;
                ELSIF v_reference.refclassid = 'pg_catalog.pg_class'::REGCLASS
                    AND v_reference.refobjid <> v_relation THEN
                    -- A sequence a default draws from needs USAGE; any other relation is read.
                    v_relation_queue := v_relation_queue || (v_reference.refobjid::TEXT || CASE
                        WHEN (SELECT relation.relkind FROM pg_catalog.pg_class AS relation
                            WHERE relation.oid = v_reference.refobjid) = 'S' THEN ':USAGE' ELSE ':SELECT' END);
                END IF;
            END LOOP;
        END LOOP;

        -- Grants: only what mesh_runtime itself holds, on objects the migrator owns.
        FOREACH v_function IN ARRAY v_function_seen LOOP
            CONTINUE WHEN NOT EXISTS (
                SELECT 1 FROM pg_catalog.pg_proc AS routine
                CROSS JOIN LATERAL pg_catalog.aclexplode(routine.proacl) AS acl
                WHERE routine.oid = v_function AND acl.grantee = v_source AND acl.privilege_type = 'EXECUTE');
            IF (SELECT routine.proowner FROM pg_catalog.pg_proc AS routine WHERE routine.oid = v_function)
                <> (SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = CURRENT_USER)
                OR (SELECT pg_catalog.regexp_replace(routine.proname, '_v[0-9]+$', '')
                    FROM pg_catalog.pg_proc AS routine WHERE routine.oid = v_function) = ANY(v_operator_families) THEN
                v_owner_held := v_owner_held + 1;
                CONTINUE;
            END IF;
            EXECUTE pg_catalog.format('GRANT EXECUTE ON FUNCTION %s TO %I', v_function::REGPROCEDURE, v_group);
            v_granted := v_granted + 1;
        END LOOP;
        FOREACH v_entry IN ARRAY v_relation_seen LOOP
            CONTINUE WHEN v_entry LIKE '%:DONE';
            v_relation := pg_catalog.split_part(v_entry, ':', 1)::OID;
            v_type := pg_catalog.split_part(v_entry, ':', 2);
            IF (SELECT relation.relowner FROM pg_catalog.pg_class AS relation WHERE relation.oid = v_relation)
                <> (SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = CURRENT_USER) THEN
                v_foreign := v_foreign + 1;
                CONTINUE;
            END IF;
            FOR v_reference IN
                SELECT DISTINCT acl.privilege_type, relation.relkind
                FROM pg_catalog.pg_class AS relation
                CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) AS acl
                WHERE relation.oid = v_relation AND acl.grantee = v_source
                  AND acl.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'USAGE')
                  AND acl.privilege_type = v_type
            LOOP
                EXECUTE pg_catalog.format('GRANT %s ON %s %s TO %I', v_reference.privilege_type,
                    CASE WHEN v_reference.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END,
                    v_relation::REGCLASS, v_group);
                v_granted := v_granted + 1;
            END LOOP;
            FOR v_reference IN
                SELECT acl.privilege_type, attribute.attname
                FROM pg_catalog.pg_attribute AS attribute
                CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS acl
                WHERE attribute.attrelid = v_relation AND attribute.attnum > 0 AND NOT attribute.attisdropped
                  AND acl.grantee = v_source
                  AND acl.privilege_type IN ('SELECT', 'INSERT', 'UPDATE')
                  AND acl.privilege_type = v_type
            LOOP
                EXECUTE pg_catalog.format('GRANT %s (%I) ON TABLE %s TO %I', v_reference.privilege_type,
                    v_reference.attname, v_relation::REGCLASS, v_group);
                v_granted := v_granted + 1;
            END LOOP;
        END LOOP;
        FOR v_reference IN
            SELECT namespace.nspname
            FROM pg_catalog.pg_namespace AS namespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) AS acl
            WHERE namespace.nspname IN ('mesh', 'mesh_ops', 'mesh_audit')
              AND acl.grantee = v_source AND acl.privilege_type = 'USAGE'
              AND namespace.nspowner = (SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = CURRENT_USER)
        LOOP
            EXECUTE pg_catalog.format('GRANT USAGE ON SCHEMA %I TO %I', v_reference.nspname, v_group);
        END LOOP;
        FOR v_reference IN
            SELECT DISTINCT acl.privilege_type
            FROM pg_catalog.pg_database AS database
            CROSS JOIN LATERAL pg_catalog.aclexplode(database.datacl) AS acl
            WHERE database.datname = pg_catalog.current_database()
              AND acl.grantee = v_source AND acl.privilege_type IN ('CONNECT', 'TEMPORARY')
        LOOP
            EXECUTE pg_catalog.format('GRANT %s ON DATABASE %I TO %I', v_reference.privilege_type,
                pg_catalog.current_database(), v_group);
        END LOOP;
        -- Nothing here fails the migration (it only adds): what it left out shows in this notice, and the read-only
        -- checks of docs/runbooks (as the integration test postgres_group_roles_test.go) confirm the result.
        RAISE NOTICE 'role isolation S2.2: % received % grants; % functions left to operator step 000298; % relation privileges on relations the migrator does not own; mesh_runtime lacks %',
            v_group, v_granted, v_owner_held, v_foreign, v_missing;
    END LOOP;
END;
$grants$;
