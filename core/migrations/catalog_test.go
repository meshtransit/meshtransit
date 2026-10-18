package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestCatalogContainsOrderedFoundations(t *testing.T) {
	t.Parallel()

	catalog := Catalog()
	if len(catalog) != 184 {
		t.Fatalf("len(Catalog()) = %d, want 184", len(catalog))
	}
	cleanup := catalog[88]
	if cleanup.Description != expiredUnprovisionedShareCleanupDescription {
		t.Fatalf("migration 89 description = %q, want expired Contract cleanup", cleanup.Description)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.revoke_resource_share_v6",
		"FROM mesh_ops.revoke_resource_share_v5",
		"p_occurred_at < contract_row.expires_at",
		"expired Trust Contract requires endpoint reconciliation",
		"state = 'withdrawn'",
		"sharing_revision = revision.sharing_revision + 1",
		"SECURITY DEFINER",
	} {
		if !strings.Contains(cleanup.SQL, required) {
			t.Errorf("expired Trust Contract cleanup SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{"GRANT EXECUTE", "BYPASSRLS", "DROP "} {
		if strings.Contains(cleanup.SQL, forbidden) {
			t.Errorf("expired Trust Contract cleanup SQL contains unsafe capability %q", forbidden)
		}
	}
	cleanupOwnership := ExpiredUnprovisionedShareCleanupOwnershipSQL()
	for _, required := range []string{
		"OWNER TO mesh_share_writer",
		"REVOKE ALL ON FUNCTION mesh_ops.revoke_resource_share_v5",
		"GRANT EXECUTE ON FUNCTION mesh_ops.revoke_resource_share_v6",
		"TO mesh_runtime",
	} {
		if !strings.Contains(cleanupOwnership, required) {
			t.Errorf("expired Trust Contract cleanup ownership SQL missing %q", required)
		}
	}
	reconciliation := catalog[55]
	if reconciliation.Description != "Resource sharing Private Endpoint route reconciliation and withdrawal" {
		t.Fatalf("migration 56 description = %q, want endpoint reconciliation", reconciliation.Description)
	}
	for _, required := range []string{
		"CREATE TABLE mesh_ops.private_endpoint_route_intent",
		"CREATE FUNCTION mesh_ops.read_private_endpoint_publication_snapshot_v2",
		"CREATE FUNCTION mesh_ops.stage_private_endpoint_route_v1",
		"CREATE OR REPLACE FUNCTION mesh_ops.reject_private_endpoint_readiness_change",
		"CREATE FUNCTION mesh_ops.list_private_endpoint_withdrawal_candidates_v1",
		"CREATE FUNCTION mesh_ops.read_private_endpoint_withdrawal_snapshot_v1",
		"CREATE FUNCTION mesh_ops.finalize_private_endpoint_withdrawal_v1",
		"'route_present', route_present_value",
		"TO mesh_worker",
		"FORCE ROW LEVEL SECURITY",
		"p_reason NOT IN ('expired', 'invalidated')",
		"route_revision = revision.route_revision + 1",
		"dns_revision = revision.dns_revision + 1",
		"sharing_revision = revision.sharing_revision + 1",
	} {
		if !strings.Contains(reconciliation.SQL, required) {
			t.Errorf("Resource Sharing endpoint reconciliation SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT INSERT ON mesh_ops.private_endpoint_route_intent TO mesh_worker",
		"GRANT UPDATE ON mesh.private_endpoint TO mesh_worker",
		"GRANT UPDATE ON mesh.imported_resource_dns_publication TO mesh_worker",
		"BYPASSRLS",
		"DROP ",
	} {
		if strings.Contains(reconciliation.SQL, forbidden) {
			t.Errorf("Resource Sharing endpoint reconciliation SQL contains unsafe capability %q", forbidden)
		}
	}
	endpointPublication := catalog[54]
	if endpointPublication.Description != "Resource sharing Private Endpoint readiness and DNS publication" {
		t.Fatalf("migration 55 description = %q, want endpoint publication", endpointPublication.Description)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.private_endpoint_readiness",
		"CREATE TABLE mesh.imported_resource_dns_publication",
		"CREATE FUNCTION mesh_ops.list_private_endpoint_publication_candidates_v1",
		"CREATE FUNCTION mesh_ops.read_private_endpoint_publication_snapshot_v1",
		"CREATE FUNCTION mesh_ops.lock_private_endpoint_network_revision_internal_v1",
		"CREATE FUNCTION mesh_ops.assert_private_endpoint_scope_internal_v1",
		"CREATE FUNCTION mesh_ops.publish_private_endpoint_v1",
		"CREATE FUNCTION mesh_ops.withdraw_private_endpoint_publication_internal_v1",
		"CREATE FUNCTION mesh_ops.revoke_resource_share_v4",
		"GRANT EXECUTE ON FUNCTION mesh_ops.publish_private_endpoint_v1",
		"TO mesh_worker",
		"FORCE ROW LEVEL SECURITY",
		"route_snapshot_hash",
		"dns_revision = revision.dns_revision + 1",
		"route_revision = revision.route_revision + 1",
	} {
		if !strings.Contains(endpointPublication.SQL, required) {
			t.Errorf("Resource Sharing endpoint publication SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT INSERT ON mesh.private_endpoint_readiness TO mesh_worker",
		"GRANT UPDATE ON mesh.private_endpoint_readiness TO mesh_worker",
		"GRANT INSERT ON mesh.imported_resource_dns_publication TO mesh_worker",
		"GRANT UPDATE ON mesh.imported_resource_dns_publication TO mesh_worker",
		"GRANT UPDATE ON mesh.imported_resource_dns_publication TO mesh_share_writer",
		"BYPASSRLS",
		"DROP ",
	} {
		if strings.Contains(endpointPublication.SQL, forbidden) {
			t.Errorf("Resource Sharing endpoint publication SQL contains unsafe capability %q", forbidden)
		}
	}
	deploymentCapabilities := catalog[56]
	if deploymentCapabilities.Description != "Console Deployment capability projection" {
		t.Fatalf("migration 57 description = %q, want Console Deployment capability projection", deploymentCapabilities.Description)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.read_console_deployment_capabilities_v1",
		"deployment.profile = 'self_hosted'",
		"session.login_workspace_id",
		"GRANT EXECUTE ON FUNCTION mesh_ops.read_console_deployment_capabilities_v1",
		"TO mesh_runtime",
	} {
		if !strings.Contains(deploymentCapabilities.SQL, required) {
			t.Errorf("Console Deployment capability SQL missing %q", required)
		}
	}
	sharingScopes := catalog[57]
	if sharingScopes.Description != "Console sharing management scope projection" {
		t.Fatalf("migration 58 description = %q, want Console sharing management scope projection", sharingScopes.Description)
	}
	for _, required := range []string{
		"CREATE OR REPLACE FUNCTION mesh_ops.read_console_management_scopes_v1",
		"'policy.approve', 'share.accept', 'share.offer', 'share.read', 'share.revoke'",
		"ARRAY(\n                SELECT DISTINCT permission.permission_key",
		"binding.workspace_membership_id = authority.membership_id",
		"pg_catalog.cardinality(scope_permissions.permissions) > 0",
		"pg_catalog.to_jsonb(scopes.permissions)",
		"REVOKE ALL ON FUNCTION mesh_ops.read_console_management_scopes_v1",
		"TO mesh_runtime",
	} {
		if !strings.Contains(sharingScopes.SQL, required) {
			t.Errorf("Console sharing scope SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE",
		"GRANT ALL", "BYPASSRLS", "ALTER DEFAULT PRIVILEGES", "DROP ",
	} {
		if strings.Contains(sharingScopes.SQL, forbidden) {
			t.Errorf("Console sharing scope SQL contains excessive capability %q", forbidden)
		}
	}
	publicationOwnership := ResourceSharingEndpointPublicationOwnershipSQL()
	for _, required := range []string{
		"OWNER TO mesh_share_writer",
		"GRANT EXECUTE ON FUNCTION mesh_ops.assert_private_endpoint_scope_internal_v1",
		"TO mesh_migrator",
		"REVOKE ALL ON FUNCTION mesh_ops.revoke_resource_share_v3",
		"GRANT EXECUTE ON FUNCTION mesh_ops.revoke_resource_share_v4",
		"TO mesh_runtime",
	} {
		if !strings.Contains(publicationOwnership, required) {
			t.Errorf("Resource Sharing endpoint publication ownership SQL missing %q", required)
		}
	}
	privateEndpointAuthority := catalog[53]
	if privateEndpointAuthority.Description != "Resource sharing Private Endpoint provisioning authority" {
		t.Fatalf("migration 54 description = %q, want Private Endpoint provisioning authority", privateEndpointAuthority.Description)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.federation_alias_lease",
		"CREATE TABLE mesh.private_endpoint",
		"CREATE TABLE mesh_ops.federation_alias_pool_cursor",
		"CREATE FUNCTION mesh_ops.activate_resource_share_v2",
		"CREATE FUNCTION mesh_ops.revoke_resource_share_v3",
		"CREATE UNIQUE INDEX federation_alias_lease_current_address_uidx",
		"CREATE POLICY private_endpoint_runtime_policy",
		"CREATE POLICY private_endpoint_share_writer_policy",
		"state IN ('provisioning', 'ready', 'revoked', 'expired', 'invalidated')",
		"FORCE ROW LEVEL SECURITY",
	} {
		if !strings.Contains(privateEndpointAuthority.SQL, required) {
			t.Errorf("Resource Sharing Private Endpoint SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT INSERT ON mesh.private_endpoint TO mesh_runtime",
		"GRANT UPDATE ON mesh.private_endpoint TO mesh_runtime",
		"GRANT DELETE ON mesh.private_endpoint TO mesh_runtime",
		"GRANT EXECUTE ON FUNCTION mesh_ops.activate_resource_share_v2",
		"BYPASSRLS",
		"DROP ",
	} {
		if strings.Contains(privateEndpointAuthority.SQL, forbidden) {
			t.Errorf("Resource Sharing Private Endpoint SQL contains unsafe capability %q", forbidden)
		}
	}
	privateEndpointOwnership := ResourceSharingPrivateEndpointFunctionOwnershipSQL()
	for _, required := range []string{
		"OWNER TO mesh_share_writer",
		"REVOKE ALL ON FUNCTION mesh_ops.activate_resource_share_v1",
		"REVOKE ALL ON FUNCTION mesh_ops.revoke_resource_share_v2",
		"GRANT EXECUTE ON FUNCTION mesh_ops.activate_resource_share_v2",
		"GRANT EXECUTE ON FUNCTION mesh_ops.revoke_resource_share_v3",
		"TO mesh_runtime",
	} {
		if !strings.Contains(privateEndpointOwnership, required) {
			t.Errorf("Resource Sharing Private Endpoint ownership SQL missing %q", required)
		}
	}
	accessNameAuthority := catalog[52]
	if accessNameAuthority.Description != "Resource sharing consumer access-name authority" {
		t.Fatalf("migration 53 description = %q, want access-name authority", accessNameAuthority.Description)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.imported_resource_access_name",
		"CREATE UNIQUE INDEX imported_resource_access_name_current_uidx",
		"CREATE FUNCTION mesh_ops.decide_resource_share_offer_v2",
		"CREATE FUNCTION mesh_ops.revoke_resource_share_v2",
		"CREATE POLICY imported_resource_access_name_runtime_policy",
		"CREATE POLICY imported_resource_access_name_share_writer_policy",
		"state IN ('reserved', 'withdrawn')",
		"FORCE ROW LEVEL SECURITY",
		"p_access_name !~",
	} {
		if !strings.Contains(accessNameAuthority.SQL, required) {
			t.Errorf("Resource Sharing access-name SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT INSERT ON mesh.imported_resource_access_name TO mesh_runtime",
		"GRANT UPDATE ON mesh.imported_resource_access_name TO mesh_runtime",
		"GRANT DELETE ON mesh.imported_resource_access_name TO mesh_runtime",
		"GRANT EXECUTE ON FUNCTION mesh_ops.decide_resource_share_offer_v2",
		"BYPASSRLS",
		"DROP ",
		"state IN ('reserved', 'published'",
	} {
		if strings.Contains(accessNameAuthority.SQL, forbidden) {
			t.Errorf("Resource Sharing access-name SQL contains unsafe capability %q", forbidden)
		}
	}
	accessNameOwnership := ResourceSharingAccessNameFunctionOwnershipSQL()
	for _, required := range []string{
		"OWNER TO mesh_share_writer",
		"REVOKE ALL ON FUNCTION mesh_ops.decide_resource_share_offer_v1",
		"REVOKE ALL ON FUNCTION mesh_ops.revoke_resource_share_v1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.decide_resource_share_offer_v2",
		"GRANT EXECUTE ON FUNCTION mesh_ops.revoke_resource_share_v2",
		"TO mesh_runtime",
	} {
		if !strings.Contains(accessNameOwnership, required) {
			t.Errorf("Resource Sharing access-name ownership SQL missing %q", required)
		}
	}
	importedPolicy := catalog[51]
	if importedPolicy.Description != "policy Imported Resource destination provenance" {
		t.Fatalf("migration 52 description = %q, want Imported Resource provenance", importedPolicy.Description)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.compiled_policy_imported_resource_destination",
		"CREATE FUNCTION mesh_ops.attach_policy_imported_resource_destinations_internal_v1",
		"RENAME TO publish_compiled_policy_local_v1",
		"CREATE FUNCTION mesh_ops.publish_compiled_policy(",
		"CREATE FUNCTION mesh_ops.resolve_imported_policy_destinations_v1",
		"CREATE FUNCTION mesh_ops.lock_and_resolve_policy_imported_resources_internal_v1",
		"CREATE FUNCTION mesh_ops.read_policy_simulation_baseline_v2",
		"GRANT EXECUTE ON FUNCTION mesh_ops.read_policy_simulation_baseline_v2",
		"CREATE FUNCTION mesh_ops.explain_active_policy_v2",
		"GRANT EXECUTE ON FUNCTION mesh_ops.explain_active_policy_v2",
		"GRANT SELECT ON mesh.compiled_policy_imported_resource_destination TO mesh_runtime",
		"FORCE ROW LEVEL SECURITY",
	} {
		if !strings.Contains(importedPolicy.SQL, required) {
			t.Errorf("Imported Resource policy SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"publish_compiled_policy_v2",
		"GRANT INSERT ON mesh.compiled_policy_imported_resource_destination",
		"GRANT UPDATE ON mesh.compiled_policy_imported_resource_destination",
		"GRANT DELETE ON mesh.compiled_policy_imported_resource_destination",
		"GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_imported_resource_destinations_internal_v1",
		"BYPASSRLS",
		"ALTER DEFAULT PRIVILEGES",
		"DROP ",
	} {
		if strings.Contains(importedPolicy.SQL, forbidden) {
			t.Errorf("Imported Resource policy SQL contains unsafe capability %q", forbidden)
		}
	}
	policyImportedOwnership := PolicyImportedResourceFunctionOwnershipSQL()
	for _, required := range []string{
		"OWNER TO mesh_share_writer",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_imported_policy_destinations_v1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.lock_and_resolve_policy_imported_resources_internal_v1",
		"TO mesh_migrator",
		"TO mesh_runtime",
	} {
		if !strings.Contains(policyImportedOwnership, required) {
			t.Errorf("Imported Resource resolver ownership SQL missing %q", required)
		}
	}
	resourceSharing := catalog[50]
	if resourceSharing.Description != "Resource sharing authority foundation" {
		t.Fatalf("migration 51 description = %q, want Resource sharing authority foundation", resourceSharing.Description)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.resource_export",
		"CREATE TABLE mesh.share_offer",
		"CREATE TABLE mesh.trust_contract",
		"CREATE TABLE mesh.imported_resource",
		"CREATE FUNCTION mesh_ops.create_resource_share_offer_v1",
		"CREATE FUNCTION mesh_ops.decide_resource_share_offer_v1",
		"CREATE FUNCTION mesh_ops.activate_resource_share_v1",
		"CREATE FUNCTION mesh_ops.revoke_resource_share_v1",
		"provider_authority_generation",
		"consumer_authority_generation",
		"resource_public_id UUID NOT NULL",
		"CREATE POLICY resource_export_runtime_policy",
		"CREATE POLICY imported_resource_runtime_policy",
		"deployment.recovery_epoch = p_recovery_epoch",
		"state IN ('activating', 'active', 'revoked', 'expired', 'invalidated')",
		"FORCE ROW LEVEL SECURITY",
		"TO mesh_share_writer",
	} {
		if !strings.Contains(resourceSharing.SQL, required) {
			t.Errorf("Resource sharing authority SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"REVOKE ALL ON ALL SEQUENCES",
		"GRANT INSERT ON mesh.resource_export TO mesh_runtime",
		"GRANT UPDATE ON mesh.resource_export TO mesh_runtime",
		"GRANT DELETE ON mesh.resource_export TO mesh_runtime",
		"GRANT EXECUTE ON FUNCTION mesh_ops.create_resource_share_offer_v1",
		"BYPASSRLS",
		"DROP ",
	} {
		if strings.Contains(resourceSharing.SQL, forbidden) {
			t.Errorf("Resource sharing authority SQL contains unsafe capability %q", forbidden)
		}
	}
	ownership := ResourceSharingFunctionOwnershipSQL()
	if strings.Contains(ownership, "GRANT EXECUTE ON FUNCTION mesh_ops.set_share_scope_v1") {
		t.Error("Resource Sharing ownership SQL exposes direct share scope capability")
	}
	for _, required := range []string{
		"OWNER TO mesh_share_writer",
		"GRANT EXECUTE ON FUNCTION mesh_ops.create_resource_share_offer_v1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.decide_resource_share_offer_v1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.activate_resource_share_v1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.revoke_resource_share_v1",
		"TO mesh_runtime",
	} {
		if !strings.Contains(ownership, required) {
			t.Errorf("Resource sharing ownership hardening SQL missing %q", required)
		}
	}
	managementScopes := catalog[49]
	if managementScopes.Description != "Console management scope projection" {
		t.Fatalf("migration 50 description = %q, want Console management scope projection", managementScopes.Description)
	}
	for _, required := range []string{
		"CREATE POLICY network_console_management_scope_projection_policy",
		"'mesh.console_management_scope_workspace_public_id'",
		"CREATE FUNCTION mesh_ops.read_console_management_scopes_v1",
		"SECURITY DEFINER",
		"session.login_workspace_id",
		"membership.state = 'active'",
		"binding.state = 'active'",
		"permission.permission_key = 'policy.approve'",
		"p_after_network_public_id",
		"p_limit > 101",
		"previous_projection_workspace_public_id",
		"GRANT EXECUTE ON FUNCTION mesh_ops.read_console_management_scopes_v1",
		"TO mesh_runtime",
	} {
		if !strings.Contains(managementScopes.SQL, required) {
			t.Errorf("Console management scope SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE",
		"GRANT ALL", "BYPASSRLS", "ALTER DEFAULT PRIVILEGES", "DROP ",
	} {
		if strings.Contains(managementScopes.SQL, forbidden) {
			t.Errorf("Console management scope SQL contains excessive capability %q", forbidden)
		}
	}
	approvalManagement := catalog[48]
	if approvalManagement.Description != "Policy approval management read API" {
		t.Fatalf("migration 49 description = %q, want Policy approval management read API", approvalManagement.Description)
	}
	for _, required := range []string{
		"CREATE INDEX policy_approval_request_management_cursor_idx",
		"CREATE INDEX policy_approval_request_management_state_cursor_idx",
		"CREATE FUNCTION mesh_ops.policy_approval_request_payload_v1",
		"CREATE FUNCTION mesh_ops.read_policy_approval_request_management_v1",
		"CREATE FUNCTION mesh_ops.list_policy_approval_requests_management_v1",
		"request.workspace_id = mesh_ops.current_workspace_id()",
		"request.network_id = mesh_ops.current_network_id()",
		"proposer.deployment_id = request.deployment_id",
		"approver.deployment_id = evidence.deployment_id",
		"p_state NOT IN ('pending', 'approved', 'consumed')",
		"REVOKE ALL ON FUNCTION mesh_ops.policy_approval_request_payload_v1(BIGINT)",
		"GRANT EXECUTE ON FUNCTION mesh_ops.read_policy_approval_request_management_v1(UUID)",
		"TO mesh_runtime",
	} {
		if !strings.Contains(approvalManagement.SQL, required) {
			t.Errorf("Policy approval management read SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE",
		"GRANT ALL", "BYPASSRLS", "ALTER DEFAULT PRIVILEGES", "DROP ",
	} {
		if strings.Contains(approvalManagement.SQL, forbidden) {
			t.Errorf("Policy approval management read SQL contains excessive capability %q", forbidden)
		}
	}
	approvalGate := catalog[47]
	if approvalGate.Description != "Policy approval publication gate" {
		t.Fatalf("migration 48 description = %q, want Policy approval publication gate", approvalGate.Description)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.lock_policy_approval_for_publication_v1",
		"CREATE FUNCTION mesh_ops.consume_policy_approval_for_publication_v1",
		"FOR UPDATE OF request",
		"FOR SHARE OF evidence",
		"request_row.state <> 'approved'",
		"current_network <> request_row.proposed_network_revision",
		"release_row.semantic_hash <> p_candidate_hash",
		"state = 'consumed'",
		"consumed_policy_release_id = release_row.id",
		"GRANT EXECUTE ON FUNCTION mesh_ops.consume_policy_approval_for_publication_v1",
		"TO mesh_runtime",
	} {
		if !strings.Contains(approvalGate.SQL, required) {
			t.Errorf("Policy approval publication gate SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE",
		"GRANT ALL", "BYPASSRLS", "DROP ",
	} {
		if strings.Contains(approvalGate.SQL, forbidden) {
			t.Errorf("Policy approval publication gate SQL contains excessive capability %q", forbidden)
		}
	}
	approvalPersistence := catalog[46]
	if approvalPersistence.Description != "Policy approval persistence" {
		t.Fatalf("migration 47 description = %q, want Policy approval persistence", approvalPersistence.Description)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.policy_approval_request",
		"CREATE TABLE mesh.policy_approval_evidence",
		"CREATE FUNCTION mesh_ops.create_policy_approval_request_v1",
		"CREATE FUNCTION mesh_ops.lock_policy_approval_request_v1",
		"CREATE FUNCTION mesh_ops.approve_policy_approval_request_v1",
		"CREATE FUNCTION mesh_ops.load_policy_approval_evidence_v1",
		"proposed_network_revision = baseline_network_revision + 1",
		"FROM mesh_ops.lock_network_revision() AS revision",
		"OR current_isolation <> p_baseline_isolation",
		"state = 'consumed'",
		"FOR UPDATE OF request",
		"FORCE ROW LEVEL SECURITY",
		"GRANT EXECUTE ON FUNCTION mesh_ops.create_policy_approval_request_v1",
		"TO mesh_runtime",
	} {
		if !strings.Contains(approvalPersistence.SQL, required) {
			t.Errorf("Policy approval persistence SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"DROP ",
	} {
		if strings.Contains(approvalPersistence.SQL, forbidden) {
			t.Errorf("Policy approval persistence SQL contains excessive capability %q", forbidden)
		}
	}

	simulationBaseline := catalog[45]
	if simulationBaseline.Description != "Policy simulation active baseline" {
		t.Fatalf("migration 46 description = %q, want Policy simulation baseline", simulationBaseline.Description)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.read_policy_simulation_baseline_v1",
		"'policy.validate'",
		"FROM mesh_ops.resolve_network_permission_v1",
		"FROM mesh_ops.read_network_revision_v1()",
		"JOIN mesh.compiled_policy_rule",
		"LEFT JOIN mesh.compiled_policy_resource_destination",
		"LEFT JOIN mesh.compiled_policy_resource_group_destination",
		"LIMIT p_rule_limit",
		"SECURITY DEFINER",
		"GRANT EXECUTE ON FUNCTION mesh_ops.read_policy_simulation_baseline_v1",
		"TO mesh_runtime",
	} {
		if !strings.Contains(simulationBaseline.SQL, required) {
			t.Errorf("Policy simulation baseline SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"DROP ",
	} {
		if strings.Contains(simulationBaseline.SQL, forbidden) {
			t.Errorf("Policy simulation baseline SQL contains excessive capability %q", forbidden)
		}
	}

	persistence := catalog[26]
	if persistence.Description != "OIDC authentication transaction persistence" {
		t.Fatalf("migration 27 description = %q, want OIDC transaction persistence", persistence.Description)
	}
	for _, required := range []string{
		"ADD COLUMN authorization_endpoint TEXT",
		"ADD COLUMN token_endpoint TEXT",
		"ADD COLUMN binding_semantic_hash BYTEA",
		"auth_transaction_open_expiry_idx",
		"workspace_oidc_auth_transaction_scope_policy",
		"workspace_oidc_auth_transaction_lock_policy",
		"mesh.requested_workspace_public_id",
		"CREATE FUNCTION mesh_audit.lock_deployment_stream_head",
		"CREATE FUNCTION mesh_ops.create_oidc_auth_transaction_v1",
		"CREATE FUNCTION mesh_ops.load_oidc_auth_transaction_creation_v1",
		"provider.authorization_endpoint = p_authorization_endpoint",
		"provider.token_endpoint = p_token_endpoint",
		"provider.current_generation = p_provider_generation",
		"generation.valid_from <= pg_catalog.transaction_timestamp()",
		"deployment.recovery_epoch = p_recovery_epoch",
		"workspace_provider.organization_digest IS NULL",
		"FOR SHARE OF",
		"GRANT EXECUTE ON FUNCTION mesh_ops.create_oidc_auth_transaction_v1",
	} {
		if !strings.Contains(persistence.SQL, required) {
			t.Errorf("OIDC transaction persistence SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"DROP ",
	} {
		if strings.Contains(persistence.SQL, forbidden) {
			t.Errorf("OIDC transaction persistence SQL contains excessive capability %q", forbidden)
		}
	}

	rotation := catalog[25]
	if rotation.Description != "authenticated Node-key rotation authority" {
		t.Fatalf("migration 26 description = %q, want Node-key rotation authority", rotation.Description)
	}
	for _, required := range []string{
		"device_node_key_epoch_key_history_uidx",
		"workspace_node_key_rotation_scope_policy",
		"network_node_key_rotation_scope_policy",
		"CREATE FUNCTION mesh_ops.resolve_node_key_rotation_scope",
		"p_old_node_key = p_new_node_key THEN",
		"node_key.public_key IN (p_old_node_key, p_new_node_key)",
		"mesh.node_key_rotation_workspace_id",
		"COALESCE(previous_workspace_id, '')",
		"SECURITY DEFINER",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_node_key_rotation_scope",
	} {
		if !strings.Contains(rotation.SQL, required) {
			t.Errorf("Node-key rotation migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"BYPASSRLS",
		"DROP ",
	} {
		if strings.Contains(rotation.SQL, forbidden) {
			t.Errorf("Node-key rotation migration SQL contains excessive capability %q", forbidden)
		}
	}
	for index, migration := range catalog {
		if migration.Version != int64(index+1) {
			t.Fatalf("migration %d version = %d, want %d", index, migration.Version, index+1)
		}
		digest := sha256.Sum256([]byte(migration.SQL))
		if migration.Checksum != hex.EncodeToString(digest[:]) {
			t.Fatalf("migration %d checksum = %q, want SHA-256 of SQL", migration.Version, migration.Checksum)
		}
	}

	platform := catalog[0]
	if platform.Description != "platform migration foundation" {
		t.Fatalf("migration 1 description = %q, want platform foundation", platform.Description)
	}
	for _, required := range []string{
		"REVOKE ALL ON DATABASE",
		"GRANT CONNECT ON DATABASE",
		"CREATE SCHEMA mesh;",
		"CREATE SCHEMA mesh_ops;",
		"CREATE SCHEMA mesh_audit;",
		"CREATE TABLE mesh_ops.schema_migration",
		"CREATE TABLE mesh_ops.schema_compatibility",
		"CREATE TABLE mesh_ops.data_backfill",
	} {
		if !strings.Contains(platform.SQL, required) {
			t.Errorf("migration SQL missing %q", required)
		}
	}
	if strings.Contains(platform.SQL, "CREATE TABLE mesh.") {
		t.Fatal("platform migration created a business table")
	}

	authority := catalog[1]
	if authority.Description != "tenancy and address authority foundation" {
		t.Fatalf("migration 2 description = %q, want tenancy and address authority foundation", authority.Description)
	}
	for _, required := range []string{
		"REVOKE ALL ON DATABASE",
		"GRANT CONNECT ON DATABASE",
		"CREATE TABLE mesh.deployment",
		"CREATE TABLE mesh.principal",
		"CREATE TABLE mesh.workspace",
		"CREATE TABLE mesh.network",
		"CREATE TABLE mesh.address_realm",
		"CREATE TABLE mesh.address_pool",
		"CREATE TABLE mesh.network_prefix",
		"CREATE TABLE mesh_ops.network_revision",
		"EXCLUDE USING gist",
		"prefix inet_ops WITH &&",
		"ENABLE ROW LEVEL SECURITY",
		"FORCE ROW LEVEL SECURITY",
		"CREATE POLICY",
		"GRANT SELECT",
	} {
		if !strings.Contains(authority.SQL, required) {
			t.Errorf("authority migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"CREATE TABLE mesh.device",
		"CREATE TABLE mesh.access_rule",
		"CREATE TABLE mesh.enrollment",
	} {
		if strings.Contains(authority.SQL, forbidden) {
			t.Errorf("authority migration SQL contains deferred capability %q", forbidden)
		}
	}

	integrity := catalog[2]
	if integrity.Description != "audit and outbox integrity foundation" {
		t.Fatalf("migration 3 description = %q, want audit and outbox integrity foundation", integrity.Description)
	}
	for _, required := range []string{
		"CREATE TABLE mesh_ops.outbox_event",
		"CREATE TABLE mesh_audit.audit_stream",
		"CREATE TABLE mesh_audit.audit_event_identity",
		"CREATE TABLE mesh_audit.authority_mutation",
		"CREATE TABLE mesh_audit.audit_event",
		"PARTITION BY RANGE (occurred_at)",
		"CREATE TABLE mesh_audit.audit_event_default",
		"CREATE CONSTRAINT TRIGGER authority_mutation_evidence_check",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh_audit, mesh_ops, mesh",
		"REVOKE ALL ON FUNCTION mesh_audit.append_authority_evidence",
		"ENABLE ROW LEVEL SECURITY",
		"FORCE ROW LEVEL SECURITY",
		"CREATE TRIGGER deployment_authority_mutation",
		"CREATE TRIGGER principal_authority_mutation",
		"CREATE TRIGGER workspace_authority_mutation",
		"CREATE TRIGGER network_authority_mutation",
		"CREATE TRIGGER address_realm_authority_mutation",
		"CREATE TRIGGER address_pool_authority_mutation",
		"CREATE TRIGGER network_prefix_authority_mutation",
		"outbox_event_pending_idx",
	} {
		if !strings.Contains(integrity.SQL, required) {
			t.Errorf("integrity migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT INSERT ON mesh_ops.outbox_event TO mesh_runtime",
		"GRANT UPDATE ON mesh_ops.outbox_event TO mesh_worker",
		"GRANT EXECUTE ON FUNCTION mesh_audit.append_authority_evidence TO mesh_runtime",
	} {
		if strings.Contains(integrity.SQL, forbidden) {
			t.Errorf("integrity migration SQL exposes deferred serving capability %q", forbidden)
		}
	}

	delivery := catalog[3]
	if delivery.Description != "outbox worker delivery capability" {
		t.Fatalf("migration 4 description = %q, want outbox worker delivery capability", delivery.Description)
	}
	for _, required := range []string{
		"CREATE POLICY outbox_event_worker_policy",
		"TO mesh_worker",
		"GRANT SELECT (",
		"GRANT UPDATE (",
		"GRANT INSERT (",
		"GRANT USAGE, SELECT ON SEQUENCE mesh_ops.outbox_attempt_id_seq TO mesh_worker",
	} {
		if !strings.Contains(delivery.SQL, required) {
			t.Errorf("outbox delivery migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"TO mesh_runtime",
		"GRANT DELETE",
		"GRANT TRUNCATE",
		"GRANT ALL",
		"BYPASSRLS",
	} {
		if strings.Contains(delivery.SQL, forbidden) {
			t.Errorf("outbox delivery migration SQL contains excessive capability %q", forbidden)
		}
	}

	registration := catalog[4]
	if registration.Description != "node enrollment and registration authority" {
		t.Fatalf("migration 5 description = %q, want node enrollment authority", registration.Description)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.enrollment_profile",
		"CREATE TABLE mesh.enrollment_credential",
		"CREATE TABLE mesh.device",
		"CREATE TABLE mesh.device_machine_key_epoch",
		"CREATE TABLE mesh.device_node_key_epoch",
		"CREATE TABLE mesh.pending_registration",
		"CREATE TABLE mesh.enrollment_credential_use",
		"CREATE TABLE mesh.node_address_lease",
		"ENABLE ROW LEVEL SECURITY",
		"FORCE ROW LEVEL SECURITY",
		"CREATE TRIGGER enrollment_credential_authority_mutation",
		"CREATE TRIGGER device_authority_mutation",
		"CREATE TRIGGER node_address_lease_authority_mutation",
		"GRANT EXECUTE ON FUNCTION mesh_audit.append_authority_evidence",
	} {
		if !strings.Contains(registration.SQL, required) {
			t.Errorf("registration migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"plaintext",
		"GRANT DELETE",
		"GRANT TRUNCATE",
		"GRANT ALL",
		"BYPASSRLS",
	} {
		if strings.Contains(registration.SQL, forbidden) {
			t.Errorf("registration migration SQL contains forbidden capability %q", forbidden)
		}
	}
	intentHash := catalog[5]
	if intentHash.Description != "registration intent semantic hash" {
		t.Fatalf("migration 6 description = %q, want registration intent semantic hash", intentHash.Description)
	}
	for _, required := range []string{
		"ADD COLUMN request_hash BYTEA",
		"uuid_send(public_id) || pg_catalog.uuid_send(public_id)",
		"ALTER COLUMN request_hash SET NOT NULL",
		"pending_registration_request_hash_check",
	} {
		if !strings.Contains(intentHash.SQL, required) {
			t.Errorf("registration intent hash migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT UPDATE",
		"DROP COLUMN",
		"DISABLE ROW LEVEL SECURITY",
	} {
		if strings.Contains(intentHash.SQL, forbidden) {
			t.Errorf("registration intent hash migration SQL contains unsafe change %q", forbidden)
		}
	}
	scopeResolver := catalog[6]
	if scopeResolver.Description != "transaction-local public network scope" {
		t.Fatalf("migration 7 description = %q, want public network scope", scopeResolver.Description)
	}
	for _, required := range []string{
		"CREATE POLICY workspace_scope_resolution_policy",
		"CREATE POLICY network_scope_resolution_policy",
		"'mesh.requested_workspace_public_id'",
		"'mesh.requested_network_public_id'",
		"CREATE FUNCTION mesh_ops.set_network_scope",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"pg_catalog.set_config(",
		"'mesh.workspace_id'",
		"'mesh.network_id'",
		"REVOKE ALL ON FUNCTION mesh_ops.set_network_scope",
		"GRANT EXECUTE ON FUNCTION mesh_ops.set_network_scope",
	} {
		if !strings.Contains(scopeResolver.SQL, required) {
			t.Errorf("network scope migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"USING (TRUE)",
		"WITH CHECK (TRUE)",
		"GRANT EXECUTE ON FUNCTION mesh_ops.set_network_scope(UUID, UUID) TO mesh_worker",
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"BYPASSRLS",
	} {
		if strings.Contains(scopeResolver.SQL, forbidden) {
			t.Errorf("network scope migration SQL contains excessive capability %q", forbidden)
		}
	}
	auditStreamHead := catalog[7]
	if auditStreamHead.Description != "transaction-local network audit stream head" {
		t.Fatalf(
			"migration 8 description = %q, want Network audit stream head",
			auditStreamHead.Description,
		)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_audit.lock_network_stream_head",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh_audit, mesh_ops",
		"pg_catalog.current_setting('mesh.workspace_id', TRUE)",
		"pg_catalog.current_setting('mesh.network_id', TRUE)",
		"stream.scope_kind = 'network'",
		"FOR UPDATE",
		"REVOKE ALL ON FUNCTION mesh_audit.lock_network_stream_head",
		"GRANT USAGE ON SCHEMA mesh_audit TO mesh_runtime",
		"GRANT EXECUTE ON FUNCTION mesh_audit.lock_network_stream_head() TO mesh_runtime",
	} {
		if !strings.Contains(auditStreamHead.SQL, required) {
			t.Errorf("Network audit stream head migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(auditStreamHead.SQL, forbidden) {
			t.Errorf("Network audit stream head migration SQL contains excessive capability %q", forbidden)
		}
	}
	inventoryAdvance := catalog[8]
	if inventoryAdvance.Description != "transaction-local network inventory revision advance" {
		t.Fatalf(
			"migration 9 description = %q, want Network inventory revision advance",
			inventoryAdvance.Description,
		)
	}
	for _, required := range []string{
		"CREATE POLICY network_revision_scoped_read_policy",
		"FOR SELECT",
		"CREATE POLICY network_revision_scoped_mutation_policy",
		"FOR UPDATE",
		"TO mesh_migrator",
		"CREATE FUNCTION mesh_ops.advance_network_inventory_revision",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh_ops",
		"pg_catalog.current_setting('mesh.workspace_id', TRUE)",
		"pg_catalog.current_setting('mesh.network_id', TRUE)",
		"UPDATE mesh_ops.network_revision AS revision",
		"network_revision = revision.network_revision + 1",
		"inventory_revision = revision.inventory_revision + 1",
		"REVOKE ALL ON FUNCTION mesh_ops.advance_network_inventory_revision",
		"GRANT EXECUTE ON FUNCTION mesh_ops.advance_network_inventory_revision() TO mesh_runtime",
	} {
		if !strings.Contains(inventoryAdvance.SQL, required) {
			t.Errorf("Network inventory revision migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"USING (TRUE)",
		"WITH CHECK (TRUE)",
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(inventoryAdvance.SQL, forbidden) {
			t.Errorf("Network inventory revision migration SQL contains excessive capability %q", forbidden)
		}
	}
	replayEvidence := catalog[9]
	if replayEvidence.Description != "registration idempotency replay evidence" {
		t.Fatalf(
			"migration 10 description = %q, want registration replay evidence",
			replayEvidence.Description,
		)
	}
	for _, required := range []string{
		"ADD COLUMN intent_format_version SMALLINT NOT NULL DEFAULT 1",
		"ALTER COLUMN intent_format_version SET DEFAULT 2",
		"ADD COLUMN requested_node_key BYTEA",
		"ADD COLUMN completed_hostname TEXT",
		"ADD COLUMN completed_disposition TEXT",
		"ADD COLUMN completed_network_revision BIGINT",
		"pending_registration_requested_node_key_check",
		"pg_catalog.octet_length(requested_node_key) = 32",
		"pending_registration_completion_replay_check",
		"completed_disposition IN ('created', 'resumed')",
		"completed_network_revision > 0",
		"GRANT UPDATE (",
		"completed_hostname",
		"completed_disposition",
		"completed_network_revision",
		") ON mesh.pending_registration TO mesh_runtime",
	} {
		if !strings.Contains(replayEvidence.SQL, required) {
			t.Errorf("registration replay evidence migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"plaintext",
		"GRANT DELETE",
		"GRANT TRUNCATE",
		"GRANT ALL",
		"BYPASSRLS",
		"DISABLE ROW LEVEL SECURITY",
	} {
		if strings.Contains(replayEvidence.SQL, forbidden) {
			t.Errorf("registration replay evidence migration SQL contains unsafe capability %q", forbidden)
		}
	}
	networkRevisionLock := catalog[10]
	if networkRevisionLock.Description != "transaction-local network revision lock" {
		t.Fatalf(
			"migration 11 description = %q, want Network revision lock",
			networkRevisionLock.Description,
		)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.lock_network_revision",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh_ops",
		"pg_catalog.current_setting('mesh.workspace_id', TRUE)",
		"pg_catalog.current_setting('mesh.network_id', TRUE)",
		"FROM mesh_ops.network_revision AS revision",
		"FOR UPDATE",
		"REVOKE ALL ON FUNCTION mesh_ops.lock_network_revision",
		"GRANT EXECUTE ON FUNCTION mesh_ops.lock_network_revision() TO mesh_runtime",
	} {
		if !strings.Contains(networkRevisionLock.SQL, required) {
			t.Errorf("Network revision lock migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"USING (TRUE)",
		"WITH CHECK (TRUE)",
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(networkRevisionLock.SQL, forbidden) {
			t.Errorf("Network revision lock migration SQL contains excessive capability %q", forbidden)
		}
	}
	registrationTransactionLocks := catalog[11]
	if registrationTransactionLocks.Description != "registration transaction scoped lock helpers" {
		t.Fatalf(
			"migration 12 description = %q, want registration transaction lock helpers",
			registrationTransactionLocks.Description,
		)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.lock_registration_credential",
		"CREATE FUNCTION mesh_ops.lock_registration_prefixes",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"pg_catalog.current_setting('mesh.workspace_id', TRUE)",
		"pg_catalog.current_setting('mesh.network_id', TRUE)",
		"FOR UPDATE OF credential",
		"pg_catalog.pg_advisory_xact_lock(",
		"meshtransit:registration_allocator:",
		"REVOKE ALL ON FUNCTION mesh_ops.lock_registration_credential(UUID) FROM PUBLIC",
		"REVOKE ALL ON FUNCTION mesh_ops.lock_registration_prefixes(BIGINT) FROM PUBLIC",
		"GRANT EXECUTE ON FUNCTION mesh_ops.lock_registration_credential(UUID) TO mesh_runtime",
		"GRANT EXECUTE ON FUNCTION mesh_ops.lock_registration_prefixes(BIGINT) TO mesh_runtime",
	} {
		if !strings.Contains(registrationTransactionLocks.SQL, required) {
			t.Errorf("registration transaction lock migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"FOR UPDATE OF realm, pool, prefix",
		"TO mesh_worker",
	} {
		if strings.Contains(registrationTransactionLocks.SQL, forbidden) {
			t.Errorf("registration transaction lock migration SQL contains excessive capability %q", forbidden)
		}
	}
	intakeScope := catalog[12]
	if intakeScope.Description != "registration intake scope resolution" {
		t.Fatalf(
			"migration 13 description = %q, want registration intake scope resolution",
			intakeScope.Description,
		)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.resolve_registration_intake_scope",
		"RETURNS TABLE (",
		"deployment_public_id UUID",
		"workspace_public_id UUID",
		"network_public_id UUID",
		"recovery_epoch BIGINT",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"credential.public_id = p_credential_public_id",
		"deployment.state = 'active'",
		"deployment.recovery_state = 'verified'",
		"workspace.state = 'active'",
		"network.state = 'active'",
		"REVOKE ALL ON FUNCTION mesh_ops.resolve_registration_intake_scope(UUID) FROM PUBLIC",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_registration_intake_scope(UUID) TO mesh_runtime",
	} {
		if !strings.Contains(intakeScope.SQL, required) {
			t.Errorf("registration intake scope migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(intakeScope.SQL, forbidden) {
			t.Errorf("registration intake scope migration SQL contains excessive capability %q", forbidden)
		}
	}
	intakeScopeQuery := catalog[13]
	if intakeScopeQuery.Description != "registration intake scope query correction" {
		t.Fatalf(
			"migration 14 description = %q, want registration intake scope query correction",
			intakeScopeQuery.Description,
		)
	}
	for _, required := range []string{
		"CREATE POLICY workspace_registration_intake_scope_policy",
		"CREATE POLICY network_registration_intake_scope_policy",
		"TO mesh_migrator",
		"credential.workspace_id = workspace.id",
		"credential.network_id = network.id",
		"CREATE OR REPLACE FUNCTION mesh_ops.resolve_registration_intake_scope",
		"LANGUAGE plpgsql",
		"SECURITY DEFINER",
		"mesh.registration_intake_credential_public_id",
		"credential.public_id = p_credential_public_id",
		"REVOKE ALL ON FUNCTION mesh_ops.resolve_registration_intake_scope(UUID) FROM PUBLIC",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_registration_intake_scope(UUID) TO mesh_runtime",
	} {
		if !strings.Contains(intakeScopeQuery.SQL, required) {
			t.Errorf("registration intake scope-query migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(intakeScopeQuery.SQL, forbidden) {
			t.Errorf("registration intake scope-query migration SQL contains excessive capability %q", forbidden)
		}
	}
	mapSessionScope := catalog[14]
	if mapSessionScope.Description != "map session scope resolution" {
		t.Fatalf(
			"migration 15 description = %q, want map session scope resolution",
			mapSessionScope.Description,
		)
	}
	for _, required := range []string{
		"CREATE POLICY workspace_map_session_scope_policy",
		"CREATE POLICY network_map_session_scope_policy",
		"TO mesh_migrator",
		"mesh.map_session_workspace_id",
		"mesh.map_session_network_id",
		"CREATE FUNCTION mesh_ops.resolve_map_session_scope",
		"p_machine_key_fingerprint BYTEA",
		"p_node_key BYTEA",
		"RETURNS TABLE (",
		"workspace_public_id UUID",
		"network_public_id UUID",
		"recovery_epoch BIGINT",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"machine.fingerprint = p_machine_key_fingerprint",
		"node_key.public_key = p_node_key",
		"machine.epoch = device.current_machine_key_epoch",
		"node_key.epoch = device.current_node_key_epoch",
		"deployment.recovery_state = 'verified'",
		"device.expires_at > pg_catalog.transaction_timestamp()",
		"REVOKE ALL ON FUNCTION mesh_ops.resolve_map_session_scope(BYTEA, BYTEA) FROM PUBLIC",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_map_session_scope(BYTEA, BYTEA) TO mesh_runtime",
	} {
		if !strings.Contains(mapSessionScope.SQL, required) {
			t.Errorf("map session scope migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(mapSessionScope.SQL, forbidden) {
			t.Errorf("map session scope migration SQL contains excessive capability %q", forbidden)
		}
	}
	peerCandidates := catalog[15]
	if peerCandidates.Description != "bounded map session peer candidate projection" {
		t.Fatalf(
			"migration 16 description = %q, want map peer candidates",
			peerCandidates.Description,
		)
	}
	for _, required := range []string{
		"CREATE POLICY workspace_map_peer_candidate_scope_policy",
		"CREATE POLICY network_map_peer_candidate_scope_policy",
		"TO mesh_migrator",
		"CREATE FUNCTION mesh_ops.load_map_peer_candidates",
		"p_machine_key_fingerprint BYTEA",
		"p_node_key BYTEA",
		"p_limit INTEGER",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"candidate.workspace_id = scoped_workspace_id",
		"candidate.network_id = scoped_network_id",
		"candidate.id <> authenticated_device_id",
		"candidate.state = 'active'",
		"candidate.expires_at > pg_catalog.transaction_timestamp()",
		"machine.state = 'active'",
		"current_node_key.state = 'active'",
		"owner.state = 'active'",
		"lease.state = 'active'",
		"ORDER BY candidate.created_at DESC, candidate.id DESC",
		"LIMIT p_limit",
		"REVOKE ALL ON FUNCTION mesh_ops.load_map_peer_candidates",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_map_peer_candidates(BYTEA, BYTEA, INTEGER)",
	} {
		if !strings.Contains(peerCandidates.SQL, required) {
			t.Errorf("map peer candidate migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"USING (TRUE)",
		"WITH CHECK (TRUE)",
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(peerCandidates.SQL, forbidden) {
			t.Errorf("map peer candidate migration SQL contains excessive capability %q", forbidden)
		}
	}
	identityProviderAuthority := catalog[16]
	if identityProviderAuthority.Description != "identity provider authority foundation" {
		t.Fatalf(
			"migration 17 description = %q, want identity provider authority foundation",
			identityProviderAuthority.Description,
		)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.identity_provider",
		"CREATE TABLE mesh.identity_provider_generation",
		"CREATE TABLE mesh.identity_provider_client",
		"CREATE TABLE mesh.workspace_identity_provider",
		"identity_provider_current_generation_fk",
		"CREATE CONSTRAINT TRIGGER identity_provider_current_generation_state_check",
		"CREATE CONSTRAINT TRIGGER identity_provider_generation_current_check",
		"workspace_identity_provider_workspace_fk",
		"workspace_identity_provider_client_fk",
		"ENABLE ROW LEVEL SECURITY",
		"FORCE ROW LEVEL SECURITY",
		"CREATE POLICY workspace_identity_provider_exact_scope_policy",
		"CREATE TRIGGER identity_provider_authority_mutation",
		"CREATE TRIGGER identity_provider_generation_authority_mutation",
		"CREATE TRIGGER identity_provider_client_authority_mutation",
		"CREATE TRIGGER workspace_identity_provider_authority_mutation",
		"REVOKE ALL ON",
	} {
		if !strings.Contains(identityProviderAuthority.SQL, required) {
			t.Errorf("identity provider migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"client_secret TEXT",
		"provider_token",
		"refresh_token",
		"raw_subject",
		"GRANT SELECT ON",
		"GRANT INSERT ON",
		"GRANT UPDATE ON",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(identityProviderAuthority.SQL, forbidden) {
			t.Errorf("identity provider migration SQL contains unsafe capability %q", forbidden)
		}
	}
	accountIdentityPermission := catalog[17]
	if accountIdentityPermission.Description != "account identity and permission catalog foundation" {
		t.Fatalf(
			"migration 18 description = %q, want account identity and permission catalog foundation",
			accountIdentityPermission.Description,
		)
	}
	for _, required := range []string{
		"ADD CONSTRAINT principal_deployment_id_kind_unique",
		"CREATE TABLE mesh.account",
		"account_principal_scope_fk",
		"CREATE TABLE mesh.identity_subject",
		"identity_subject_provider_scope_fk",
		"identity_subject_account_scope_fk",
		"subject_digest_algorithm = 'hmac-sha256-v1'",
		"CREATE TABLE mesh.permission",
		"permission_immutable",
		"catalog_version",
		"'share.read'",
		"'share.offer'",
		"'share.accept'",
		"'share.revoke'",
		"CREATE TRIGGER account_authority_mutation",
		"CREATE TRIGGER identity_subject_authority_mutation",
		"REVOKE ALL ON",
	} {
		if !strings.Contains(accountIdentityPermission.SQL, required) {
			t.Errorf("account identity migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"raw_subject",
		"subject TEXT",
		"email TEXT",
		"provider_token",
		"refresh_token",
		"GRANT SELECT ON",
		"GRANT INSERT ON",
		"GRANT UPDATE ON",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(accountIdentityPermission.SQL, forbidden) {
			t.Errorf("account identity migration SQL contains unsafe capability %q", forbidden)
		}
	}
	humanAuthenticationSession := catalog[18]
	if humanAuthenticationSession.Description != "human authentication and account session authority" {
		t.Fatalf(
			"migration 19 description = %q, want human authentication and account session authority",
			humanAuthenticationSession.Description,
		)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.auth_transaction",
		"CREATE TABLE mesh.account_session",
		"CREATE TABLE mesh.identity_link_request",
		"CREATE TABLE mesh.oidc_logout_replay",
		"identity_subject_provider_principal_id_unique",
		"auth_transaction_provider_generation_fk",
		"account_session_subject_scope_fk",
		"identity_link_request_current_proof_fk",
		"oidc_logout_replay_provider_client_fk",
		"CREATE FUNCTION mesh_ops.enforce_human_auth_state_transition",
		"CREATE FUNCTION mesh_ops.resolve_account_session",
		"CREATE FUNCTION mesh_ops.revoke_account_session",
		"pg_catalog.set_config(",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"CREATE TRIGGER auth_transaction_authority_mutation",
		"CREATE TRIGGER account_session_authority_mutation",
		"CREATE TRIGGER identity_link_request_authority_mutation",
		"CREATE TRIGGER oidc_logout_replay_authority_mutation",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_account_session",
		"GRANT EXECUTE ON FUNCTION mesh_ops.revoke_account_session",
	} {
		if !strings.Contains(humanAuthenticationSession.SQL, required) {
			t.Errorf("human authentication migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"state_token",
		"nonce TEXT",
		"pkce_verifier TEXT",
		"session_token TEXT",
		"provider_token",
		"refresh_token",
		"raw_subject",
		"email TEXT",
		"USING (TRUE)",
		"WITH CHECK (TRUE)",
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(humanAuthenticationSession.SQL, forbidden) {
			t.Errorf("human authentication migration SQL contains unsafe capability %q", forbidden)
		}
	}
	compiledPacketPolicy := catalog[19]
	if compiledPacketPolicy.Description != "compiled packet policy authority" {
		t.Fatalf(
			"migration 20 description = %q, want compiled packet policy authority",
			compiledPacketPolicy.Description,
		)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.policy_release",
		"CREATE TABLE mesh.compiled_policy_rule",
		"INT4MULTIRANGE",
		"policy_release_active_uidx",
		"compiled_policy_rule_release_scope_fk",
		"compiled_policy_rule_source_device_scope_fk",
		"compiled_policy_rule_destination_device_scope_fk",
		"compiled_policy_rule_edge_unique",
		"CREATE FUNCTION mesh_ops.advance_network_policy_revision",
		"network_revision = revision.network_revision + 1",
		"policy_revision = revision.policy_revision + 1",
		"ENABLE ROW LEVEL SECURITY",
		"FORCE ROW LEVEL SECURITY",
		"CREATE POLICY policy_release_exact_scope_policy",
		"CREATE POLICY compiled_policy_rule_exact_scope_policy",
		"CREATE TRIGGER policy_release_authority_mutation",
		"CREATE TRIGGER compiled_policy_rule_authority_mutation",
		"CREATE TRIGGER compiled_policy_rule_immutable",
		"GRANT SELECT ON",
		"TO mesh_runtime",
	} {
		if !strings.Contains(compiledPacketPolicy.SQL, required) {
			t.Errorf("compiled packet policy migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT INSERT ON",
		"GRANT UPDATE ON",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
		"TO mesh_observer",
	} {
		if strings.Contains(compiledPacketPolicy.SQL, forbidden) {
			t.Errorf("compiled packet policy migration SQL contains unsafe capability %q", forbidden)
		}
	}
	policyPublication := catalog[20]
	if policyPublication.Description != "atomic packet policy publication" {
		t.Fatalf(
			"migration 21 description = %q, want atomic packet policy publication",
			policyPublication.Description,
		)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.lock_active_policy_release",
		"CREATE FUNCTION mesh_ops.publish_compiled_policy",
		"p_expected_policy_revision",
		"FOR UPDATE",
		"MT001",
		"jsonb_to_recordset",
		"advance_network_policy_revision",
		"activated_network_revision",
		"compiled policy rule count mismatch",
		"GRANT EXECUTE ON FUNCTION mesh_ops.publish_compiled_policy",
		"GRANT EXECUTE ON FUNCTION mesh_ops.lock_active_policy_release",
		"TO mesh_runtime",
	} {
		if !strings.Contains(policyPublication.SQL, required) {
			t.Errorf("policy publication migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT INSERT ON",
		"GRANT UPDATE ON",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
		"TO mesh_observer",
	} {
		if strings.Contains(policyPublication.SQL, forbidden) {
			t.Errorf("policy publication migration SQL contains unsafe capability %q", forbidden)
		}
	}
	mapPeerProtocolIdentity := catalog[21]
	if mapPeerProtocolIdentity.Description != "map peer protocol identity projection" {
		t.Fatalf(
			"migration 22 description = %q, want map peer protocol identity projection",
			mapPeerProtocolIdentity.Description,
		)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.load_map_peer_candidates_v2",
		"numeric_node_id BIGINT",
		"numeric_owner_id BIGINT",
		"mesh_ops.load_map_peer_candidates(",
		"candidate.public_id = projected.node_public_id",
		"owner.public_id = projected.owner_public_id",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"REVOKE ALL ON FUNCTION mesh_ops.load_map_peer_candidates_v2",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_map_peer_candidates_v2",
		"TO mesh_runtime",
	} {
		if !strings.Contains(mapPeerProtocolIdentity.SQL, required) {
			t.Errorf("map peer protocol identity migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(mapPeerProtocolIdentity.SQL, forbidden) {
			t.Errorf("map peer protocol identity migration SQL contains unsafe capability %q", forbidden)
		}
	}
	networkIdempotency := catalog[22]
	if networkIdempotency.Description != "network idempotency record foundation" {
		t.Fatalf(
			"migration 23 description = %q, want Network idempotency record foundation",
			networkIdempotency.Description,
		)
	}
	for _, required := range []string{
		"CREATE TABLE mesh_ops.idempotency_record",
		"hmac-sha256-v1",
		"UNIQUE NULLS NOT DISTINCT",
		"idempotency_record_outbox_unique UNIQUE",
		"CREATE FUNCTION mesh_ops.enforce_idempotency_record_transition",
		"CREATE FUNCTION mesh_ops.enforce_idempotency_record_completion",
		"CREATE FUNCTION mesh_ops.claim_network_idempotency",
		"CREATE FUNCTION mesh_ops.load_network_idempotency",
		"CREATE FUNCTION mesh_ops.complete_network_idempotency",
		"CREATE CONSTRAINT TRIGGER idempotency_record_completion",
		"ENABLE ROW LEVEL SECURITY",
		"FORCE ROW LEVEL SECURITY",
		"CREATE POLICY idempotency_record_exact_scope_policy",
		"GRANT EXECUTE ON FUNCTION mesh_ops.claim_network_idempotency",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_network_idempotency",
		"GRANT EXECUTE ON FUNCTION mesh_ops.complete_network_idempotency",
	} {
		if !strings.Contains(networkIdempotency.SQL, required) {
			t.Errorf("Network idempotency migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"plaintext",
		"GRANT SELECT ON mesh_ops.idempotency_record TO mesh_runtime",
		"GRANT INSERT (",
		"GRANT UPDATE (",
		"GRANT DELETE",
		"GRANT TRUNCATE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
		"TO mesh_observer",
	} {
		if strings.Contains(networkIdempotency.SQL, forbidden) {
			t.Errorf("Network idempotency migration SQL contains unsafe capability %q", forbidden)
		}
	}
	accountSessionResolution := catalog[23]
	if accountSessionResolution.Description != "deployment-bound account session resolution" {
		t.Fatalf(
			"migration 24 description = %q, want deployment-bound account session resolution",
			accountSessionResolution.Description,
		)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.resolve_account_session_v2",
		"p_expected_deployment_public_id UUID",
		"p_expected_recovery_epoch BIGINT",
		"deployment.installation_public_id = p_expected_deployment_public_id",
		"deployment.recovery_epoch = p_expected_recovery_epoch",
		"session.deployment_recovery_epoch = p_expected_recovery_epoch",
		"session.principal_authority_generation",
		"session.account_session_generation",
		"session.provider_generation",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_account_session_v2",
	} {
		if !strings.Contains(accountSessionResolution.SQL, required) {
			t.Errorf("Account Session resolution migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
		"TO mesh_observer",
	} {
		if strings.Contains(accountSessionResolution.SQL, forbidden) {
			t.Errorf("Account Session resolution migration SQL contains unsafe capability %q", forbidden)
		}
	}
	networkManagementRBAC := catalog[24]
	if networkManagementRBAC.Description != "network management RBAC authority" {
		t.Fatalf(
			"migration 25 description = %q, want Network management RBAC authority",
			networkManagementRBAC.Description,
		)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.workspace_membership",
		"CREATE TABLE mesh.role_definition",
		"CREATE TABLE mesh.role_permission",
		"CREATE TABLE mesh.role_binding",
		"CREATE FUNCTION mesh_ops.resolve_network_permission_v1",
		"p_session_public_id UUID",
		"session.principal_authority_generation = p_principal_authority_generation",
		"membership.state = 'active'",
		"binding.state = 'active'",
		"permission.permission_key = p_permission_key",
		"FOR SHARE OF session",
		"FORCE ROW LEVEL SECURITY",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_network_permission_v1",
	} {
		if !strings.Contains(networkManagementRBAC.SQL, required) {
			t.Errorf("Network management RBAC migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT ON mesh.workspace_membership TO mesh_runtime",
		"GRANT SELECT ON mesh.role_binding TO mesh_runtime",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
		"TO mesh_observer",
	} {
		if strings.Contains(networkManagementRBAC.SQL, forbidden) {
			t.Errorf("Network management RBAC migration SQL contains unsafe capability %q", forbidden)
		}
	}
	if LatestVersion() != 184 {
		t.Fatalf("LatestVersion() = %d, want 184", LatestVersion())
	}
}

func TestResourceSharingNeverExpiryMigrationSeparatesOfferDeadline(t *testing.T) {
	t.Parallel()
	migration := Catalog()[90]
	if migration.Version != 91 || migration.Description != resourceSharingNeverExpiryDescription {
		t.Fatalf("migration 91 = %+v, want separate sharing deadlines", migration)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.create_resource_share_offer_v2",
		"CREATE FUNCTION mesh_ops.decide_resource_share_offer_base_v2",
		"CREATE FUNCTION mesh_ops.decide_resource_share_offer_v3",
		"p_provider_workspace_id = p_consumer_workspace_id",
		"p_expires_at = TIMESTAMPTZ '2200-01-01 00:00:00+00'",
		"p_occurred_at + INTERVAL '168 hours'",
		"ELSE p_expires_at",
		"OR NOT p_occurred_at < offer_row.expires_at",
		"WHEN export_row.expires_at = TIMESTAMPTZ '2200-01-01 00:00:00+00'",
		"ELSE LEAST(offer_row.expires_at, export_row.expires_at)",
		"FROM mesh_ops.decide_resource_share_offer_base_v2",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("migration 91 missing %q", required)
		}
	}
	for _, forbidden := range []string{"GRANT EXECUTE", "BYPASSRLS", "DROP "} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("migration 91 contains unsafe capability %q", forbidden)
		}
	}
	ownership := ResourceSharingNeverExpiryOwnershipSQL()
	for _, required := range []string{
		"OWNER TO mesh_share_writer",
		"GRANT EXECUTE ON FUNCTION mesh_ops.create_resource_share_offer_v2",
		"GRANT EXECUTE ON FUNCTION mesh_ops.decide_resource_share_offer_v3",
		"REVOKE ALL ON FUNCTION mesh_ops.decide_resource_share_offer_base_v2",
	} {
		if !strings.Contains(ownership, required) {
			t.Errorf("migration 91 ownership missing %q", required)
		}
	}
}

func TestNetworkEnrollmentMembershipMigrationKeepsExactScope(t *testing.T) {
	t.Parallel()
	migration := Catalog()[58]
	if migration.Version != 59 || migration.Description != networkEnrollmentMembershipDescription {
		t.Fatalf("migration 59 = %+v, want Network enrollment membership", migration)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.network_membership",
		"CONSTRAINT network_membership_network_scope_fk FOREIGN KEY",
		"CONSTRAINT network_membership_workspace_member_fk FOREIGN KEY",
		"CREATE UNIQUE INDEX network_membership_current_uidx",
		"CREATE TRIGGER network_membership_authority_mutation",
		"ALTER TABLE mesh.network_membership FORCE ROW LEVEL SECURITY",
		"workspace_id = mesh_ops.current_workspace_id()",
		"network_id = mesh_ops.current_network_id()",
		"WITH CHECK (",
		"REVOKE ALL ON TABLE mesh.network_membership",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Network membership SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "BYPASSRLS",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Network membership SQL grants broad authority through %q", forbidden)
		}
	}
}

func TestBrowserIntentIssueUsesOnlyNarrowRuntimeFunction(t *testing.T) {
	t.Parallel()
	migration := Catalog()[62]
	if migration.Version != 63 || migration.Description != browserRegistrationIntentIssueDescription {
		t.Fatalf("migration 63 = %+v, want browser intent issuance", migration)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.issue_browser_registration_intent_v1",
		"SECURITY DEFINER",
		"FOR SHARE",
		"FOR UPDATE",
		"ON CONFLICT DO NOTHING",
		"current_intent.machine_key <> p_machine_key",
		"current_intent.requested_node_key <> p_requested_node_key",
		"GRANT EXECUTE ON FUNCTION mesh_ops.issue_browser_registration_intent_v1",
		"TO mesh_runtime",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("browser intent issuance SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "BYPASSRLS",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("browser intent issuance SQL grants broad authority through %q", forbidden)
		}
	}
}

func TestBrowserFollowupRequiresExactMachineAndNode(t *testing.T) {
	t.Parallel()
	migration := Catalog()[63]
	if migration.Version != 64 || migration.Description != browserRegistrationIntentFollowupDescription {
		t.Fatalf("migration 64 = %+v, want browser followup", migration)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.read_browser_registration_followup_v1",
		"SECURITY DEFINER",
		"intent.token_digest = p_token_digest",
		"intent.machine_key = p_machine_key",
		"intent.machine_key_fingerprint = p_machine_key_fingerprint",
		"intent.requested_node_key = p_requested_node_key",
		"intent.issued_recovery_epoch = p_recovery_epoch",
		"intent.expires_at > pg_catalog.transaction_timestamp()",
		"GRANT EXECUTE ON FUNCTION mesh_ops.read_browser_registration_followup_v1",
		"TO mesh_runtime",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("browser followup SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "BYPASSRLS",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("browser followup SQL grants broad authority through %q", forbidden)
		}
	}
}

func TestBrowserLandingRequiresCurrentSSOSession(t *testing.T) {
	t.Parallel()
	migration := Catalog()[64]
	if migration.Version != 65 || migration.Description != browserRegistrationLandingDescription {
		t.Fatalf("migration 65 = %+v, want browser landing", migration)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.read_browser_registration_landing_v1",
		"SECURITY DEFINER",
		"mesh_ops.resolve_account_session_v2(",
		"intent.token_digest = p_intent_token_digest",
		"intent.issued_recovery_epoch = admitted.deployment_recovery_epoch",
		"admitted.login_workspace_public_id IS NOT NULL",
		"intent.expires_at > pg_catalog.transaction_timestamp()",
		"GRANT EXECUTE ON FUNCTION mesh_ops.read_browser_registration_landing_v1",
		"TO mesh_runtime",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("browser landing SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "BYPASSRLS",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("browser landing SQL grants broad authority through %q", forbidden)
		}
	}
}

func TestBrowserApprovalAuthorityLocksAndRechecksExactEligibility(t *testing.T) {
	t.Parallel()
	migration := Catalog()[65]
	if migration.Version != 66 || migration.Description != browserRegistrationApprovalAuthorityDescription {
		t.Fatalf("migration 66 = %+v, want browser approval authority", migration)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.lock_browser_registration_approval_authority_v1",
		"SECURITY DEFINER",
		"FOR UPDATE OF intent",
		"mesh_ops.lock_network_revision()",
		"FOR SHARE OF subject, provider, client",
		"mesh.network_membership",
		"profile.interactive_authorization_enabled",
		"mesh_ops.resolve_account_session_v2(",
		"v_now := pg_catalog.clock_timestamp()",
		"GRANT EXECUTE ON FUNCTION mesh_ops.lock_browser_registration_approval_authority_v1",
		"TO mesh_runtime",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("browser approval authority SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "BYPASSRLS",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("browser approval authority SQL grants broad authority through %q", forbidden)
		}
	}
}

func TestBrowserApprovalRecordRequiresNarrowAuthorityAndEvidence(t *testing.T) {
	t.Parallel()
	migration := Catalog()[66]
	if migration.Version != 67 || migration.Description != browserRegistrationApprovalRecordDescription {
		t.Fatalf("migration 67 = %+v, want browser approval record", migration)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.record_browser_registration_approval_v1",
		"SECURITY DEFINER",
		"mesh_ops.lock_browser_registration_approval_authority_v1(",
		"INSERT INTO mesh.pending_registration",
		"'interactive'",
		"'authorized'",
		"UPDATE mesh.browser_registration_intent",
		"state = 'approved'",
		"mesh.change_public_id",
		"GRANT EXECUTE ON FUNCTION mesh_ops.record_browser_registration_approval_v1",
		"TO mesh_runtime",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("browser approval record SQL missing %q", required)
		}
	}
}

func TestBrowserCompletionAuthorityBindsNoiseAndApprovedSession(t *testing.T) {
	t.Parallel()
	migration := Catalog()[67]
	if migration.Version != 68 || migration.Description != browserRegistrationCompletionAuthorityDescription {
		t.Fatalf("migration 68 = %+v, want browser completion authority", migration)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.lock_browser_registration_completion_authority_v1",
		"SECURITY DEFINER",
		"intent.token_digest=p_intent_token_digest",
		"intent.machine_key=p_machine_key",
		"intent.requested_node_key=p_requested_node_key",
		"intent.approved_session_public_id",
		"mesh_ops.lock_browser_registration_approval_authority_v1(",
		"FOR UPDATE",
		"pending_row.state <> 'authorized'",
		"pending_row.request_hash <> expected_request_hash",
		"GRANT EXECUTE ON FUNCTION mesh_ops.lock_browser_registration_completion_authority_v1",
		"CREATE FUNCTION mesh_ops.complete_browser_registration_intent_v1",
		"CREATE FUNCTION mesh_ops.read_completed_browser_registration_v1",
		"intent.approved_workspace_public_id",
		"mesh_ops.set_network_scope(",
		"TO mesh_runtime",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("browser completion authority SQL missing %q", required)
		}
	}
}

func TestSubjectResolutionMigrationIsAdditiveNoGrant(t *testing.T) {
	t.Parallel()
	migration := Catalog()[31]
	for _, required := range []string{"CREATE FUNCTION mesh_ops.resolve_oidc_login_subject_v1", "SECURITY DEFINER", "SET search_path = pg_catalog, mesh, mesh_ops", "matched_subject AS MATERIALIZED", "LIMIT 2", "pg_catalog.count(*) FROM matched_subject", "pg_catalog.clock_timestamp()", "auth.state = 'consuming'", "auth.binding_semantic_hash = p_binding_hash", "auth.consumed_at = p_consumed_at", "provider.current_generation = p_provider_generation", "deployment.recovery_epoch = p_recovery_epoch", "membership.state = 'active'", "membership.expires_at > decision.at", "account.recovery_state = 'verified'", "principal.kind = 'account'", "EXCEPTION WHEN OTHERS THEN", "FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer", "TO mesh_runtime"} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("subject resolution SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{"CREATE TABLE", "CREATE INDEX", "ALTER TABLE", "INSERT INTO", "UPDATE mesh.", "DELETE FROM", "FOR SHARE", "FOR UPDATE", "GRANT SELECT", "GRANT ALL", "DROP ", "BYPASSRLS"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("subject read has excess capability %q", forbidden)
		}
	}
	if migration.MinimumReaderGeneration != 1 || migration.MaximumReaderGeneration != 1 || migration.MinimumWriterGeneration != 1 || migration.MaximumWriterGeneration != 1 {
		t.Fatal("read capability changed application generations")
	}
}

func TestOIDCLoginRouteAdmissionIsNarrowReadOnlyCapability(t *testing.T) {
	t.Parallel()
	admission := Catalog()[27]
	if admission.Description != "durable OIDC login route admission" {
		t.Fatalf("migration 28 description = %q", admission.Description)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.admit_oidc_login_route_v1",
		"RETURNS BOOLEAN", "SECURITY DEFINER", "SET search_path = pg_catalog, mesh, mesh_ops",
		"SELECT EXISTS", "INTO STRICT admitted", "EXCEPTION WHEN OTHERS",
		"mesh.requested_workspace_public_id", "p_workspace_public_id::TEXT",
		"deployment.recovery_epoch = p_recovery_epoch",
		"provider.current_generation = p_provider_generation",
		"provider.authorization_endpoint = p_authorization_endpoint",
		"provider.token_endpoint = p_token_endpoint",
		"client.allowed_scopes = p_scopes", "client.allowed_algorithms = p_allowed_algorithms",
		"p_redirect_uri = ANY (client.redirect_uris)", "workspace_provider.organization_digest IS NULL",
		"FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer", "TO mesh_runtime;",
	} {
		if !strings.Contains(admission.SQL, required) {
			t.Errorf("route admission SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"INSERT INTO", "UPDATE mesh.", "DELETE FROM", "FOR SHARE", "FOR UPDATE",
		"BYPASSRLS", "ALTER TABLE", "DROP ",
	} {
		if strings.Contains(admission.SQL, forbidden) {
			t.Errorf("route admission SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestOIDCPendingBrowserEvidenceIsReadOnlyAndNotAClaim(t *testing.T) {
	t.Parallel()
	migration := Catalog()[28]
	if migration.Description != "read-only OIDC pending browser evidence" {
		t.Fatal("incorrect migration 29 description")
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.load_oidc_pending_browser_v1", "SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops", "mesh_ops.admit_oidc_login_route_v1",
		"p_workspace_public_id::TEXT", "EXCEPTION WHEN OTHERS", "pg_catalog.clock_timestamp()",
		"auth.state = 'pending' AND auth.version = 1", "auth.binding_semantic_hash IS NOT NULL",
		"auth.state_digest = p_state_digest", "auth.return_route_id = p_return_route_id",
		"auth.expires_at > observed_at", "provider.current_generation = p_provider_generation",
		"client.allowed_scopes = p_scopes", "client.allowed_algorithms = p_allowed_algorithms",
		"FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer", "TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("pending browser SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT UPDATE", "GRANT INSERT", "GRANT DELETE", "GRANT ALL", "BYPASSRLS",
		"INSERT INTO", "UPDATE mesh.", "DELETE FROM", "ALTER TABLE", "FOR SHARE", "FOR UPDATE", "DROP ",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("pending browser SQL excessive capability %q", forbidden)
		}
	}
}

func TestBrowserClaimMigrationPreservesBindingAndExplicitLockOrder(t *testing.T) {
	t.Parallel()
	migration := Catalog()[29]
	if migration.Description != "single-use OIDC browser transaction claim" {
		t.Fatal("incorrect claim description")
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.claim_oidc_browser_v1", "SECURITY DEFINER", "SET search_path = pg_catalog, mesh, mesh_ops",
		"mesh_ops.admit_oidc_login_route_v1", "EXCEPTION WHEN OTHERS", "p_workspace_public_id::TEXT",
		"auth.state = 'pending' AND auth.version = p_expected_version AND auth.binding_semantic_hash = p_binding_hash",
		"auth.pkce_verifier_encryption_algorithm = 'aead-aes-256-gcm-v1'", "auth.expires_at > observed_at",
		"SET state = 'consuming', version = auth.version + 1, consumed_at = observed_at",
		"FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer", "TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("claim SQL missing %q", required)
		}
	}
	previous := -1
	for _, lock := range []string{
		"FROM mesh.workspace WHERE", "FROM mesh.deployment WHERE", "FROM mesh.identity_provider AS provider",
		"FROM mesh.identity_provider_generation AS generation", "FROM mesh.identity_provider_client AS client",
		"FROM mesh.workspace_identity_provider AS workspace_provider", "FOR UPDATE OF auth", "observed_at := pg_catalog.clock_timestamp()",
	} {
		position := strings.Index(migration.SQL, lock)
		if position <= previous {
			t.Errorf("claim lock/clock order lost at %q", lock)
		}
		previous = position
	}
	for _, forbidden := range []string{"GRANT SELECT", "GRANT UPDATE", "GRANT ALL", "BYPASSRLS", "binding_semantic_hash = observed", "pkce_verifier_ciphertext =", "INSERT INTO", "DELETE FROM", "DROP ", "transaction_timestamp()"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("claim SQL excessive or stale capability %q", forbidden)
		}
	}
}

func TestBrowserFailureMigrationNarrowErasureAndLiveClock(t *testing.T) {
	t.Parallel()
	sql := Catalog()[30].SQL
	for _, required := range []string{"CREATE FUNCTION mesh_ops.fail_oidc_browser_v1", "SECURITY DEFINER", "SET search_path = pg_catalog, mesh, mesh_ops", "auth.version = p_expected_version", "auth.binding_semantic_hash = p_binding_hash", "auth.consumed_at = p_consumed_at", "EXCEPTION WHEN OTHERS", "pkce_verifier_encryption_algorithm = NULL", "pkce_verifier_encryption_key_id = NULL", "pkce_verifier_ciphertext = NULL", "TO mesh_runtime;", "FROM PUBLIC, mesh_worker, mesh_observer"} {
		if !strings.Contains(sql, required) {
			t.Errorf("terminal SQL missing %q", required)
		}
	}
	previous := -1
	for _, required := range []string{"FOR UPDATE OF auth", "FROM mesh_audit.lock_deployment_stream_head", "finished_at := pg_catalog.clock_timestamp()", "UPDATE mesh.auth_transaction AS auth"} {
		position := strings.Index(sql, required)
		if position <= previous {
			t.Errorf("terminal lock/clock order %q", required)
		}
		previous = position
	}
	for _, forbidden := range []string{"admit_oidc_login_route", "FOR SHARE", "transaction_timestamp()", "INSERT INTO", "GRANT SELECT", "GRANT UPDATE", "GRANT ALL", "UPDATE mesh.account", "state = 'succeeded'", "provider.state =", "workspace.state ="} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("terminal excessive capability %q", forbidden)
		}
	}
}

func TestCatalogReturnsDefensiveCopy(t *testing.T) {
	t.Parallel()

	first := Catalog()
	first[0].Description = "changed"
	first[0].SQL = "changed"

	second := Catalog()
	if second[0].Description == "changed" || second[0].SQL == "changed" {
		t.Fatal("Catalog() returned mutable shared state")
	}
}

func TestAccountSessionLogoutIsDeploymentBoundAndLeastPrivilege(t *testing.T) {
	t.Parallel()
	migration := Catalog()[34]
	if migration.Description != "deployment-bound local account session logout" {
		t.Fatalf("migration 35 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.logout_account_session_v1",
		"p_expected_deployment_public_id UUID",
		"p_expected_recovery_epoch BIGINT",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"deployment.installation_public_id = p_expected_deployment_public_id",
		"deployment.recovery_epoch = p_expected_recovery_epoch",
		"session.deployment_recovery_epoch = p_expected_recovery_epoch",
		"session.state = 'active'",
		"end_reason = 'local_logout'",
		"version = session.version + 1",
		"pg_catalog.clock_timestamp()",
		"FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Account Session logout SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"BYPASSRLS", "TO mesh_worker;", "TO mesh_observer;", "DROP ", "p_end_reason",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Account Session logout SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestAccountSessionLogoutEvidenceIsPrincipalBoundAndLeastPrivilege(t *testing.T) {
	t.Parallel()
	migration := Catalog()[35]
	if migration.Description != "audited account session logout evidence" {
		t.Fatalf("migration 36 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.logout_account_session_v2",
		"mesh_ops.logout_account_session_v1(",
		"principal_public_id UUID",
		"ended_at TIMESTAMPTZ",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"principal.deployment_id = session.deployment_id",
		"principal.id = session.principal_id",
		"session.state = 'revoked'",
		"session.end_reason = 'local_logout'",
		"account session logout evidence is unavailable",
		"FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Account Session logout evidence SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"BYPASSRLS", "TO mesh_worker;", "TO mesh_observer;", "DROP ",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Account Session logout evidence SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestResourceGroupAuthorityIsScopedVersionedAndLeastPrivilege(t *testing.T) {
	t.Parallel()
	migration := Catalog()[36]
	if migration.Description != "Resource and Resource Group authority foundation" {
		t.Fatalf("migration 37 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.resource (",
		"CREATE TABLE mesh.resource_device_target (",
		"CREATE TABLE mesh.resource_group (",
		"CREATE TABLE mesh.resource_group_version (",
		"CREATE TABLE mesh.resource_group_version_member (",
		"target_generation BIGINT NOT NULL",
		"active_definition_version BIGINT NOT NULL",
		"resource_active_target_generation_fk",
		"resource_group_active_version_fk",
		"DEFERRABLE INITIALLY DEFERRED",
		"capture_authority_mutation('resource'",
		"capture_authority_mutation('resource_group'",
		"CREATE FUNCTION mesh_ops.create_device_resource_v1",
		"CREATE FUNCTION mesh_ops.create_resource_group_v1",
		"CREATE FUNCTION mesh_ops.resolve_resource_v1",
		"CREATE FUNCTION mesh_ops.resolve_resource_group_v1",
		"p_expected_inventory_revision BIGINT",
		"p_expected_group_revision BIGINT",
		"FROM mesh_ops.lock_network_revision()",
		"resource.version = member.resource_version",
		"resource.target_generation = member.target_generation",
		"SECURITY DEFINER",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Resource authority SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"BYPASSRLS", "TO mesh_worker;", "TO mesh_observer;", "DROP ",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Resource authority SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestResourceManagementReadsAreScopedBoundedAndLeastPrivilege(t *testing.T) {
	t.Parallel()
	migration := Catalog()[37]
	if migration.Description != "Resource management read API" {
		t.Fatalf("migration 38 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.read_network_revision_v1",
		"CREATE FUNCTION mesh_ops.read_resource_v2",
		"CREATE FUNCTION mesh_ops.list_resources_v1",
		"CREATE FUNCTION mesh_ops.read_resource_group_v2",
		"CREATE FUNCTION mesh_ops.list_resource_groups_v1",
		"mesh_ops.current_workspace_id()",
		"mesh_ops.current_network_id()",
		"p_limit > 101",
		"ORDER BY resource.public_id",
		"ORDER BY resource_group.public_id",
		"FROM mesh_ops.network_revision AS revision",
		"SECURITY DEFINER",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Resource management read SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"BYPASSRLS", "TO mesh_worker;", "TO mesh_observer;", "FOR UPDATE", "DROP ",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Resource management read SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestResourceLifecycleIsRetainedVersionedAndLeastPrivilege(t *testing.T) {
	t.Parallel()
	migration := Catalog()[38]
	if migration.Description != "Resource lifecycle authority" {
		t.Fatalf("migration 39 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE OR REPLACE FUNCTION mesh_ops.enforce_resource_authority_transition",
		"CREATE FUNCTION mesh_ops.transition_resource_lifecycle_v1",
		"CREATE FUNCTION mesh_ops.transition_resource_group_lifecycle_v1",
		"p_expected_resource_version BIGINT",
		"p_expected_group_version BIGINT",
		"FROM mesh_ops.lock_network_revision()",
		"FOR SHARE OF workspace, principal, membership",
		"FOR UPDATE;",
		"OLD.state = 'deleted'",
		"state = p_target_state",
		"version = resource.version + 1",
		"version = resource_group.version + 1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.transition_resource_lifecycle_v1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.transition_resource_group_lifecycle_v1",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Resource lifecycle SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"BYPASSRLS", "TO mesh_worker;", "TO mesh_observer;", "DROP ", "DELETE FROM",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Resource lifecycle SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestResourceTargetRebindingIsVersionedAndLeastPrivilege(t *testing.T) {
	t.Parallel()
	migration := Catalog()[39]
	if migration.Description != "Resource target rebinding authority" {
		t.Fatalf("migration 40 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE OR REPLACE FUNCTION mesh_ops.enforce_resource_authority_transition",
		"CREATE FUNCTION mesh_ops.preview_device_resource_rebind_v1",
		"CREATE FUNCTION mesh_ops.lock_device_resource_rebind_v1",
		"CREATE FUNCTION mesh_ops.rebind_device_resource_v1",
		"p_expected_resource_version BIGINT",
		"FROM mesh_ops.lock_network_revision()",
		"FOR SHARE OF workspace, principal, membership",
		"SET state = 'superseded'",
		"target_generation = advanced_target_generation",
		"version = resource.version + 1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.rebind_device_resource_v1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.preview_device_resource_rebind_v1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.lock_device_resource_rebind_v1",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Resource target rebinding SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"BYPASSRLS", "TO mesh_worker;", "TO mesh_observer;", "DROP ", "DELETE FROM",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Resource target rebinding SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestResourceGroupReplacementIsImmutableAndLeastPrivilege(t *testing.T) {
	t.Parallel()
	migration := Catalog()[40]
	if migration.Description != "Resource Group definition replacement authority" {
		t.Fatalf("migration 41 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE OR REPLACE FUNCTION mesh_ops.enforce_resource_authority_transition",
		"CREATE FUNCTION mesh_ops.preview_resource_group_replace_v1",
		"CREATE FUNCTION mesh_ops.lock_resource_group_replace_v1",
		"CREATE FUNCTION mesh_ops.replace_resource_group_definition_v1",
		"p_expected_group_version BIGINT",
		"FROM mesh_ops.lock_network_revision()",
		"FOR SHARE OF workspace, principal, membership",
		"INSERT INTO mesh.resource_group_version",
		"INSERT INTO mesh.resource_group_version_member",
		"active_definition_version = advanced_definition_version",
		"version = resource_group.version + 1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.replace_resource_group_definition_v1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.preview_resource_group_replace_v1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.lock_resource_group_replace_v1",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Resource Group replacement SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"BYPASSRLS", "TO mesh_worker;", "TO mesh_observer;", "DROP ", "DELETE FROM",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Resource Group replacement SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestResourceAuthorityChangeRequiresStepUpAndSecondActor(t *testing.T) {
	t.Parallel()
	migration := Catalog()[41]
	if migration.Description != "protected Resource ownership and custody authority" {
		t.Fatalf("migration 42 description = %q", migration.Description)
	}
	for _, required := range []string{
		"('resource.transfer'",
		"('resource_group.transfer'",
		"CREATE TABLE mesh.resource_authority_change_request",
		"CREATE TABLE mesh.resource_authority_step_up_evidence",
		"CREATE TRIGGER resource_authority_change_request_authority_mutation",
		"CREATE TRIGGER resource_authority_step_up_authority_mutation",
		"EXECUTE FUNCTION mesh_audit.capture_authority_mutation",
		"FORCE ROW LEVEL SECURITY",
		"UNIQUE (account_session_id)",
		"authentication_time > created_at - INTERVAL '5 minutes'",
		"required_confirmations = 1",
		"target_principal_id <> requested_by_principal_id",
		"CREATE FUNCTION mesh_ops.require_resource_authority_step_up_v1",
		"routing.minimum_assurance IS NOT NULL",
		"session.acr = routing.minimum_assurance",
		"CREATE FUNCTION mesh_ops.request_resource_authority_change_v1",
		"CREATE FUNCTION mesh_ops.confirm_resource_authority_change_v1",
		"CREATE FUNCTION mesh_ops.lock_resource_authority_change_request_v1",
		"FOR UPDATE OF session",
		"FOR UPDATE OF request",
		"GRANT EXECUTE ON FUNCTION mesh_ops.confirm_resource_authority_change_v1",
		"REVOKE ALL ON mesh.resource_authority_change_request",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Resource authority change SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"BYPASSRLS", "TO mesh_worker;", "TO mesh_observer;", "DROP ", "DELETE FROM",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Resource authority change SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestPolicyResourceDestinationPinsAuthorityAndExactScope(t *testing.T) {
	t.Parallel()
	migration := Catalog()[42]
	if migration.Description != "policy Resource destination provenance" {
		t.Fatalf("migration 43 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.compiled_policy_resource_destination",
		"compiled_policy_resource_destination_rule_scope_fk",
		"compiled_policy_resource_destination_resource_scope_fk",
		"resource_version BIGINT NOT NULL",
		"target_generation BIGINT NOT NULL",
		"inventory_revision BIGINT NOT NULL",
		"resource_semantic_hash BYTEA NOT NULL",
		"FORCE ROW LEVEL SECURITY",
		"CREATE TRIGGER compiled_policy_resource_destination_authority_mutation",
		"CREATE TRIGGER compiled_policy_resource_destination_immutable",
		"CREATE FUNCTION mesh_ops.attach_policy_resource_destinations",
		"FROM mesh.policy_release AS release",
		"FROM mesh.resource AS resource",
		"FOR KEY SHARE OF resource",
		"target.state = 'active'",
		"ERRCODE = 'MT001'",
		"GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_resource_destinations",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("policy Resource destination SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"BYPASSRLS", "DROP ", "DELETE FROM", "TO mesh_worker;", "TO mesh_observer;",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("policy Resource destination SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestPolicyResourceGroupDestinationPinsDefinitionMembersAndExactScope(t *testing.T) {
	t.Parallel()
	migration := Catalog()[43]
	if migration.Description != "policy Resource Group destination provenance" {
		t.Fatalf("migration 44 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.compiled_policy_resource_group_destination",
		"compiled_policy_resource_group_destination_rule_scope_fk",
		"compiled_policy_resource_group_destination_group_scope_fk",
		"compiled_policy_resource_group_destination_resource_scope_fk",
		"resource_group_version BIGINT NOT NULL",
		"definition_version BIGINT NOT NULL",
		"group_revision BIGINT NOT NULL",
		"resource_group_semantic_hash BYTEA NOT NULL",
		"resource_semantic_hash BYTEA NOT NULL",
		"FORCE ROW LEVEL SECURITY",
		"CREATE TRIGGER compiled_policy_resource_group_destination_authority_mutation",
		"CREATE TRIGGER compiled_policy_resource_group_destination_immutable",
		"CREATE FUNCTION mesh_ops.attach_policy_resource_group_destinations",
		"FROM mesh.resource_group AS resource_group",
		"JOIN mesh.resource_group_version AS version",
		"JOIN mesh.resource_group_version_member AS member",
		"FOR KEY SHARE OF resource_group",
		"FOR KEY SHARE OF resource",
		"target.state = 'active'",
		"ERRCODE = 'MT001'",
		"GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_resource_group_destinations",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("policy Resource Group destination SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"BYPASSRLS", "DROP ", "DELETE FROM", "TO mesh_worker;", "TO mesh_observer;",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("policy Resource Group destination SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestAccessGraphExplanationIsBoundedAuthorizedAndReadOnly(t *testing.T) {
	t.Parallel()
	migration := Catalog()[44]
	if migration.Description != "Access Graph active policy explanation" {
		t.Fatalf("migration 45 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.explain_active_policy_v1",
		"'policy.explain'",
		"mesh_ops.resolve_network_permission_v1",
		"mesh_ops.read_network_revision_v1",
		"release.state = 'active'",
		"source.state = 'active'",
		"destination.state = 'active'",
		"resource.state = 'active'",
		"p_protocol IS NULL",
		"p_destination_port IS NULL",
		"p_path_limit IS NULL",
		"p_path_limit NOT BETWEEN 1 AND 65",
		"rule.destination_ports @> p_destination_port",
		"compiled_policy_resource_destination",
		"compiled_policy_resource_group_destination",
		"AND resource_provenance.id IS NOT NULL THEN 'invalid'",
		"GRANT EXECUTE ON FUNCTION mesh_ops.explain_active_policy_v1",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Access Graph explanation SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"BYPASSRLS", "DROP ", "INSERT INTO", "UPDATE ", "DELETE FROM",
		"TO mesh_worker;", "TO mesh_observer;",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Access Graph explanation SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestUnifiedDeviceAliasMigrationScopesUniquenessToNetworks(t *testing.T) {
	t.Parallel()
	migration := Catalog()[91]
	if migration.Version != 92 {
		t.Fatalf("migration 92 = %+v, want unified alias sharing", migration)
	}
	for _, required := range []string{
		"ADD CONSTRAINT device_alias_lease_network_scope_check",
		"CHECK (provider_network_id <> consumer_network_id)",
		"DROP INDEX mesh.device_alias_address_retained_uidx",
		"DROP INDEX mesh.federation_alias_lease_current_address_uidx",
		"CREATE TRIGGER device_alias_network_uniqueness BEFORE INSERT ON mesh.device_alias_lease",
		"CREATE TRIGGER federation_alias_network_uniqueness BEFORE INSERT ON mesh.federation_alias_lease",
		"OR lease.consumer_network_id IN (p_provider_network_id, p_consumer_network_id)",
		"CREATE FUNCTION mesh_ops.allocate_network_scoped_alias_v1(",
		"CREATE FUNCTION mesh_ops.activate_resource_share_v4(",
		"allocated_alias := mesh_ops.allocate_network_scoped_alias_v1(",
		"CREATE FUNCTION mesh_ops.reserve_device_aliases_internal_v2(",
		"CREATE FUNCTION mesh_ops.load_device_alias_map_edges_v2(",
		"CASE WHEN self_network=endpoint_row.provider_network_id THEN",
		"CREATE FUNCTION mesh_ops.prepare_device_alias_change_v2(",
		"mesh_ops.reserve_device_aliases_internal_v2(p_endpoint",
		"mesh_ops.load_device_alias_map_edges_v2(fingerprint",
		"CREATE FUNCTION mesh_ops.prepare_device_alias_withdrawal_v2(",
		"CREATE FUNCTION mesh_ops.finalize_device_alias_withdrawal_v2(",
		"CREATE FUNCTION mesh_ops.prepare_device_alias_resource_quarantine_v2(",
		"CREATE FUNCTION mesh_ops.load_device_alias_work_v2(",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("migration 92 missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"profile='cloud'",
		"provider_workspace_id<>consumer_workspace_id AND",
		"provider_workspace_id <> endpoint.consumer_workspace_id",
		"endpoint.provider_workspace_id=endpoint.consumer_workspace_id",
		"CASE WHEN self_workspace=",
		"INSERT INTO mesh.direct_device_endpoint",
		"BYPASSRLS",
		"TO mesh_runtime",
		"TO mesh_worker",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("migration 92 contains %q", forbidden)
		}
	}
	ownership := UnifiedDeviceAliasOwnershipSQL()
	for _, required := range []string{
		"activate_resource_share_v3(\n    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ\n) FROM mesh_runtime;",
		"load_device_alias_map_edges_v1(BYTEA,BYTEA,INTEGER) FROM mesh_runtime;",
		"load_device_alias_work_v1(UUID,UUID,UUID,INTEGER) FROM mesh_worker;",
		"load_device_alias_work_v2(UUID,UUID,UUID,INTEGER) TO mesh_worker;",
	} {
		if !strings.Contains(ownership, required) {
			t.Errorf("schema 92 ownership missing %q", required)
		}
	}
}

func TestAliasMapReaderBoundsPlanning(t *testing.T) {
	t.Parallel()
	migration := Catalog()[92]
	if migration.Version != 93 {
		t.Fatalf("migration 93 = %+v", migration)
	}
	previous := Catalog()[91].SQL
	start := strings.Index(previous, "CREATE FUNCTION mesh_ops.load_device_alias_map_edges_v2(")
	end := strings.Index(previous[start:], "$function$;\n")
	if start < 0 || end < 0 {
		t.Fatal("migration 92 reader not found")
	}
	want := strings.Replace(previous[start:start+end], "load_device_alias_map_edges_v2(", "load_device_alias_map_edges_v3(", 1)
	want = strings.Replace(want, "SET search_path = pg_catalog, mesh, mesh_ops\n",
		"SET search_path = pg_catalog, mesh, mesh_ops\nSET join_collapse_limit = 1\nSET from_collapse_limit = 1\nSET plan_cache_mode = force_generic_plan\n", 1)
	if !strings.Contains(migration.SQL, want) {
		t.Fatal("v3 must be v2 verbatim plus the three planner settings")
	}
	if !strings.Contains(AliasMapReaderOwnershipSQL(), "load_device_alias_map_edges_v2(BYTEA,BYTEA,INTEGER) FROM mesh_runtime;") {
		t.Fatal("schema 93 ownership must close the v2 runtime entry point")
	}
}

func TestShareOfferAccessLabelMigrationFreezesProviderLabels(t *testing.T) {
	t.Parallel()
	migration := Catalog()[93]
	if migration.Version != 94 {
		t.Fatalf("migration 94 = %+v", migration)
	}
	previous := Catalog()[90].SQL
	start := strings.Index(previous, "CREATE FUNCTION mesh_ops.create_resource_share_offer_v2(")
	end := strings.Index(previous[start:], "$function$;\n")
	if start < 0 || end < 0 {
		t.Fatal("migration 91 offer creation not found")
	}
	// v3 must remain v2 apart from the label parameter, validation, binding
	// check and stored column, so every v2 authority check is preserved.
	want := previous[start : start+end]
	for _, edit := range [][2]string{
		{"create_resource_share_offer_v2(", "create_resource_share_offer_v3("},
		{"    p_occurred_at TIMESTAMPTZ\n)", "    p_occurred_at TIMESTAMPTZ,\n    p_access_label TEXT\n)"},
		{"expires_at, state, created_at, updated_at\n    ) VALUES (\n        p_offer_public_id",
			"expires_at, state, created_at, updated_at, access_label\n    ) VALUES (\n        p_offer_public_id"},
		{"'offered', p_occurred_at, p_occurred_at\n    ) RETURNING id, version INTO offer_internal_id",
			"'offered', p_occurred_at, p_occurred_at, p_access_label\n    ) RETURNING id, version INTO offer_internal_id"},
	} {
		if !strings.Contains(want, edit[0]) {
			t.Fatalf("v2 anchor %q not found", edit[0])
		}
		want = strings.Replace(want, edit[0], edit[1], 1)
	}
	for _, inserted := range []string{
		"        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid share access label';\n    END IF;\n",
		"    IF mesh_ops.share_access_label_conflicts_v1(\n        p_provider_workspace_id, p_provider_network_id,\n        p_access_label, resource_internal_id, p_occurred_at\n    ) THEN\n        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'share access label names another Resource';\n    END IF;\n",
	} {
		if !strings.Contains(migration.SQL, inserted) {
			t.Fatalf("schema 94 missing %q", inserted)
		}
	}
	got := migration.SQL[strings.Index(migration.SQL, "CREATE FUNCTION mesh_ops.create_resource_share_offer_v3("):]
	got = got[:strings.Index(got, "$function$;\n")]
	for _, inserted := range []string{
		"    IF p_access_label IS NULL\n        OR pg_catalog.char_length(p_access_label) NOT BETWEEN 1 AND 63\n        OR pg_catalog.octet_length(p_access_label) <> pg_catalog.char_length(p_access_label)\n        OR p_access_label !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'\n        OR p_access_label ~ '^[0-9]+$' THEN\n        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid share access label';\n    END IF;\n",
		"    IF mesh_ops.share_access_label_conflicts_v1(\n        p_provider_workspace_id, p_provider_network_id,\n        p_access_label, resource_internal_id, p_occurred_at\n    ) THEN\n        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'share access label names another Resource';\n    END IF;\n",
	} {
		got = strings.Replace(got, inserted, "", 1)
	}
	if got != want {
		t.Fatal("create v3 must be v2 plus only the label input, binding check and stored column")
	}
	for _, required := range []string{
		"ALTER TABLE mesh.share_offer ADD COLUMN access_label TEXT;",
		"CREATE TRIGGER share_offer_access_label_frozen\nBEFORE UPDATE ON mesh.share_offer",
		"IF OLD.access_label IS DISTINCT FROM NEW.access_label THEN",
		"RETURN p_access_label || '.' || workspace_code || '.' || network_code || '.shared.mesh';",
		"AND locator.local_workspace_id = mesh_ops.current_workspace_id()\n     AND locator.local_network_id = mesh_ops.current_network_id()",
		"IF p_access_name IS NOT NULL AND p_access_name <> effective_access_name THEN",
		"FROM mesh_ops.decide_resource_share_offer_v3(",
		"GRANT EXECUTE ON FUNCTION mesh_ops.read_share_offer_access_name_v1(UUID) TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 94 missing %q", required)
		}
	}
	ownership := ShareOfferAccessLabelOwnershipSQL()
	for _, required := range []string{
		"BYTEA, BYTEA, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT\n) OWNER TO mesh_share_writer;",
		"BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ\n) OWNER TO mesh_share_writer;",
		"BYTEA, BYTEA, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT\n) TO mesh_runtime;",
		"BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ\n) TO mesh_runtime;",
	} {
		if !strings.Contains(ownership, required) {
			t.Errorf("schema 94 ownership missing %q", required)
		}
	}
}

func TestBuiltinWorkspaceRolesKeepOwnerAndLegacyResolution(t *testing.T) {
	t.Parallel()
	migration := Catalog()[94]
	if migration.Version != 95 {
		t.Fatalf("migration 95 = %+v", migration)
	}
	previous := Catalog()[75].SQL
	start := strings.Index(previous, "CREATE FUNCTION mesh_ops.resolve_network_permission_v2(")
	split := strings.Index(previous, "    -- Members retain the existing exact-Network role resolver and its locks.")
	end := strings.Index(previous[start:], "$function$;\n")
	if start < 0 || split < 0 || end < 0 {
		t.Fatal("migration 76 resolver not found")
	}
	ownerBranch := strings.Replace(previous[start:split],
		"CREATE FUNCTION mesh_ops.resolve_network_permission_v2(",
		"CREATE OR REPLACE FUNCTION mesh_ops.resolve_network_permission_v2(", 1)
	legacyBranch := previous[split : start+end]
	// The owner branch and the legacy custom-role fallback stay verbatim; the
	// built-in branch is inserted between them.
	if !strings.Contains(migration.SQL, ownerBranch) || !strings.Contains(migration.SQL, legacyBranch) {
		t.Fatal("resolver v2 must keep the owner branch and legacy fallback verbatim")
	}
	if strings.Index(migration.SQL, ownerBranch) > strings.Index(migration.SQL, "JOIN mesh.workspace_role_assignment AS assignment") ||
		strings.Index(migration.SQL, "JOIN mesh.workspace_role_assignment AS assignment") > strings.Index(migration.SQL, legacyBranch) {
		t.Fatal("built-in branch must sit between ownership and the legacy fallback")
	}
	for _, required := range []string{
		"CREATE TRIGGER builtin_role_immutable",
		"CREATE TRIGGER builtin_role_permission_immutable",
		"CREATE TRIGGER workspace_role_assignment_transition",
		"mesh_audit.capture_authority_mutation(\n    'workspace_role_assignment', 'public_id'",
		"network_id IS NULL OR role_key IN ('network_admin', 'it_admin', 'auditor')",
		"AND (assignment.network_id IS NULL OR assignment.network_id = network.id)",
		"AND assignment.network_id IS NULL\n     AND assignment.state = 'active'",
		"CREATE OR REPLACE FUNCTION mesh_ops.read_console_management_scopes_v1(",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_workspace_permission_v1(",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 95 missing %q", required)
		}
	}
}

func TestTrustContractExpiryFinalizerIsWorkerOnly(t *testing.T) {
	t.Parallel()
	migration := Catalog()[111]
	if migration.Version != 112 {
		t.Fatalf("migration 112 = %+v", migration)
	}
	for _, required := range []string{
		"WHERE state IN ('activating', 'active');",
		"AND expires_at <= pg_catalog.clock_timestamp()",
		"FOR UPDATE SKIP LOCKED;",
		"OR v_contract.expires_at > pg_catalog.clock_timestamp() THEN",
		"SET state = 'withdrawn', version = version + 1, updated_at = v_decision, withdrawn_at = v_decision",
		"'trust_contract.expired',\n            'system.reconcile',",
		"NULL::UUID,\n            'trust_contract.expired',",
		"Trust Contract expiry mutation set is invalid",
		"Trust Contract expiry evidence mismatch",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 112 missing %q", required)
		}
	}
	for _, forbidden := range []string{"TO mesh_worker", "TO mesh_runtime", "OWNER TO"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 112 must leave exposure to the operator step, found %q", forbidden)
		}
	}
	ownership := TrustContractExpiryOwnershipSQL()
	for _, required := range []string{
		"list_expired_trust_contracts_v1(UUID, TIMESTAMPTZ, UUID, INTEGER)\n    OWNER TO mesh_share_writer;",
		"prepare_trust_contract_expiry_v1(UUID, UUID, UUID)\n    OWNER TO mesh_share_writer;",
		"finalize_trust_contract_expiry_v1(UUID, UUID, UUID, JSONB)\n    OWNER TO mesh_share_writer;",
		"prepare_trust_contract_expiry_v1(UUID, UUID, UUID)\n    TO mesh_worker;",
	} {
		if !strings.Contains(ownership, required) {
			t.Errorf("schema 112 ownership missing %q", required)
		}
	}
	if strings.Contains(ownership, "TO mesh_runtime") {
		t.Error("schema 112 ownership must not expose expiry to runtime")
	}
}

func TestNetworkAliasRangeKeepsAllocationContract(t *testing.T) {
	t.Parallel()
	migration := Catalog()[112]
	if migration.Version != 113 {
		t.Fatalf("migration 113 = %+v", migration)
	}
	for _, required := range []string{
		"CREATE OR REPLACE FUNCTION mesh_ops.allocate_network_scoped_alias_v1(\n    p_deployment_id BIGINT, p_pool_id BIGINT, p_provider_network_id BIGINT, p_consumer_network_id BIGINT\n)",
		"IF pool_row.purpose = 'federation_resource_alias' THEN",
		"IF NOT chosen_prefix <<= pool_row.prefix THEN",
		"attempt_limit := LEAST(maximum_offset, 65536);",
		"'network.update', p_evaluated_at",
		"'network.read', p_evaluated_at",
		"RAISE EXCEPTION USING ERRCODE = 'MTR02'",
		"FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('network_alias_range', 'public_id');",
		"ALTER TABLE mesh.network_alias_range FORCE ROW LEVEL SECURITY;",
		"GRANT SELECT ON mesh.network_alias_range TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 113 missing %q", required)
		}
	}
	for _, forbidden := range []string{"GRANT INSERT", "GRANT UPDATE", "TO mesh_worker", "OWNER TO"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 113 must keep writes inside its definer functions, found %q", forbidden)
		}
	}
}

func TestAliasMapReachableSharesIsVerbatimExceptSelection(t *testing.T) {
	t.Parallel()
	previous, migration := Catalog()[92], Catalog()[113]
	if previous.Version != 93 || migration.Version != 114 {
		t.Fatalf("migrations = %d, %d", previous.Version, migration.Version)
	}
	selection := "              AND self_rule.source_device_id = self_id\n" +
		"                WHERE self_revision.workspace_id = self_workspace AND self_revision.network_id = self_network)"
	if !strings.Contains(migration.SQL, selection) {
		t.Fatal("v4 must filter receiving endpoints by this Device's compiled rules")
	}
	// Remove the added selection and rename v4: what remains is v3 verbatim.
	start := strings.Index(migration.SQL, "              -- A receiving Device sees only shares")
	end := strings.Index(migration.SQL, selection)
	body := migration.SQL[:start] + migration.SQL[end+len(selection):]
	body = strings.ReplaceAll(body, "load_device_alias_map_edges_v4", "load_device_alias_map_edges_v3")
	body = strings.Replace(body, "network_id=self_network\n))\n        ORDER BY", "network_id=self_network))\n        ORDER BY", 1)
	original := previous.SQL[strings.Index(previous.SQL, "CREATE FUNCTION mesh_ops.load_device_alias_map_edges_v3("):]
	copied := body[strings.Index(body, "CREATE FUNCTION mesh_ops.load_device_alias_map_edges_v3("):]
	if copied != original {
		t.Fatal("v4 differs from v3 beyond the receiving-side selection")
	}
	ownership := AliasMapReachableSharesOwnershipSQL()
	for _, required := range []string{
		"load_device_alias_map_edges_v4(BYTEA,BYTEA,INTEGER) OWNER TO mesh_device_alias_map_reader;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v4(BYTEA,BYTEA,INTEGER) TO mesh_runtime;",
	} {
		if !strings.Contains(ownership, required) {
			t.Errorf("schema 114 ownership missing %q", required)
		}
	}
	if strings.Contains(migration.SQL, "TO mesh_runtime") {
		t.Error("schema 114 must leave runtime exposure to the operator step")
	}
}

func TestAuditPartitionsAndWorkspaceStreams(t *testing.T) {
	t.Parallel()
	migration := Catalog()[114]
	if migration.Version != 115 {
		t.Fatalf("migration 115 = %+v", migration)
	}
	for _, required := range []string{
		"SELECT mesh_ops.ensure_audit_event_partitions_v1(24);",
		"'CREATE TABLE mesh_audit.%I PARTITION OF mesh_audit.audit_event FOR VALUES FROM (%L) TO (%L)'",
		"'ALTER TABLE mesh_audit.%I FORCE ROW LEVEL SECURITY'",
		"GRANT EXECUTE ON FUNCTION mesh_ops.ensure_audit_event_partitions_v1(INTEGER) TO mesh_worker;",
		"ADD CONSTRAINT audit_stream_public_id_key UNIQUE (public_id)",
		"AFTER INSERT ON mesh.workspace",
		"DROP POLICY workspace_audit_stream_backfill ON mesh.workspace;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 115 missing %q", required)
		}
	}
	if strings.Contains(migration.SQL, "TO mesh_runtime") {
		t.Error("schema 115 must not expose audit storage to runtime")
	}
}

func TestAuditEventSealV2(t *testing.T) {
	t.Parallel()
	migration := Catalog()[115]
	if migration.Version != 116 {
		t.Fatalf("migration 116 = %+v", migration)
	}
	for _, required := range []string{
		"pg_catalog.convert_to('meshtransit/audit-event/v2', 'UTF8') || '\\x00'::BYTEA",
		"BEFORE INSERT ON mesh_audit.audit_event",
		"'audit seal is computed by the database'",
		"'audit seal sequence is not contiguous'",
		"ADD CONSTRAINT audit_stream_scope_public_id_check CHECK (",
		"DROP POLICY audit_stream_scope_backfill_network ON mesh.network;",
		"DROP POLICY audit_stream_scope_backfill_workspace ON mesh.workspace;",
		"GRANT EXECUTE ON FUNCTION mesh_audit.lock_workspace_stream_head(UUID, UUID) TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 116 missing %q", required)
		}
	}
	if strings.Count(migration.SQL, "TO mesh_runtime") != 1 {
		t.Error("schema 116 may grant runtime only the Workspace stream head lock")
	}
}

func TestWorkspaceAuditHistory(t *testing.T) {
	t.Parallel()
	migration := Catalog()[116]
	if migration.Version != 117 {
		t.Fatalf("migration 117 = %+v", migration)
	}
	for _, required := range []string{
		"mesh_ops.session_bound_to_workspace_v1(p_session_public_id, scoped_workspace_id)",
		"p_workspace_public_id, 'audit.read', evaluated_at",
		"p_workspace_public_id, p_network_public_id, 'audit.read', evaluated_at",
		"(event.occurred_at, identity.public_id) < (p_cursor_occurred_at, p_cursor_event_public_id)",
		"ORDER BY event.occurred_at DESC, identity.public_id DESC",
		"OR p_limit IS NULL OR p_limit < 1 OR p_limit > 100",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 117 missing %q", required)
		}
	}
	if strings.Count(migration.SQL, "TO mesh_runtime;") != 1 {
		t.Error("schema 117 may grant runtime only the history read")
	}
}

func TestWorkspaceAuditExport(t *testing.T) {
	t.Parallel()
	migration := Catalog()[117]
	if migration.Version != 118 {
		t.Fatalf("migration 118 = %+v", migration)
	}
	for _, required := range []string{
		"p_workspace_public_id, 'audit.export', evaluated_at",
		"p_workspace_public_id, p_network_public_id, 'audit.export', evaluated_at",
		"(event.occurred_at, identity.public_id) > (p_cursor_occurred_at, p_cursor_event_public_id)",
		"ORDER BY event.occurred_at, identity.public_id",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 118 missing %q", required)
		}
	}
	if strings.Contains(migration.SQL, "p_target_kinds") || strings.Count(migration.SQL, "TO mesh_runtime;") != 1 {
		t.Error("schema 118 exports whole streams and grants runtime only the export")
	}
}

func TestWorkspaceGuardrails(t *testing.T) {
	t.Parallel()
	migration := Catalog()[118]
	if migration.Version != 119 {
		t.Fatalf("migration 119 = %+v", migration)
	}
	for _, required := range []string{
		"'security_admin', '01a10e00-0000-7000-8000-000000000006', 'Security admin', FALSE",
		"kind IN ('network_isolation', 'network_sharing', 'external_sharing')",
		"mesh_audit.capture_authority_mutation('guardrail', 'public_id')",
		"OR (p_operation = 'delete' AND p_permission <> 'guardrail.weaken')",
		"p_workspace_public_id, p_permission, evaluated_at",
		"ERRCODE = 'MTG01'",
		"GRANT EXECUTE ON FUNCTION mesh_ops.active_workspace_guardrails_v1() TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 119 missing %q", required)
		}
	}
	if strings.Contains(migration.SQL, "GRANT SELECT") {
		t.Error("schema 119 must not grant direct table access")
	}
}

func TestNetworkDeviceGroups(t *testing.T) {
	t.Parallel()
	migration := Catalog()[119]
	if migration.Version != 120 {
		t.Fatalf("migration 120 = %+v", migration)
	}
	for _, required := range []string{
		"mesh_audit.capture_authority_mutation('device_group', 'public_id')",
		"mesh_audit.capture_authority_mutation('device_group_member', 'public_id')",
		"mesh_audit.capture_authority_mutation('compiled_policy_group_rule', 'public_id')",
		"'device_group.members.manage', p_evaluated_at",
		"ERRCODE = 'MTD05'",
		"group_revision = revision.group_revision + 1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_group_policy_edges_v1(BIGINT) TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 120 missing %q", required)
		}
	}
	if strings.Contains(migration.SQL, "GRANT SELECT") {
		t.Error("schema 120 must not grant direct table access")
	}
}

func TestIdentityGroupsAndDeviceTags(t *testing.T) {
	t.Parallel()
	migration := Catalog()[120]
	if migration.Version != 121 {
		t.Fatalf("migration 121 = %+v", migration)
	}
	for _, required := range []string{
		"mesh_audit.capture_authority_mutation('identity_group', 'public_id')",
		"mesh_audit.capture_authority_mutation('identity_group_member', 'public_id')",
		"mesh_audit.capture_authority_mutation('device_tag', 'public_id')",
		"mesh_audit.capture_authority_mutation('device_tag_owner', 'public_id')",
		"mesh_audit.capture_authority_mutation('device_tag_assignment', 'public_id')",
		"'identity_group.manage', p_evaluated_at",
		"'device_tag.manage', p_evaluated_at",
		"ERRCODE = 'MTI05'",
		"ERRCODE = 'MTT05'",
		"v_device.owner_principal_id <> v_principal AND NOT v_manage_devices",
		"GRANT EXECUTE ON FUNCTION mesh_audit.lock_workspace_network_stream_head_v1(UUID) TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 121 missing %q", required)
		}
	}
	if strings.Contains(migration.SQL, "GRANT SELECT") {
		t.Error("schema 121 must not grant direct table access")
	}
}

func TestIdentityAndTagRules(t *testing.T) {
	t.Parallel()
	migration := Catalog()[121]
	if migration.Version != 122 {
		t.Fatalf("migration 122 = %+v", migration)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.attach_policy_group_rules_v2(",
		"CREATE OR REPLACE FUNCTION mesh_ops.resolve_group_policy_edges_v1(",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_group_policy_edges_v2(BIGINT) TO mesh_runtime;",
		"SELECT 1 FROM mesh.device_tag_assignment AS assignment WHERE assignment.device_id = device.id",
		"AND membership.state = 'active'",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 122 missing %q", required)
		}
	}
}

func TestAccessGraphGroupEdges(t *testing.T) {
	t.Parallel()
	migration := Catalog()[122]
	if migration.Version != 123 {
		t.Fatalf("migration 123 = %+v", migration)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.read_access_graph_v2(",
		"FROM mesh_ops.resolve_group_policy_edges_v2(v_device_internal) AS edge",
		"ERRCODE = 'MTA01'",
		") TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 123 missing %q", required)
		}
	}
	if strings.Contains(migration.SQL, "GRANT SELECT") {
		t.Error("schema 123 must not grant direct table access")
	}
}

func TestNetworkTagOptions(t *testing.T) {
	t.Parallel()
	migration := Catalog()[123]
	if migration.Version != 124 {
		t.Fatalf("migration 124 = %+v", migration)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.read_network_tag_options_v1(",
		"'device.read', p_evaluated_at",
		"mesh_ops.device_tag_owned_by_internal_v1(",
		"WHERE option.apply <> 'none' OR option.assigned",
		") TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 124 missing %q", required)
		}
	}
}

func TestDeviceLifecycle(t *testing.T) {
	t.Parallel()
	migration := Catalog()[124]
	if migration.Version != 125 {
		t.Fatalf("migration 125 = %+v", migration)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.change_device_lifecycle_v1(",
		"CREATE FUNCTION mesh_ops.read_console_devices_v2(",
		"WHEN 'transfer_member' THEN 'device.transfer'",
		"WHEN 'suspend' THEN 'device.quarantine'",
		"GRANT UPDATE (ownership, suspended_reason, handover_principal_id, hostname_locked)",
		"REFERENCES mesh.principal (id) ON DELETE RESTRICT",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 125 missing %q", required)
		}
	}
	if strings.Contains(migration.SQL, "GRANT SELECT") {
		t.Error("schema 125 must not grant direct table access")
	}
}

func TestMapSessionSuspension(t *testing.T) {
	t.Parallel()
	migration := Catalog()[125]
	if migration.Version != 126 {
		t.Fatalf("migration 126 = %+v", migration)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.map_session_suspended_v1(",
		"AND device.state = 'suspended'",
		"AND machine.epoch = device.current_machine_key_epoch",
		"AND node_key.epoch = device.current_node_key_epoch",
		"GRANT EXECUTE ON FUNCTION mesh_ops.map_session_suspended_v1(BYTEA, BYTEA) TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 126 missing %q", required)
		}
	}
	if strings.Contains(migration.SQL, "GRANT SELECT") {
		t.Error("schema 126 must not grant direct table access")
	}
}

func TestWorkspaceMemberSuspension(t *testing.T) {
	t.Parallel()
	migration := Catalog()[126]
	if migration.Version != 127 {
		t.Fatalf("migration 127 = %+v", migration)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.change_workspace_member_v1(",
		"CREATE OR REPLACE FUNCTION mesh_ops.change_device_lifecycle_v1(",
		"suspended_reason IN ('admin', 'handover', 'member')",
		"'member.manage'",
		"NOT (role.assignable_by && mesh_ops.workspace_role_assigners_v1(v_workspace, v_actor, v_now))",
		"resume the member to resume this Device",
		"AND session.login_workspace_id = v_workspace",
		") TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 127 missing %q", required)
		}
	}
	if strings.Contains(migration.SQL, "GRANT SELECT") {
		t.Error("schema 127 must not grant direct table access")
	}
}

func TestWorkspaceInvitations(t *testing.T) {
	t.Parallel()
	migration := Catalog()[127]
	if migration.Version != 128 {
		t.Fatalf("migration 128 = %+v", migration)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.workspace_invitation (",
		"token_digest BYTEA NOT NULL UNIQUE",
		"WHERE state = 'pending'",
		"'member.invite'",
		"role exceeds the delegation ceiling",
		"capture_authority_mutation('workspace_invitation', 'public_id')",
		"CREATE FUNCTION mesh_ops.change_workspace_invitation_v1(",
		"CREATE FUNCTION mesh_ops.list_workspace_invitations_v1(",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 128 missing %q", required)
		}
	}
	if strings.Contains(migration.SQL, "GRANT SELECT") || strings.Contains(migration.SQL, "token TEXT") {
		t.Error("schema 128 must not grant table access or store a token")
	}
}

func TestWorkspaceInvitationAcceptance(t *testing.T) {
	t.Parallel()
	migration := Catalog()[128]
	if migration.Version != 129 {
		t.Fatalf("migration 129 = %+v", migration)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.preview_workspace_invitation_v1(",
		"CREATE FUNCTION mesh_ops.accept_workspace_invitation_v1(",
		"AND auth.state = 'consuming' AND auth.version = p_transaction_version",
		"AND auth.principal_id IS NULL AND auth.binding_semantic_hash = p_binding_hash",
		"a suspended member cannot accept an invitation",
		"SET state = 'accepted'",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 129 missing %q", required)
		}
	}
}

// Schema 160 binds acceptance to the invited address: under the invitation
// lock it refuses a non-ASCII or differently spelled address before v1
// consumes the link, folds ASCII case only, and keeps v1 for rollback.
func TestInvitationEmailBinding(t *testing.T) {
	t.Parallel()
	migration := Catalog()[159]
	if migration.Version != 160 {
		t.Fatalf("migration 160 = %+v", migration)
	}
	sql := migration.SQL
	body := sql[strings.Index(sql, "AS $function$"):]
	ascii := regexp.MustCompile(`OR pg_catalog\.octet_length\(p_verified_email\) <> pg_catalog\.char_length\(p_verified_email\)\s+` +
		`OR p_verified_email ~ '\[\[:space:\]\[:cntrl:\]\]' THEN\s+RAISE EXCEPTION USING ERRCODE = 'MTV06'`)
	compare := regexp.MustCompile(`IF v_invited IS NOT NULL AND pg_catalog\.translate\(p_verified_email,\s+` +
		`'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'\) <> v_invited THEN\s+` +
		`RAISE EXCEPTION USING ERRCODE = 'MTV06'`)
	asciiAt, compareAt := ascii.FindStringIndex(body), compare.FindStringIndex(body)
	lockAt := strings.Index(body, "FOR UPDATE OF invitation")
	consumeAt := strings.Index(body, "mesh_ops.accept_workspace_invitation_v1(")
	if asciiAt == nil || compareAt == nil || lockAt < 0 || consumeAt < 0 ||
		asciiAt[1] >= lockAt || lockAt >= compareAt[0] || compareAt[1] >= consumeAt {
		t.Fatal("schema 160 must refuse non-ASCII, lock, then refuse another address, all before v1 consumes the link")
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.accept_workspace_invitation_v2(",
		"AND invitation.state = 'pending'",
		"AND deployment.installation_public_id = p_deployment_public_id",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("schema 160 missing %q", required)
		}
	}
	// lower() follows the database locale and folds non-ASCII letters.
	for _, forbidden := range []string{"lower(p_verified_email)", "REVOKE ALL ON FUNCTION mesh_ops.accept_workspace_invitation_v1",
		"DROP FUNCTION"} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("schema 160 must not contain %q", forbidden)
		}
	}
}

// Schema 161 answers "revoked" only for the exact current keys of a Device
// revoked with them, and only to the runtime role.
func TestMapSessionRevocation(t *testing.T) {
	t.Parallel()
	migration := Catalog()[160]
	if migration.Version != 161 {
		t.Fatalf("migration 161 = %+v", migration)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.map_session_revoked_v1(",
		"AND machine.fingerprint = p_machine_key_fingerprint",
		"AND machine.state = 'revoked'",
		"AND machine.epoch = device.current_machine_key_epoch",
		"AND node_key.public_key = p_node_key",
		"AND node_key.state = 'revoked'",
		"AND node_key.epoch = device.current_node_key_epoch",
		"AND device.state = 'revoked'",
		"GRANT EXECUTE ON FUNCTION mesh_ops.map_session_revoked_v1(BYTEA, BYTEA) TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 161 missing %q", required)
		}
	}
	for _, forbidden := range []string{"INSERT", "UPDATE", "DELETE", "'deleted'", "'expired'"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 161 must only read revoked authority: found %q", forbidden)
		}
	}
}

// Schema 162 advances the Account's session generation and ends every active
// session for the person and the operator, while an administrator ends only
// the sessions signed in to their Workspace, under the suspension guards.
func TestAccountSessionRevocation(t *testing.T) {
	t.Parallel()
	migration := Catalog()[161]
	if migration.Version != 162 {
		t.Fatalf("migration 162 = %+v", migration)
	}
	sql := migration.SQL
	section := func(name string) string {
		start := strings.Index(sql, "CREATE FUNCTION mesh_ops."+name+"(")
		if start < 0 {
			t.Fatalf("schema 162 missing %s", name)
		}
		end := strings.Index(sql[start:], "$function$;")
		if end < 0 {
			t.Fatalf("schema 162 %s is unterminated", name)
		}
		return sql[start : start+end]
	}
	for name, required := range map[string][]string{
		"logout_all_account_sessions_v1": {
			"ORDER BY session.id\n    FOR UPDATE;",
			"AND session.version >= p_session_version;",
			"FROM mesh_ops.resolve_account_session_v1(",
			"OR v_account.recovery_state <> 'verified' THEN",
			"SET session_generation = account.session_generation + 1, version = account.version + 1,",
			"SET state = 'revoked', ended_at = v_now, end_reason = 'logout_all',",
			"WHERE session.deployment_id = v_deployment AND session.principal_id = v_principal",
		},
		"revoke_workspace_member_sessions_v1": {
			"NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, v_workspace)",
			"p_workspace_public_id, 'member.manage', v_now",
			"IF v_member = v_owner OR v_member = v_actor THEN",
			"NOT (role.assignable_by && mesh_ops.workspace_role_assigners_v1(v_workspace, v_actor, v_now))",
			"WHERE session.deployment_id = v_membership.deployment_id AND session.principal_id = v_member\n" +
				"      AND session.login_workspace_id = v_workspace",
		},
		"change_account_recovery_v1": {
			"SECURITY INVOKER",
			"IF p_action = 'release' AND v_account.recovery_state <> 'quarantined' THEN",
			"WHEN 'quarantine' THEN 'quarantined'",
			"+ CASE WHEN p_action = 'release' THEN 0 ELSE 1 END,",
		},
	} {
		body := section(name)
		for _, text := range required {
			if !strings.Contains(body, text) {
				t.Errorf("schema 162 %s missing %q", name, text)
			}
		}
	}
	// An administrator never moves the Account-wide generation.
	if strings.Contains(section("revoke_workspace_member_sessions_v1"), "UPDATE mesh.account ") {
		t.Error("schema 162 lets a Workspace administrator end sessions in other Workspaces")
	}
	for _, required := range []string{
		"GRANT EXECUTE ON FUNCTION mesh_ops.logout_all_account_sessions_v1(\n    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID\n) TO mesh_runtime;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.revoke_workspace_member_sessions_v1(\n    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ\n) TO mesh_runtime;",
		"REVOKE ALL ON FUNCTION mesh_ops.change_account_recovery_v1(UUID, TEXT, UUID)\n    FROM PUBLIC, mesh_runtime,",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("schema 162 missing %q", required)
		}
	}
	if strings.Contains(sql, "change_account_recovery_v1(UUID, TEXT, UUID) TO") {
		t.Error("schema 162 must not grant operator Account recovery to any role")
	}
}

// Schema 163 hands a consumer's transaction the provider's guardrails only
// for a share that scope is the consumer of, under the provider's Workspace
// lock, and only to the runtime role.
func TestShareProviderGuardrails(t *testing.T) {
	t.Parallel()
	migration := Catalog()[162]
	if migration.Version != 163 {
		t.Fatalf("migration 163 = %+v", migration)
	}
	for _, required := range []string{
		"WHERE locator.local_workspace_id = scoped_workspace_id",
		"IF v_provider IS NULL THEN",
		"IF v_provider = v_consumer THEN",
		"WHERE imported.workspace_id = scoped_workspace_id\n      AND imported.network_id = scoped_network_id",
		"AND imported.state IN ('activating', 'active')",
		"AND locator.state IN ('offered', 'accepted');",
		"PERFORM 1 FROM mesh.workspace_guardrail_state AS state WHERE state.workspace_id = v_provider FOR SHARE;",
		"AFTER INSERT OR UPDATE ON mesh.guardrail",
		"AFTER INSERT ON mesh.workspace",
		"GRANT EXECUTE ON FUNCTION mesh_ops.share_offer_provider_guardrails_v1(UUID) TO mesh_runtime;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.imported_resource_provider_guardrails_v1() TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 163 missing %q", required)
		}
	}
	// The replaced guardrail change is schema 119's, plus the state row lock
	// taken before the Workspace row.
	extract := func(sql string) string {
		start := strings.Index(sql, "FUNCTION mesh_ops.change_workspace_guardrail_v1(")
		end := strings.Index(sql[start:], "$function$;")
		if start < 0 || end < 0 {
			t.Fatal("schema 163 lost change_workspace_guardrail_v1")
		}
		return sql[start : start+end]
	}
	const stateLock = `    -- The guardrail state row first, then the Workspace row: share and
    -- publication transactions hold the state row FOR SHARE and may then need
    -- the Workspace row (schema 163).
    PERFORM 1 FROM mesh.workspace_guardrail_state AS state
    WHERE state.workspace_id = scoped_workspace_id FOR UPDATE;
`
	replaced := extract(migration.SQL)
	if !strings.Contains(replaced, stateLock+"    SELECT workspace.deployment_id INTO deployment_internal_id") ||
		strings.Replace(replaced, stateLock, "", 1) != extract(Catalog()[118].SQL) {
		t.Error("schema 163 must replace change_workspace_guardrail_v1 with only the state row lock added")
	}
	// The readers lock only the guardrail state row, never the Workspace row
	// other flows lock before Network revisions.
	if strings.Contains(migration.SQL, "FROM mesh.workspace AS workspace WHERE workspace.id = v_provider FOR SHARE") ||
		strings.Contains(migration.SQL, "ORDER BY workspace.id\n    FOR SHARE") {
		t.Error("schema 163 locks the Workspace row")
	}
}

// Schema 164 serves enforced guardrails to map transactions only for the
// Workspaces of their own shares, previews shares to guardrail.manage, and
// lets only a transaction that changed a guardrail advance the revisions of
// the shares it cuts or restores. The schema 163 readers take the guardrail
// state row with NOWAIT and are otherwise unchanged.
func TestRetroactiveShareGuardrails(t *testing.T) {
	t.Parallel()
	migration := Catalog()[163]
	if migration.Version != 164 {
		t.Fatalf("migration 164 = %+v", migration)
	}
	for _, required := range []string{
		"WHERE locator.local_workspace_id = scoped_workspace_id\n          AND locator.local_network_id = scoped_network_id\n          AND side.public_id = ANY (p_workspaces)",
		"AND guardrail.mode = 'enforce'",
		"RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Workspace is unavailable to this Network';",
		"OR v_requested > 16384",
		"p_workspace_public_id, 'guardrail.manage', evaluated_at",
		"AND mutation.aggregate_kind = 'guardrail'\n              AND guardrail.workspace_id = scoped_workspace_id",
		"AND scoped_workspace_id IN (contract.provider_workspace_id, contract.consumer_workspace_id);",
		"ORDER BY revision.workspace_id, revision.network_id\n        FOR UPDATE",
		"ORDER BY stream.id\n        FOR UPDATE OF stream\n    ) AS head;",
		"PERFORM pg_catalog.set_config('mesh.guardrail_share_fanout', '', TRUE);",
		"GRANT EXECUTE ON FUNCTION mesh_ops.map_share_guardrails_v1(UUID[]) TO mesh_runtime;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.guardrail_change_share_contracts_v1(UUID) TO mesh_runtime;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.bump_guardrail_share_networks_v1(UUID[], UUID) TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 164 missing %q", required)
		}
	}
	// The internal helpers are never callable by a login role.
	for _, internal := range []string{
		"REVOKE ALL ON FUNCTION mesh_ops.guardrail_share_contracts_internal_v1(BIGINT)\n    FROM PUBLIC, mesh_runtime,",
		"REVOKE ALL ON FUNCTION mesh_ops.guardrail_change_workspace_internal_v1(UUID)\n    FROM PUBLIC, mesh_runtime,",
	} {
		if !strings.Contains(migration.SQL, internal) {
			t.Errorf("schema 164 exposes %q", internal)
		}
	}
	if strings.Contains(migration.SQL, "GRANT EXECUTE ON FUNCTION mesh_ops.guardrail_share_contracts_internal_v1") ||
		strings.Contains(migration.SQL, "GRANT EXECUTE ON FUNCTION mesh_ops.guardrail_change_workspace_internal_v1") ||
		strings.Contains(migration.SQL, "FROM mesh.workspace AS") {
		t.Error("schema 164 grants an internal helper or reads Workspace rows")
	}
	// The replaced schema 163 readers differ only by NOWAIT.
	extract := func(sql, name string) string {
		start := strings.Index(sql, "FUNCTION mesh_ops."+name+"(")
		if start < 0 {
			t.Fatalf("%s not found", name)
		}
		end := strings.Index(sql[start:], "$function$;")
		return sql[start : start+end]
	}
	for _, name := range []string{"share_offer_provider_guardrails_v1", "imported_resource_provider_guardrails_v1"} {
		replaced := extract(migration.SQL, name)
		if !strings.Contains(replaced, "FOR SHARE NOWAIT;") ||
			strings.ReplaceAll(replaced, "FOR SHARE NOWAIT;", "FOR SHARE;") != extract(Catalog()[162].SQL, name) {
			t.Errorf("schema 164 must replace %s with only NOWAIT added", name)
		}
	}
}

// Schema 167 keeps the schema 164 functions for the previous binary and
// adds versions that differ only where review required: the guardrail
// change takes the Workspace row FOR NO KEY UPDATE, the acting Workspace's
// guardrail reader locks its state row with NOWAIT, the share readers take
// their bound (at most 20000) from the caller, the preview also admits
// guardrail.weaken, the bump rechecks the evaluated shares after its
// revision locks, a change that only restores wakes at most 1024 Networks
// chosen in SQL, and the map reader looks Workspaces up through the
// accepted-offer indexes.
func TestGuardrailShareConsistency(t *testing.T) {
	t.Parallel()
	migration := migrationVersion(t, 167)
	extract := func(sql, name string) string {
		start := strings.Index(sql, "FUNCTION mesh_ops."+name+"(")
		if start < 0 {
			t.Fatalf("%s not found", name)
		}
		end := strings.Index(sql[start:], "$function$;")
		return sql[start : start+end]
	}
	change := extract(migration.SQL, "change_workspace_guardrail_v2")
	previous := strings.Replace(extract(Catalog()[162].SQL, "change_workspace_guardrail_v1"),
		"change_workspace_guardrail_v1(", "change_workspace_guardrail_v2(", 1)
	if strings.Replace(change, "scoped_workspace_id FOR NO KEY UPDATE;", "scoped_workspace_id FOR UPDATE;", 1) != previous {
		t.Error("change_workspace_guardrail_v2 must be v1 with only the Workspace row lock weakened")
	}
	active := extract(migration.SQL, "active_workspace_guardrails_v2")
	if !strings.Contains(active, "VOLATILE") ||
		!strings.Contains(active, "WHERE state.workspace_id = scoped_workspace_id FOR SHARE NOWAIT;") {
		t.Error("active_workspace_guardrails_v2 must lock the acting state row with NOWAIT")
	}
	bump := extract(migration.SQL, "bump_guardrail_share_networks_v2")
	locked := strings.Index(bump, "        FOR UPDATE\n        LOOP")
	recheck := strings.Index(bump, "RAISE EXCEPTION USING ERRCODE = 'MTG03', MESSAGE = 'a share changed during the guardrail change';")
	if locked < 0 || recheck < 0 || recheck < locked ||
		!strings.Contains(bump, "IF v_live <> v_inventory OR v_matched <> v_inventory THEN") {
		t.Error("the bump must recheck the evaluated shares after locking revisions")
	}
	listing := extract(migration.SQL, "list_guardrail_share_contracts_v2")
	if !strings.Contains(listing, "'guardrail.manage', evaluated_at))") ||
		!strings.Contains(listing, "'guardrail.weaken', evaluated_at)) THEN") {
		t.Error("the preview must admit guardrail.manage or guardrail.weaken")
	}
	internal := extract(migration.SQL, "guardrail_share_contracts_internal_v2")
	if !strings.Contains(internal, "LIMIT p_limit + 1") || !strings.Contains(internal, "p_limit > 20000 THEN") ||
		strings.Contains(internal, "20001") {
		t.Error("the share reader must take its bound from the caller")
	}
	wake := extract(migration.SQL, "wake_guardrail_share_networks_v1")
	for _, required := range []string{
		"OR p_limit IS NULL OR p_limit < 1 OR p_limit > 1024 THEN",
		"scoped_workspace_id := mesh_ops.guardrail_change_workspace_internal_v1(p_change);",
		"ORDER BY side.workspace_id, side.network_id\n        LIMIT p_limit + 1",
		"ORDER BY revision.workspace_id, revision.network_id\n        FOR UPDATE",
		"PERFORM pg_catalog.set_config('mesh.guardrail_share_fanout', '', TRUE);",
	} {
		if !strings.Contains(wake, required) {
			t.Errorf("wake_guardrail_share_networks_v1 missing %q", required)
		}
	}
	if strings.Contains(wake, "jsonb_agg(pg_catalog.jsonb_build_object(\n            'trust_contract_id'") {
		t.Error("the wakeup must not return a share list")
	}
	mapReader := extract(migration.SQL, "map_share_guardrails_v2")
	for _, required := range []string{
		"AND locator.provider_workspace_public_id = v_public_id\n              AND locator.state = 'accepted'",
		"AND locator.consumer_workspace_public_id = v_public_id\n              AND locator.state = 'accepted'",
		"RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Workspace is unavailable to this Network';",
		"AND guardrail.mode = 'enforce'",
	} {
		if !strings.Contains(mapReader, required) {
			t.Errorf("map_share_guardrails_v2 missing %q", required)
		}
	}
	for _, required := range []string{
		"CREATE INDEX share_offer_locator_accepted_provider_idx",
		"CREATE INDEX share_offer_locator_accepted_consumer_idx",
		"GRANT EXECUTE ON FUNCTION mesh_ops.map_share_guardrails_v2(UUID[]) TO mesh_runtime;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.bump_guardrail_share_networks_v2(UUID[], UUID[], UUID) TO mesh_runtime;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.active_workspace_guardrails_v2() TO mesh_runtime;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.wake_guardrail_share_networks_v1(UUID, UUID[], INTEGER) TO mesh_runtime;",
		"REVOKE ALL ON FUNCTION mesh_ops.guardrail_share_contracts_internal_v2(BIGINT, INTEGER)\n    FROM PUBLIC, mesh_runtime,",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 167 missing %q", required)
		}
	}
	if strings.Contains(migration.SQL, "DROP FUNCTION") || strings.Contains(migration.SQL, "REVOKE EXECUTE") ||
		strings.Contains(migration.SQL, "CREATE OR REPLACE FUNCTION") {
		t.Error("schema 167 must keep every previous function for the previous binary")
	}
}

func TestWorkspaceMemberRemoval(t *testing.T) {
	t.Parallel()
	migration := Catalog()[129]
	if migration.Version != 130 {
		t.Fatalf("migration 130 = %+v", migration)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.remove_workspace_member_v1(",
		"CREATE FUNCTION mesh_ops.revoke_member_device_internal_v1(",
		"'member.manage'",
		"NOT (role.assignable_by && mesh_ops.workspace_role_assigners_v1(v_workspace, v_actor, v_now))",
		"v_action := COALESCE(v_item.choice ->> 'action', 'revoke');",
		"WHERE device.workspace_id = v_workspace AND device.handover_principal_id = v_member",
		"credential.issuer_principal_id = v_member",
		"DELETE FROM mesh.identity_group_member AS member",
		"AND session.login_workspace_id = v_workspace",
		") TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 130 missing %q", required)
		}
	}
	if strings.Contains(migration.SQL, "GRANT SELECT") {
		t.Error("schema 130 must not grant direct table access")
	}
}

func TestAccountSelfSignup(t *testing.T) {
	t.Parallel()
	migration := Catalog()[130]
	if migration.Version != 131 {
		t.Fatalf("migration 131 = %+v", migration)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.account_signup (",
		"CREATE FUNCTION mesh_ops.sign_up_account_v1(",
		"AND auth.state = 'consuming' AND auth.version = p_transaction_version",
		"RETURN pg_catalog.jsonb_build_object('created', FALSE);",
		"v_deployment.profile <> 'cloud'",
		"ERRCODE = 'MTS02'",
		"ERRCODE = 'MTS03'",
		"v_workspace := mesh_ops.provision_workspace_v1(",
		") TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("schema 131 missing %q", required)
		}
	}
	if strings.Contains(migration.SQL, "GRANT SELECT") {
		t.Error("schema 131 must not grant direct table access")
	}
}

func TestCloudLoginWithoutWorkspace(t *testing.T) {
	t.Parallel()
	migration := Catalog()[131]
	if migration.Version != 132 {
		t.Fatalf("migration 132 = %+v", migration)
	}
	for _, name := range []string{"admit_oidc_login_route_v2", "create_oidc_auth_transaction_v2",
		"load_oidc_pending_browser_v2", "claim_oidc_browser_v2"} {
		if !strings.Contains(migration.SQL, "CREATE OR REPLACE FUNCTION mesh_ops."+name+"(") {
			t.Errorf("schema 132 must replace %s", name)
		}
	}
	if strings.Count(migration.SQL, "AND ((deployment.profile = 'cloud' AND NOT EXISTS (") != 4 {
		t.Error("schema 132 must relax exactly the four route checks")
	}
	if strings.Contains(migration.SQL, "GRANT ") {
		t.Error("schema 132 keeps the existing grants")
	}
}

func TestDeviceDistributionRead(t *testing.T) {
	t.Parallel()
	migration := Catalog()[132]
	if migration.Version != 133 {
		t.Fatalf("migration 133 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE FUNCTION mesh_ops.read_device_distribution_v1(",
		"SECURITY DEFINER",
		"'device.read'",
		"state IN ('active', 'suspended')",
		"'network_revision', current_network_revision",
		") TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 133 must contain %q", want)
		}
	}
	if strings.Contains(migration.SQL, "CREATE OR REPLACE") {
		t.Error("schema 133 only adds a new read function")
	}
}

func TestAccessEdgeLedger(t *testing.T) {
	t.Parallel()
	migration := Catalog()[133]
	if migration.Version != 134 {
		t.Fatalf("migration 134 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE TABLE mesh_ops.network_revision_history",
		"AFTER INSERT OR UPDATE OF network_revision ON mesh_ops.network_revision",
		"CREATE UNIQUE INDEX access_edge_history_open_uidx",
		"mesh_audit.capture_authority_mutation('access_edge_snapshot', 'public_id')",
		"pg_try_advisory_xact_lock",
		"source.state = 'active' AND source.expires_at > p_now",
		"contract.state = 'active' AND contract.expires_at > p_now",
		"'access_graph.recorded', 'system.reconcile'",
		"INTERVAL '13 months'",
		"'policy.read'",
		"'device.read'",
		"GRANT EXECUTE ON FUNCTION mesh_ops.record_access_edges_v1(UUID, UUID, UUID, UUID, UUID) TO mesh_worker;",
		") TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 134 must contain %q", want)
		}
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "BYPASSRLS", "DROP "} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 134 must not contain %q", forbidden)
		}
	}
}

func TestRelayRevocationsRead(t *testing.T) {
	t.Parallel()
	migration := Catalog()[134]
	if migration.Version != 135 {
		t.Fatalf("migration 135 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE FUNCTION mesh_ops.relay_revocations_v1(p_since TIMESTAMPTZ)",
		"SECURITY DEFINER",
		"p_since < v_now - INTERVAL '1 hour'",
		"ended.state <> 'active'",
		"current_key.epoch = device.current_node_key_epoch",
		"device.state <> 'active'",
		"contract.ended_at >= p_since",
		"contract.expires_at <= v_now",
		"GRANT EXECUTE ON FUNCTION mesh_ops.relay_revocations_v1(TIMESTAMPTZ) TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 135 must contain %q", want)
		}
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "BYPASSRLS", "DROP ", "UPDATE ", "INSERT "} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 135 must not contain %q", forbidden)
		}
	}
}

func TestDeviceEnforcementLedger(t *testing.T) {
	t.Parallel()
	migration := Catalog()[135]
	if migration.Version != 136 {
		t.Fatalf("migration 136 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE TABLE mesh_ops.device_enforcement_history",
		"CREATE TABLE mesh_ops.device_enforcement_event",
		"WHERE valid_to IS NULL;",
		"(state = 'enforced') = (delivered_digest = enforced_digest)",
		"mesh_audit.capture_authority_mutation('device_enforcement_event', 'public_id')",
		"pg_try_advisory_xact_lock",
		"'device.enforcement_mismatch'",
		"'device.enforcement_restored'",
		"'system.reconcile'",
		"INTERVAL '13 months'",
		"'device.read', p_evaluated_at",
		") TO mesh_worker;",
		") TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 136 must contain %q", want)
		}
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "BYPASSRLS", "DROP "} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 136 must not contain %q", forbidden)
		}
	}
}

func TestMTCPMachineTimestamp(t *testing.T) {
	t.Parallel()
	migration := Catalog()[136]
	if migration.Version != 137 {
		t.Fatalf("migration 137 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE TABLE mesh_ops.mtcp_machine_timestamp",
		"mesh_ops.resolve_map_session_scope(p_machine_fingerprint, p_node_key)",
		"WHERE stored.last_timestamp_ms < EXCLUDED.last_timestamp_ms",
		"GRANT EXECUTE ON FUNCTION mesh_ops.accept_mtcp_timestamp_v1(BYTEA, BYTEA, BIGINT) TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 137 must contain %q", want)
		}
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "BYPASSRLS", "DROP "} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 137 must not contain %q", forbidden)
		}
	}
}

func TestPrivateInterchange(t *testing.T) {
	t.Parallel()
	migration := Catalog()[138]
	if migration.Version != 139 {
		t.Fatalf("migration 139 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE TABLE mesh.private_interchange (",
		"CREATE TABLE mesh.private_interchange_network (",
		"ALTER TABLE mesh.private_interchange FORCE ROW LEVEL SECURITY;",
		"CREATE UNIQUE INDEX private_interchange_active_key_idx",
		"mesh_audit.capture_authority_mutation('private_interchange', 'public_id')",
		"'interchange.manage', evaluated_at",
		"mesh_ops.advance_identity_networks_internal_v1(scoped_workspace_id, affected)",
		"GRANT EXECUTE ON FUNCTION mesh_ops.private_interchange_directory_v1() TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 139 must contain %q", want)
		}
	}
	// The control plane read must not reach mesh.network outside a scope.
	directory := migration.SQL[strings.Index(migration.SQL, "CREATE FUNCTION mesh_ops.private_interchange_directory_v1()"):]
	if strings.Contains(directory[:strings.Index(directory, "$function$;")], "mesh.network ") {
		t.Error("the directory function must not read mesh.network")
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "BYPASSRLS", "DROP ", "ON mesh.network\n"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 139 must not contain %q", forbidden)
		}
	}
}

func TestMapNetworkInventory(t *testing.T) {
	t.Parallel()
	migration := Catalog()[139]
	if migration.Version != 140 {
		t.Fatalf("migration 140 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE FUNCTION mesh_ops.load_map_network_devices_v1(",
		"SECURITY DEFINER",
		"pg_catalog.current_setting('mesh.workspace_id', TRUE)",
		"candidate.workspace_id = scoped_workspace_id",
		"candidate.network_id = scoped_network_id",
		"candidate.expires_at > pg_catalog.transaction_timestamp()",
		"owner.state = 'active'",
		"deployment.recovery_state = 'verified'",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_devices_v1(INTEGER)\n    TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 140 must contain %q", want)
		}
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "BYPASSRLS", "DROP ", "INSERT ", "UPDATE ", "DELETE "} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 140 must not contain %q", forbidden)
		}
	}
}

func TestMapNetworkPolicy(t *testing.T) {
	t.Parallel()
	migration := Catalog()[140]
	if migration.Version != 141 {
		t.Fatalf("migration 141 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE FUNCTION mesh_ops.load_map_network_policy_rules_v1(",
		"CREATE FUNCTION mesh_ops.load_map_network_selector_members_v1(",
		"CREATE FUNCTION mesh_ops.load_map_network_policy_devices_v1(",
		"policy_release.state = 'active'",
		"membership.expires_at > pg_catalog.transaction_timestamp()",
		"device.expires_at > pg_catalog.transaction_timestamp()",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_policy_rules_v1(BIGINT, INTEGER) TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 141 must contain %q", want)
		}
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "BYPASSRLS", "DROP ", "INSERT ", "UPDATE ", "DELETE "} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 141 must not contain %q", forbidden)
		}
	}
}

func TestMapNetworkHeader(t *testing.T) {
	t.Parallel()
	migration := Catalog()[141]
	if migration.Version != 142 {
		t.Fatalf("migration 142 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE FUNCTION mesh_ops.load_map_network_header_v1()",
		"deployment.recovery_state = 'verified'",
		"network.state = 'active'",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_header_v1() TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 142 must contain %q", want)
		}
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "BYPASSRLS", "DROP ", "INSERT ", "UPDATE ", "DELETE "} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 142 must not contain %q", forbidden)
		}
	}
}

func TestNodeAddressQuarantine(t *testing.T) {
	t.Parallel()
	migration := Catalog()[142]
	if migration.Version != 143 {
		t.Fatalf("migration 143 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE FUNCTION mesh_ops.node_address_quarantine_v1()",
		"SELECT INTERVAL '24 hours'",
		"CREATE FUNCTION mesh_ops.quarantine_device_leases_v1(",
		"SECURITY INVOKER",
		"WHERE device.id = p_device_id AND device.state = 'revoked'",
		"SET state = 'quarantined',",
		"GREATEST(p_now, lease.updated_at) + mesh_ops.node_address_quarantine_v1()",
		"CREATE OR REPLACE FUNCTION mesh_ops.revoke_member_device_internal_v1(",
		"PERFORM mesh_ops.quarantine_device_leases_v1(v_device.id, p_now);",
		"GRANT EXECUTE ON FUNCTION mesh_ops.quarantine_device_leases_v1(BIGINT, TIMESTAMPTZ) TO mesh_runtime;",
		"FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 143 must contain %q", want)
		}
	}
	for _, forbidden := range []string{"BYPASSRLS", "DROP ", "INSERT ", "DELETE ", "SECURITY DEFINER", "'released'"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 143 must not contain %q", forbidden)
		}
	}
}

func TestPolicyInactiveDeviceRules(t *testing.T) {
	t.Parallel()
	migration := Catalog()[143]
	if migration.Version != 144 {
		t.Fatalf("migration 144 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE OR REPLACE FUNCTION mesh_ops.publish_compiled_policy_local_v1(",
		"CREATE OR REPLACE FUNCTION mesh_ops.attach_policy_group_rules_v2(",
		"source.state IN ('active', 'expired', 'suspended')",
		"WHERE carried.policy_release_id = active_release_id",
		"WHERE carried.policy_release_id = v_previous_release",
		"ERRCODE = 'MTP05'",
		"MESSAGE = 'compiled policy rule count mismatch'",
		"GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_group_rules_v2(UUID, TIMESTAMPTZ, JSONB) TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 144 must contain %q", want)
		}
	}
	for _, forbidden := range []string{
		"BYPASSRLS", "DROP ", "DELETE ",
		"source_device.state = 'active'", "destination_device.state = 'active'",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 144 must not contain %q", forbidden)
		}
	}
}

func TestMapNetworkSharing(t *testing.T) {
	t.Parallel()
	migration := Catalog()[144]
	if migration.Version != 145 {
		t.Fatalf("migration 145 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE FUNCTION mesh_ops.map_network_has_sharing_v1()",
		"SECURITY DEFINER",
		"contract.state IN ('activating', 'active')",
		"contract.expires_at > pg_catalog.transaction_timestamp()",
		"contract.provider_network_id = scoped_network_id",
		"contract.consumer_network_id = scoped_network_id",
		"GRANT EXECUTE ON FUNCTION mesh_ops.map_network_has_sharing_v1() TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 145 must contain %q", want)
		}
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "BYPASSRLS", "DROP ", "INSERT ", "UPDATE ", "DELETE "} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 145 must not contain %q", forbidden)
		}
	}
}

func TestMapSharingDevices(t *testing.T) {
	t.Parallel()
	migration := Catalog()[145]
	if migration.Version != 146 {
		t.Fatalf("migration 146 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE INDEX compiled_policy_imported_destination_release_source_idx",
		"CREATE FUNCTION mesh_ops.map_network_sharing_devices_v1(p_limit INTEGER)",
		"target.target_generation = contract.target_generation",
		"rule.policy_release_id = release.id",
		"GRANT EXECUTE ON FUNCTION mesh_ops.map_network_sharing_devices_v1(INTEGER) TO mesh_runtime;",
		"CREATE FUNCTION mesh_ops.load_device_sharing_dependencies_v2(",
		"rule.source_device_id=self_id",
		"loop_rule.source_device_id=self_id",
		"FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer,mesh_direct_map_reader;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 146 must contain %q", want)
		}
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "BYPASSRLS", "DROP ", "INSERT ", "UPDATE ", "DELETE "} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 146 must not contain %q", forbidden)
		}
	}
	operator := DeviceSharingDependenciesV2OwnershipSQL()
	for _, want := range []string{
		"OWNER TO mesh_device_alias_map_reader",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v2(BYTEA,BYTEA,INTEGER) TO mesh_runtime;",
	} {
		if !strings.Contains(operator, want) {
			t.Errorf("operator step 146 must contain %q", want)
		}
	}
}

func TestShareMapReaderScale(t *testing.T) {
	t.Parallel()
	migration := Catalog()[146]
	if migration.Version != 147 {
		t.Fatalf("migration 147 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE FUNCTION mesh_ops.load_device_alias_map_edges_v5(",
		"CREATE FUNCTION mesh_ops.load_device_sharing_dependencies_v3(",
		"p_limit > 10000 THEN",
		"ORDER BY endpoint.id LIMIT p_limit + 1",
		"LIMIT p_limit - edge_count + 1",
		`RETURN NEXT '{"limited":true}'::JSONB;`,
		"self_rule.source_device_id = self_id",
		"loop_rule.source_device_id=self_id",
		"remote_network IS DISTINCT FROM last_network",
		"CREATE FUNCTION mesh_ops.reserve_device_aliases_internal_v3(",
		"lease.alias_role = 'consumer_source') >= 10000 THEN",
		"CREATE FUNCTION mesh_ops.prepare_device_alias_change_v3(",
		"PERFORM mesh_ops.reserve_device_aliases_internal_v3(",
		"CREATE FUNCTION mesh_ops.load_device_alias_map_endpoint_edges_v1(",
		"WHERE endpoint.public_id = p_endpoint AND endpoint.provider_network_id <> endpoint.consumer_network_id",
		"mesh_ops.load_device_alias_map_endpoint_edges_v1(fingerprint,node_key,p_endpoint)",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_endpoint_edges_v1(BYTEA,BYTEA,UUID) TO mesh_device_alias_writer;",
		"CREATE FUNCTION mesh_ops.share_limit_reached_v1(",
		"LIMIT 10001) AS live) > 10000 THEN 'consumer_network'",
		"LANGUAGE sql VOLATILE PARALLEL UNSAFE SECURITY DEFINER",
		"CREATE FUNCTION mesh_ops.decide_resource_share_offer_v5(",
		"RAISE EXCEPTION USING ERRCODE = 'MT012'",
		"RETURN QUERY SELECT * FROM mesh_ops.decide_resource_share_offer_v4(",
		"FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer,mesh_direct_map_reader;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 147 must contain %q", want)
		}
	}
	for _, forbidden := range []string{
		"CREATE OR REPLACE", "BYPASSRLS", "DROP ",
		"ERRCODE = '54000'", "ERRCODE='54000'", "LIMIT 257", "seen_networks", "_v2(fingerprint,node_key,257)",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 147 must not contain %q", forbidden)
		}
	}
	// The map readers only read; the worker copies write as their v2 does.
	readers, _, found := strings.Cut(migration.SQL, "CREATE FUNCTION mesh_ops.reserve_device_aliases_internal_v3(")
	if !found {
		t.Fatal("schema 147 has no alias worker section")
	}
	for _, forbidden := range []string{"INSERT ", "UPDATE ", "DELETE "} {
		if strings.Contains(readers, forbidden) {
			t.Errorf("schema 147 map readers must not contain %q", forbidden)
		}
	}
	operator := ShareMapReaderScaleOwnershipSQL()
	for _, want := range []string{
		"load_device_alias_map_edges_v5(BYTEA,BYTEA,INTEGER) OWNER TO mesh_device_alias_map_reader",
		"load_device_sharing_dependencies_v3(BYTEA,BYTEA,INTEGER) OWNER TO mesh_device_alias_map_reader",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v5(BYTEA,BYTEA,INTEGER) TO mesh_runtime;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v3(BYTEA,BYTEA,INTEGER) TO mesh_runtime;",
		"prepare_device_alias_change_v3(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) OWNER TO mesh_device_alias_writer;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.prepare_device_alias_change_v3(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) TO mesh_worker;",
		"load_device_alias_map_endpoint_edges_v1(BYTEA,BYTEA,UUID) OWNER TO mesh_device_alias_map_reader;",
		") OWNER TO mesh_share_writer;",
		"BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ\n) TO mesh_runtime;",
	} {
		if !strings.Contains(operator, want) {
			t.Errorf("operator step 147 must contain %q", want)
		}
	}
}

func TestPolicyImportedResourceScale(t *testing.T) {
	t.Parallel()
	migration := Catalog()[147]
	if migration.Version != 148 {
		t.Fatalf("migration 148 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE FUNCTION mesh_ops.attach_policy_imported_resource_destinations_internal_v2(",
		"pg_catalog.jsonb_array_length(p_authority) > 10000 THEN",
		"CREATE FUNCTION mesh_ops.publish_compiled_policy_v2(",
		"mesh_ops.lock_and_resolve_policy_imported_resources_internal_v2(",
		"mesh_ops.attach_policy_imported_resource_destinations_internal_v2(",
		"CREATE FUNCTION mesh_ops.resolve_imported_policy_destinations_v2(",
		"OR requested_count NOT BETWEEN 1 AND 10000",
		"jsonb_array_length(p_groups) NOT BETWEEN 1 AND 10000",
		"FROM mesh_ops.publish_compiled_policy_local_v1(",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 148 must contain %q", want)
		}
	}
	for _, forbidden := range []string{
		"CREATE OR REPLACE", "BYPASSRLS", "DROP ", "AND 256", "> 256",
		"resolve_imported_policy_destinations_v1(", "lock_and_resolve_policy_imported_resources_internal_v1(",
		"attach_policy_imported_resource_destinations_internal_v1(", "mesh_ops.publish_compiled_policy(",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 148 must not contain %q", forbidden)
		}
	}
	operator := PolicyImportedResourceScaleOwnershipSQL()
	for _, want := range []string{
		") OWNER TO mesh_share_writer;",
		"UUID, UUID, UUID, UUID, UUID[], TIMESTAMPTZ\n) TO mesh_runtime;",
		"JSONB, TIMESTAMPTZ\n) TO mesh_migrator;",
	} {
		if !strings.Contains(operator, want) {
			t.Errorf("operator step 148 must contain %q", want)
		}
	}
}

func TestShareMapReaderSelection(t *testing.T) {
	t.Parallel()
	migration := Catalog()[148]
	if migration.Version != 149 {
		t.Fatalf("migration 149 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE INDEX compiled_policy_imported_destination_release_source_contract_idx",
		"workspace_id, network_id, policy_release_id, source_device_id, trust_contract_id",
		"CREATE FUNCTION mesh_ops.load_device_alias_map_edges_v6(",
		"CREATE FUNCTION mesh_ops.load_device_sharing_dependencies_v4(",
		"p_limit > 10000 THEN",
		"ORDER BY shared.id LIMIT p_limit + 1",
		"JOIN mesh.private_endpoint AS endpoint ON endpoint.trust_contract_id = contract.id",
		"CREATE INDEX private_endpoint_trust_contract_idx ON mesh.private_endpoint (trust_contract_id);",
		"SELECT DISTINCT self_rule.imported_resource_id",
		"SELECT DISTINCT loop_rule.trust_contract_id",
		"AND target.device_id = self_id AND target.state = 'active'",
		"AND target.device_id=self_id AND target.state='active'",
		"UNION ALL",
		`RETURN NEXT '{"limited":true}'::JSONB;`,
		"remote_network IS DISTINCT FROM last_network",
		"FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer,mesh_direct_map_reader;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 149 must contain %q", want)
		}
	}
	// The readers only read; the superseded index is dropped by a later
	// contract step, not under this migration's locks.
	for _, forbidden := range []string{
		"CREATE OR REPLACE", "BYPASSRLS", "DROP ", "INSERT ", "UPDATE ", "DELETE ", "GRANT ",
		"edges_v5(", "dependencies_v3(", "ORDER BY endpoint.id LIMIT",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 149 must not contain %q", forbidden)
		}
	}
	operator := ShareMapReaderSelectionOwnershipSQL()
	for _, want := range []string{
		"load_device_alias_map_edges_v6(BYTEA,BYTEA,INTEGER) OWNER TO mesh_device_alias_map_reader",
		"load_device_sharing_dependencies_v4(BYTEA,BYTEA,INTEGER) OWNER TO mesh_device_alias_map_reader",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v6(BYTEA,BYTEA,INTEGER) TO mesh_runtime;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v4(BYTEA,BYTEA,INTEGER) TO mesh_runtime;",
	} {
		if !strings.Contains(operator, want) {
			t.Errorf("operator step 149 must contain %q", want)
		}
	}
}

func TestPolicyAttachJoinOrder(t *testing.T) {
	t.Parallel()
	migration := Catalog()[149]
	if migration.Version != 150 {
		t.Fatalf("migration 150 = %+v", migration)
	}
	for _, version := range []string{"v1", "v2"} {
		want := "ALTER FUNCTION mesh_ops.attach_policy_imported_resource_destinations_internal_" + version +
			"(\n    UUID, TIMESTAMPTZ, JSONB, JSONB\n) SET join_collapse_limit = 1 SET from_collapse_limit = 1;"
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 150 must fix the join order of attach %s", version)
		}
	}
	for _, forbidden := range []string{"CREATE", "DROP ", "GRANT", "REVOKE", "OWNER", "SECURITY", "search_path", "INSERT", "UPDATE"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 150 must not contain %q", forbidden)
		}
	}
}

func TestDeviceSharedOnce(t *testing.T) {
	t.Parallel()
	migration := Catalog()[150]
	if migration.Version != 151 {
		t.Fatalf("migration 151 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE FUNCTION mesh_ops.device_already_shared_v1(",
		"LANGUAGE sql VOLATILE PARALLEL UNSAFE SECURITY DEFINER",
		"AND contract.public_id IS DISTINCT FROM p_except_contract_public_id",
		"AND contract.state IN ('activating', 'active')",
		"TO mesh_share_writer;",
		"CREATE FUNCTION mesh_ops.decide_resource_share_offer_v6(",
		"RETURN QUERY SELECT * FROM mesh_ops.decide_resource_share_offer_v5(",
		"RAISE EXCEPTION USING ERRCODE = 'MT013'",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 151 must contain %q", want)
		}
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "BYPASSRLS", "DROP ", "decide_resource_share_offer_v4("} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 151 must not contain %q", forbidden)
		}
	}
	operator := DeviceSharedOnceOwnershipSQL()
	for _, want := range []string{") OWNER TO mesh_share_writer;", "BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ\n) TO mesh_runtime;"} {
		if !strings.Contains(operator, want) {
			t.Errorf("operator step 151 must contain %q", want)
		}
	}
}

func TestMapReaderIndexLookups(t *testing.T) {
	t.Parallel()
	migration := Catalog()[151]
	if migration.Version != 152 {
		t.Fatalf("migration 152 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE INDEX device_machine_key_epoch_device_active_key_idx",
		"CREATE INDEX device_node_key_epoch_device_active_key_idx",
		"CREATE INDEX node_address_lease_device_primary_address_idx",
		"CREATE OR REPLACE FUNCTION mesh_ops.load_map_network_devices_v1(\n    p_limit INTEGER\n)",
		"CREATE OR REPLACE FUNCTION mesh_ops.load_map_peer_candidates(\n    p_machine_key_fingerprint BYTEA,",
		"FROM mesh.device_node_key_epoch AS current_node_key\n    CROSS JOIN LATERAL (",
		"AND pg_catalog.cardinality(lease.addresses) > 0",
		"AND candidate.id <> authenticated_device_id",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 152 must contain %q", want)
		}
	}
	if got := strings.Count(migration.SQL, "SECURITY DEFINER\nSET search_path = pg_catalog, mesh, mesh_ops"); got != 2 {
		t.Errorf("schema 152 keeps both readers' definer and search_path: %d", got)
	}
	for _, forbidden := range []string{"GRANT", "REVOKE", "OWNER", "DROP ", "BYPASSRLS", "INSERT", "UPDATE", "DELETE"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 152 must not contain %q", forbidden)
		}
	}
}

func TestMapInventoryChanges(t *testing.T) {
	t.Parallel()
	migration := Catalog()[152]
	if migration.Version != 153 {
		t.Fatalf("migration 153 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE TABLE mesh_ops.map_inventory_change_head (",
		"CREATE TABLE mesh_ops.map_inventory_change (",
		"CREATE INDEX map_inventory_change_seq_idx\n    ON mesh_ops.map_inventory_change (workspace_id, network_id, change_seq, device_id);",
		"ALTER TABLE mesh_ops.map_inventory_change_head FORCE ROW LEVEL SECURITY;",
		"ALTER TABLE mesh_ops.map_inventory_change FORCE ROW LEVEL SECURITY;",
		"DO UPDATE SET change_seq = head.change_seq + 1",
		"CREATE CONSTRAINT TRIGGER device_map_inventory_change_write",
		"CREATE CONSTRAINT TRIGGER device_map_inventory_change_update",
		"CREATE CONSTRAINT TRIGGER device_machine_key_epoch_map_inventory_change_update",
		"CREATE CONSTRAINT TRIGGER device_node_key_epoch_map_inventory_change_update",
		"CREATE CONSTRAINT TRIGGER node_address_lease_map_inventory_change_update",
		"CREATE CONSTRAINT TRIGGER principal_map_inventory_change_update",
		"GRANT EXECUTE ON FUNCTION mesh_ops.read_map_inventory_change_head_v1() TO mesh_runtime;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_device_changes_v1(BIGINT, INTEGER) TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 153 must contain %q", want)
		}
	}
	if got := strings.Count(migration.SQL, "DEFERRABLE INITIALLY DEFERRED"); got != 9 {
		t.Errorf("schema 153 has %d deferred triggers, want 9", got)
	}
	for _, forbidden := range []string{"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "TO mesh_worker", "BYPASSRLS",
		"DROP ", "CREATE OR REPLACE", "AFTER UPDATE OF", "mesh.map_inventory_seq_"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 153 must not contain %q", forbidden)
		}
	}
}

func TestMapNetworkDirectEndpoints(t *testing.T) {
	t.Parallel()
	migration := Catalog()[153]
	if migration.Version != 154 {
		t.Fatalf("migration 154 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE FUNCTION mesh_ops.map_network_has_direct_endpoints_v1()",
		"LANGUAGE sql\nSTABLE\nSECURITY DEFINER\nSET search_path = pg_catalog, mesh, mesh_ops",
		"AND endpoint.provider_network_id = mesh_ops.current_network_id()",
		"AND endpoint.consumer_network_id = mesh_ops.current_network_id()",
		"GRANT EXECUTE ON FUNCTION mesh_ops.map_network_has_direct_endpoints_v1() TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 154 must contain %q", want)
		}
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "DROP ", "INSERT", "UPDATE", "DELETE", "TO mesh_worker"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 154 must not contain %q", forbidden)
		}
	}
}

func TestShareReaderKeyLookup(t *testing.T) {
	t.Parallel()
	migration := Catalog()[154]
	if migration.Version != 155 {
		t.Fatalf("migration 155 = %+v", migration)
	}
	selection := Catalog()[148].SQL
	for _, reader := range []struct{ previous, next string }{
		{"load_device_alias_map_edges_v6", "load_device_alias_map_edges_v7"},
		{"load_device_sharing_dependencies_v4", "load_device_sharing_dependencies_v5"},
	} {
		previous := functionDefinition(t, selection, reader.previous)
		next := functionDefinition(t, migration.SQL, reader.next)
		lookup := strings.Index(previous, "    SELECT device.id INTO self_id\n")
		end := strings.Index(previous, "AND owner.state = 'active' AND owner.deleted_at IS NULL;\n")
		if lookup < 0 || end < lookup {
			t.Fatalf("%s: self lookup not found", reader.previous)
		}
		end += len("AND owner.state = 'active' AND owner.deleted_at IS NULL;\n")
		want := strings.Replace(previous[:lookup], reader.previous, reader.next, 1) +
			"    self_id := mesh_ops.authenticate_map_share_device_v1(\n" +
			"        p_machine_key_fingerprint, p_node_key, self_workspace, self_network);\n" + previous[end:]
		if next != want {
			t.Errorf("%s must be %s with only the self lookup replaced", reader.next, reader.previous)
		}
	}
	for _, want := range []string{
		"LANGUAGE sql\nSTABLE\nSECURITY INVOKER\nSET search_path = pg_catalog, mesh, mesh_ops",
		"WHERE node_key.public_key = p_node_key",
		"GRANT EXECUTE ON FUNCTION mesh_ops.authenticate_map_share_device_v1(BYTEA, BYTEA, BIGINT, BIGINT)\n    TO mesh_device_alias_map_reader;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 155 must contain %q", want)
		}
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "DROP ", "GRANT EXECUTE ON FUNCTION mesh_ops.load_device", "OWNER TO"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 155 must not contain %q", forbidden)
		}
	}
	operator := ShareReaderKeyLookupOwnershipSQL()
	for _, want := range []string{
		"load_device_alias_map_edges_v7(BYTEA,BYTEA,INTEGER) OWNER TO mesh_device_alias_map_reader",
		"load_device_sharing_dependencies_v5(BYTEA,BYTEA,INTEGER) OWNER TO mesh_device_alias_map_reader",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v7(BYTEA,BYTEA,INTEGER) TO mesh_runtime;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v5(BYTEA,BYTEA,INTEGER) TO mesh_runtime;",
	} {
		if !strings.Contains(operator, want) {
			t.Errorf("operator step 155 must contain %q", want)
		}
	}
}

// functionDefinition returns one CREATE FUNCTION statement of sql.
func functionDefinition(t *testing.T, sql, name string) string {
	t.Helper()
	start := strings.Index(sql, "CREATE FUNCTION mesh_ops."+name+"(")
	if start < 0 {
		t.Fatalf("%s not defined", name)
	}
	end := strings.Index(sql[start:], "$function$;")
	if end < 0 {
		t.Fatalf("%s not terminated", name)
	}
	return sql[start : start+end+len("$function$;")]
}

func TestDependencyReaderNetworkOnce(t *testing.T) {
	t.Parallel()
	migration := Catalog()[155]
	if migration.Version != 156 {
		t.Fatalf("migration 156 = %+v", migration)
	}
	previous := functionDefinition(t, Catalog()[154].SQL, "load_device_sharing_dependencies_v5")
	next := functionDefinition(t, migration.SQL, "load_device_sharing_dependencies_v6")
	skip := `      -- Contracts come ordered by the other side's Network: once one proved
      -- a dependency on that Network, the rest of its contracts add nothing.
      IF last_network_id = (CASE WHEN contract_row.provider_network_id=self_network
          THEN contract_row.consumer_network_id ELSE contract_row.provider_network_id END) THEN
        CONTINUE;
      END IF;
`
	remember := `        last_network_id:=CASE WHEN contract_row.provider_network_id=self_network
          THEN contract_row.consumer_network_id ELSE contract_row.provider_network_id END;
`
	want := strings.Replace(previous, "load_device_sharing_dependencies_v5(", "load_device_sharing_dependencies_v6(", 1)
	for _, insert := range []struct{ after, text string }{
		{"    last_network UUID;\n", "    last_network_id BIGINT;\n"},
		{"        RETURN NEXT '{\"limited\":true}'::JSONB;\n        EXIT;\n      END IF;\n", skip},
		{"        last_network:=remote_network;\n", remember},
	} {
		if strings.Count(want, insert.after) != 1 {
			t.Fatalf("v5 has %d of %q", strings.Count(want, insert.after), insert.after)
		}
		want = strings.Replace(want, insert.after, insert.after+insert.text, 1)
	}
	if next != want {
		t.Error("dependencies v6 must be v5 with only the per-Network skip added")
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "DROP ", "GRANT ", "OWNER TO"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 156 must not contain %q", forbidden)
		}
	}
	operator := DependencyReaderNetworkOnceOwnershipSQL()
	for _, want := range []string{
		"load_device_sharing_dependencies_v6(BYTEA,BYTEA,INTEGER) OWNER TO mesh_device_alias_map_reader",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_device_sharing_dependencies_v6(BYTEA,BYTEA,INTEGER) TO mesh_runtime;",
	} {
		if !strings.Contains(operator, want) {
			t.Errorf("operator step 156 must contain %q", want)
		}
	}
}

func TestRegistrationAddressFloor(t *testing.T) {
	t.Parallel()
	migration := Catalog()[156]
	if migration.Version != 157 {
		t.Fatalf("migration 157 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE TABLE mesh_ops.registration_address_floor (",
		"ALTER TABLE mesh_ops.registration_address_floor FORCE ROW LEVEL SECURITY;",
		"GRANT SELECT, INSERT, UPDATE ON mesh_ops.registration_address_floor TO mesh_runtime;",
		"AND network_prefix.prefix = registration_address_floor.prefix",
		"ON mesh.node_address_lease (network_prefix_id, address)\n    WHERE state IN ('active', 'quarantined');",
		"INCLUDE (quarantine_until)\n    WHERE state = 'quarantined';",
		"AFTER UPDATE ON mesh.node_address_lease\nFOR EACH ROW\nWHEN (OLD.state IN ('active', 'quarantined')",
		"AFTER DELETE ON mesh.node_address_lease\nFOR EACH ROW\nWHEN (OLD.state IN ('active', 'quarantined'))",
		"AND NOT (lease.state = 'active' AND device.id IS NOT NULL)",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 157 must contain %q", want)
		}
	}
	// The floor only goes down outside the allocator, and the triggers
	// cannot be reached as functions.
	for _, want := range []string{
		"AND address_floor.floor_address > OLD.address;",
		"REVOKE ALL ON FUNCTION mesh_ops.lower_registration_address_floor_v1() FROM PUBLIC;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 157 must contain %q", want)
		}
	}
	// Revocation must not read leases (a revocation commits while the lease
	// table is locked, see the peer candidate tests).
	for _, forbidden := range []string{"CREATE OR REPLACE", "DROP ", "OWNER TO", "GRANT EXECUTE", "DELETE ON mesh_ops",
		"ON mesh.device"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 157 must not contain %q", forbidden)
		}
	}
}

func TestRegistrationRecentDevices(t *testing.T) {
	t.Parallel()
	migration := Catalog()[157]
	if migration.Version != 158 {
		t.Fatalf("migration 158 = %+v", migration)
	}
	want := "CREATE INDEX device_registered_principal_recent_idx\n" +
		"    ON mesh.device (registered_by_principal_id, workspace_id, network_id, created_at)\n" +
		"    WHERE registered_by_kind = 'principal';"
	if !strings.Contains(migration.SQL, want) {
		t.Errorf("schema 158 must contain %q", want)
	}
	// An index alone: no function, grant or row change.
	for _, forbidden := range []string{"FUNCTION", "GRANT", "UPDATE ", "DELETE ", "DROP ", "ALTER "} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 158 must not contain %q", forbidden)
		}
	}
}

func TestNetworkAddressUsage(t *testing.T) {
	t.Parallel()
	migration := Catalog()[158]
	if migration.Version != 159 {
		t.Fatalf("migration 159 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE FUNCTION mesh_ops.read_network_address_usage_v1(",
		"SECURITY DEFINER\nSET search_path = pg_catalog",
		"p_workspace_public_id, p_network_public_id, 'network.read', p_evaluated_at",
		"WHERE prefix.workspace_id = v_workspace AND prefix.network_id = v_network",
		") TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 159 must contain %q", want)
		}
	}
	// A read: nothing written, locked or granted beyond the runtime.
	for _, forbidden := range []string{"INSERT ", "UPDATE ", "DELETE ", "FOR UPDATE", "DROP ", "ALTER ",
		"TO mesh_worker", "OWNER TO"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 159 must not contain %q", forbidden)
		}
	}
}

// migrationVersion returns the catalog migration with version.
func migrationVersion(t *testing.T, version int64) Migration {
	t.Helper()
	for _, migration := range Catalog() {
		if migration.Version == version {
			return migration
		}
	}
	t.Fatalf("migration %d is not in the catalog", version)
	return Migration{}
}

// functionSignature returns the part of a function definition from its name
// to the start of its body: arguments, result, attributes and settings.
func functionSignature(t *testing.T, sql, name string) string {
	t.Helper()
	start := strings.Index(sql, "FUNCTION mesh_ops."+name+"(")
	if start < 0 {
		t.Fatalf("%s not defined", name)
	}
	end := strings.Index(sql[start:], "AS $function$")
	if end < 0 {
		t.Fatalf("%s has no body", name)
	}
	return sql[start : start+end]
}

// Schema 165 keeps rules to a Resource, a Resource Group member or an
// Imported Resource publishing after their Device leaves the active state,
// as schema 144 does for Device and group rules, and compares kept rules in
// full. Signatures, settings and grants stay the same.
func TestPolicyGoneDeviceDestinations(t *testing.T) {
	t.Parallel()
	migration := migrationVersion(t, 165)
	previous := map[string]string{
		"publish_compiled_policy_local_v1":                         migrationVersion(t, 144).SQL,
		"attach_policy_group_rules_v2":                             migrationVersion(t, 144).SQL,
		"attach_policy_resource_destinations":                      migrationVersion(t, 43).SQL,
		"attach_policy_resource_group_destinations":                migrationVersion(t, 44).SQL,
		"attach_policy_imported_resource_destinations_internal_v1": migrationVersion(t, 52).SQL,
		"attach_policy_imported_resource_destinations_internal_v2": migrationVersion(t, 148).SQL,
	}
	for name, sql := range previous {
		if !strings.Contains(migration.SQL, "CREATE OR REPLACE FUNCTION mesh_ops."+name+"(") {
			t.Errorf("schema 165 must replace %s", name)
			continue
		}
		want := functionSignature(t, sql, name)
		if strings.HasPrefix(name, "attach_policy_imported_resource_destinations_internal_") {
			// Schema 150 fixed their join order; a replacement must keep it.
			want = strings.Replace(want, "SET search_path = pg_catalog, mesh, mesh_ops\n",
				"SET search_path = pg_catalog, mesh, mesh_ops\nSET join_collapse_limit = 1\nSET from_collapse_limit = 1\n", 1)
		}
		if got := functionSignature(t, migration.SQL, name); got != want {
			t.Errorf("schema 165 changed the signature or settings of %s:\n%s\nwant\n%s", name, got, want)
		}
	}
	// The two Imported attach versions differ only in name and bound, as before.
	imported := func(version string) string {
		start := strings.Index(migration.SQL,
			"FUNCTION mesh_ops.attach_policy_imported_resource_destinations_internal_"+version+"(")
		end := strings.Index(migration.SQL[start:], "$function$;")
		return migration.SQL[start : start+end]
	}
	if strings.Replace(strings.Replace(imported("v1"), "internal_v1(", "internal_v2(", 1),
		"jsonb_array_length(p_authority) > 256", "jsonb_array_length(p_authority) > 10000", 1) != imported("v2") {
		t.Error("schema 165 Imported attach v1 and v2 must differ only in name and bound")
	}
	for _, want := range []struct {
		text  string
		count int
	}{
		// Live states as in schema 144; expires_at is not checked.
		{"WHERE destination.state IN ('active', 'expired', 'suspended')", 2},
		{"                source.state IN ('active', 'expired', 'suspended')\n                OR EXISTS (", 2},
		// Kept means unchanged in full.
		{"AND carried.protocol = rule.protocol\n                      AND carried.destination_ports = rule.destination_ports", 1},
		{"AND carried.source_device_group_id IS NOT DISTINCT FROM source_group.id", 1},
		{"AND carried.source_identity_group_id IS NOT DISTINCT FROM source_identity.id", 1},
		{"AND carried.destination_device_tag_id IS NOT DISTINCT FROM destination_tag.id", 1},
		{"AND carried.destination_ports = ports.destination_ports", 3},
		{"AND carried.destination_ports = compiled.destination_ports", 2},
		{"AND carried_destination.destination_resource_id = resource.id", 2},
		{"AND carried_destination.destination_resource_group_id = resource_group.id", 1},
		{"AND carried.imported_resource_id = imported.id", 2},
		{"AND previous.policy_revision = release_policy_revision - 1\n      AND previous.state = 'superseded';", 4},
		// A new or changed rule for a gone Device is MTP05 in every function.
		{"ERRCODE = 'MTP05'", 6},
		// Every function tells a left-out rule by its projection ID.
		{"WHERE attached.public_id = rule.projection_public_id", 6},
		{"GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_resource_destinations(UUID, TIMESTAMPTZ, JSONB) TO mesh_runtime;", 1},
		{"GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_group_rules_v2(UUID, TIMESTAMPTZ, JSONB) TO mesh_runtime;", 1},
	} {
		if got := strings.Count(migration.SQL, want.text); got != want.count {
			t.Errorf("schema 165 has %d of %q, want %d", got, want.text, want.count)
		}
	}
	for _, forbidden := range []string{
		"AND destination.state = 'active'", "AND source.state = 'active'", "source.expires_at",
		"source_device.state IN ('active', 'expired', 'suspended') OR EXISTS",
		"BYPASSRLS", "DROP ", "DELETE ", "OWNER TO", "TO mesh_worker", "TO mesh_share_writer",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 165 must not contain %q", forbidden)
		}
	}
}

// Schema 166 lets network.member.manage list, add and remove the members of
// one Network, removing a member's Devices there as schema 130 does for the
// Workspace.
func TestNetworkMemberManagement(t *testing.T) {
	t.Parallel()
	catalog := Catalog()
	if len(catalog) < 166 {
		t.Fatalf("len(Catalog()) = %d, want schema 166", len(catalog))
	}
	migration := catalog[165]
	if migration.Version != 166 {
		t.Fatalf("migration 166 = %+v", migration)
	}
	for _, want := range []string{
		"('network.member.manage', 'Add and remove the members of a Network', 'privileged', ARRAY['network'], 1)",
		"('admin', 'network.member.manage'),\n    ('it_admin', 'network.member.manage')",
		"CREATE FUNCTION mesh_ops.list_network_members_v1(",
		"CREATE FUNCTION mesh_ops.add_network_members_v1(",
		"CREATE FUNCTION mesh_ops.remove_network_member_v1(",
		"p_workspace_public_id, p_network_public_id, 'network.read', p_evaluated_at",
		"p_workspace_public_id, p_network_public_id, 'network.member.manage', v_now",
		"pg_catalog.cardinality(p_member_public_ids) NOT BETWEEN 1 AND 150",
		"RAISE EXCEPTION USING ERRCODE = 'MTM01'",
		"RAISE EXCEPTION USING ERRCODE = 'MTM02'",
		"RAISE EXCEPTION USING ERRCODE = 'MTM03'",
		"RAISE EXCEPTION USING ERRCODE = 'MTM04'",
		"AND ((assignment.network_id IS NULL AND NOT (role.assignable_by && v_assigners))",
		"AND assignment.network_id = v_scope.network_id AND assignment.role_key IN ('admin', 'it_admin')",
		"OR (pg_catalog.cardinality(v_assigners) = 0 AND EXISTS (",
		"PERFORM mesh_ops.revoke_member_device_internal_v1(v_device.id, 'network member removed', v_now);",
		"mesh_ops.advance_member_networks_internal_v1(v_scope.workspace_id, ARRAY[v_scope.network_id])",
		"AND credential.issuer_principal_id = v_member AND credential.state = 'active'",
		") TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 166 must contain %q", want)
		}
	}
	// The Workspace row is locked before the Network revision in every write.
	for _, name := range []string{"add_network_members_v1(", "remove_network_member_v1("} {
		start := strings.Index(migration.SQL, "CREATE FUNCTION mesh_ops."+name)
		body := migration.SQL[start:]
		body = body[:strings.Index(body, "$function$;")]
		workspaceLock := strings.Index(body, "FROM mesh.workspace AS workspace")
		revision := strings.Index(body, "mesh_ops.network_revision")
		if workspaceLock < 0 || revision < 0 || workspaceLock > revision {
			t.Errorf("%s must lock the Workspace row before the Network revision", name)
		}
		if !strings.Contains(body, "SET join_collapse_limit = 1\nSET from_collapse_limit = 1\n"+
			"SET plan_cache_mode = force_generic_plan") {
			t.Errorf("%s must keep its written join order and a generic plan", name)
		}
	}
	// Sessions, Identity Groups and the Workspace membership stay as they are.
	for _, forbidden := range []string{"UPDATE mesh.account_session", "DELETE FROM mesh.identity_group_member",
		"UPDATE mesh.workspace_membership", "DELETE ", "DROP ", "OWNER TO", "TO mesh_worker", "GRANT SELECT"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 166 must not contain %q", forbidden)
		}
	}
}

// Schema 168 keeps the schema 55 and 56 publication functions for the
// previous binary. The candidate list v2 is v1 that also waits for the
// database clock to reach the endpoint's creation, and the snapshot read v3
// refuses a snapshot taken before it, as the confirmation does.
func TestPrivateEndpointPublicationClock(t *testing.T) {
	t.Parallel()
	migration := migrationVersion(t, 168)
	extract := func(sql, name string) string {
		start := strings.Index(sql, "FUNCTION mesh_ops."+name+"(")
		if start < 0 {
			t.Fatalf("%s not found", name)
		}
		end := strings.Index(sql[start:], "$function$;")
		return sql[start : start+end]
	}
	list := extract(migration.SQL, "list_private_endpoint_publication_candidates_v2")
	previous := strings.Replace(extract(migrationVersion(t, 55).SQL, "list_private_endpoint_publication_candidates_v1"),
		"list_private_endpoint_publication_candidates_v1(", "list_private_endpoint_publication_candidates_v2(", 1)
	if strings.Replace(list, "          AND endpoint.created_at <= decision_at\n", "", 1) != previous ||
		!strings.Contains(list, "AND endpoint.created_at <= decision_at") {
		t.Error("list_private_endpoint_publication_candidates_v2 must be v1 that also waits for the endpoint's creation")
	}
	read := extract(migration.SQL, "read_private_endpoint_publication_snapshot_v3")
	for _, required := range []string{
		"SECURITY DEFINER\nSET search_path = pg_catalog, mesh, mesh_ops\n",
		"snapshot := mesh_ops.read_private_endpoint_publication_snapshot_v2(",
		"IF (snapshot->>'snapshot_at')::TIMESTAMPTZ < endpoint_created_at THEN\n        RAISE EXCEPTION USING ERRCODE = '40001',",
	} {
		if !strings.Contains(read, required) {
			t.Errorf("read_private_endpoint_publication_snapshot_v3 missing %q", required)
		}
	}
	for _, name := range []string{
		"list_private_endpoint_publication_candidates_v2(UUID, INTEGER)",
		"read_private_endpoint_publication_snapshot_v3(UUID, UUID)",
	} {
		if !strings.Contains(migration.SQL, "REVOKE ALL ON FUNCTION mesh_ops."+name+"\nFROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;") ||
			!strings.Contains(migration.SQL, "GRANT EXECUTE ON FUNCTION mesh_ops."+name+"\nTO mesh_worker;") {
			t.Errorf("schema 168 must grant %s to mesh_worker only", name)
		}
	}
	if strings.Contains(migration.SQL, "DROP FUNCTION") || strings.Contains(migration.SQL, "REVOKE EXECUTE") ||
		strings.Contains(migration.SQL, "CREATE OR REPLACE FUNCTION") {
		t.Error("schema 168 must keep every previous function for the previous binary")
	}
}

// Schema 169 names every live Device of a Network with a unique DNS label
// kept beside the Device row, so neither the backfill nor a later label
// change versions the Device or needs audit evidence.
func TestDeviceDNSNames(t *testing.T) {
	t.Parallel()
	catalog := Catalog()
	if len(catalog) < 169 {
		t.Fatalf("len(Catalog()) = %d, want schema 169", len(catalog))
	}
	migration := catalog[168]
	if migration.Version != 169 {
		t.Fatalf("migration 169 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE TABLE mesh.device_dns_label (",
		"dns_label TEXT COLLATE \"C\" NOT NULL",
		"CONSTRAINT device_dns_label_network_label_key UNIQUE (workspace_id, network_id, dns_label)",
		"AND dns_label ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'\n        AND dns_label !~ '^[0-9]+$'",
		"REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE CASCADE",
		"ALTER TABLE mesh.device_dns_label FORCE ROW LEVEL SECURITY;",
		"CREATE POLICY device_dns_label_exact_scope_policy ON mesh.device_dns_label\n    FOR SELECT\n    TO mesh_runtime",
		"GRANT SELECT ON mesh.device_dns_label TO mesh_runtime;",
		"CREATE FUNCTION mesh_ops.derive_device_dns_label_v1(p_hostname TEXT)",
		"CREATE FUNCTION mesh_ops.assign_device_dns_label_internal_v1(",
		"WHEN ((OLD.hostname, OLD.state, OLD.deleted_at) IS DISTINCT FROM (NEW.hostname, NEW.state, NEW.deleted_at))",
		"IF NEW.state IN ('revoked', 'deleted') OR NEW.deleted_at IS NOT NULL THEN",
		"ORDER BY device.workspace_id, device.network_id, device.id",
		"GRANT EXECUTE ON FUNCTION mesh_ops.read_scope_display_codes_v1() TO mesh_runtime;",
		"CREATE FUNCTION mesh_ops.read_console_devices_v3(",
		"v_page := mesh_ops.read_console_devices_v2(",
		"CREATE OR REPLACE FUNCTION mesh_ops.change_device_lifecycle_v1(",
		"AND other.dns_label = mesh_ops.derive_device_dns_label_v1(v_hostname)",
		"RAISE EXCEPTION USING ERRCODE = 'MTL03', MESSAGE = 'another Device has this DNS name';",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 169 must contain %q", want)
		}
	}
	// Internal helpers stay with their owner; only the readers are granted.
	for _, name := range []string{"derive_device_dns_label_v1(TEXT)", "device_dns_label_variant_v1(TEXT, INTEGER)",
		"assign_device_dns_label_internal_v1(BIGINT, BIGINT, BIGINT, TEXT)", "maintain_device_dns_label_v1()"} {
		if !strings.Contains(migration.SQL, "REVOKE ALL ON FUNCTION mesh_ops."+name+"\n    FROM PUBLIC, mesh_runtime,") ||
			strings.Contains(migration.SQL, "GRANT EXECUTE ON FUNCTION mesh_ops."+name) {
			t.Errorf("schema 169 must keep mesh_ops.%s from the application roles", name)
		}
	}
	// The rename keeps schema 127's function otherwise: same signature,
	// configuration and every other action.
	previous := catalog[126].SQL
	start := strings.Index(previous, "CREATE OR REPLACE FUNCTION mesh_ops.change_device_lifecycle_v1(")
	end := strings.Index(previous[start:], "$function$;") + start
	current := migration.SQL[strings.Index(migration.SQL, "CREATE OR REPLACE FUNCTION mesh_ops.change_device_lifecycle_v1("):]
	current = current[:strings.Index(current, "$function$;")]
	labelCheck := `        IF EXISTS (
            SELECT 1 FROM mesh.device_dns_label AS other
            WHERE other.workspace_id = v_workspace AND other.network_id = v_network
              AND other.dns_label = mesh_ops.derive_device_dns_label_v1(v_hostname)
              AND other.device_id <> v_device.id
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL03', MESSAGE = 'another Device has this DNS name';
        END IF;
`
	if strings.Replace(current, labelCheck, "", 1) != previous[start:end] {
		t.Error("schema 169 change_device_lifecycle_v1 must be schema 127's plus the label check")
	}
	// Device rows are neither altered nor written by the migration itself
	// (only by the unchanged actions of the lifecycle function).
	outside := strings.Replace(migration.SQL, current, "", 1)
	for _, forbidden := range []string{"ALTER TABLE mesh.device ", "UPDATE mesh.device",
		"DROP ", "OWNER TO", "TO mesh_worker", "BYPASSRLS", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE"} {
		if strings.Contains(outside, forbidden) {
			t.Errorf("schema 169 must not contain %q", forbidden)
		}
	}
}

// Schema 170 readmits a consumer Device whose share was withdrawn: each
// admission is new readiness and source lease rows, so the per-pair unique
// constraints become partial unique indexes over the live rows, and the
// worker copies differ from their previous version only where the
// readmission needs it.
func TestDeviceAliasConsumerReadmission(t *testing.T) {
	t.Parallel()
	catalog := Catalog()
	if len(catalog) < 170 {
		t.Fatalf("len(Catalog()) = %d, want schema 170", len(catalog))
	}
	migration := catalog[169]
	if migration.Version != 170 {
		t.Fatalf("migration 170 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE UNIQUE INDEX device_alias_readiness_ready_uidx\n    ON mesh.device_alias_client_readiness (private_endpoint_id, consumer_device_id) WHERE state = 'ready';",
		"CREATE UNIQUE INDEX device_alias_lease_reserved_owner_uidx\n    ON mesh.device_alias_lease (private_endpoint_id, alias_role, owner_device_id, family) WHERE state = 'reserved';",
		"pg_catalog.pg_get_constraintdef(constraint_row.oid) = 'UNIQUE (private_endpoint_id, consumer_device_id)'",
		"pg_catalog.pg_get_constraintdef(constraint_row.oid) = 'UNIQUE (private_endpoint_id, alias_role, owner_device_id, family)'",
		"GRANT EXECUTE ON FUNCTION mesh_ops.reserve_device_aliases_internal_v4(UUID, UUID, BIGINT, BIGINT, BIGINT, UUID[])\n    TO mesh_device_alias_writer;",
		"REVOKE ALL ON FUNCTION mesh_ops.prepare_device_alias_change_v4(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) FROM PUBLIC,mesh_runtime,mesh_worker,",
		"REVOKE ALL ON FUNCTION mesh_ops.load_device_alias_work_v3(UUID,UUID,UUID,INTEGER) FROM PUBLIC,mesh_runtime,mesh_worker,",
		// Only the same Device's quarantined source alias of the same slot may
		// share the new lease's address.
		"AND NOT (NEW.alias_role = 'consumer_source' AND lease.state = 'quarantined'\n            AND lease.private_endpoint_id = NEW.private_endpoint_id AND lease.alias_role = 'consumer_source'\n            AND lease.owner_device_id = NEW.owner_device_id AND lease.family = NEW.family)",
		"DROP TRIGGER device_alias_network_uniqueness ON mesh.device_alias_lease;\nCREATE TRIGGER device_alias_network_uniqueness BEFORE INSERT ON mesh.device_alias_lease\n    FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_device_alias_network_uniqueness_v2();",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 170 must contain %q", want)
		}
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "BYPASSRLS", "OWNER TO", "TO mesh_worker", "TO mesh_runtime",
		"DROP FUNCTION", "DROP INDEX", "DROP TABLE", "DROP POLICY"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 170 must not contain %q", forbidden)
		}
	}
	function := func(sql, name, end string) string {
		start := strings.Index(sql, "CREATE FUNCTION mesh_ops."+name+"(")
		if start < 0 {
			t.Fatalf("no %s", name)
		}
		stop := strings.Index(sql[start:], end)
		if stop < 0 {
			t.Fatalf("no end of %s", name)
		}
		return sql[start : start+stop+len(end)]
	}
	replace := func(text, previous, current string) string {
		if strings.Count(text, previous) != 1 {
			t.Fatalf("previous version must contain %q once", previous)
		}
		return strings.Replace(text, previous, current, 1)
	}
	revoke := "\nREVOKE ALL ON FUNCTION mesh_ops."
	reserve := strings.ReplaceAll(function(catalog[146].SQL, "reserve_device_aliases_internal_v3", "$function$;"), "_v3(", "_v4(")
	reserve = replace(reserve, "AND lease.owner_device_id = owner_device.id;\n            IF FOUND THEN",
		"AND lease.owner_device_id = owner_device.id\n              AND (role_value = 'resource' OR lease.state = 'reserved');\n            IF FOUND THEN")
	reserve = replace(reserve, `            ELSE
                candidate := mesh_ops.allocate_network_scoped_alias_v1(endpoint_row.deployment_id,
                    pool_row.id, endpoint_row.provider_network_id, endpoint_row.consumer_network_id);
            END IF;`, `            ELSE
                -- A readmitted consumer Device gets its own quarantined source
                -- alias back while its keys are unchanged; it is retained in
                -- both Networks, so no other Device can hold it.
                candidate := NULL;
                IF role_value = 'consumer_source' THEN
                    SELECT lease.address INTO candidate FROM mesh.device_alias_lease AS lease
                    WHERE lease.private_endpoint_id = endpoint_row.id AND lease.alias_role = role_value
                      AND lease.family = family_value AND lease.owner_device_id = owner_device.id
                      AND lease.state = 'quarantined' AND lease.address_pool_id = pool_row.id
                      AND lease.address << pool_row.prefix AND lease.node_public_key = node_key
                      AND lease.machine_key_epoch = owner_device.current_machine_key_epoch
                    ORDER BY lease.id DESC LIMIT 1;
                END IF;
                IF candidate IS NULL THEN
                    candidate := mesh_ops.allocate_network_scoped_alias_v1(endpoint_row.deployment_id,
                        pool_row.id, endpoint_row.provider_network_id, endpoint_row.consumer_network_id);
                END IF;
            END IF;`)
	if function(migration.SQL, "reserve_device_aliases_internal_v4", "$function$;") != reserve {
		t.Error("reserve v4 must be v3 that reuses only a reserved source lease and gives a readmitted Device its own alias back")
	}
	prepare := strings.ReplaceAll(function(catalog[146].SQL, "prepare_device_alias_change_v3", revoke), "_v3(", "_v4(")
	prepare = replace(prepare, "consumer_device_id=consumer.id) THEN", "consumer_device_id=consumer.id AND state='ready') THEN")
	if function(migration.SQL, "prepare_device_alias_change_v4", revoke) != prepare {
		t.Error("prepare v4 must be v3 that calls reserve v4 and inserts readiness without a ready row")
	}
	work := strings.ReplaceAll(function(catalog[91].SQL, "load_device_alias_work_v2", revoke), "_v2(", "_v3(")
	for _, change := range [][2]string{
		{"readiness_expiry TIMESTAMPTZ;", "readiness_expiry TIMESTAMPTZ; readiness_leases UUID[];"},
		{"SELECT state,expires_at INTO readiness_state,readiness_expiry FROM mesh.device_alias_client_readiness WHERE private_endpoint_id=endpoint.id AND consumer_device_id=consumer.id;",
			"SELECT state,expires_at,lease_public_ids INTO readiness_state,readiness_expiry,readiness_leases FROM mesh.device_alias_client_readiness\n    WHERE private_endpoint_id=endpoint.id AND consumer_device_id=consumer.id ORDER BY state='ready' DESC,id DESC LIMIT 1;"},
		{"OR readiness_state='withdrawn' OR readiness_expiry<=decision_at",
			"OR readiness_state='ready' AND (readiness_expiry<=decision_at\n     OR EXISTS(SELECT 1 FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND public_id=ANY(readiness_leases) AND state<>'reserved'))"},
		{"AND readiness_state IS NULL THEN", "AND readiness_state IS DISTINCT FROM 'ready' THEN"},
		{"IF source_count=0 AND", "IF source_reserved=0 AND"},
	} {
		work = replace(work, change[0], change[1])
	}
	if function(migration.SQL, "load_device_alias_work_v3", revoke) != work {
		t.Error("load work v3 must be v2 that readmits a Device with no live readiness or source lease")
	}
	operator := DeviceAliasConsumerReadmissionOwnershipSQL()
	for _, want := range []string{
		"load_device_alias_work_v3(UUID,UUID,UUID,INTEGER) OWNER TO mesh_device_alias_writer;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_work_v3(UUID,UUID,UUID,INTEGER) TO mesh_worker;",
		"prepare_device_alias_change_v4(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) OWNER TO mesh_device_alias_writer;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.prepare_device_alias_change_v4(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) TO mesh_worker;",
	} {
		if !strings.Contains(operator, want) {
			t.Errorf("operator step 170 must contain %q", want)
		}
	}
	if strings.Contains(operator, "_v2(") || strings.Contains(operator, "_v3(UUID,UUID,UUID,BIGINT") {
		t.Error("operator step 170 must keep the previous versions for rollback")
	}
}

// Schema 171 gives a resumed provider Device the endpoint's own Resource
// aliases back: each admission is new Resource lease rows, so the unique
// index over every Resource lease of an endpoint and family becomes a partial
// one over the reserved lease, and the worker copies differ from their
// previous version only where the readmission needs it.
func TestDeviceAliasProviderReadmission(t *testing.T) {
	t.Parallel()
	catalog := Catalog()
	if len(catalog) < 171 {
		t.Fatalf("len(Catalog()) = %d, want schema 171", len(catalog))
	}
	migration := catalog[170]
	if migration.Version != 171 {
		t.Fatalf("migration 171 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE UNIQUE INDEX device_alias_resource_reserved_uidx\n    ON mesh.device_alias_lease (private_endpoint_id, family) WHERE alias_role = 'resource' AND state = 'reserved';\nDROP INDEX mesh.device_alias_resource_owner_uidx;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.reserve_device_aliases_internal_v5(UUID, UUID, BIGINT, BIGINT, BIGINT, UUID[])\n    TO mesh_device_alias_writer;",
		"REVOKE ALL ON FUNCTION mesh_ops.reserve_device_aliases_internal_v5(UUID, UUID, BIGINT, BIGINT, BIGINT, UUID[])\n    FROM PUBLIC, mesh_runtime, mesh_worker,",
		"REVOKE ALL ON FUNCTION mesh_ops.prepare_device_alias_change_v5(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) FROM PUBLIC,mesh_runtime,mesh_worker,",
		"REVOKE ALL ON FUNCTION mesh_ops.load_device_alias_work_v4(UUID,UUID,UUID,INTEGER) FROM PUBLIC,mesh_runtime,mesh_worker,",
		"REVOKE ALL ON FUNCTION mesh_ops.enforce_device_alias_network_uniqueness_v3() FROM PUBLIC;",
		"DROP TRIGGER device_alias_network_uniqueness ON mesh.device_alias_lease;\nCREATE TRIGGER device_alias_network_uniqueness BEFORE INSERT ON mesh.device_alias_lease\n    FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_device_alias_network_uniqueness_v3();",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 171 must contain %q", want)
		}
	}
	if strings.Count(migration.SQL, "DROP INDEX") != 1 {
		t.Error("schema 171 must drop only the Resource owner index")
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "BYPASSRLS", "OWNER TO", "TO mesh_worker", "TO mesh_runtime",
		"DROP FUNCTION", "DROP TABLE", "DROP POLICY", "DISABLE ROW LEVEL SECURITY", "NO FORCE ROW LEVEL SECURITY"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 171 must not contain %q", forbidden)
		}
	}
	function := func(sql, name, end string) string {
		start := strings.Index(sql, "CREATE FUNCTION mesh_ops."+name+"(")
		if start < 0 {
			t.Fatalf("no %s", name)
		}
		stop := strings.Index(sql[start:], end)
		if stop < 0 {
			t.Fatalf("no end of %s", name)
		}
		return sql[start : start+stop+len(end)]
	}
	replace := func(text, previous, current string) string {
		if strings.Count(text, previous) != 1 {
			t.Fatalf("previous version must contain %q once", previous)
		}
		return strings.Replace(text, previous, current, 1)
	}
	previous := catalog[169].SQL
	revoke := "\nREVOKE ALL ON FUNCTION mesh_ops."
	trigger := strings.ReplaceAll(function(previous, "enforce_device_alias_network_uniqueness_v2", "$function$;"), "_v2(", "_v3(")
	// Only the same endpoint, role, owner Device and family's quarantined
	// lease may share the new lease's address.
	trigger = replace(trigger, `          AND NOT (NEW.alias_role = 'consumer_source' AND lease.state = 'quarantined'
            AND lease.private_endpoint_id = NEW.private_endpoint_id AND lease.alias_role = 'consumer_source'
            AND lease.owner_device_id = NEW.owner_device_id AND lease.family = NEW.family)`, `          AND NOT (lease.state = 'quarantined'
            AND lease.private_endpoint_id = NEW.private_endpoint_id AND lease.alias_role = NEW.alias_role
            AND lease.owner_device_id = NEW.owner_device_id AND lease.family = NEW.family)`)
	if function(migration.SQL, "enforce_device_alias_network_uniqueness_v3", "$function$;") != trigger {
		t.Error("uniqueness v3 must be v2 that lets a Resource lease share only its own slot's quarantined address")
	}
	reserve := strings.ReplaceAll(function(previous, "reserve_device_aliases_internal_v4", "$function$;"), "_v4(", "_v5(")
	for _, change := range [][2]string{
		{"WHERE lease.private_endpoint_id = endpoint_row.id AND lease.alias_role = 'resource')\n        AND (SELECT count(*)",
			"WHERE lease.private_endpoint_id = endpoint_row.id AND lease.alias_role = 'resource' AND lease.state = 'reserved')\n        AND (SELECT count(*)"},
		{"WHERE lease.private_endpoint_id = endpoint_row.id AND lease.alias_role = 'resource')\n            <>",
			"WHERE lease.private_endpoint_id = endpoint_row.id AND lease.alias_role = 'resource' AND lease.state = 'reserved')\n            <>"},
		{"AND (role_value = 'resource' OR lease.state = 'reserved');", "AND lease.state = 'reserved';"},
		{`                      AND lease.machine_key_epoch = owner_device.current_machine_key_epoch
                    ORDER BY lease.id DESC LIMIT 1;
                END IF;`, `                      AND lease.machine_key_epoch = owner_device.current_machine_key_epoch
                    ORDER BY lease.id DESC LIMIT 1;
                ELSE
                    -- A resumed provider Device gets the endpoint's own
                    -- quarantined Resource alias back whatever its keys: the
                    -- share's name points at it. It is retained in both
                    -- Networks, so no other endpoint can hold it.
                    SELECT lease.address INTO candidate FROM mesh.device_alias_lease AS lease
                    WHERE lease.private_endpoint_id = endpoint_row.id AND lease.alias_role = role_value
                      AND lease.family = family_value AND lease.owner_device_id = owner_device.id
                      AND lease.state = 'quarantined' AND lease.address_pool_id = pool_row.id
                      AND lease.address << pool_row.prefix
                    ORDER BY lease.id DESC LIMIT 1;
                END IF;`},
	} {
		reserve = replace(reserve, change[0], change[1])
	}
	if function(migration.SQL, "reserve_device_aliases_internal_v5", "$function$;") != reserve {
		t.Error("reserve v5 must be v4 that reuses only a reserved Resource lease and gives a resumed provider its own Resource aliases back")
	}
	prepare := strings.ReplaceAll(function(previous, "prepare_device_alias_change_v4", revoke), "_v4(", "_v5(")
	if function(migration.SQL, "prepare_device_alias_change_v5", revoke) != prepare {
		t.Error("prepare v5 must be v4 that calls reserve v5")
	}
	work := strings.ReplaceAll(function(previous, "load_device_alias_work_v3", revoke), "_v3(", "_v4(")
	work = replace(work, `     IF source_reserved=0 AND NOT EXISTS(SELECT 1 FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND alias_role='resource' AND state<>'reserved') THEN mode:='reserve';
     ELSIF source_reserved>0 AND resource_reserved>0 THEN mode:='ready'; END IF;`, `     IF source_reserved=0 OR resource_reserved=0 THEN mode:='reserve';
     ELSE mode:='ready'; END IF;`)
	if function(migration.SQL, "load_device_alias_work_v4", revoke) != work {
		t.Error("load work v4 must be v3 that reserves when the pair lacks reserved source or Resource leases")
	}
	operator := DeviceAliasProviderReadmissionOwnershipSQL()
	for _, want := range []string{
		"load_device_alias_work_v4(UUID,UUID,UUID,INTEGER) OWNER TO mesh_device_alias_writer;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_work_v4(UUID,UUID,UUID,INTEGER) TO mesh_worker;",
		"prepare_device_alias_change_v5(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) OWNER TO mesh_device_alias_writer;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.prepare_device_alias_change_v5(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) TO mesh_worker;",
	} {
		if !strings.Contains(operator, want) {
			t.Errorf("operator step 171 must contain %q", want)
		}
	}
	if strings.Contains(operator, "_v3(") || strings.Contains(operator, "_v4(UUID,UUID,UUID,BIGINT") {
		t.Error("operator step 171 must keep the previous versions for rollback")
	}
}

// Schema 172 keeps updated_at in order on the Resource sharing rows: one
// trigger function raises an older updated_at to the previous version's, and
// a trigger named to fire before every other BEFORE UPDATE trigger of each
// table calls it. It changes no table, constraint, grant or older function.
func TestSharingUpdatedAtOrder(t *testing.T) {
	t.Parallel()
	catalog := Catalog()
	if len(catalog) < 172 {
		t.Fatalf("len(Catalog()) = %d, want schema 172", len(catalog))
	}
	migration := catalog[171]
	if migration.Version != 172 {
		t.Fatalf("migration 172 = %+v", migration)
	}
	for _, want := range []string{
		"CREATE FUNCTION mesh_ops.keep_updated_at_order_v1()\nRETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog",
		"    IF NEW.updated_at < OLD.updated_at THEN\n        NEW.updated_at := OLD.updated_at;\n    END IF;\n    RETURN NEW;",
		"REVOKE ALL ON FUNCTION mesh_ops.keep_updated_at_order_v1() FROM PUBLIC;",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 172 must contain %q", want)
		}
	}
	tables := []string{
		"resource_export", "share_offer", "trust_contract", "imported_resource",
		"imported_resource_access_name", "imported_resource_dns_publication",
		"private_endpoint", "federation_alias_lease",
	}
	for _, table := range tables {
		trigger := table + "_clock_order"
		want := "CREATE TRIGGER " + trigger + " BEFORE UPDATE ON mesh." + table +
			"\n    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v1();"
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 172 must contain %q", want)
		}
		// PostgreSQL fires triggers of one event in name order: the order
		// keeper must run before the table's transition and other checks.
		checks := []string{table + "_transition"}
		if table == "federation_alias_lease" {
			checks = append(checks, "federation_alias_network_uniqueness")
		}
		for _, other := range checks {
			if trigger >= other {
				t.Errorf("trigger %s does not fire before %s", trigger, other)
			}
		}
	}
	if count := strings.Count(migration.SQL, "CREATE TRIGGER "); count != len(tables) {
		t.Errorf("schema 172 creates %d triggers, want %d", count, len(tables))
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "BYPASSRLS", "OWNER TO", "GRANT ", "TO mesh_worker",
		"TO mesh_runtime", "DROP ", "ALTER TABLE", "DISABLE ROW LEVEL SECURITY", "NO FORCE ROW LEVEL SECURITY"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 172 must not contain %q", forbidden)
		}
	}
}

// Schema 173 is schema 172's order keeper that also logs each raise to the
// server log; the same triggers move to it and v1 stays.
func TestSharingUpdatedAtOrderLog(t *testing.T) {
	t.Parallel()
	catalog := Catalog()
	if len(catalog) < 173 {
		t.Fatalf("len(Catalog()) = %d, want schema 173", len(catalog))
	}
	migration := catalog[172]
	if migration.Version != 173 {
		t.Fatalf("migration 173 = %+v", migration)
	}
	function := func(sql, name string) string {
		start := strings.Index(sql, "CREATE FUNCTION mesh_ops."+name+"(")
		if start < 0 {
			t.Fatalf("no %s", name)
		}
		stop := strings.Index(sql[start:], "$function$;")
		if stop < 0 {
			t.Fatalf("no end of %s", name)
		}
		return sql[start : start+stop+len("$function$;")]
	}
	previous := strings.ReplaceAll(function(catalog[171].SQL, "keep_updated_at_order_v1"), "_v1(", "_v2(")
	logLine := "        RAISE LOG 'kept updated_at in order on %: version % was % behind version %',\n" +
		"            TG_TABLE_NAME, NEW.version, OLD.updated_at - NEW.updated_at, OLD.version;\n"
	want := strings.Replace(previous, "    IF NEW.updated_at < OLD.updated_at THEN\n",
		"    IF NEW.updated_at < OLD.updated_at THEN\n"+logLine, 1)
	if function(migration.SQL, "keep_updated_at_order_v2") != want {
		t.Error("keep v2 must be v1 that logs the raise")
	}
	if !strings.Contains(migration.SQL, "REVOKE ALL ON FUNCTION mesh_ops.keep_updated_at_order_v2() FROM PUBLIC;") {
		t.Error("schema 173 must revoke v2 from PUBLIC")
	}
	tables := []string{
		"resource_export", "share_offer", "trust_contract", "imported_resource",
		"imported_resource_access_name", "imported_resource_dns_publication",
		"private_endpoint", "federation_alias_lease",
	}
	for _, table := range tables {
		trigger := table + "_clock_order"
		want := "\nCREATE OR REPLACE TRIGGER " + trigger +
			" BEFORE UPDATE ON mesh." + table + "\n    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v2();"
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 173 must contain %q", want)
		}
	}
	if strings.Count(migration.SQL, "CREATE OR REPLACE TRIGGER ") != len(tables) ||
		strings.Count(migration.SQL, "CREATE TRIGGER ") != 0 || strings.Contains(migration.SQL, "DROP ") {
		t.Error("schema 173 must re-point exactly the schema 172 triggers")
	}
	for _, forbidden := range []string{"CREATE OR REPLACE FUNCTION", "BYPASSRLS", "OWNER TO", "GRANT ", "ALTER TABLE",
		"DROP FUNCTION", "DISABLE ROW LEVEL SECURITY", "NO FORCE ROW LEVEL SECURITY"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 173 must not contain %q", forbidden)
		}
	}
}

// Schema 174 stores one fingerprint row per Policy Release behind two
// definer functions that only the runtime role runs; the table stays closed
// to every application role and its rows never change.
func TestPolicyReleaseRuleFingerprints(t *testing.T) {
	t.Parallel()
	catalog := Catalog()
	if len(catalog) < 174 {
		t.Fatalf("len(Catalog()) = %d, want schema 174", len(catalog))
	}
	migration := catalog[173]
	if migration.Version != 174 {
		t.Fatalf("migration 174 = %+v", migration)
	}
	for _, want := range []string{
		"ALTER TABLE mesh.policy_release_rule_fingerprint FORCE ROW LEVEL SECURITY;",
		"REVOKE ALL ON mesh.policy_release_rule_fingerprint\n    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;",
		"BEFORE UPDATE OR DELETE ON mesh.policy_release_rule_fingerprint\nFOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();",
		"GRANT EXECUTE ON FUNCTION mesh_ops.record_policy_release_rule_fingerprints_v1(UUID, BYTEA) TO mesh_runtime;",
		"GRANT EXECUTE ON FUNCTION mesh_ops.read_policy_release_rule_fingerprints_v1(UUID) TO mesh_runtime;",
		"REVOKE ALL ON FUNCTION mesh_ops.record_policy_release_rule_fingerprints_v1(UUID, BYTEA)\n    FROM PUBLIC,",
		"REVOKE ALL ON FUNCTION mesh_ops.read_policy_release_rule_fingerprints_v1(UUID)\n    FROM PUBLIC,",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 174 lacks %q", want)
		}
	}
	if count := strings.Count(migration.SQL, "SECURITY DEFINER\nSET search_path = pg_catalog\n"); count != 2 {
		t.Errorf("schema 174 has %d definer functions pinned to pg_catalog, want 2", count)
	}
	if strings.Contains(migration.SQL, "clock_timestamp") || strings.Contains(migration.SQL, "TIMESTAMPTZ,") {
		t.Error("schema 174 must take no time from the caller and use the transaction clock")
	}
}

// Schema 179 adds the Network's Device lifetime to its interactive profile
// without rewriting any row, behind two definer functions only the runtime
// role runs.
func TestNetworkDeviceLifetime(t *testing.T) {
	t.Parallel()
	catalog := Catalog()
	if len(catalog) < 179 {
		t.Fatalf("len(Catalog()) = %d, want schema 179", len(catalog))
	}
	migration := catalog[178]
	if migration.Version != 179 {
		t.Fatalf("migration 179 = %+v", migration)
	}
	for _, want := range []string{
		"ADD COLUMN device_lifetime_seconds BIGINT,",
		"ADD COLUMN device_never_expires BOOLEAN NOT NULL DEFAULT FALSE,",
		"device_lifetime_seconds BETWEEN 3600 AND 15552000",
		"NOT (device_never_expires AND device_lifetime_seconds IS NOT NULL)",
		"'network.read', p_evaluated_at",
		"'network.update', p_evaluated_at",
		"node_lifetime_seconds = v_mirror,",
		"updated_at = pg_catalog.transaction_timestamp()",
		"GRANT EXECUTE ON FUNCTION mesh_ops.read_network_device_lifetime_v1(",
		"GRANT EXECUTE ON FUNCTION mesh_ops.set_network_device_lifetime_v1(",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 179 lacks %q", want)
		}
	}
	if count := strings.Count(migration.SQL, "SECURITY DEFINER\nSET search_path = pg_catalog\n"); count != 2 {
		t.Errorf("schema 179 has %d definer functions pinned to pg_catalog, want 2", count)
	}
	// No row is rewritten, so no authority evidence is owed, and no time
	// other than the database's is used.
	for _, forbidden := range []string{"\nUPDATE ", "\nINSERT ", "clock_timestamp", "GREATEST", "OWNER TO", "BYPASSRLS",
		"TO mesh_worker", "TO mesh_observer", "DISABLE TRIGGER", "DROP "} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 179 must not contain %q", forbidden)
		}
	}
}

// Schema 180 lets device.manage extend an expired member Device within fixed
// bounds, on the database clock, through one definer function.
func TestDeviceExpiryExtension(t *testing.T) {
	t.Parallel()
	catalog := Catalog()
	if len(catalog) < 180 {
		t.Fatalf("len(Catalog()) = %d, want schema 180", len(catalog))
	}
	migration := catalog[179]
	if migration.Version != 180 {
		t.Fatalf("migration 180 = %+v", migration)
	}
	for _, want := range []string{
		"p_extension_seconds NOT BETWEEN 3600 AND 604800",
		"'device.manage', p_evaluated_at",
		"v_device.ownership <> 'member'",
		"v_device.expires_at > v_now + INTERVAL '1 day'",
		"v_expires_at <= v_device.expires_at",
		"v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();",
		"inventory_revision = revision.inventory_revision + 1,",
		"GRANT EXECUTE ON FUNCTION mesh_ops.extend_device_v1(",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Errorf("schema 180 lacks %q", want)
		}
	}
	if count := strings.Count(migration.SQL, "SECURITY DEFINER\nSET search_path = pg_catalog\n"); count != 1 {
		t.Errorf("schema 180 has %d definer functions pinned to pg_catalog, want 1", count)
	}
	for _, forbidden := range []string{"clock_timestamp", "GREATEST", "OWNER TO", "ALTER TABLE", "TO mesh_worker",
		"TO mesh_observer", "DROP "} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 180 must not contain %q", forbidden)
		}
	}
}

// Schema 181 replaces the 17 functions that took GREATEST(clock_timestamp(),
// p_evaluated_at) as now: each uses transaction_timestamp() for now and for
// its permission check, keeps its signature, and changes nothing else.
func TestDatabaseClockNow(t *testing.T) {
	t.Parallel()
	catalog := Catalog()
	if len(catalog) < 181 {
		t.Fatalf("len(Catalog()) = %d, want schema 181", len(catalog))
	}
	migration := catalog[180]
	if migration.Version != 181 {
		t.Fatalf("migration 181 = %+v", migration)
	}
	functions := databaseClockNowFunctions
	if count := strings.Count(migration.SQL, "CREATE OR REPLACE FUNCTION mesh_ops."); count != len(functions) {
		t.Errorf("schema 181 replaces %d functions, want %d", count, len(functions))
	}
	for _, block := range strings.Split(migration.SQL, "CREATE OR REPLACE FUNCTION mesh_ops.")[1:] {
		name, _, _ := strings.Cut(block, "(")
		if !slices.Contains(functions, name) {
			t.Errorf("schema 181 replaces unexpected %s", name)
		}
		if !strings.Contains(block, "pg_catalog.transaction_timestamp()") ||
			!strings.Contains(block, "SET search_path TO 'pg_catalog'") || !strings.Contains(block, "SECURITY DEFINER") {
			t.Errorf("schema 181 %s is not a pinned definer on the transaction time", name)
		}
	}
	// A stamp on an existing row never goes below that row's own times.
	if count := strings.Count(migration.SQL, "ended_at = GREATEST(v_now, session.issued_at)"); count != 3 {
		t.Errorf("schema 181 clamps %d session ends to issued_at, want 3", count)
	}
	// The parameter remains only in each signature and its null check.
	for _, line := range strings.Split(migration.SQL, "\n") {
		if strings.Contains(line, "p_evaluated_at") && !strings.Contains(line, "p_evaluated_at timestamp with time zone") &&
			!strings.Contains(line, "p_evaluated_at IS NULL") && !strings.HasPrefix(line, "--") {
			t.Errorf("schema 181 still uses the caller's time: %q", strings.TrimSpace(line))
		}
	}
	for _, forbidden := range []string{"GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at)", "OWNER TO",
		"ALTER TABLE", "DROP ", "GRANT ", "REVOKE "} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 181 must not contain %q", forbidden)
		}
	}
	if count := strings.Count(migration.SQL, "SET search_path TO 'pg_catalog'"); count != len(functions) {
		t.Errorf("schema 181 pins %d functions to pg_catalog, want %d", count, len(functions))
	}
}

// databaseClockNowFunctions are the functions schema 181 moves onto the
// transaction time.
var databaseClockNowFunctions = []string{
	"add_network_members_v1", "change_device_group_members_v1", "change_device_group_v1",
	"change_device_lifecycle_v1", "change_device_tag_v1", "change_device_tags_v1",
	"change_identity_group_members_v1", "change_identity_group_v1", "change_workspace_invitation_v1",
	"change_workspace_member_v1", "list_workspace_invitations_v1", "logout_device_v1",
	"preview_workspace_invitation_v1", "remove_network_member_v1", "remove_workspace_member_v1",
	"revoke_workspace_member_sessions_v1", "set_network_alias_ranges_v1",
}

// Schema 182 locks the Workspace row FOR NO KEY UPDATE in the 16 functions
// that locked it FOR UPDATE, and changes nothing else.
func TestWorkspaceNoKeyUpdate(t *testing.T) {
	t.Parallel()
	catalog := Catalog()
	if len(catalog) < 182 {
		t.Fatalf("len(Catalog()) = %d, want schema 182", len(catalog))
	}
	migration := catalog[181]
	if migration.Version != 182 {
		t.Fatalf("migration 182 = %+v", migration)
	}
	functions := []string{
		"accept_workspace_invitation_v1", "add_network_members_v1", "assign_workspace_role_v1",
		"change_device_tag_v1", "change_identity_group_v1", "change_workspace_guardrail_v1",
		"change_workspace_invitation_v1", "change_workspace_member_v1", "change_workspace_private_interchange_v1",
		"create_network_v1", "create_network_v2", "remove_network_member_v1", "remove_workspace_member_v1",
		"rename_owned_workspace_v1", "revoke_workspace_member_sessions_v1", "revoke_workspace_role_v1",
	}
	workspaceLock := regexp.MustCompile(`FROM\s+mesh\.workspace\s+AS\s+\w+[^;]*?FOR\s+(NO KEY )?UPDATE`)
	blocks := strings.Split(migration.SQL, "CREATE OR REPLACE FUNCTION mesh_ops.")[1:]
	if len(blocks) != len(functions) {
		t.Fatalf("schema 182 replaces %d functions, want %d", len(blocks), len(functions))
	}
	for _, block := range blocks {
		name, _, _ := strings.Cut(block, "(")
		if !slices.Contains(functions, name) {
			t.Errorf("schema 182 replaces unexpected %s", name)
		}
		locks := workspaceLock.FindAllStringSubmatch(block, -1)
		if len(locks) != 1 || locks[0][1] != "NO KEY " {
			t.Errorf("schema 182 %s locks its Workspace %v, want once FOR NO KEY UPDATE", name, locks)
		}
		if !strings.Contains(block, "SECURITY DEFINER") || !strings.Contains(block, "SET search_path TO") {
			t.Errorf("schema 182 %s is not a pinned definer", name)
		}
	}
	for _, forbidden := range []string{"OWNER TO", "ALTER TABLE", "DROP ", "GRANT ", "REVOKE ", "GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at)"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 182 must not contain %q", forbidden)
		}
	}
}

// Schema 183 makes the three Workspace changes that checked permission
// before locking their Workspace lock it first.
func TestWorkspaceLockBeforeAuthorize(t *testing.T) {
	t.Parallel()
	catalog := Catalog()
	if len(catalog) < 183 {
		t.Fatalf("len(Catalog()) = %d, want schema 183", len(catalog))
	}
	migration := catalog[182]
	if migration.Version != 183 {
		t.Fatalf("migration 183 = %+v", migration)
	}
	blocks := strings.Split(migration.SQL, "CREATE OR REPLACE FUNCTION mesh_ops.")[1:]
	authorizers := map[string]string{
		"change_device_tag_v1":           "authorize_identity_catalog_internal_v1(",
		"change_identity_group_v1":       "authorize_identity_catalog_internal_v1(",
		"change_workspace_invitation_v1": "authorize_workspace_people_internal_v1(",
	}
	if len(blocks) != len(authorizers) {
		t.Fatalf("schema 183 replaces %d functions, want %d", len(blocks), len(authorizers))
	}
	const lock = "PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = v_locked FOR NO KEY UPDATE;"
	for _, block := range blocks {
		name, _, _ := strings.Cut(block, "(")
		authorizer, ok := authorizers[name]
		if !ok {
			t.Errorf("schema 183 replaces unexpected %s", name)
			continue
		}
		lockAt, authorizeAt := strings.Index(block, lock), strings.Index(block, authorizer)
		if strings.Count(block, "FOR NO KEY UPDATE") != 1 || lockAt < 0 || authorizeAt < 0 || lockAt > authorizeAt {
			t.Errorf("schema 183 %s does not lock its Workspace once, before %s", name, authorizer)
		}
		if !strings.Contains(block, "mesh_ops.session_bound_to_workspace_v1(p_session_public_id, v_locked)") {
			t.Errorf("schema 183 %s locks a Workspace its session is not bound to", name)
		}
		// A tag or group update or deletion still locks no Workspace row.
		createOnly := strings.Contains(block, "IF p_operation = 'create' THEN\n        v_locked :=")
		if (name != "change_workspace_invitation_v1") != createOnly {
			t.Errorf("schema 183 %s locks its Workspace for the wrong operations", name)
		}
	}
	for _, forbidden := range []string{"OWNER TO", "ALTER TABLE", "DROP ", "GRANT ", "REVOKE ",
		"GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at)"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 183 must not contain %q", forbidden)
		}
	}
}

// Schema 184 makes the three permission resolvers lock the Workspace row
// before the statement that locks the caller's session.
func TestResolverWorkspaceFirst(t *testing.T) {
	t.Parallel()
	catalog := Catalog()
	if len(catalog) < 184 {
		t.Fatalf("len(Catalog()) = %d, want schema 184", len(catalog))
	}
	migration := catalog[183]
	if migration.Version != 184 {
		t.Fatalf("migration 184 = %+v", migration)
	}
	resolvers := []string{"resolve_network_permission_v1", "resolve_network_permission_v2", "resolve_workspace_permission_v1"}
	blocks := strings.Split(migration.SQL, "CREATE OR REPLACE FUNCTION mesh_ops.")[1:]
	if len(blocks) != len(resolvers) {
		t.Fatalf("schema 184 replaces %d functions, want %d", len(blocks), len(resolvers))
	}
	const lock = "PERFORM 1 FROM mesh.workspace AS workspace\n    WHERE workspace.public_id = p_workspace_public_id\n    FOR SHARE;"
	for _, block := range blocks {
		name, _, _ := strings.Cut(block, "(")
		if !slices.Contains(resolvers, name) {
			t.Errorf("schema 184 replaces unexpected %s", name)
		}
		lockAt, sessionAt := strings.Index(block, lock), strings.Index(block, "FROM mesh.account_session AS session")
		if strings.Count(block, lock) != 1 || lockAt < 0 || sessionAt < 0 || lockAt > sessionAt {
			t.Errorf("schema 184 %s does not lock the Workspace once, before the session", name)
		}
	}
	for _, forbidden := range []string{"OWNER TO", "ALTER TABLE", "DROP ", "GRANT ", "REVOKE "} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("schema 184 must not contain %q", forbidden)
		}
	}
}
