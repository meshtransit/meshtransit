package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestCatalogContainsOrderedFoundations(t *testing.T) {
	t.Parallel()

	catalog := Catalog()
	if len(catalog) != 115 {
		t.Fatalf("len(Catalog()) = %d, want 115", len(catalog))
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
	if LatestVersion() != 115 {
		t.Fatalf("LatestVersion() = %d, want 115", LatestVersion())
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
