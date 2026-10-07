// Package migrations owns the immutable, forward-only MeshTransit database
// migration catalog embedded in the meshcore binary.
package migrations

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

const (
	// ApplicationGeneration is the reader and writer generation implemented by
	// this binary. It advances only with a reviewed compatibility change.
	ApplicationGeneration int64 = 1

	platformFoundationDescription                     = "platform migration foundation"
	authorityFoundationDescription                    = "tenancy and address authority foundation"
	integrityFoundationDescription                    = "audit and outbox integrity foundation"
	outboxDeliveryDescription                         = "outbox worker delivery capability"
	registrationAuthorityDescription                  = "node enrollment and registration authority"
	registrationIntentHashDescription                 = "registration intent semantic hash"
	transactionNetworkScopeDescription                = "transaction-local public network scope"
	networkAuditStreamHeadDescription                 = "transaction-local network audit stream head"
	networkInventoryAdvanceDescription                = "transaction-local network inventory revision advance"
	registrationReplayDescription                     = "registration idempotency replay evidence"
	networkRevisionLockDescription                    = "transaction-local network revision lock"
	registrationTransactionLocksDescription           = "registration transaction scoped lock helpers"
	registrationIntakeScopeDescription                = "registration intake scope resolution"
	registrationIntakeScopeQueryDescription           = "registration intake scope query correction"
	mapSessionScopeDescription                        = "map session scope resolution"
	mapSessionPeerCandidatesDescription               = "bounded map session peer candidate projection"
	identityProviderAuthorityDescription              = "identity provider authority foundation"
	accountIdentityPermissionDescription              = "account identity and permission catalog foundation"
	humanAuthenticationSessionDescription             = "human authentication and account session authority"
	compiledPacketPolicyDescription                   = "compiled packet policy authority"
	atomicPacketPolicyPublicationDescription          = "atomic packet policy publication"
	mapPeerProtocolIdentityDescription                = "map peer protocol identity projection"
	networkIdempotencyDescription                     = "network idempotency record foundation"
	accountSessionResolutionDescription               = "deployment-bound account session resolution"
	networkManagementRBACDescription                  = "network management RBAC authority"
	nodeKeyRotationAuthorityDescription               = "authenticated Node-key rotation authority"
	oidcAuthTransactionPersistenceDescription         = "OIDC authentication transaction persistence"
	oidcLoginRouteAdmissionDescription                = "durable OIDC login route admission"
	oidcPendingBrowserEvidenceDescription             = "read-only OIDC pending browser evidence"
	oidcBrowserClaimDescription                       = "single-use OIDC browser transaction claim"
	oidcBrowserFailureDescription                     = "OIDC browser failure terminal proof erasure"
	oidcLoginSubjectResolutionDescription             = "read-only exact OIDC login subject resolution"
	oidcSessionIssuanceDescription                    = "atomic existing-subject OIDC session issuance"
	oidcBrowserExpiryDescription                      = "bounded abandoned OIDC browser expiry"
	accountSessionLogoutDescription                   = "deployment-bound local account session logout"
	accountSessionLogoutEvidenceDescription           = "audited account session logout evidence"
	resourceGroupAuthorityDescription                 = "Resource and Resource Group authority foundation"
	resourceManagementReadDescription                 = "Resource management read API"
	resourceLifecycleAuthorityDescription             = "Resource lifecycle authority"
	resourceTargetRebindingDescription                = "Resource target rebinding authority"
	resourceGroupReplacementDescription               = "Resource Group definition replacement authority"
	resourceAuthorityChangeDescription                = "protected Resource ownership and custody authority"
	policyResourceDestinationDescription              = "policy Resource destination provenance"
	policyResourceGroupDestinationDescription         = "policy Resource Group destination provenance"
	accessGraphPolicyExplanationDescription           = "Access Graph active policy explanation"
	policySimulationBaselineDescription               = "Policy simulation active baseline"
	policyApprovalPersistenceDescription              = "Policy approval persistence"
	policyApprovalPublicationGateDescription          = "Policy approval publication gate"
	policyApprovalManagementReadDescription           = "Policy approval management read API"
	consoleManagementScopeDescription                 = "Console management scope projection"
	resourceSharingAuthorityDescription               = "Resource sharing authority foundation"
	policyImportedResourceDescription                 = "policy Imported Resource destination provenance"
	resourceSharingAccessNameDescription              = "Resource sharing consumer access-name authority"
	resourceSharingPrivateEndpointDescription         = "Resource sharing Private Endpoint provisioning authority"
	resourceSharingEndpointPublicationDescription     = "Resource sharing Private Endpoint readiness and DNS publication"
	resourceSharingEndpointReconciliationDescription  = "Resource sharing Private Endpoint route reconciliation and withdrawal"
	consoleDeploymentCapabilitiesDescription          = "Console Deployment capability projection"
	consoleSharingScopeDescription                    = "Console sharing management scope projection"
	networkEnrollmentMembershipDescription            = "Network enrollment membership authority"
	browserRegistrationIntentDescription              = "pre-Network browser registration intent"
	interactiveEnrollmentProfileDescription           = "explicit interactive enrollment profile gate"
	browserEnrollmentNetworkChoicesDescription        = "session-bound browser enrollment Network choices"
	browserRegistrationIntentIssueDescription         = "durable browser registration intent issuance"
	browserRegistrationIntentFollowupDescription      = "machine-bound browser registration followup"
	browserRegistrationLandingDescription             = "session-bound browser registration landing"
	browserRegistrationApprovalAuthorityDescription   = "locked browser registration approval authority"
	browserRegistrationApprovalRecordDescription      = "atomic browser registration approval record"
	browserRegistrationCompletionAuthorityDescription = "machine-bound browser registration completion authority"
	browserWorkspaceChoicesDescription                = "session-bound browser Workspace and scoped Network choices"
	browserWorkspaceApprovalDescription               = "exact chosen Workspace browser approval authority"
	browserWorkspaceCompletionDescription             = "chosen Workspace browser completion reauthorization"
	consoleInventoryScopeDescription                  = "Console inventory management scope projection"
	consoleDeviceInventoryDescription                 = "Console exact-scope Device inventory read"
	consolePolicyAuthoringScopeDescription            = "Console policy authoring management scope projection"
	expiredUnprovisionedShareCleanupDescription       = "expired unprovisioned Trust Contract cleanup"
	resourceSharingNeverExpiryDescription             = "same-Workspace Resource sharing with separate offer and contract deadlines"
)

//go:embed 000001_platform_foundation.up.sql
var platformFoundationSQL string

//go:embed 000002_tenancy_address_authority.up.sql
var authorityFoundationSQL string

//go:embed 000003_audit_outbox_integrity.up.sql
var integrityFoundationSQL string

//go:embed 000004_outbox_worker_delivery.up.sql
var outboxDeliverySQL string

//go:embed 000005_node_enrollment_registration.up.sql
var registrationAuthoritySQL string

//go:embed 000006_registration_intent_hash.up.sql
var registrationIntentHashSQL string

//go:embed 000007_transaction_network_scope.up.sql
var transactionNetworkScopeSQL string

//go:embed 000008_network_audit_stream_head.up.sql
var networkAuditStreamHeadSQL string

//go:embed 000009_network_inventory_revision_advance.up.sql
var networkInventoryAdvanceSQL string

//go:embed 000010_registration_replay_evidence.up.sql
var registrationReplaySQL string

//go:embed 000011_network_revision_lock.up.sql
var networkRevisionLockSQL string

//go:embed 000012_registration_transaction_locks.up.sql
var registrationTransactionLocksSQL string

//go:embed 000013_registration_intake_scope.up.sql
var registrationIntakeScopeSQL string

//go:embed 000014_registration_intake_scope_query.up.sql
var registrationIntakeScopeQuerySQL string

//go:embed 000015_map_session_scope.up.sql
var mapSessionScopeSQL string

//go:embed 000016_map_session_peer_candidates.up.sql
var mapSessionPeerCandidatesSQL string

//go:embed 000017_identity_provider_authority.up.sql
var identityProviderAuthoritySQL string

//go:embed 000018_account_identity_permission_catalog.up.sql
var accountIdentityPermissionSQL string

//go:embed 000019_human_authentication_session_authority.up.sql
var humanAuthenticationSessionSQL string

//go:embed 000020_compiled_packet_policy_authority.up.sql
var compiledPacketPolicySQL string

//go:embed 000021_atomic_packet_policy_publication.up.sql
var atomicPacketPolicyPublicationSQL string

//go:embed 000022_map_peer_protocol_identity.up.sql
var mapPeerProtocolIdentitySQL string

//go:embed 000023_network_idempotency_foundation.up.sql
var networkIdempotencySQL string

//go:embed 000024_account_session_resolution_v2.up.sql
var accountSessionResolutionSQL string

//go:embed 000025_network_management_rbac_authority.up.sql
var networkManagementRBACSQL string

//go:embed 000026_node_key_rotation_authority.up.sql
var nodeKeyRotationAuthoritySQL string

//go:embed 000027_oidc_auth_transaction_persistence.up.sql
var oidcAuthTransactionPersistenceSQL string

//go:embed 000028_oidc_login_route_admission.up.sql
var oidcLoginRouteAdmissionSQL string

//go:embed 000029_oidc_pending_browser_evidence.up.sql
var oidcPendingBrowserEvidenceSQL string

//go:embed 000030_oidc_browser_claim.up.sql
var oidcBrowserClaimSQL string

//go:embed 000031_oidc_browser_failure.up.sql
var oidcBrowserFailureSQL string

//go:embed 000032_oidc_login_subject_resolution.up.sql
var oidcLoginSubjectResolutionSQL string

//go:embed 000033_oidc_existing_subject_session_issuance.up.sql
var oidcSessionIssuanceSQL string

//go:embed 000034_oidc_abandoned_browser_expiry.up.sql
var oidcBrowserExpirySQL string

//go:embed 000035_account_session_local_logout.up.sql
var accountSessionLogoutSQL string

//go:embed 000036_account_session_logout_evidence.up.sql
var accountSessionLogoutEvidenceSQL string

//go:embed 000037_resource_group_authority.up.sql
var resourceGroupAuthoritySQL string

//go:embed 000038_resource_management_read_api.up.sql
var resourceManagementReadSQL string

//go:embed 000039_resource_lifecycle_authority.up.sql
var resourceLifecycleAuthoritySQL string

//go:embed 000040_resource_target_rebinding.up.sql
var resourceTargetRebindingSQL string

//go:embed 000041_resource_group_definition_replacement.up.sql
var resourceGroupReplacementSQL string

//go:embed 000042_resource_authority_change_workflow.up.sql
var resourceAuthorityChangeSQL string

//go:embed 000043_policy_resource_destination_provenance.up.sql
var policyResourceDestinationSQL string

//go:embed 000044_policy_resource_group_destination_provenance.up.sql
var policyResourceGroupDestinationSQL string

//go:embed 000045_access_graph_policy_explanation.up.sql
var accessGraphPolicyExplanationSQL string

//go:embed 000046_policy_simulation_baseline.up.sql
var policySimulationBaselineSQL string

//go:embed 000047_policy_approval_persistence.up.sql
var policyApprovalPersistenceSQL string

//go:embed 000048_policy_approval_publication_gate.up.sql
var policyApprovalPublicationGateSQL string

//go:embed 000049_policy_approval_management_read.up.sql
var policyApprovalManagementReadSQL string

//go:embed 000050_console_management_scope_projection.up.sql
var consoleManagementScopeSQL string

//go:embed 000051_resource_sharing_authority.up.sql
var resourceSharingAuthoritySQL string

//go:embed 000052_policy_imported_resource_destination.up.sql
var policyImportedResourceSQL string

//go:embed 000053_resource_sharing_access_name_authority.up.sql
var resourceSharingAccessNameSQL string

//go:embed 000054_resource_sharing_private_endpoint_provisioning.up.sql
var resourceSharingPrivateEndpointSQL string

//go:embed 000055_resource_sharing_private_endpoint_publication.up.sql
var resourceSharingEndpointPublicationSQL string

//go:embed 000056_resource_sharing_private_endpoint_reconciliation.up.sql
var resourceSharingEndpointReconciliationSQL string

//go:embed 000057_console_deployment_capability_projection.up.sql
var consoleDeploymentCapabilitiesSQL string

//go:embed 000058_console_management_share_scope_projection.up.sql
var consoleSharingScopeSQL string

//go:embed 000059_network_enrollment_membership.up.sql
var networkEnrollmentMembershipSQL string

//go:embed 000060_browser_registration_intent.up.sql
var browserRegistrationIntentSQL string

//go:embed 000061_interactive_enrollment_profile.up.sql
var interactiveEnrollmentProfileSQL string

//go:embed 000062_browser_enrollment_network_choices.up.sql
var browserEnrollmentNetworkChoicesSQL string

//go:embed 000063_browser_registration_intent_issue.up.sql
var browserRegistrationIntentIssueSQL string

//go:embed 000064_browser_registration_intent_followup.up.sql
var browserRegistrationIntentFollowupSQL string

//go:embed 000065_browser_registration_landing.up.sql
var browserRegistrationLandingSQL string

//go:embed 000066_browser_registration_approval_authority.up.sql
var browserRegistrationApprovalAuthoritySQL string

//go:embed 000067_browser_registration_approval_record.up.sql
var browserRegistrationApprovalRecordSQL string

//go:embed 000068_browser_registration_completion_authority.up.sql
var browserRegistrationCompletionAuthoritySQL string

//go:embed 000069_browser_workspace_enrollment_choices.up.sql
var browserWorkspaceChoicesSQL string

//go:embed 000070_browser_workspace_approval_authority.up.sql
var browserWorkspaceApprovalSQL string

//go:embed 000071_browser_workspace_completion_authority.up.sql
var browserWorkspaceCompletionSQL string

//go:embed 000072_console_inventory_scope_projection.up.sql
var consoleInventoryScopeSQL string

//go:embed 000073_console_device_inventory.up.sql
var consoleDeviceInventorySQL string

//go:embed 000074_console_policy_authoring_scope.up.sql
var consolePolicyAuthoringScopeSQL string

//go:embed 000075_active_policy_read.up.sql
var activePolicyReadSQL string

const activePolicyReadDescription = "active policy read"

//go:embed 000076_workspace_owner_authority.up.sql
var workspaceOwnerAuthoritySQL string

//go:embed 000077_tenant_display_identity.up.sql
var tenantDisplayIdentitySQL string

//go:embed 000078_workspace_rename.up.sql
var workspaceRenameSQL string

//go:embed 000079_direct_device_endpoint_authority.up.sql
var directDeviceEndpointAuthoritySQL string

//go:embed 000080_direct_device_map_authority.up.sql
var directDeviceMapSQL string

//go:embed 000081_device_alias_reservation.up.sql
var deviceAliasReservationSQL string

// Migration is one immutable, ordered, forward-only catalog entry.
type Migration struct {
	Version                 int64
	Description             string
	Checksum                string
	SQL                     string
	MinimumReaderGeneration int64
	MaximumReaderGeneration int64
	MinimumWriterGeneration int64
	MaximumWriterGeneration int64
}

// Catalog returns a caller-owned copy of the complete ordered catalog.
func Catalog() []Migration {
	return []Migration{
		newMigration(1, platformFoundationDescription, platformFoundationSQL),
		newMigration(2, authorityFoundationDescription, authorityFoundationSQL),
		newMigration(3, integrityFoundationDescription, integrityFoundationSQL),
		newMigration(4, outboxDeliveryDescription, outboxDeliverySQL),
		newMigration(5, registrationAuthorityDescription, registrationAuthoritySQL),
		newMigration(6, registrationIntentHashDescription, registrationIntentHashSQL),
		newMigration(7, transactionNetworkScopeDescription, transactionNetworkScopeSQL),
		newMigration(8, networkAuditStreamHeadDescription, networkAuditStreamHeadSQL),
		newMigration(9, networkInventoryAdvanceDescription, networkInventoryAdvanceSQL),
		newMigration(10, registrationReplayDescription, registrationReplaySQL),
		newMigration(11, networkRevisionLockDescription, networkRevisionLockSQL),
		newMigration(12, registrationTransactionLocksDescription, registrationTransactionLocksSQL),
		newMigration(13, registrationIntakeScopeDescription, registrationIntakeScopeSQL),
		newMigration(14, registrationIntakeScopeQueryDescription, registrationIntakeScopeQuerySQL),
		newMigration(15, mapSessionScopeDescription, mapSessionScopeSQL),
		newMigration(16, mapSessionPeerCandidatesDescription, mapSessionPeerCandidatesSQL),
		newMigration(17, identityProviderAuthorityDescription, identityProviderAuthoritySQL),
		newMigration(18, accountIdentityPermissionDescription, accountIdentityPermissionSQL),
		newMigration(19, humanAuthenticationSessionDescription, humanAuthenticationSessionSQL),
		newMigration(20, compiledPacketPolicyDescription, compiledPacketPolicySQL),
		newMigration(21, atomicPacketPolicyPublicationDescription, atomicPacketPolicyPublicationSQL),
		newMigration(22, mapPeerProtocolIdentityDescription, mapPeerProtocolIdentitySQL),
		newMigration(23, networkIdempotencyDescription, networkIdempotencySQL),
		newMigration(24, accountSessionResolutionDescription, accountSessionResolutionSQL),
		newMigration(25, networkManagementRBACDescription, networkManagementRBACSQL),
		newMigration(26, nodeKeyRotationAuthorityDescription, nodeKeyRotationAuthoritySQL),
		newMigration(
			27,
			oidcAuthTransactionPersistenceDescription,
			oidcAuthTransactionPersistenceSQL,
		),
		newMigration(28, oidcLoginRouteAdmissionDescription, oidcLoginRouteAdmissionSQL),
		newMigration(29, oidcPendingBrowserEvidenceDescription, oidcPendingBrowserEvidenceSQL),
		newMigration(30, oidcBrowserClaimDescription, oidcBrowserClaimSQL),
		newMigration(31, oidcBrowserFailureDescription, oidcBrowserFailureSQL),
		newMigration(32, oidcLoginSubjectResolutionDescription, oidcLoginSubjectResolutionSQL),
		newMigration(33, oidcSessionIssuanceDescription, oidcSessionIssuanceSQL),
		newMigration(34, oidcBrowserExpiryDescription, oidcBrowserExpirySQL),
		newMigration(35, accountSessionLogoutDescription, accountSessionLogoutSQL),
		newMigration(36, accountSessionLogoutEvidenceDescription, accountSessionLogoutEvidenceSQL),
		newMigration(37, resourceGroupAuthorityDescription, resourceGroupAuthoritySQL),
		newMigration(38, resourceManagementReadDescription, resourceManagementReadSQL),
		newMigration(39, resourceLifecycleAuthorityDescription, resourceLifecycleAuthoritySQL),
		newMigration(40, resourceTargetRebindingDescription, resourceTargetRebindingSQL),
		newMigration(41, resourceGroupReplacementDescription, resourceGroupReplacementSQL),
		newMigration(42, resourceAuthorityChangeDescription, resourceAuthorityChangeSQL),
		newMigration(43, policyResourceDestinationDescription, policyResourceDestinationSQL),
		newMigration(44, policyResourceGroupDestinationDescription, policyResourceGroupDestinationSQL),
		newMigration(45, accessGraphPolicyExplanationDescription, accessGraphPolicyExplanationSQL),
		newMigration(46, policySimulationBaselineDescription, policySimulationBaselineSQL),
		newMigration(47, policyApprovalPersistenceDescription, policyApprovalPersistenceSQL),
		newMigration(48, policyApprovalPublicationGateDescription, policyApprovalPublicationGateSQL),
		newMigration(49, policyApprovalManagementReadDescription, policyApprovalManagementReadSQL),
		newMigration(50, consoleManagementScopeDescription, consoleManagementScopeSQL),
		newMigration(51, resourceSharingAuthorityDescription, resourceSharingAuthoritySQL),
		newMigration(52, policyImportedResourceDescription, policyImportedResourceSQL),
		newMigration(53, resourceSharingAccessNameDescription, resourceSharingAccessNameSQL),
		newMigration(
			54,
			resourceSharingPrivateEndpointDescription,
			resourceSharingPrivateEndpointSQL,
		),
		newMigration(
			55,
			resourceSharingEndpointPublicationDescription,
			resourceSharingEndpointPublicationSQL,
		),
		newMigration(
			56,
			resourceSharingEndpointReconciliationDescription,
			resourceSharingEndpointReconciliationSQL,
		),
		newMigration(57, consoleDeploymentCapabilitiesDescription, consoleDeploymentCapabilitiesSQL),
		newMigration(58, consoleSharingScopeDescription, consoleSharingScopeSQL),
		newMigration(59, networkEnrollmentMembershipDescription, networkEnrollmentMembershipSQL),
		newMigration(60, browserRegistrationIntentDescription, browserRegistrationIntentSQL),
		newMigration(61, interactiveEnrollmentProfileDescription, interactiveEnrollmentProfileSQL),
		newMigration(62, browserEnrollmentNetworkChoicesDescription, browserEnrollmentNetworkChoicesSQL),
		newMigration(63, browserRegistrationIntentIssueDescription, browserRegistrationIntentIssueSQL),
		newMigration(64, browserRegistrationIntentFollowupDescription, browserRegistrationIntentFollowupSQL),
		newMigration(65, browserRegistrationLandingDescription, browserRegistrationLandingSQL),
		newMigration(66, browserRegistrationApprovalAuthorityDescription, browserRegistrationApprovalAuthoritySQL),
		newMigration(67, browserRegistrationApprovalRecordDescription, browserRegistrationApprovalRecordSQL),
		newMigration(68, browserRegistrationCompletionAuthorityDescription, browserRegistrationCompletionAuthoritySQL),
		newMigration(69, browserWorkspaceChoicesDescription, browserWorkspaceChoicesSQL),
		newMigration(70, browserWorkspaceApprovalDescription, browserWorkspaceApprovalSQL),
		newMigration(71, browserWorkspaceCompletionDescription, browserWorkspaceCompletionSQL),
		newMigration(72, consoleInventoryScopeDescription, consoleInventoryScopeSQL),
		newMigration(73, consoleDeviceInventoryDescription, consoleDeviceInventorySQL),
		newMigration(74, consolePolicyAuthoringScopeDescription, consolePolicyAuthoringScopeSQL),
		newMigration(75, activePolicyReadDescription, activePolicyReadSQL),
		newMigration(76, "Workspace owner tenant administration authority", workspaceOwnerAuthoritySQL),
		newMigration(77, "immutable Workspace and Network display identifiers", tenantDisplayIdentitySQL),
		newMigration(78, "owner-authorized Workspace name changes", workspaceRenameSQL),
		newMigration(79, "same-Workspace direct Device endpoint authority", directDeviceEndpointAuthoritySQL),
		newMigration(80, "authenticated bilateral direct Device map authority", directDeviceMapSQL),
		newMigration(81, "durable Device alias reservation foundation", deviceAliasReservationSQL),
		newMigration(82, "Device alias authenticated client compatibility", deviceAliasClientVersionSQL),
		newMigration(83, "Device alias client readiness and authenticated map reader", deviceAliasMapReadinessSQL),
		newMigration(84, "authenticated accepted Device sharing dependencies", deviceSharingDependenciesSQL),
		newMigration(85, "guarded bilateral Device alias worker changes", deviceAliasGuardedWorkerSQL),
		newMigration(86, "guarded Device alias withdrawal and quarantine", deviceAliasGuardedWithdrawalSQL),
		newMigration(87, "bounded keyset Device alias work hints", deviceAliasWorkCandidatesSQL),
		newMigration(88, "Consumer-scoped immutable Imported policy baseline evidence", importedPolicySimulationReaderSQL),
		newMigration(89, expiredUnprovisionedShareCleanupDescription, expiredUnprovisionedShareCleanupSQL),
		newMigration(90, "bounded Console Account Session activity renewal", accountSessionActivityRenewalSQL),
		newMigration(91, resourceSharingNeverExpiryDescription, resourceSharingNeverExpirySQL),
		newMigration(92, "one Network-scoped alias path for every Device share", unifiedDeviceAliasSharingSQL),
		newMigration(93, "bounded planning for the alias map reader", aliasMapReaderBoundedPlanningSQL),
		newMigration(94, "provider-chosen frozen Device share DNS labels", shareOfferAccessLabelSQL),
		newMigration(95, "built-in Workspace roles and Workspace-scope assignments", builtinWorkspaceRolesSQL),
		newMigration(96, "Workspace member and built-in role management", workspaceRoleManagementSQL),
		newMigration(97, "signed Deployment entitlement authority and capabilities v2", deploymentEntitlementSQL),
		newMigration(98, "one reviewed Workspace provisioning path", workspaceProvisioningSQL),
		newMigration(99, "Account-initiated Workspace creation within entitlement quotas", workspaceCreationSQL),
		newMigration(100, "Network creation with non-overlapping Workspace prefixes", networkCreationSQL),
		newMigration(101, "browser login with an Account-selected Workspace", accountSelectedLoginWorkspaceSQL),
		newMigration(102, "stable provisioning error codes and assigned Network IPv6", provisioningErrorCodesSQL),
		newMigration(103, "Account Session Workspace switch", sessionWorkspaceSwitchSQL),
		newMigration(104, "cross-Workspace shares without expiry", crossWorkspaceShareNoExpirySQL),
		newMigration(105, "share target resolution by Network display code", shareTargetResolutionSQL),
		newMigration(106, "Workspace permissions in the Console management scope", managementScopeWorkspacePermissionsSQL),
		newMigration(107, "cached written-order plans for session authority functions", sessionAuthorityPlanningSQL),
		newMigration(108, "Policy Explain for shared destinations with denial context", explainSharedDestinationsSQL),
		newMigration(109, "Policy Explain finds shares from another Workspace", explainCrossWorkspaceSharesSQL),
		newMigration(110, "Access Graph listing of the effective policy", accessGraphListingSQL),
		newMigration(111, "Share offers name both ends by display code", shareOfferDisplayCodesSQL),
		newMigration(112, "Expired Trust Contracts release their access names", trustContractExpiryFinalizerSQL),
		newMigration(113, "Receiving Networks choose their shared Device alias range", networkAliasRangeSQL),
		newMigration(114, "Alias maps count only shares a Device may reach", aliasMapReachableSharesSQL),
		newMigration(115, "Audit partitions stay ahead and every Workspace has a stream", auditPartitionsWorkspaceStreamsSQL),
		newMigration(116, "Audit events carry a database-computed seal a third party can verify", auditEventSealV2SQL),
		newMigration(117, "Workspace administrators read their audit history", workspaceAuditHistorySQL),
		newMigration(118, "Workspace administrators export verifiable audit evidence", workspaceAuditExportSQL),
		newMigration(119, "Workspace guardrails bound what rules and shares may open", workspaceGuardrailsSQL),
		newMigration(120, "Network Device Groups and rules that select them", networkDeviceGroupsSQL),
		newMigration(121, "Workspace Identity Groups and device tags", identityGroupsAndDeviceTagsSQL),
		newMigration(122, "Access Rules that select Identity Groups and tags", identityAndTagRulesSQL),
		newMigration(123, "Access Graph edges of group and tag rules", accessGraphGroupEdgesSQL),
		newMigration(124, "Tags a person may apply in one Network", networkTagOptionsSQL),
	}
}

// LatestVersion returns the latest schema version known to this binary.
func LatestVersion() int64 {
	catalog := Catalog()
	return catalog[len(catalog)-1].Version
}

func newMigration(version int64, description, sql string) Migration {
	digest := sha256.Sum256([]byte(sql))
	return Migration{
		Version:                 version,
		Description:             description,
		Checksum:                hex.EncodeToString(digest[:]),
		SQL:                     sql,
		MinimumReaderGeneration: ApplicationGeneration,
		MaximumReaderGeneration: ApplicationGeneration,
		MinimumWriterGeneration: ApplicationGeneration,
		MaximumWriterGeneration: ApplicationGeneration,
	}
}

//go:embed 000082_device_alias_client_version.up.sql
var deviceAliasClientVersionSQL string

//go:embed 000083_device_alias_map_readiness.up.sql
var deviceAliasMapReadinessSQL string

//go:embed 000084_device_sharing_dependencies.up.sql
var deviceSharingDependenciesSQL string

//go:embed 000085_device_alias_guarded_worker.up.sql
var deviceAliasGuardedWorkerSQL string

//go:embed 000086_device_alias_guarded_withdrawal.up.sql
var deviceAliasGuardedWithdrawalSQL string

//go:embed 000087_device_alias_work_candidates.up.sql
var deviceAliasWorkCandidatesSQL string

//go:embed 000088_imported_policy_simulation_reader.up.sql
var importedPolicySimulationReaderSQL string

//go:embed 000089_expired_unprovisioned_share_cleanup.up.sql
var expiredUnprovisionedShareCleanupSQL string

//go:embed 000090_account_session_activity_renewal.up.sql
var accountSessionActivityRenewalSQL string

//go:embed 000091_resource_sharing_never_expiry.up.sql
var resourceSharingNeverExpirySQL string

//go:embed 000092_unified_device_alias_sharing.up.sql
var unifiedDeviceAliasSharingSQL string

//go:embed 000093_alias_map_reader_bounded_planning.up.sql
var aliasMapReaderBoundedPlanningSQL string

//go:embed 000094_share_offer_access_label.up.sql
var shareOfferAccessLabelSQL string

//go:embed 000095_builtin_workspace_roles.up.sql
var builtinWorkspaceRolesSQL string

//go:embed 000096_workspace_role_management.up.sql
var workspaceRoleManagementSQL string

//go:embed 000097_deployment_entitlement.up.sql
var deploymentEntitlementSQL string

//go:embed 000098_workspace_provisioning.up.sql
var workspaceProvisioningSQL string

//go:embed 000099_workspace_creation.up.sql
var workspaceCreationSQL string

//go:embed 000100_network_creation.up.sql
var networkCreationSQL string

//go:embed 000101_account_selected_login_workspace.up.sql
var accountSelectedLoginWorkspaceSQL string

//go:embed 000102_provisioning_error_codes.up.sql
var provisioningErrorCodesSQL string

//go:embed 000103_session_workspace_switch.up.sql
var sessionWorkspaceSwitchSQL string

//go:embed 000104_cross_workspace_share_no_expiry.up.sql
var crossWorkspaceShareNoExpirySQL string

//go:embed 000105_share_target_resolution.up.sql
var shareTargetResolutionSQL string

//go:embed 000106_management_scope_workspace_permissions.up.sql
var managementScopeWorkspacePermissionsSQL string

//go:embed 000107_session_authority_planning.up.sql
var sessionAuthorityPlanningSQL string

//go:embed 000108_explain_shared_destinations.up.sql
var explainSharedDestinationsSQL string

//go:embed 000109_explain_cross_workspace_shares.up.sql
var explainCrossWorkspaceSharesSQL string

//go:embed 000110_access_graph_listing.up.sql
var accessGraphListingSQL string

//go:embed 000111_share_offer_display_codes.up.sql
var shareOfferDisplayCodesSQL string

//go:embed 000112_trust_contract_expiry_finalizer.up.sql
var trustContractExpiryFinalizerSQL string

//go:embed 000113_network_alias_range.up.sql
var networkAliasRangeSQL string

//go:embed 000114_alias_map_reachable_shares.up.sql
var aliasMapReachableSharesSQL string

//go:embed 000115_audit_partitions_workspace_streams.up.sql
var auditPartitionsWorkspaceStreamsSQL string

//go:embed 000116_audit_event_seal_v2.up.sql
var auditEventSealV2SQL string

//go:embed 000117_workspace_audit_history.up.sql
var workspaceAuditHistorySQL string

//go:embed 000118_workspace_audit_export.up.sql
var workspaceAuditExportSQL string

//go:embed 000119_workspace_guardrails.up.sql
var workspaceGuardrailsSQL string

//go:embed 000120_network_device_groups.up.sql
var networkDeviceGroupsSQL string

//go:embed 000121_identity_groups_and_device_tags.up.sql
var identityGroupsAndDeviceTagsSQL string

//go:embed 000122_identity_and_tag_rules.up.sql
var identityAndTagRulesSQL string

//go:embed 000123_access_graph_group_edges.up.sql
var accessGraphGroupEdgesSQL string

//go:embed 000124_network_tag_options.up.sql
var networkTagOptionsSQL string
