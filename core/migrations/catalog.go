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
		newMigration(125, "Device ownership, suspension, transfer and rename", deviceLifecycleSQL),
		newMigration(126, "Suspended Devices wait instead of stopping", mapSessionSuspensionSQL),
		newMigration(127, "Suspend and resume Workspace members", workspaceMemberSuspensionSQL),
		newMigration(128, "Workspace invitations", workspaceInvitationsSQL),
		newMigration(129, "Accept Workspace invitations at sign-in", workspaceInvitationAcceptanceSQL),
		newMigration(130, "Remove Workspace members with a Device plan", workspaceMemberRemovalSQL),
		newMigration(131, "Self sign-up with a default Workspace", accountSelfSignupSQL),
		newMigration(132, "Cloud sign-in before the first Workspace", cloudLoginWithoutWorkspaceSQL),
		newMigration(133, "Read policy distribution status", deviceDistributionReadSQL),
		newMigration(134, "Access edge ledger and history read", accessEdgeLedgerSQL),
		newMigration(135, "Relay revocation read", relayRevocationsReadSQL),
		newMigration(136, "Device enforcement ledger and history read", deviceEnforcementLedgerSQL),
		newMigration(137, "MTCP machine timestamps", mtcpMachineTimestampSQL),
		newMigration(138, "Device logout", deviceLogoutSQL),
		newMigration(139, "Private Interchange", privateInterchangeSQL),
		newMigration(140, "Map Network inventory", mapNetworkInventorySQL),
		newMigration(141, "Map Network policy", mapNetworkPolicySQL),
		newMigration(142, "Map Network header", mapNetworkHeaderSQL),
		newMigration(143, "Node address quarantine", nodeAddressQuarantineSQL),
		newMigration(144, "Policy rules for inactive Devices", policyInactiveDeviceRulesSQL),
		newMigration(145, "Map Network sharing", mapNetworkSharingSQL),
		newMigration(146, "Map sharing Devices", mapSharingDevicesSQL),
		newMigration(147, "Share map reader scale", shareMapReaderScaleSQL),
		newMigration(148, "Policy Imported Resource scale", policyImportedResourceScaleSQL),
		newMigration(149, "Share map reader selection", shareMapReaderSelectionSQL),
		newMigration(150, "Policy attach join order", policyAttachJoinOrderSQL),
		newMigration(151, "Device shared once per Network", deviceSharedOnceSQL),
		newMigration(152, "Map reader index lookups", mapReaderIndexLookupsSQL),
		newMigration(153, "Map inventory changes", mapInventoryChangesSQL),
		newMigration(154, "Map Network direct endpoints", mapNetworkDirectEndpointsSQL),
		newMigration(155, "Share reader key lookup", shareReaderKeyLookupSQL),
		newMigration(156, "Dependency reader Network once", dependencyReaderNetworkOnceSQL),
		newMigration(157, "Registration address floor", registrationAddressFloorSQL),
		newMigration(158, "Registration recent Devices", registrationRecentDevicesSQL),
		newMigration(159, "Network address usage", networkAddressUsageSQL),
		newMigration(160, "Invitation email binding", invitationEmailBindingSQL),
		newMigration(161, "Map session revocation", mapSessionRevocationSQL),
		newMigration(162, "Account session revocation", accountSessionRevocationSQL),
		newMigration(163, "Share provider guardrails", shareProviderGuardrailsSQL),
		newMigration(164, "Retroactive share guardrails", retroactiveShareGuardrailsSQL),
		newMigration(165, "Policy rules to gone Devices", policyGoneDeviceDestinationsSQL),
		newMigration(166, "Network member management", networkMemberManagementSQL),
		newMigration(167, "Guardrail share consistency", guardrailShareConsistencySQL),
		newMigration(168, "Private Endpoint publication clock", privateEndpointPublicationClockSQL),
		newMigration(169, "Device DNS names", deviceDNSNamesSQL),
		newMigration(170, "Device alias consumer readmission", deviceAliasConsumerReadmissionSQL),
		newMigration(171, "Device alias provider readmission", deviceAliasProviderReadmissionSQL),
		newMigration(172, "Sharing updated_at order", sharingUpdatedAtOrderSQL),
		newMigration(173, "Sharing updated_at order log", sharingUpdatedAtOrderLogSQL),
		newMigration(174, "Policy release rule fingerprints", policyReleaseRuleFingerprintsSQL),
		newMigration(175, "Enrollment keys", enrollmentKeysSQL),
		newMigration(176, "Used enrollment keys are managed through their Device", enrollmentKeyUsedRevokeSQL),
		newMigration(177, "Devices listed by name and read one at a time", deviceInventorySearchSQL),
		newMigration(178, "Shares end when their provider Device is removed", trustContractDeviceRemovalSQL),
		newMigration(179, "Each Network chooses how long signed-in Devices live", networkDeviceLifetimeSQL),
		newMigration(180, "An administrator briefly extends an expired Device", deviceExpiryExtensionSQL),
		newMigration(181, "SQL functions take the database clock as now", databaseClockNowSQL),
		newMigration(182, "Workspace changes no longer block foreign key checks", workspaceNoKeyUpdateSQL),
		newMigration(183, "Workspace changes lock the Workspace before checking permission", workspaceLockBeforeAuthorizeSQL),
		newMigration(184, "Permission checks lock the Workspace before the session", resolverWorkspaceFirstSQL),
		newMigration(185, "Removing a Device retires its Resource", resourceDeviceRemovalSQL),
		newMigration(186, "Deleting a Resource supersedes its Device target", resourceDeleteSupersedesTargetSQL),
		newMigration(187, "Overlay and alias pools stay inside the client overlay frame", addressPoolFrameSQL),
		newMigration(188, "Network Sites and their routers", networkSitesSQL),
		newMigration(189, "Access Rules whose destination is a Site", siteRouteRulesSQL),
		newMigration(190, "Devices report the subnets they offer to forward", deviceRouteOfferSQL),
		newMigration(191, "Maps read a Network's subnet routes", mapNetworkRoutesSQL),
		newMigration(192, "The Console reads what each Device offers to forward", consoleDeviceOffersSQL),
		newMigration(193, "Core elects each Site's primary router", sitePrimaryElectionSQL),
		newMigration(194, "A Site's read carries its elected primary and history", sitePrimaryReadsSQL),
		newMigration(195, "Maps name each Site", mapSiteNamesSQL),
		newMigration(196, "Sites may use IPv6 unique local prefixes", siteUniqueLocalPrefixesSQL),
		newMigration(197, "Explain answers for an address inside a Site", explainSiteAccessSQL),
		newMigration(198, "The Access Graph lists the Devices rules to Sites reach", accessGraphSiteEdgesSQL),
		newMigration(199, "The access edge ledger records rules to Sites", accessLedgerSiteEdgesSQL),
		newMigration(200, "A route offer is stored in one statement and dropped with its Device", routeOfferOneStatementSQL),
		newMigration(201, "Networks have Exit Pools of exit nodes", networkExitPoolsSQL),
		newMigration(202, "Access Rules may grant the Internet through an Exit Pool", policyExitRulesSQL),
		newMigration(203, "A node reports whether it offers to be an exit node", deviceExitOfferReportSQL),
		newMigration(204, "Core elects each Exit Pool's primary exit node", exitPoolPrimaryElectionSQL),
		newMigration(205, "Maps read each Network's Exit Pools", mapNetworkExitsSQL),
		newMigration(206, "Explain answers for Internet addresses through Exit Pools", explainExitAccessSQL),
		newMigration(207, "The Access Graph lists the Devices rules to Exit Pools reach", accessGraphExitEdgesSQL),
		newMigration(208, "The access ledger records rules to Exit Pools", accessLedgerExitEdgesSQL),
		newMigration(209, "The Console reads the mesh addresses a Device holds", consoleDeviceAddressesSQL),
		newMigration(210, "Exit Pools spread their consumers over their exit nodes", exitPoolSpreadSQL),
		newMigration(211, "Exit Pools may turn captive portal windows off", exitPoolCaptiveWindowsSQL),
		newMigration(212, "Captive portal windows enter the audit trail", deviceCaptiveWindowsSQL),
		newMigration(213, "Networks send chosen domains to chosen DNS resolvers", networkDNSZonesSQL),
		newMigration(214, "Maps carry a Network's DNS zones", mapNetworkDNSZonesSQL),
		newMigration(215, "DNS zones hold names an administrator sets", networkDNSNamesSQL),
		newMigration(216, "Maps carry DNS names, and DNS changes reach them together", mapNetworkDNSNamesSQL),
		newMigration(217, "DNS names can point at a share the Network imports", networkDNSShareNamesSQL),
		newMigration(218, "Share offers suggest service names", shareOfferServiceNamesSQL),
		newMigration(219, "Maps read the DNS names that point at a share", mapNetworkDNSShareNamesSQL),
		newMigration(220, "Running shares keep service names of their own", trustContractServiceNamesSQL),
		newMigration(221, "Device Groups whose Devices get no DNS from MeshTransit", networkDNSUnmanagedSQL),
		newMigration(222, "DNS debt close-out: Device DNS labels taken one writer at a time", dnsDebtCloseoutSQL),
		newMigration(223, "A DNS zone's page counts only the Devices that still receive it", dnsZoneReceiversSQL),
		newMigration(224, "Kubernetes clusters, join keys and replica requests approved by code", kubernetesClustersSQL),
		newMigration(225, "A replica's session completes its approved request into a gateway Device", kubernetesReplicaCompletionSQL),
		newMigration(226, "A Kubernetes gateway proves its node key on every session", kubernetesGatewaySessionProofSQL),
		newMigration(227, "A Kubernetes gateway moves to a new machine key", kubernetesGatewayMachineKeyRotationSQL),
		newMigration(228, "User groups and device tags belong to one Network", networkScopedGroupsTagsSQL),
		newMigration(229, "A Kubernetes gateway's stale or contested keys enter the audit trail", kubernetesGatewayKeyEventsSQL),
		newMigration(230, "Rules grant a Kubernetes cluster as a whole through its own Device Group", kubernetesClusterPolicyGroupsSQL),
		newMigration(231, "Maps name a Kubernetes cluster instead of its gateway replicas", mapKubernetesGatewaysSQL),
		newMigration(232, "A Kubernetes gateway rotates a key only with its pod's ServiceAccount token",
			kubernetesGatewayRotationTokensSQL),
		newMigration(233, "A Kubernetes gateway's refused rotation tokens enter the audit trail",
			kubernetesGatewayTokenAuditSQL),
		newMigration(234, "A revoked Kubernetes gateway no longer holds its pod", kubernetesRevokedGatewayPodsSQL),
		newMigration(235, "An administrator pastes a Kubernetes cluster's signing keys", kubernetesSigningTrustPasteSQL),
		newMigration(236, "A rule to a Kubernetes cluster names the Kubernetes groups it grants", kubernetesRuleGroupsSQL),
		newMigration(237, "What a Kubernetes gateway's map knows of the Devices that reach it", kubernetesGatewaySourcesSQL),
		newMigration(238, "The worker keeps each Kubernetes cluster's CA, sealed under its Network's data key",
			kubernetesClusterCASQL),
		newMigration(239, "Kubernetes clusters get a root and short-lived intermediates; data keys can be wrapped again",
			kubernetesClusterCATwoTierSQL),
		newMigration(240, "The worker signs Kubernetes gateway certificates; CA work stops after a database restore",
			kubernetesGatewayCertificatesSQL),
		newMigration(241, "Pod tokens leave the certificate queue at the first claim; Workspaces share it fairly",
			kubernetesGatewayCertificateQueueSQL),
		newMigration(242, "A Kubernetes gateway's map names its cluster's root and signing CA", mapKubernetesClusterCAsSQL),
		newMigration(243, "The signer reads the gateway certificate fleet for its gauges",
			kubernetesGatewayCertificateFleetSQL),
		newMigration(244, "A client's map names its clusters' TLS name and the roots it trusts",
			kubernetesClientCAsSQL),
		newMigration(245, "Kubernetes gateways record type A operations before forwarding them",
			kubernetesOperationEventsSQL),
		newMigration(246, "A Kubernetes gateway presents its pod token on every session",
			kubernetesGatewaySessionTokensSQL),
		newMigration(247, "A cluster's join keys and replica requests read a page at a time",
			kubernetesClusterPagesSQL),
		newMigration(248, "A cluster's replicas and certificate authorities read a page at a time",
			kubernetesClusterReplicaCAReadsSQL),
		newMigration(249, "Audit readers read a cluster's Kubernetes operations with a bounded scan",
			kubernetesOperationReadsSQL),
		newMigration(250, "An administrator sets what audit-check treats as privileged and secret-like",
			kubernetesAuditSettingsSQL),
		newMigration(251, "Audit exporters export a cluster's operations for audit-check, a page at a time",
			kubernetesOperationExportsSQL),
		newMigration(252, "Approvers ask the CA worker to retire a cluster's CA",
			kubernetesCARetireRequestsSQL),
		newMigration(253, "Approvers suspend a gateway's pod token ratchet for at most a day",
			kubernetesGatewayRatchetSuspensionSQL),
		newMigration(254, "Kubernetes gateways report their groups' RBAC check",
			kubernetesGatewayGroupReportsSQL),
		newMigration(255, "Readers of a Kubernetes cluster see approvers added within a day",
			kubernetesClusterApproverAdditionsSQL),
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

//go:embed 000125_device_lifecycle.up.sql
var deviceLifecycleSQL string

//go:embed 000126_map_session_suspension.up.sql
var mapSessionSuspensionSQL string

//go:embed 000127_workspace_member_suspension.up.sql
var workspaceMemberSuspensionSQL string

//go:embed 000128_workspace_invitations.up.sql
var workspaceInvitationsSQL string

//go:embed 000129_workspace_invitation_acceptance.up.sql
var workspaceInvitationAcceptanceSQL string

//go:embed 000130_workspace_member_removal.up.sql
var workspaceMemberRemovalSQL string

//go:embed 000131_account_self_signup.up.sql
var accountSelfSignupSQL string

//go:embed 000132_cloud_login_without_workspace.up.sql
var cloudLoginWithoutWorkspaceSQL string

//go:embed 000133_device_distribution_read.up.sql
var deviceDistributionReadSQL string

//go:embed 000134_access_edge_ledger.up.sql
var accessEdgeLedgerSQL string

//go:embed 000135_relay_revocations_read.up.sql
var relayRevocationsReadSQL string

//go:embed 000136_device_enforcement_ledger.up.sql
var deviceEnforcementLedgerSQL string

//go:embed 000137_mtcp_machine_timestamp.up.sql
var mtcpMachineTimestampSQL string

//go:embed 000138_device_logout.up.sql
var deviceLogoutSQL string

//go:embed 000139_private_interchange.up.sql
var privateInterchangeSQL string

//go:embed 000140_map_network_inventory.up.sql
var mapNetworkInventorySQL string

//go:embed 000141_map_network_policy.up.sql
var mapNetworkPolicySQL string

//go:embed 000142_map_network_header.up.sql
var mapNetworkHeaderSQL string

//go:embed 000143_node_address_quarantine.up.sql
var nodeAddressQuarantineSQL string

//go:embed 000144_policy_inactive_device_rules.up.sql
var policyInactiveDeviceRulesSQL string

//go:embed 000145_map_network_sharing.up.sql
var mapNetworkSharingSQL string

//go:embed 000146_map_sharing_devices.up.sql
var mapSharingDevicesSQL string

//go:embed 000147_share_map_reader_scale.up.sql
var shareMapReaderScaleSQL string

//go:embed 000148_policy_imported_resource_scale.up.sql
var policyImportedResourceScaleSQL string

//go:embed 000149_share_map_reader_selection.up.sql
var shareMapReaderSelectionSQL string

//go:embed 000150_policy_attach_join_order.up.sql
var policyAttachJoinOrderSQL string

//go:embed 000151_device_shared_once.up.sql
var deviceSharedOnceSQL string

//go:embed 000152_map_reader_index_lookups.up.sql
var mapReaderIndexLookupsSQL string

//go:embed 000153_map_inventory_changes.up.sql
var mapInventoryChangesSQL string

//go:embed 000154_map_network_direct_endpoints.up.sql
var mapNetworkDirectEndpointsSQL string

//go:embed 000155_share_reader_key_lookup.up.sql
var shareReaderKeyLookupSQL string

//go:embed 000156_dependency_reader_network_once.up.sql
var dependencyReaderNetworkOnceSQL string

//go:embed 000157_registration_address_floor.up.sql
var registrationAddressFloorSQL string

//go:embed 000158_registration_recent_devices.up.sql
var registrationRecentDevicesSQL string

//go:embed 000159_network_address_usage.up.sql
var networkAddressUsageSQL string

//go:embed 000160_invitation_email_binding.up.sql
var invitationEmailBindingSQL string

//go:embed 000161_map_session_revocation.up.sql
var mapSessionRevocationSQL string

//go:embed 000162_account_session_revocation.up.sql
var accountSessionRevocationSQL string

//go:embed 000163_share_provider_guardrails.up.sql
var shareProviderGuardrailsSQL string

//go:embed 000164_retroactive_share_guardrails.up.sql
var retroactiveShareGuardrailsSQL string

//go:embed 000165_policy_gone_device_destinations.up.sql
var policyGoneDeviceDestinationsSQL string

//go:embed 000166_network_member_management.up.sql
var networkMemberManagementSQL string

//go:embed 000167_guardrail_share_consistency.up.sql
var guardrailShareConsistencySQL string

//go:embed 000168_private_endpoint_publication_clock.up.sql
var privateEndpointPublicationClockSQL string

//go:embed 000169_device_dns_names.up.sql
var deviceDNSNamesSQL string

//go:embed 000170_device_alias_consumer_readmission.up.sql
var deviceAliasConsumerReadmissionSQL string

//go:embed 000171_device_alias_provider_readmission.up.sql
var deviceAliasProviderReadmissionSQL string

//go:embed 000172_sharing_updated_at_order.up.sql
var sharingUpdatedAtOrderSQL string

//go:embed 000173_sharing_updated_at_order_log.up.sql
var sharingUpdatedAtOrderLogSQL string

//go:embed 000174_policy_release_rule_fingerprints.up.sql
var policyReleaseRuleFingerprintsSQL string

//go:embed 000175_enrollment_keys.up.sql
var enrollmentKeysSQL string

//go:embed 000176_enrollment_key_used_revoke.up.sql
var enrollmentKeyUsedRevokeSQL string

//go:embed 000177_device_inventory_search.up.sql
var deviceInventorySearchSQL string

//go:embed 000178_trust_contract_device_removal.up.sql
var trustContractDeviceRemovalSQL string

//go:embed 000179_network_device_lifetime.up.sql
var networkDeviceLifetimeSQL string

//go:embed 000180_device_expiry_extension.up.sql
var deviceExpiryExtensionSQL string

//go:embed 000181_database_clock_now.up.sql
var databaseClockNowSQL string

//go:embed 000182_workspace_no_key_update.up.sql
var workspaceNoKeyUpdateSQL string

//go:embed 000183_workspace_lock_before_authorize.up.sql
var workspaceLockBeforeAuthorizeSQL string

//go:embed 000184_resolver_workspace_first.up.sql
var resolverWorkspaceFirstSQL string

//go:embed 000185_resource_device_removal.up.sql
var resourceDeviceRemovalSQL string

//go:embed 000186_resource_delete_supersedes_target.up.sql
var resourceDeleteSupersedesTargetSQL string

//go:embed 000187_address_pool_frame.up.sql
var addressPoolFrameSQL string

//go:embed 000188_network_sites.up.sql
var networkSitesSQL string

//go:embed 000189_site_route_rules.up.sql
var siteRouteRulesSQL string

//go:embed 000190_device_route_offer.up.sql
var deviceRouteOfferSQL string

//go:embed 000191_map_network_routes.up.sql
var mapNetworkRoutesSQL string

//go:embed 000192_console_device_offers.up.sql
var consoleDeviceOffersSQL string

//go:embed 000193_site_primary_election.up.sql
var sitePrimaryElectionSQL string

//go:embed 000194_site_primary_reads.up.sql
var sitePrimaryReadsSQL string

//go:embed 000195_map_site_names.up.sql
var mapSiteNamesSQL string

//go:embed 000196_site_unique_local_prefixes.up.sql
var siteUniqueLocalPrefixesSQL string

//go:embed 000197_explain_site_access.up.sql
var explainSiteAccessSQL string

//go:embed 000198_access_graph_site_edges.up.sql
var accessGraphSiteEdgesSQL string

//go:embed 000199_access_ledger_site_edges.up.sql
var accessLedgerSiteEdgesSQL string

//go:embed 000200_route_offer_one_statement.up.sql
var routeOfferOneStatementSQL string

//go:embed 000201_network_exit_pools.up.sql
var networkExitPoolsSQL string

//go:embed 000202_policy_exit_rules.up.sql
var policyExitRulesSQL string

//go:embed 000203_device_exit_offer_report.up.sql
var deviceExitOfferReportSQL string

//go:embed 000204_exit_pool_primary_election.up.sql
var exitPoolPrimaryElectionSQL string

//go:embed 000205_map_network_exits.up.sql
var mapNetworkExitsSQL string

//go:embed 000206_explain_exit_access.up.sql
var explainExitAccessSQL string

//go:embed 000207_access_graph_exit_edges.up.sql
var accessGraphExitEdgesSQL string

//go:embed 000208_access_ledger_exit_edges.up.sql
var accessLedgerExitEdgesSQL string

//go:embed 000209_console_device_addresses.up.sql
var consoleDeviceAddressesSQL string

//go:embed 000210_exit_pool_spread.up.sql
var exitPoolSpreadSQL string

//go:embed 000211_exit_pool_captive_windows.up.sql
var exitPoolCaptiveWindowsSQL string

//go:embed 000212_device_captive_windows.up.sql
var deviceCaptiveWindowsSQL string

//go:embed 000213_network_dns_zones.up.sql
var networkDNSZonesSQL string

//go:embed 000214_map_network_dns_zones.up.sql
var mapNetworkDNSZonesSQL string

//go:embed 000215_network_dns_names.up.sql
var networkDNSNamesSQL string

//go:embed 000216_map_network_dns_names.up.sql
var mapNetworkDNSNamesSQL string

//go:embed 000217_network_dns_share_names.up.sql
var networkDNSShareNamesSQL string

//go:embed 000218_share_offer_service_names.up.sql
var shareOfferServiceNamesSQL string

//go:embed 000219_map_network_dns_share_names.up.sql
var mapNetworkDNSShareNamesSQL string

//go:embed 000220_trust_contract_service_names.up.sql
var trustContractServiceNamesSQL string

//go:embed 000221_network_dns_unmanaged.up.sql
var networkDNSUnmanagedSQL string

//go:embed 000222_dns_debt_closeout.up.sql
var dnsDebtCloseoutSQL string

//go:embed 000223_dns_zone_receivers.up.sql
var dnsZoneReceiversSQL string

//go:embed 000224_kubernetes_clusters.up.sql
var kubernetesClustersSQL string

//go:embed 000225_kubernetes_replica_completion.up.sql
var kubernetesReplicaCompletionSQL string

//go:embed 000226_kubernetes_gateway_session_proof.up.sql
var kubernetesGatewaySessionProofSQL string

//go:embed 000227_kubernetes_gateway_machine_key_rotation.up.sql
var kubernetesGatewayMachineKeyRotationSQL string

//go:embed 000228_network_scoped_groups_tags.up.sql
var networkScopedGroupsTagsSQL string

//go:embed 000229_kubernetes_gateway_key_events.up.sql
var kubernetesGatewayKeyEventsSQL string

//go:embed 000230_kubernetes_cluster_policy_groups.up.sql
var kubernetesClusterPolicyGroupsSQL string

//go:embed 000231_map_kubernetes_gateways.up.sql
var mapKubernetesGatewaysSQL string

//go:embed 000232_kubernetes_gateway_rotation_tokens.up.sql
var kubernetesGatewayRotationTokensSQL string

//go:embed 000233_kubernetes_gateway_token_audit.up.sql
var kubernetesGatewayTokenAuditSQL string

//go:embed 000234_kubernetes_revoked_gateway_pods.up.sql
var kubernetesRevokedGatewayPodsSQL string

//go:embed 000235_kubernetes_signing_trust_paste.up.sql
var kubernetesSigningTrustPasteSQL string

//go:embed 000236_kubernetes_rule_groups.up.sql
var kubernetesRuleGroupsSQL string

//go:embed 000237_kubernetes_gateway_sources.up.sql
var kubernetesGatewaySourcesSQL string

//go:embed 000238_kubernetes_cluster_ca.up.sql
var kubernetesClusterCASQL string

//go:embed 000239_kubernetes_cluster_ca_two_tier.up.sql
var kubernetesClusterCATwoTierSQL string

//go:embed 000240_kubernetes_gateway_certificates.up.sql
var kubernetesGatewayCertificatesSQL string

//go:embed 000241_kubernetes_gateway_certificate_queue.up.sql
var kubernetesGatewayCertificateQueueSQL string

//go:embed 000242_map_kubernetes_cluster_cas.up.sql
var mapKubernetesClusterCAsSQL string

//go:embed 000243_kubernetes_gateway_certificate_fleet.up.sql
var kubernetesGatewayCertificateFleetSQL string

//go:embed 000244_kubernetes_client_cas.up.sql
var kubernetesClientCAsSQL string

//go:embed 000245_kubernetes_operation_events.up.sql
var kubernetesOperationEventsSQL string

//go:embed 000246_kubernetes_gateway_session_tokens.up.sql
var kubernetesGatewaySessionTokensSQL string

//go:embed 000247_kubernetes_cluster_pages.up.sql
var kubernetesClusterPagesSQL string

//go:embed 000248_kubernetes_cluster_replica_ca_reads.up.sql
var kubernetesClusterReplicaCAReadsSQL string

//go:embed 000249_kubernetes_operation_reads.up.sql
var kubernetesOperationReadsSQL string

//go:embed 000250_kubernetes_audit_settings.up.sql
var kubernetesAuditSettingsSQL string

//go:embed 000251_kubernetes_operation_exports.up.sql
var kubernetesOperationExportsSQL string

//go:embed 000252_kubernetes_ca_retire_requests.up.sql
var kubernetesCARetireRequestsSQL string

//go:embed 000253_kubernetes_gateway_ratchet_suspension.up.sql
var kubernetesGatewayRatchetSuspensionSQL string

//go:embed 000254_kubernetes_gateway_group_reports.up.sql
var kubernetesGatewayGroupReportsSQL string

//go:embed 000255_kubernetes_cluster_approver_additions.up.sql
var kubernetesClusterApproverAdditionsSQL string
