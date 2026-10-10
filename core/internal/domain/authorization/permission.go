package authorization

import "errors"

// ErrUnknownPermission reports a permission outside the approved catalog.
var ErrUnknownPermission = errors.New("authorization: unknown permission")

// Permission is one stable management action identifier.
type Permission string

const (
	// PermissionDeploymentRead reads deployment configuration.
	PermissionDeploymentRead Permission = "deployment.read"
	// PermissionDeploymentSecurityManage changes deployment security configuration.
	PermissionDeploymentSecurityManage Permission = "deployment.security.manage"
	// PermissionDeploymentRoleBind changes deployment-scoped role bindings.
	PermissionDeploymentRoleBind Permission = "deployment.role.bind"
	// PermissionDeploymentOperate performs bounded deployment operations.
	PermissionDeploymentOperate Permission = "deployment.operate"
	// PermissionSupportGrantUse uses a separately authorized support grant.
	PermissionSupportGrantUse Permission = "support.grant.use"

	// PermissionWorkspaceRead reads workspace configuration.
	PermissionWorkspaceRead Permission = "workspace.read"
	// PermissionWorkspaceUpdate changes ordinary workspace configuration.
	PermissionWorkspaceUpdate Permission = "workspace.update"
	// PermissionWorkspaceDelete deletes a workspace through its protected workflow.
	PermissionWorkspaceDelete Permission = "workspace.delete"
	// PermissionWorkspaceOwnerTransfer transfers workspace ownership.
	PermissionWorkspaceOwnerTransfer Permission = "workspace.owner.transfer"

	// PermissionNetworkRead reads network configuration.
	PermissionNetworkRead Permission = "network.read"
	// PermissionNetworkCreate creates a network inside a workspace.
	PermissionNetworkCreate Permission = "network.create"
	// PermissionNetworkUpdate changes ordinary network configuration.
	PermissionNetworkUpdate Permission = "network.update"
	// PermissionNetworkSuspend suspends a network.
	PermissionNetworkSuspend Permission = "network.suspend"
	// PermissionNetworkDelete deletes a network through its protected workflow.
	PermissionNetworkDelete Permission = "network.delete"
	// PermissionDNSManage changes network DNS configuration.
	PermissionDNSManage Permission = "dns.manage"

	// PermissionMemberRead reads workspace membership.
	PermissionMemberRead Permission = "member.read"
	// PermissionMemberInvite invites a workspace member.
	PermissionMemberInvite Permission = "member.invite"
	// PermissionMemberManage changes ordinary workspace membership.
	PermissionMemberManage Permission = "member.manage"
	// PermissionIdentityProviderManage changes workspace identity-provider configuration.
	PermissionIdentityProviderManage Permission = "identity_provider.manage"
	// PermissionIdentityGroupManage changes workspace identity groups.
	PermissionIdentityGroupManage Permission = "identity_group.manage"
	// PermissionIdentityGroupRead reads workspace identity groups.
	PermissionIdentityGroupRead Permission = "identity_group.read"
	// PermissionDeviceTagRead reads the workspace device tag catalog.
	PermissionDeviceTagRead Permission = "device_tag.read"
	// PermissionDeviceTagManage changes the device tag catalog and applies any tag.
	PermissionDeviceTagManage Permission = "device_tag.manage"
	// PermissionInterchangeRead reads the Workspace's Private Interchange relays.
	PermissionInterchangeRead Permission = "interchange.read"
	// PermissionInterchangeManage adds, changes and removes Private Interchange relays.
	PermissionInterchangeManage Permission = "interchange.manage"

	// PermissionRoleDefinitionRead reads role definitions.
	PermissionRoleDefinitionRead Permission = "role_definition.read"
	// PermissionRoleDefinitionManage changes eligible custom role definitions.
	PermissionRoleDefinitionManage Permission = "role_definition.manage"
	// PermissionRoleBindingRead reads role bindings.
	PermissionRoleBindingRead Permission = "role_binding.read"
	// PermissionRoleBindingManage changes eligible role bindings.
	PermissionRoleBindingManage Permission = "role_binding.manage"
	// PermissionApprovalPolicyManage changes approval policy.
	PermissionApprovalPolicyManage Permission = "approval_policy.manage"

	// PermissionDeviceRead reads device inventory.
	PermissionDeviceRead Permission = "device.read"
	// PermissionDeviceManage changes ordinary device lifecycle state.
	PermissionDeviceManage Permission = "device.manage"
	// PermissionDeviceTransfer transfers device ownership or custody.
	PermissionDeviceTransfer Permission = "device.transfer"
	// PermissionDeviceQuarantine quarantines a device.
	PermissionDeviceQuarantine Permission = "device.quarantine"
	// PermissionSessionRevoke revokes an authenticated session.
	PermissionSessionRevoke Permission = "session.revoke"

	// PermissionEnrollmentProfileRead reads enrollment profiles.
	PermissionEnrollmentProfileRead Permission = "enrollment_profile.read"
	// PermissionEnrollmentProfileManage changes enrollment profiles.
	PermissionEnrollmentProfileManage Permission = "enrollment_profile.manage"
	// PermissionEnrollmentCredentialIssue issues an enrollment credential.
	PermissionEnrollmentCredentialIssue Permission = "enrollment_credential.issue"
	// PermissionEnrollmentCredentialRevoke revokes an enrollment credential.
	PermissionEnrollmentCredentialRevoke Permission = "enrollment_credential.revoke"

	// PermissionDeviceGroupRead reads device groups.
	PermissionDeviceGroupRead Permission = "device_group.read"
	// PermissionDeviceGroupManage changes device-group definitions.
	PermissionDeviceGroupManage Permission = "device_group.manage"
	// PermissionDeviceGroupMembersManage changes eligible device-group membership.
	PermissionDeviceGroupMembersManage Permission = "device_group.members.manage"
	// PermissionDeviceGroupDelegationManage changes device-group delegation.
	PermissionDeviceGroupDelegationManage Permission = "device_group.delegation.manage"

	// PermissionPolicyRead reads policy intent and effective state.
	PermissionPolicyRead Permission = "policy.read"
	// PermissionPolicyDraft changes a policy draft.
	PermissionPolicyDraft Permission = "policy.draft"
	// PermissionPolicyValidate validates and tests a policy draft.
	PermissionPolicyValidate Permission = "policy.validate"
	// PermissionPolicyApprove approves an unchanged policy candidate.
	PermissionPolicyApprove Permission = "policy.approve"
	// PermissionPolicyPublish publishes an approved policy release.
	PermissionPolicyPublish Permission = "policy.publish"
	// PermissionPolicyRollback activates an eligible previous policy release.
	PermissionPolicyRollback Permission = "policy.rollback"
	// PermissionPolicyExplain reads bounded policy explanations.
	PermissionPolicyExplain Permission = "policy.explain"

	// PermissionRouteRead reads routes and connector health.
	PermissionRouteRead Permission = "route.read"
	// PermissionRouteApprove approves a route advertisement.
	PermissionRouteApprove Permission = "route.approve"
	// PermissionRouteWithdraw withdraws an approved route.
	PermissionRouteWithdraw Permission = "route.withdraw"
	// PermissionConnectorRead reads connector configuration.
	PermissionConnectorRead Permission = "connector.read"
	// PermissionConnectorManage changes connector configuration.
	PermissionConnectorManage Permission = "connector.manage"

	// PermissionResourceRead reads local resources.
	PermissionResourceRead Permission = "resource.read"
	// PermissionResourceManage changes local resources.
	PermissionResourceManage Permission = "resource.manage"
	// PermissionResourceExport exports a resource through a protected workflow.
	PermissionResourceExport Permission = "resource.export"
	// PermissionResourceTransfer changes Resource ownership or custody.
	PermissionResourceTransfer Permission = "resource.transfer"
	// PermissionResourceGroupRead reads resource groups.
	PermissionResourceGroupRead Permission = "resource_group.read"
	// PermissionResourceGroupManage changes resource groups.
	PermissionResourceGroupManage Permission = "resource_group.manage"
	// PermissionResourceGroupTransfer changes Resource Group ownership or custody.
	PermissionResourceGroupTransfer Permission = "resource_group.transfer"

	// PermissionShareRead reads local sharing state.
	PermissionShareRead Permission = "share.read"
	// PermissionShareOffer creates a resource share offer.
	PermissionShareOffer Permission = "share.offer"
	// PermissionShareAccept accepts a share into an authorized network.
	PermissionShareAccept Permission = "share.accept"
	// PermissionShareRevoke revokes local sharing authority.
	PermissionShareRevoke Permission = "share.revoke"

	// PermissionIsolationRead reads isolation state.
	PermissionIsolationRead Permission = "isolation.read"
	// PermissionIsolationQuarantine narrows authority through quarantine.
	PermissionIsolationQuarantine Permission = "isolation.quarantine"
	// PermissionIsolationRestore restores authority through a protected workflow.
	PermissionIsolationRestore Permission = "isolation.restore"

	// PermissionGuardrailRead reads governance guardrails.
	PermissionGuardrailRead Permission = "guardrail.read"
	// PermissionGuardrailManage creates or strengthens governance guardrails.
	PermissionGuardrailManage Permission = "guardrail.manage"
	// PermissionGuardrailWeaken weakens a guardrail through a protected workflow.
	PermissionGuardrailWeaken Permission = "guardrail.weaken"
	// PermissionAuditRead reads scoped audit evidence.
	PermissionAuditRead Permission = "audit.read"
	// PermissionAuditExport exports scoped audit evidence.
	PermissionAuditExport Permission = "audit.export"
	// PermissionAccessReviewManage changes access-review lifecycle state.
	PermissionAccessReviewManage Permission = "access_review.manage"

	// PermissionSupportGrantRead reads workspace support grants.
	PermissionSupportGrantRead Permission = "support.grant.read"
	// PermissionSupportGrantManage changes workspace support grants.
	PermissionSupportGrantManage Permission = "support.grant.manage"
	// PermissionBillingRead reads workspace billing state.
	PermissionBillingRead Permission = "billing.read"
	// PermissionBillingManage changes workspace billing state.
	PermissionBillingManage Permission = "billing.manage"
)

// Permissions returns a defensive copy of the complete v1 permission catalog.
func Permissions() []Permission {
	return []Permission{
		PermissionDeploymentRead,
		PermissionDeploymentSecurityManage,
		PermissionDeploymentRoleBind,
		PermissionDeploymentOperate,
		PermissionSupportGrantUse,
		PermissionWorkspaceRead,
		PermissionWorkspaceUpdate,
		PermissionWorkspaceDelete,
		PermissionWorkspaceOwnerTransfer,
		PermissionNetworkRead,
		PermissionNetworkCreate,
		PermissionNetworkUpdate,
		PermissionNetworkSuspend,
		PermissionNetworkDelete,
		PermissionDNSManage,
		PermissionMemberRead,
		PermissionMemberInvite,
		PermissionMemberManage,
		PermissionIdentityProviderManage,
		PermissionIdentityGroupManage,
		PermissionRoleDefinitionRead,
		PermissionRoleDefinitionManage,
		PermissionRoleBindingRead,
		PermissionRoleBindingManage,
		PermissionApprovalPolicyManage,
		PermissionDeviceRead,
		PermissionDeviceManage,
		PermissionDeviceTransfer,
		PermissionDeviceQuarantine,
		PermissionSessionRevoke,
		PermissionEnrollmentProfileRead,
		PermissionEnrollmentProfileManage,
		PermissionEnrollmentCredentialIssue,
		PermissionEnrollmentCredentialRevoke,
		PermissionDeviceGroupRead,
		PermissionDeviceGroupManage,
		PermissionDeviceGroupMembersManage,
		PermissionDeviceGroupDelegationManage,
		PermissionPolicyRead,
		PermissionPolicyDraft,
		PermissionPolicyValidate,
		PermissionPolicyApprove,
		PermissionPolicyPublish,
		PermissionPolicyRollback,
		PermissionPolicyExplain,
		PermissionRouteRead,
		PermissionRouteApprove,
		PermissionRouteWithdraw,
		PermissionConnectorRead,
		PermissionConnectorManage,
		PermissionResourceRead,
		PermissionResourceManage,
		PermissionResourceExport,
		PermissionResourceGroupRead,
		PermissionResourceGroupManage,
		PermissionShareRead,
		PermissionShareOffer,
		PermissionShareAccept,
		PermissionShareRevoke,
		PermissionIsolationRead,
		PermissionIsolationQuarantine,
		PermissionIsolationRestore,
		PermissionGuardrailRead,
		PermissionGuardrailManage,
		PermissionGuardrailWeaken,
		PermissionAuditRead,
		PermissionAuditExport,
		PermissionAccessReviewManage,
		PermissionSupportGrantRead,
		PermissionSupportGrantManage,
		PermissionBillingRead,
		PermissionBillingManage,
		PermissionResourceTransfer,
		PermissionResourceGroupTransfer,
		PermissionIdentityGroupRead,
		PermissionDeviceTagRead,
		PermissionDeviceTagManage,
		PermissionInterchangeRead,
		PermissionInterchangeManage,
	}
}
