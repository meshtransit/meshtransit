package authorization

type scopeRelation uint16

const (
	relationDeploymentDeployment scopeRelation = 1 << iota
	relationDeploymentWorkspace
	relationDeploymentNetwork
	relationWorkspaceDeployment
	relationWorkspaceWorkspace
	relationWorkspaceNetwork
	relationNetworkDeployment
	relationNetworkWorkspace
	relationNetworkNetwork
)

const (
	deploymentExact = relationDeploymentDeployment
	workspaceExact  = relationWorkspaceWorkspace
	networkExact    = relationNetworkNetwork
	isolatable      = relationWorkspaceWorkspace | relationNetworkNetwork
	auditable       = relationDeploymentDeployment | relationWorkspaceWorkspace |
		relationNetworkNetwork
)

// PermissionDefinition describes the approved binding-to-target scope relations.
type PermissionDefinition struct {
	permission Permission
	relations  scopeRelation
}

// Permission returns the stable action identifier for this definition.
func (d PermissionDefinition) Permission() Permission { return d.permission }

// Applies reports whether a binding scope may authorize the exact target scope.
func (d PermissionDefinition) Applies(binding Scope, target Scope) bool {
	if !binding.isValid() || !target.isValid() || !binding.contains(target) {
		return false
	}
	return d.relations&relationFor(binding.kind, target.kind) != 0
}

func (d PermissionDefinition) allowsBinding(kind ScopeKind) bool {
	for target := ScopeDeployment; target <= ScopeNetwork; target++ {
		if d.relations&relationFor(kind, target) != 0 {
			return true
		}
	}
	return false
}

func (d PermissionDefinition) allowsTarget(kind ScopeKind) bool {
	for binding := ScopeDeployment; binding <= ScopeNetwork; binding++ {
		if d.relations&relationFor(binding, kind) != 0 {
			return true
		}
	}
	return false
}

func relationFor(binding ScopeKind, target ScopeKind) scopeRelation {
	if binding < ScopeDeployment || binding > ScopeNetwork ||
		target < ScopeDeployment || target > ScopeNetwork {
		return 0
	}
	shift := uint(binding-ScopeDeployment)*3 + uint(target-ScopeDeployment)
	return 1 << shift
}

// LookupPermission resolves an exact permission identifier without wildcard matching.
func LookupPermission(permission Permission) (PermissionDefinition, bool) {
	var relations scopeRelation
	switch permission {
	case PermissionDeploymentRead,
		PermissionDeploymentSecurityManage,
		PermissionDeploymentRoleBind,
		PermissionDeploymentOperate,
		PermissionSupportGrantUse:
		relations = deploymentExact
	case PermissionWorkspaceRead,
		PermissionWorkspaceUpdate,
		PermissionWorkspaceDelete,
		PermissionWorkspaceOwnerTransfer,
		PermissionNetworkCreate,
		PermissionMemberRead,
		PermissionMemberInvite,
		PermissionMemberManage,
		PermissionIdentityProviderManage,
		PermissionIdentityGroupManage,
		PermissionIdentityGroupRead,
		PermissionDeviceTagRead,
		PermissionDeviceTagManage,
		PermissionInterchangeRead,
		PermissionInterchangeManage,
		PermissionRoleDefinitionRead,
		PermissionRoleDefinitionManage,
		PermissionRoleBindingRead,
		PermissionRoleBindingManage,
		PermissionApprovalPolicyManage,
		PermissionAccessReviewManage,
		PermissionSupportGrantRead,
		PermissionSupportGrantManage,
		PermissionBillingRead,
		PermissionBillingManage:
		relations = workspaceExact
	case PermissionNetworkRead,
		PermissionNetworkUpdate,
		PermissionNetworkSuspend,
		PermissionNetworkDelete,
		PermissionDNSManage,
		PermissionNetworkMemberManage,
		PermissionKubernetesClusterManage,
		PermissionKubernetesClusterApprove,
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
		PermissionResourceTransfer,
		PermissionResourceGroupRead,
		PermissionResourceGroupManage,
		PermissionResourceGroupTransfer,
		PermissionShareRead,
		PermissionShareOffer,
		PermissionShareAccept,
		PermissionShareRevoke:
		relations = networkExact
	case PermissionIsolationRead,
		PermissionIsolationQuarantine,
		PermissionIsolationRestore,
		PermissionGuardrailRead,
		PermissionGuardrailManage,
		PermissionGuardrailWeaken:
		relations = isolatable
	case PermissionAuditRead, PermissionAuditExport:
		relations = auditable
	default:
		return PermissionDefinition{}, false
	}
	return PermissionDefinition{permission: permission, relations: relations}, true
}
