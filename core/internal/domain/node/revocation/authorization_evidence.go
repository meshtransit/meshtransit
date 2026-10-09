package revocation

import (
	"github.com/meshtransit/meshtransit/core/internal/domain/authorization"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

// AuthorizationEvidence identifies the current durable rows locked for device.manage.
type AuthorizationEvidence struct {
	accountSessionID                  accountsession.ID
	roleBindingID                     publicid.ID
	roleDefinitionID                  publicid.ID
	scopeAuthorityGeneration          authorization.AuthorityGeneration
	membershipAuthorityGeneration     authorization.AuthorityGeneration
	bindingAuthorityGeneration        authorization.AuthorityGeneration
	roleAuthorityGeneration           authorization.AuthorityGeneration
	workspaceOwnerAuthorityGeneration authorization.AuthorityGeneration
}

// AuthorizationEvidenceParams contains one locked device.manage decision.
type AuthorizationEvidenceParams struct {
	AccountSessionID              accountsession.ID
	RoleBindingID                 publicid.ID
	RoleDefinitionID              publicid.ID
	ScopeAuthorityGeneration      authorization.AuthorityGeneration
	MembershipAuthorityGeneration authorization.AuthorityGeneration
	BindingAuthorityGeneration    authorization.AuthorityGeneration
	RoleAuthorityGeneration       authorization.AuthorityGeneration
	// WorkspaceOwnerAuthorityGeneration is the current Workspace generation; no role is needed.
	WorkspaceOwnerAuthorityGeneration authorization.AuthorityGeneration
}

// NewAuthorizationEvidence validates locked Account Session and RBAC evidence.
func NewAuthorizationEvidence(params AuthorizationEvidenceParams) (AuthorizationEvidence, error) {
	evidence := AuthorizationEvidence{
		accountSessionID:                  params.AccountSessionID,
		roleBindingID:                     params.RoleBindingID,
		roleDefinitionID:                  params.RoleDefinitionID,
		scopeAuthorityGeneration:          params.ScopeAuthorityGeneration,
		membershipAuthorityGeneration:     params.MembershipAuthorityGeneration,
		bindingAuthorityGeneration:        params.BindingAuthorityGeneration,
		roleAuthorityGeneration:           params.RoleAuthorityGeneration,
		workspaceOwnerAuthorityGeneration: params.WorkspaceOwnerAuthorityGeneration,
	}
	if !evidence.IsValid() {
		return AuthorizationEvidence{}, ErrInvalidResolution
	}
	return evidence, nil
}

// AccountSessionID returns the authenticated session locked for authorization.
func (evidence AuthorizationEvidence) AccountSessionID() accountsession.ID {
	return evidence.accountSessionID
}

// RoleBindingID returns the exact direct-Principal Network binding.
func (evidence AuthorizationEvidence) RoleBindingID() publicid.ID {
	return evidence.roleBindingID
}

// RoleDefinitionID returns the RoleDefinition expanded by the binding.
func (evidence AuthorizationEvidence) RoleDefinitionID() publicid.ID {
	return evidence.roleDefinitionID
}

// ScopeAuthorityGeneration returns the current Network authority generation.
func (evidence AuthorizationEvidence) ScopeAuthorityGeneration() authorization.AuthorityGeneration {
	return evidence.scopeAuthorityGeneration
}

// MembershipAuthorityGeneration returns the current Workspace membership generation.
func (evidence AuthorizationEvidence) MembershipAuthorityGeneration() authorization.AuthorityGeneration {
	return evidence.membershipAuthorityGeneration
}

// BindingAuthorityGeneration returns the current RoleBinding generation.
func (evidence AuthorizationEvidence) BindingAuthorityGeneration() authorization.AuthorityGeneration {
	return evidence.bindingAuthorityGeneration
}

// RoleAuthorityGeneration returns the current RoleDefinition generation.
func (evidence AuthorizationEvidence) RoleAuthorityGeneration() authorization.AuthorityGeneration {
	return evidence.roleAuthorityGeneration
}

// WorkspaceOwnerAuthorityGeneration returns the locked Workspace ownership generation.
func (evidence AuthorizationEvidence) WorkspaceOwnerAuthorityGeneration() authorization.AuthorityGeneration {
	return evidence.workspaceOwnerAuthorityGeneration
}

// IsValid requires either current ownership or a complete direct role grant.
func (evidence AuthorizationEvidence) IsValid() bool {
	if !evidence.accountSessionID.IsValid() || evidence.scopeAuthorityGeneration == 0 || evidence.membershipAuthorityGeneration == 0 {
		return false
	}
	if evidence.workspaceOwnerAuthorityGeneration > 0 {
		return evidence.roleBindingID == (publicid.ID{}) && evidence.roleDefinitionID == (publicid.ID{}) && evidence.bindingAuthorityGeneration == 0 && evidence.roleAuthorityGeneration == 0
	}
	return evidence.roleBindingID.IsValid() && evidence.roleDefinitionID.IsValid() && evidence.bindingAuthorityGeneration > 0 && evidence.roleAuthorityGeneration > 0
}
