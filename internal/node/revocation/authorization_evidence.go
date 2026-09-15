package revocation

import (
	"github.com/meshtransit/meshtransit/internal/authorization"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

// AuthorizationEvidence identifies the current durable rows locked for device.manage.
type AuthorizationEvidence struct {
	accountSessionID              accountsession.ID
	roleBindingID                 publicid.ID
	roleDefinitionID              publicid.ID
	scopeAuthorityGeneration      authorization.AuthorityGeneration
	membershipAuthorityGeneration authorization.AuthorityGeneration
	bindingAuthorityGeneration    authorization.AuthorityGeneration
	roleAuthorityGeneration       authorization.AuthorityGeneration
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
}

// NewAuthorizationEvidence validates locked Account Session and RBAC evidence.
func NewAuthorizationEvidence(params AuthorizationEvidenceParams) (AuthorizationEvidence, error) {
	evidence := AuthorizationEvidence{
		accountSessionID:              params.AccountSessionID,
		roleBindingID:                 params.RoleBindingID,
		roleDefinitionID:              params.RoleDefinitionID,
		scopeAuthorityGeneration:      params.ScopeAuthorityGeneration,
		membershipAuthorityGeneration: params.MembershipAuthorityGeneration,
		bindingAuthorityGeneration:    params.BindingAuthorityGeneration,
		roleAuthorityGeneration:       params.RoleAuthorityGeneration,
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

// IsValid reports whether every locked authorization identity and generation is present.
func (evidence AuthorizationEvidence) IsValid() bool {
	return evidence.accountSessionID.IsValid() && evidence.roleBindingID.IsValid() &&
		evidence.roleDefinitionID.IsValid() && evidence.scopeAuthorityGeneration > 0 &&
		evidence.membershipAuthorityGeneration > 0 && evidence.bindingAuthorityGeneration > 0 &&
		evidence.roleAuthorityGeneration > 0
}
