package revocation

import (
	"testing"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

func TestWorkspaceOwnerRevocationEvidence(t *testing.T) {
	t.Parallel()
	id, err := publicid.Parse("01890f00-0000-7000-8000-000000000821")
	if err != nil {
		t.Fatal(err)
	}
	params := AuthorizationEvidenceParams{
		AccountSessionID:                  accountsession.ID(id),
		ScopeAuthorityGeneration:          2,
		MembershipAuthorityGeneration:     1,
		WorkspaceOwnerAuthorityGeneration: 3,
	}
	evidence, err := NewAuthorizationEvidence(params)
	if err != nil || !evidence.IsValid() || evidence.WorkspaceOwnerAuthorityGeneration() != 3 {
		t.Fatal("current owner cannot manage Devices without a role", err)
	}
	params.RoleBindingID = id
	if _, err := NewAuthorizationEvidence(params); err == nil {
		t.Fatal("mixed role and owner authority accepted")
	}
	params.RoleBindingID = publicid.ID{}
	params.WorkspaceOwnerAuthorityGeneration = 0
	if _, err := NewAuthorizationEvidence(params); err == nil {
		t.Fatal("absent owner and role authority accepted")
	}
}
