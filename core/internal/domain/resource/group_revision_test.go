package resource

import (
	"errors"
	"testing"
)

func TestGroupRevisionCanonicalizesMembershipAndPreservesSemanticHash(t *testing.T) {
	definition := groupDefinitionRevisionFixture(t)
	members := definition.Members()
	revision, err := NewGroupRevision(GroupRevisionParams{
		Scope: definition.Scope(), DisplayName: definition.DisplayName(),
		OwnerPrincipalID:     definition.OwnerPrincipalID(),
		CustodianPrincipalID: definition.CustodianPrincipalID(), DefinitionVersion: 2,
		Members: []Reference{members[1], members[0]},
	})
	if err != nil {
		t.Fatalf("resource.NewGroupRevision() error = %v", err)
	}
	if !revision.IsValid() || revision.DefinitionVersion() != 2 ||
		revision.SemanticHash() != definition.SemanticHash() {
		t.Fatalf("revision = %#v, want canonical valid definition", revision)
	}
	canonical := revision.Members()
	if canonical[0].ResourceID().String() >= canonical[1].ResourceID().String() {
		t.Fatalf("members are not canonical: %#v", canonical)
	}
}

func TestGroupRevisionRejectsDuplicateMembership(t *testing.T) {
	definition := groupDefinitionRevisionFixture(t)
	member := definition.Members()[0]
	_, err := NewGroupRevision(GroupRevisionParams{
		Scope: definition.Scope(), DisplayName: definition.DisplayName(),
		OwnerPrincipalID:     definition.OwnerPrincipalID(),
		CustodianPrincipalID: definition.CustodianPrincipalID(), DefinitionVersion: 2,
		Members: []Reference{member, member},
	})
	if !errors.Is(err, ErrInvalidGroupDefinition) {
		t.Fatalf("error = %v, want ErrInvalidGroupDefinition", err)
	}
}

func groupDefinitionRevisionFixture(t *testing.T) GroupDefinition {
	t.Helper()
	scope := resourceScopeFixture(t, 101, 201)
	owner := principalIDFixture(t, 11)
	definition, err := NewGroupDefinition(GroupDefinitionParams{
		Scope: scope, DisplayName: nameFixture(t, "Production databases"),
		OwnerPrincipalID: owner, CustodianPrincipalID: owner,
		Members: []Reference{referenceFixture(t, scope, 401), referenceFixture(t, scope, 402)},
	})
	if err != nil {
		t.Fatalf("NewGroupDefinition() error = %v", err)
	}
	return definition
}
