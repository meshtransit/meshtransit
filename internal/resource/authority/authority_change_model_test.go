package authority

import (
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/internal/resource"
)

func TestAuthorityChangeImpactBindsSubjectActionTargetAndVersion(t *testing.T) {
	t.Parallel()
	ownerID := authorityPrincipalID(t, 11)
	targetID := authorityPrincipalID(t, 12)
	otherTargetID := authorityPrincipalID(t, 13)
	session := authoritySessionFixture(t, ownerID)
	scope := authorityScopeFixture(t)
	resourceID, err := resource.ParseID(authorityPublicID(501))
	if err != nil {
		t.Fatal(err)
	}
	groupID, err := resource.ParseGroupID(authorityPublicID(501))
	if err != nil {
		t.Fatal(err)
	}
	ownerPreview, err := NewResourceAuthorityChangePreview(
		scope, resourceID, 1, AuthorityChangeTransferOwner, targetID, session,
	)
	if err != nil {
		t.Fatal(err)
	}
	versionPreview, err := NewResourceAuthorityChangePreview(
		scope, resourceID, 2, AuthorityChangeTransferOwner, targetID, session,
	)
	if err != nil {
		t.Fatal(err)
	}
	targetPreview, err := NewResourceAuthorityChangePreview(
		scope, resourceID, 1, AuthorityChangeTransferOwner, otherTargetID, session,
	)
	if err != nil {
		t.Fatal(err)
	}
	custodianPreview, err := NewResourceAuthorityChangePreview(
		scope, resourceID, 1, AuthorityChangeDelegateCustodian, targetID, session,
	)
	if err != nil {
		t.Fatal(err)
	}
	groupPreview, err := NewGroupAuthorityChangePreview(
		scope, groupID, 1, AuthorityChangeTransferOwner, targetID, session,
	)
	if err != nil {
		t.Fatal(err)
	}

	ownerImpact := authorityChangeImpactFixture(t, ownerPreview)
	versionImpact := authorityChangeImpactFixture(t, versionPreview)
	targetImpact := authorityChangeImpactFixture(t, targetPreview)
	custodianImpact := authorityChangeImpactFixture(t, custodianPreview)
	groupImpact := authorityChangeImpactFixture(t, groupPreview)
	for name, impact := range map[string]ChangeImpact{
		"version": versionImpact, "target": targetImpact,
		"action": custodianImpact, "subject kind": groupImpact,
	} {
		if ownerImpact.Hash() == impact.Hash() {
			t.Fatalf("impact hash did not bind %s", name)
		}
	}
}

func TestAuthorityChangePreviewRejectsSelfTransfer(t *testing.T) {
	t.Parallel()
	ownerID := authorityPrincipalID(t, 11)
	resourceID, err := resource.ParseID(authorityPublicID(501))
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewResourceAuthorityChangePreview(
		authorityScopeFixture(t), resourceID, 1, AuthorityChangeTransferOwner,
		ownerID, authoritySessionFixture(t, ownerID),
	)
	if !errors.Is(err, ErrInvalidAuthorityChangePreview) {
		t.Fatalf("NewResourceAuthorityChangePreview() error = %v, want ErrInvalidAuthorityChangePreview", err)
	}
}

func TestAuthorityChangeImpactChangesExactlyOneAuthorityField(t *testing.T) {
	t.Parallel()
	ownerID := authorityPrincipalID(t, 11)
	targetID := authorityPrincipalID(t, 12)
	resourceID, err := resource.ParseID(authorityPublicID(501))
	if err != nil {
		t.Fatal(err)
	}
	preview, err := NewResourceAuthorityChangePreview(
		authorityScopeFixture(t), resourceID, 1, AuthorityChangeTransferOwner,
		targetID, authoritySessionFixture(t, ownerID),
	)
	if err != nil {
		t.Fatal(err)
	}
	currentHash, proposedHash := authorityChangeSemanticHashes(t)
	_, err = NewAuthorityChangeImpact(ChangeImpactParams{
		Preview: preview, CurrentOwnerPrincipalID: ownerID,
		CurrentCustodianPrincipalID: ownerID, ProposedOwnerPrincipalID: targetID,
		ProposedCustodianPrincipalID: targetID, CurrentSemanticHash: currentHash,
		ProposedSemanticHash: proposedHash,
	})
	if !errors.Is(err, ErrInvalidAuthorityChangeImpact) {
		t.Fatalf("NewAuthorityChangeImpact() error = %v, want ErrInvalidAuthorityChangeImpact", err)
	}
}

func authorityChangeImpactFixture(
	t *testing.T,
	preview ChangePreview,
) ChangeImpact {
	t.Helper()
	ownerID := preview.AccountSession().PrincipalID()
	targetID := preview.TargetPrincipalID()
	currentHash, proposedHash := authorityChangeSemanticHashes(t)
	params := ChangeImpactParams{
		Preview: preview, CurrentOwnerPrincipalID: ownerID,
		CurrentCustodianPrincipalID: ownerID, ProposedOwnerPrincipalID: targetID,
		ProposedCustodianPrincipalID: ownerID, CurrentSemanticHash: currentHash,
		ProposedSemanticHash: proposedHash,
	}
	if preview.Action() == AuthorityChangeDelegateCustodian {
		params.ProposedOwnerPrincipalID = ownerID
		params.ProposedCustodianPrincipalID = targetID
	}
	impact, err := NewAuthorityChangeImpact(params)
	if err != nil {
		t.Fatal(err)
	}
	return impact
}

func authorityChangeSemanticHashes(
	t *testing.T,
) (resource.SemanticHash, resource.SemanticHash) {
	t.Helper()
	current, err := resource.NewSemanticHash([32]byte{31: 1})
	if err != nil {
		t.Fatal(err)
	}
	proposed, err := resource.NewSemanticHash([32]byte{31: 2})
	if err != nil {
		t.Fatal(err)
	}
	return current, proposed
}
