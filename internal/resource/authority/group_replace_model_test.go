package authority

import (
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
)

func TestGroupReplaceImpactReportsExactPinnedMembershipDiff(t *testing.T) {
	t.Parallel()
	preview := groupReplacePreviewFixture(t)
	impact := groupReplaceImpactFixture(t, preview)

	if !impact.IsValid() || impact.CurrentRevision().DefinitionVersion() != 1 ||
		impact.ProposedRevision().DefinitionVersion() != 2 || len(impact.AddedMembers()) != 1 ||
		len(impact.RemovedMembers()) != 1 || len(impact.RetainedMembers()) != 1 ||
		!impact.Hash().IsValid() {
		t.Fatalf("impact = %+v", impact)
	}
}

func TestGroupReplaceRequestHashBindsMembershipAndImpact(t *testing.T) {
	t.Parallel()
	preview := groupReplacePreviewFixture(t)
	impact := groupReplaceImpactFixture(t, preview)
	command := groupReplaceCommandFixture(t, preview, impact.Hash())
	otherHash, err := NewGroupReplaceImpactHash([32]byte{31: 9})
	if err != nil {
		t.Fatal(err)
	}
	other := groupReplaceCommandFixture(t, preview, otherHash)
	commandHash, err := command.RequestHash()
	if err != nil {
		t.Fatal(err)
	}
	otherRequestHash, err := other.RequestHash()
	if err != nil {
		t.Fatal(err)
	}
	if commandHash == otherRequestHash {
		t.Fatal("Resource Group replacement request hash did not bind impact")
	}
}

func TestGroupReplaceImpactRejectsUnchangedDefinition(t *testing.T) {
	t.Parallel()
	preview := groupReplacePreviewFixture(t)
	impact := groupReplaceImpactFixture(t, preview)
	current := impact.CurrentRevision()
	unchanged, err := resource.NewGroupRevision(resource.GroupRevisionParams{
		Scope: current.Scope(), DisplayName: current.DisplayName(),
		OwnerPrincipalID:     current.OwnerPrincipalID(),
		CustodianPrincipalID: current.CustodianPrincipalID(),
		DefinitionVersion:    2, Members: current.Members(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewGroupReplaceImpact(GroupReplaceImpactParams{
		GroupID: preview.GroupID(), ExpectedVersion: preview.ExpectedVersion(),
		CurrentRevision: current, ProposedRevision: unchanged,
	})
	if !errors.Is(err, ErrInvalidGroupReplaceImpact) {
		t.Fatalf("NewGroupReplaceImpact() error = %v, want ErrInvalidGroupReplaceImpact", err)
	}
}

func TestGroupReplaceResolutionFailsClosedForApproval(t *testing.T) {
	t.Parallel()
	preview := groupReplacePreviewFixture(t)
	base := groupReplaceImpactFixture(t, preview)
	impact, err := NewGroupReplaceImpact(GroupReplaceImpactParams{
		GroupID: base.GroupID(), ExpectedVersion: base.ExpectedVersion(),
		CurrentRevision: base.CurrentRevision(), ProposedRevision: base.ProposedRevision(),
		ApprovalRequired: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	command := groupReplaceCommandFixture(t, preview, impact.Hash())
	requestHash, err := command.RequestHash()
	if err != nil {
		t.Fatal(err)
	}
	recordID, err := publicid.Parse(authorityPublicID(701))
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewGroupReplaceResolution(
		preview.Scope(), 7, 3, recordID, requestHash, impact,
	)
	if !errors.Is(err, ErrInvalidGroupReplaceResolution) {
		t.Fatalf("NewGroupReplaceResolution() error = %v, want ErrInvalidGroupReplaceResolution", err)
	}
}

func groupReplacePreviewFixture(t *testing.T) GroupReplacePreview {
	t.Helper()
	scope := authorityScopeFixture(t)
	groupID, err := resource.ParseGroupID(authorityPublicID(502))
	if err != nil {
		t.Fatal(err)
	}
	preview, err := NewGroupReplacePreview(
		scope, groupID, 1,
		[]resource.Reference{
			authorityResourceReference(t, scope, 501, 1, 1),
			authorityResourceReference(t, scope, 503, 1, 1),
		},
		authoritySessionFixture(t, authorityPrincipalID(t, 11)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return preview
}

func groupReplaceImpactFixture(
	t *testing.T,
	preview GroupReplacePreview,
) GroupReplaceImpact {
	t.Helper()
	name, err := resource.ParseDisplayName("Production databases")
	if err != nil {
		t.Fatal(err)
	}
	current, err := resource.NewGroupRevision(resource.GroupRevisionParams{
		Scope: preview.Scope(), DisplayName: name,
		OwnerPrincipalID:     preview.AccountSession().PrincipalID(),
		CustodianPrincipalID: preview.AccountSession().PrincipalID(), DefinitionVersion: 1,
		Members: []resource.Reference{
			authorityResourceReference(t, preview.Scope(), 501, 1, 1),
			authorityResourceReference(t, preview.Scope(), 502, 1, 1),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	proposed, err := resource.NewGroupRevision(resource.GroupRevisionParams{
		Scope: preview.Scope(), DisplayName: name,
		OwnerPrincipalID:     preview.AccountSession().PrincipalID(),
		CustodianPrincipalID: preview.AccountSession().PrincipalID(), DefinitionVersion: 2,
		Members: preview.Members(),
	})
	if err != nil {
		t.Fatal(err)
	}
	impact, err := NewGroupReplaceImpact(GroupReplaceImpactParams{
		GroupID: preview.GroupID(), ExpectedVersion: preview.ExpectedVersion(),
		CurrentRevision: current, ProposedRevision: proposed,
	})
	if err != nil {
		t.Fatal(err)
	}
	return impact
}

func groupReplaceCommandFixture(
	t *testing.T,
	preview GroupReplacePreview,
	impactHash GroupReplaceImpactHash,
) GroupReplaceCommand {
	t.Helper()
	reason, err := NewAuditReason("replace immutable production group definition")
	if err != nil {
		t.Fatal(err)
	}
	command, err := NewGroupReplaceCommand(
		preview, impactHash, reason, authorityIdempotencyProofFixture(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func authorityResourceReference(
	t *testing.T,
	scope network.Scope,
	suffix int,
	version, generation int64,
) resource.Reference {
	t.Helper()
	id, err := resource.ParseID(authorityPublicID(suffix))
	if err != nil {
		t.Fatal(err)
	}
	reference, err := resource.NewReference(scope, id, version, generation)
	if err != nil {
		t.Fatal(err)
	}
	return reference
}
