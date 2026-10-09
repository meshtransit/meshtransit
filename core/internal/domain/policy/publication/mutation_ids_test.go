package publication_test

import (
	"testing"

	publication "github.com/meshtransit/meshtransit/core/internal/domain/policy/publication"
)

func TestMutationIDsOwnProjectionIdentities(t *testing.T) {
	t.Parallel()

	projectionIDs := []publication.ProjectionID{
		publicationProjectionIDFixture(t, "000000000914"),
		publicationProjectionIDFixture(t, "000000000915"),
	}
	ids, err := publication.NewMutationIDs(publication.MutationIDParams{
		ChangeID:      publicationPublicIDFixture(t, "000000000910"),
		AuditEventID:  publicationPublicIDFixture(t, "000000000911"),
		OutboxEventID: publicationPublicIDFixture(t, "000000000912"),
		ReleaseID:     publicationReleaseIDFixture(t, "000000000913"),
		ProjectionIDs: projectionIDs,
	})
	if err != nil {
		t.Fatalf("publication.NewMutationIDs() error = %v", err)
	}
	projectionIDs[0] = publication.ProjectionID{}
	got := ids.ProjectionIDs()
	got[1] = publication.ProjectionID{}
	if !ids.IsValid() || ids.ProjectionIDs()[0].String() == "" ||
		ids.ProjectionIDs()[1].String() == "" {
		t.Fatal("MutationIDs exposed mutable projection identity storage")
	}
}

func TestMutationIDsRejectAliasesAndUnsafeProjectionCount(t *testing.T) {
	t.Parallel()

	shared := publicationPublicIDFixture(t, "000000000910")
	if _, err := publication.NewMutationIDs(publication.MutationIDParams{
		ChangeID:      shared,
		AuditEventID:  shared,
		OutboxEventID: publicationPublicIDFixture(t, "000000000912"),
		ReleaseID:     publicationReleaseIDFixture(t, "000000000913"),
		ProjectionIDs: []publication.ProjectionID{},
	}); err == nil {
		t.Fatal("NewMutationIDs() accepted aliased evidence IDs")
	}
	if _, err := publication.NewMutationIDs(publication.MutationIDParams{
		ChangeID:      publicationPublicIDFixture(t, "000000000910"),
		AuditEventID:  publicationPublicIDFixture(t, "000000000911"),
		OutboxEventID: publicationPublicIDFixture(t, "000000000912"),
		ReleaseID:     publicationReleaseIDFixture(t, "000000000913"),
		ProjectionIDs: nil,
	}); err == nil {
		t.Fatal("NewMutationIDs() accepted absent projection identity collection")
	}
}
