package accessgraph_test

import (
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph"
)

func TestRevisionVectorNextPolicyAdvancesOnlyPolicyAuthority(t *testing.T) {
	t.Parallel()

	current, err := accessgraph.NewRevisionVector(accessgraph.RevisionVectorParams{
		NetworkRevision: 12, InventoryRevision: 8, GroupRevision: 9, PolicyRevision: 6,
		DNSRevision: 2, RouteRevision: 3, SharingRevision: 4, IsolationGeneration: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	proposed, err := current.NextPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if proposed.NetworkRevision() != 13 || proposed.PolicyRevision() != 7 ||
		proposed.InventoryRevision() != 8 || proposed.GroupRevision() != 9 ||
		proposed.DNSRevision() != 2 || proposed.RouteRevision() != 3 ||
		proposed.SharingRevision() != 4 || proposed.IsolationGeneration() != 5 {
		t.Fatalf("proposed vector = %+v", proposed)
	}
}

func TestRevisionVectorRejectsSubsystemAheadOfNetwork(t *testing.T) {
	t.Parallel()

	_, err := accessgraph.NewRevisionVector(accessgraph.RevisionVectorParams{
		NetworkRevision: 8, InventoryRevision: 9, GroupRevision: 2, PolicyRevision: 2,
		DNSRevision: 2, RouteRevision: 2, SharingRevision: 2, IsolationGeneration: 1,
	})
	if !errors.Is(err, accessgraph.ErrInvalidRevisionVector) {
		t.Fatalf("NewRevisionVector() error = %v, want ErrInvalidRevisionVector", err)
	}
}
