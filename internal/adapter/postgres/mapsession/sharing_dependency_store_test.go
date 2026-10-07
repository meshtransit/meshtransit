package mapsession

import (
	"errors"
	"slices"
	"testing"

	appmapsession "github.com/meshtransit/meshtransit/internal/control/mapsession"
)

const dependencyFixture = `{"workspace_id":"01890f00-0000-7000-8000-000000000102","network_id":"01890f00-0000-7000-8000-000000000202"}`

func TestStoreWatchesAcceptedSharingBeforeFirstRule(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		store, _, tx, _, identity := validStoreFixture(t)
		store.options.EnableDeviceAliases = enabled
		tx.dependencyRows = &directEdgeRows{values: []string{dependencyFixture}}
		snapshot, err := store.Load(t.Context(), identity)
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if enabled {
			want = 1
		}
		if !tx.committed || tx.dependencyRows.closed != enabled || len(snapshot.SharingScopes()) != want {
			t.Fatal("accepted dependency did not stay in the owned immutable snapshot")
		}
		if len(snapshot.PeerCandidates()) != 1 {
			t.Fatal("dependency granted foreign peer authority")
		}
		if enabled && !slices.Contains(tx.queries, loadSharingDependenciesSQL) {
			t.Fatal("dependency read escaped map transaction")
		}
	}
}

func TestDependencyReaderRejectsUnsafeOrOverflow(t *testing.T) {
	for _, test := range []struct {
		name   string
		values []string
	}{
		{"malformed", []string{"{"}},
		{"missing Workspace", []string{`{"network_id":"01890f00-0000-7000-8000-000000000202"}`}},
		{"same Network", []string{`{"workspace_id":"01890f00-0000-7000-8000-000000000101","network_id":"01890f00-0000-7000-8000-000000000201"}`}},
		{"duplicate Network", []string{dependencyFixture, dependencyFixture}},
		{"overflow", slices.Repeat([]string{dependencyFixture}, appmapsession.MaximumDirectDeviceProjections+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, _, tx, _, identity := validStoreFixture(t)
			store.options.EnableDeviceAliases = true
			tx.dependencyRows = &directEdgeRows{values: test.values}
			if _, err := store.Load(t.Context(), identity); !errors.Is(err, ErrSnapshotEvidence) {
				t.Fatalf("unsafe dependency accepted: %v", err)
			}
			if tx.committed || !tx.dependencyRows.closed || tx.rollbackCalls != 1 {
				t.Fatal("unsafe dependency escaped rollback")
			}
		})
	}
}

func TestStoreUsesReachableAliasReaderOnceGranted(t *testing.T) {
	for _, granted := range []bool{false, true} {
		store, _, tx, _, identity := validStoreFixture(t)
		store.options.EnableDeviceAliases = true
		tx.reachableAliases = granted
		if _, err := store.Load(t.Context(), identity); err != nil {
			t.Fatal(err)
		}
		want, other := loadAliasEdgesSQL, loadReachableAliasEdgesSQL
		if granted {
			want, other = other, want
		}
		if !slices.Contains(tx.queries, reachableAliasEdgesGrantedSQL) || !slices.Contains(tx.queries, want) ||
			slices.Contains(tx.queries, other) {
			t.Fatalf("granted=%v used queries %v", granted, tx.queries)
		}
	}
}
