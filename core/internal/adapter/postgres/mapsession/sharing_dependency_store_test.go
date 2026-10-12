package mapsession

import (
	"errors"
	"slices"
	"testing"
	"time"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
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
		{"legacy overflow", slices.Repeat([]string{dependencyFixture}, legacyEdgeLimit+1)},
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

func TestStoreUsesBoundDependencyReaderOnceGranted(t *testing.T) {
	for _, granted := range []bool{false, true} {
		store, _, tx, _, identity := validStoreFixture(t)
		store.options.EnableDeviceAliases = true
		tx.boundDependencies = granted
		tx.dependencyRows = &directEdgeRows{values: []string{dependencyFixture}}
		snapshot, err := store.Load(t.Context(), identity)
		if err != nil {
			t.Fatal(err)
		}
		want, other := loadSharingDependenciesSQL, loadBoundSharingDependenciesSQL
		if granted {
			want, other = other, want
		}
		if !slices.Contains(tx.queries, boundSharingDependenciesGrantedSQL) || !slices.Contains(tx.queries, want) ||
			slices.Contains(tx.queries, other) || len(snapshot.SharingScopes()) != 1 {
			t.Fatalf("granted=%v used queries %v", granted, tx.queries)
		}
	}
}

// TestStoreScaledReadersReportLimitInsteadOfFailing: once granted, the
// schema 147 readers are asked for the map peer limit and their limitedEdge
// row reports the map limited instead of failing it; a row after it is not
// a reader's output and fails closed.
func TestStoreScaledReadersReportLimitInsteadOfFailing(t *testing.T) {
	store, _, tx, _, identity := validStoreFixture(t)
	store.options.EnableDeviceAliases = true
	tx.scaledReaders = true
	tx.dependencyRows = &directEdgeRows{values: []string{dependencyFixture, limitedEdge}}
	snapshot, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.SharingScopes()) != 1 || !snapshot.IsPeerLimited() {
		t.Fatalf("scaled reader limit: %d scopes, limited %v", len(snapshot.SharingScopes()), snapshot.IsPeerLimited())
	}
	for index, query := range tx.queries {
		switch query {
		case loadScaledSharingDependenciesSQL, loadScaledAliasEdgesSQL:
			if got := tx.arguments[index][2]; got != appmapsession.MaximumDirectDeviceProjections {
				t.Fatalf("%s asked for %v rows", query, got)
			}
		case loadSharingDependenciesSQL, loadBoundSharingDependenciesSQL, loadAliasEdgesSQL, loadReachableAliasEdgesSQL:
			t.Fatalf("a legacy reader ran once the scaled ones were granted: %s", query)
		}
	}
	if !slices.Contains(tx.queries, loadScaledAliasEdgesSQL) || !slices.Contains(tx.queries, loadScaledSharingDependenciesSQL) {
		t.Fatalf("scaled readers not used: %v", tx.queries)
	}

	for _, values := range [][]string{{limitedEdge, dependencyFixture}} {
		store, _, tx, _, identity := validStoreFixture(t)
		store.options.EnableDeviceAliases = true
		tx.scaledReaders = true
		tx.dependencyRows = &directEdgeRows{values: values}
		if _, err := store.Load(t.Context(), identity); !errors.Is(err, ErrSnapshotEvidence) {
			t.Fatalf("a row after the limit was accepted: %v", err)
		}
	}
}

func TestStoreLegacyReadersKeepTheirBound(t *testing.T) {
	store, _, tx, _, identity := validStoreFixture(t)
	store.options.EnableDeviceAliases = true
	if _, err := store.Load(t.Context(), identity); err != nil {
		t.Fatal(err)
	}
	for index, query := range tx.queries {
		switch query {
		case loadSharingDependenciesSQL, loadAliasEdgesSQL, loadDirectEdgesSQL:
			if got := tx.arguments[index][2]; got != legacyEdgeLimit+1 {
				t.Fatalf("legacy reader %s asked for %v rows, want %d", query, got, legacyEdgeLimit+1)
			}
		}
	}
}

// TestStoreSelectiveReadersPreferredOnceGranted: the schema 149 readers
// replace the schema 147 ones once granted, with the same limit and limited
// row, and no earlier reader runs.
func TestStoreSelectiveReadersPreferredOnceGranted(t *testing.T) {
	store, _, tx, _, identity := validStoreFixture(t)
	store.options.EnableDeviceAliases = true
	tx.scaledReaders = true
	tx.selectiveReaders = true
	tx.dependencyRows = &directEdgeRows{values: []string{dependencyFixture, limitedEdge}}
	snapshot, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.SharingScopes()) != 1 || !snapshot.IsPeerLimited() {
		t.Fatalf("selective reader limit: %d scopes, limited %v", len(snapshot.SharingScopes()), snapshot.IsPeerLimited())
	}
	for index, query := range tx.queries {
		switch query {
		case loadSelectiveSharingDependenciesSQL, loadSelectiveAliasEdgesSQL:
			if got := tx.arguments[index][2]; got != appmapsession.MaximumDirectDeviceProjections {
				t.Fatalf("%s asked for %v rows", query, got)
			}
		case loadSharingDependenciesSQL, loadBoundSharingDependenciesSQL, loadScaledSharingDependenciesSQL,
			loadAliasEdgesSQL, loadReachableAliasEdgesSQL, loadScaledAliasEdgesSQL:
			t.Fatalf("an earlier reader ran once the selective ones were granted: %s", query)
		}
	}
	if !slices.Contains(tx.queries, loadSelectiveAliasEdgesSQL) ||
		!slices.Contains(tx.queries, loadSelectiveSharingDependenciesSQL) {
		t.Fatalf("selective readers not used: %v", tx.queries)
	}
}

// TestStoreShareReadersRunUnderTheShareTimeout: with a share statement bound
// above the map's, the share readers run under it and the map's bound is
// restored before the next read; without one, or with one not above the
// map's (3s in the fixture), nothing changes.
func TestStoreShareReadersRunUnderTheShareTimeout(t *testing.T) {
	for _, share := range []time.Duration{0, 2 * time.Second, 3 * time.Second, 10 * time.Second} {
		store, _, tx, _, identity := validStoreFixture(t)
		store.options.EnableDeviceAliases = true
		store.options.ShareStatementTimeout = share
		tx.selectiveReaders = true
		if _, err := store.Load(t.Context(), identity); err != nil {
			t.Fatal(err)
		}
		var timeouts []any
		widenedAt, restoredAt, dependenciesAt, aliasesAt := -1, -1, -1, -1
		for index, query := range tx.queries {
			switch query {
			case setStatementTimeoutSQL:
				timeouts = append(timeouts, tx.arguments[index][0])
				if widenedAt < 0 {
					widenedAt = index
				} else {
					restoredAt = index
				}
			case loadSelectiveSharingDependenciesSQL:
				dependenciesAt = index
			case loadSelectiveAliasEdgesSQL:
				aliasesAt = index
			}
		}
		if share <= store.options.StatementTimeout {
			if len(timeouts) != 0 {
				t.Fatalf("statement bound changed without a share bound: %v", timeouts)
			}
			continue
		}
		want := []any{postgresTimeout(share), postgresTimeout(store.options.StatementTimeout)}
		if !slices.Equal(timeouts, want) || widenedAt > dependenciesAt || restoredAt < aliasesAt {
			t.Fatalf("share bound %v set at %d, restored at %d (readers at %d, %d)", timeouts, widenedAt, restoredAt,
				dependenciesAt, aliasesAt)
		}
	}
}
