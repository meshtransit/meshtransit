package mapsession

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/workspace"
)

type revisionRow struct{ revision int64 }

func (row revisionRow) Scan(destinations ...any) error {
	*destinations[0].(*int64) = row.revision
	return nil
}

// Exit node streams of one Network share a read made within
// revisionShareAge; a later one reads again, and a failure is not kept
// (TD-CORE-90).
func TestNetworkRevisionSharesARecentRead(t *testing.T) {
	t.Parallel()
	transaction := &fakeTransaction{rows: []databaseRow{
		internalScopeRow{workspaceID: 101, networkID: 201}, revisionRow{revision: 41},
		internalScopeRow{workspaceID: 101, networkID: 201}, revisionRow{revision: 42},
	}}
	database := &fakeDatabase{transaction: transaction}
	store, err := newStore(database, Options{
		StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second,
		PeerCandidateLimit: 100, PolicyRuleLimit: 100, RelayDirectory: relayDirectoryFixture(t),
	}, &recordingObserver{})
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, _ := workspace.ParseID(testWorkspaceID)
	networkID, _ := network.ParseID(testNetworkID)
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if revision, err := store.NetworkRevision(t.Context(), scope); err != nil || revision != 41 {
			t.Fatalf("NetworkRevision() = %d, %v", revision, err)
		}
	}
	if database.beginCalls != 1 {
		t.Fatalf("%d reads for three streams within the share age", database.beginCalls)
	}
	store.revisions.mu.Lock()
	store.revisions.entries[scope].at = time.Now().Add(-revisionShareAge)
	store.revisions.mu.Unlock()
	if revision, err := store.NetworkRevision(t.Context(), scope); err != nil || revision != 42 ||
		database.beginCalls != 2 {
		t.Fatalf("after the share age: %d, %v, %d reads", revision, err, database.beginCalls)
	}
	store.revisions.mu.Lock()
	store.revisions.entries[scope].at = time.Now().Add(-revisionShareAge)
	store.revisions.mu.Unlock()
	if _, err := store.NetworkRevision(t.Context(), scope); err == nil {
		t.Fatal("a read with no rows succeeded")
	}
	store.revisions.mu.Lock()
	_, kept := store.revisions.entries[scope]
	store.revisions.mu.Unlock()
	if kept {
		t.Fatal("a failed read is shared")
	}
}

// blockingDatabase holds every Begin until release closes.
type blockingDatabase struct {
	release     chan struct{}
	started     chan struct{}
	transaction *fakeTransaction
	calls       atomic.Int32
}

func (database *blockingDatabase) Begin(ctx context.Context) (databaseTransaction, error) {
	if database.calls.Add(1) == 1 {
		close(database.started)
	}
	<-database.release
	// A read on a cancelled stream's context would fail here.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return database.transaction, nil
}

// Streams that ask while a read runs wait for it, and the first caller
// giving up fails none of them (TD-CORE-90).
func TestNetworkRevisionSharesARunningRead(t *testing.T) {
	t.Parallel()
	database := &blockingDatabase{release: make(chan struct{}), started: make(chan struct{}),
		transaction: &fakeTransaction{rows: []databaseRow{
			internalScopeRow{workspaceID: 101, networkID: 201}, revisionRow{revision: 41},
		}}}
	store, err := newStore(database, Options{
		StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second,
		PeerCandidateLimit: 100, PolicyRuleLimit: 100, RelayDirectory: relayDirectoryFixture(t),
	}, &recordingObserver{})
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, _ := workspace.ParseID(testWorkspaceID)
	networkID, _ := network.ParseID(testNetworkID)
	scope, _ := network.NewScope(workspaceID, networkID)
	first, cancel := context.WithCancel(t.Context())
	firstDone := make(chan error, 1)
	go func() {
		_, err := store.NetworkRevision(first, scope)
		firstDone <- err
	}()
	<-database.started
	waiting := make(chan int64, 1)
	go func() {
		revision, _ := store.NetworkRevision(t.Context(), scope)
		waiting <- revision
	}()
	cancel()
	// The first caller stops waiting at once, while the read still runs.
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("the first caller returned %v", err)
	}
	select {
	case revision := <-waiting:
		t.Fatalf("the waiting stream returned %d before the read ended", revision)
	default:
	}
	close(database.release)
	if revision := <-waiting; revision != 41 {
		t.Fatalf("the waiting stream got %d: the read ran on the first caller's context", revision)
	}
	if calls := database.calls.Load(); calls != 1 {
		t.Fatalf("%d reads for two streams", calls)
	}
}
