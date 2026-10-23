package mapsession

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"meshtransit.net/core/internal/domain/network"
)

// revisionReadingSnapshotOpener answers NetworkRevision with revision and
// counts the reads.
type revisionReadingSnapshotOpener struct {
	refreshingSnapshotOpener
	revisionMu sync.Mutex
	revision   int64
	failing    bool
	noReader   bool
	reads      int
}

func (opener *revisionReadingSnapshotOpener) NetworkRevision(context.Context, network.Scope) (int64, error) {
	opener.revisionMu.Lock()
	defer opener.revisionMu.Unlock()
	opener.reads++
	if opener.noReader {
		return 0, ErrNoRevisionReader
	}
	if opener.failing {
		return 0, errors.New("revision read failed")
	}
	return opener.revision, nil
}

func (opener *revisionReadingSnapshotOpener) set(revision int64, failing bool) {
	opener.revisionMu.Lock()
	defer opener.revisionMu.Unlock()
	opener.revision, opener.failing = revision, failing
}

func (opener *revisionReadingSnapshotOpener) readCount() int {
	opener.revisionMu.Lock()
	defer opener.revisionMu.Unlock()
	return opener.reads
}

func servingExit(snapshot Snapshot) Snapshot {
	snapshot.routes.servedExits = []ServedExit{{Ref: "world"}}
	return snapshot
}

func exitPollService(t *testing.T, opener SnapshotOpener) *StreamService {
	t.Helper()
	options := streamOptionsFixture(t)
	options.ReconcileInterval = 5 * time.Minute
	options.ExitRevisionPoll = time.Second
	service, err := NewStreamService(opener, &streamPresenceStore{}, newStreamRevisionWatcher(),
		newStreamConnectivityWatcher(), options)
	if err != nil {
		t.Fatalf("NewStreamService() error = %v", err)
	}
	return service
}

// An exit node's stream reads its Network's revision and refreshes to a
// newer one at once, without waiting for a held DNS wakeup (TD-CORE-89).
func TestStreamServiceExitNodeRefreshesToANewerRevision(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial, advanced, _ := authorityDeltaSnapshotsFixture(t)
		initial, advanced = servingExit(initial), servingExit(advanced)
		opener := &revisionReadingSnapshotOpener{refreshingSnapshotOpener: refreshingSnapshotOpener{
			streamSnapshotOpener: streamSnapshotOpener{snapshots: []Snapshot{initial, advanced}},
		}}
		opener.set(initial.NetworkRevision(), false)
		service := exitPollService(t, opener)
		machine, request := authenticatedRequestFixture(t, initial)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, &recordingStreamSink{}) }()

		synctest.Wait()
		time.Sleep(3500 * time.Millisecond)
		synctest.Wait()
		if reads := opener.readCount(); reads != 3 {
			t.Fatalf("revision reads = %d, want 3", reads)
		}
		if minRevisions, _ := opener.refreshes(); len(minRevisions) != 0 {
			t.Fatalf("an unchanged revision refreshed %v", minRevisions)
		}
		// A failed read changes nothing; the next one finds the new revision.
		opener.set(0, true)
		time.Sleep(time.Second)
		synctest.Wait()
		if minRevisions, _ := opener.refreshes(); len(minRevisions) != 0 {
			t.Fatalf("a failed revision read refreshed %v", minRevisions)
		}
		opener.set(advanced.NetworkRevision(), false)
		time.Sleep(time.Second)
		synctest.Wait()
		minRevisions, currents := opener.refreshes()
		if len(minRevisions) != 1 || minRevisions[0] != advanced.NetworkRevision() ||
			currents[0] != initial.NetworkRevision() {
			t.Fatalf("Refresh(min=%v from=%v), want min=%d from=%d", minRevisions, currents,
				advanced.NetworkRevision(), initial.NetworkRevision())
		}
		// At that revision, the next reads refresh nothing.
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if minRevisions, _ := opener.refreshes(); len(minRevisions) != 1 {
			t.Fatalf("refreshes after catching up = %v", minRevisions)
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
	})
}

// A Device that serves no Exit Pool never reads the revision.
func TestStreamServiceOnlyExitNodesReadTheRevision(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial, advanced, _ := authorityDeltaSnapshotsFixture(t)
		opener := &revisionReadingSnapshotOpener{refreshingSnapshotOpener: refreshingSnapshotOpener{
			streamSnapshotOpener: streamSnapshotOpener{snapshots: []Snapshot{initial}},
		}}
		opener.set(advanced.NetworkRevision(), false)
		service := exitPollService(t, opener)
		machine, request := authenticatedRequestFixture(t, initial)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, &recordingStreamSink{}) }()

		synctest.Wait()
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if reads := opener.readCount(); reads != 0 {
			t.Fatalf("a Device serving no Exit Pool read the revision %d times", reads)
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
	})
}

func TestNewStreamServiceBoundsTheExitRevisionPoll(t *testing.T) {
	for poll, valid := range map[time.Duration]bool{
		-time.Second: false, time.Millisecond: false, 0: true, time.Second: true, 5 * time.Minute: true,
		5*time.Minute + time.Second: false,
	} {
		options := streamOptionsFixture(t)
		options.ExitRevisionPoll = poll
		_, err := NewStreamService(&streamSnapshotOpener{}, &streamPresenceStore{}, newStreamRevisionWatcher(),
			newStreamConnectivityWatcher(), options)
		if valid != (err == nil) {
			t.Fatalf("exit revision poll %v: error %v", poll, err)
		}
	}
}

// A stream over a store that reads no revisions asks once and stops.
func TestStreamServiceStopsPollingWithoutARevisionReader(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial, _, _ := authorityDeltaSnapshotsFixture(t)
		initial = servingExit(initial)
		opener := &revisionReadingSnapshotOpener{refreshingSnapshotOpener: refreshingSnapshotOpener{
			streamSnapshotOpener: streamSnapshotOpener{snapshots: []Snapshot{initial}},
		}}
		opener.revisionMu.Lock()
		opener.noReader = true
		opener.revisionMu.Unlock()
		service := exitPollService(t, opener)
		machine, request := authenticatedRequestFixture(t, initial)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, &recordingStreamSink{}) }()

		synctest.Wait()
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if reads := opener.readCount(); reads != 1 {
			t.Fatalf("revision reads without a reader = %d, want 1", reads)
		}
		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
	})
}
