package mapsession

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"

	"meshtransit.net/core/internal/control"
)

// refreshingSnapshotOpener records each Refresh and answers it as Open does.
type refreshingSnapshotOpener struct {
	streamSnapshotOpener
	refreshMu    sync.Mutex
	minRevisions []int64
	currents     []int64 // revision of the snapshot each Refresh started from
}

func (opener *refreshingSnapshotOpener) Refresh(
	ctx context.Context,
	machine control.AuthenticatedMachine,
	request Request,
	current Snapshot,
	minRevision int64,
) (Snapshot, error) {
	opener.refreshMu.Lock()
	opener.minRevisions = append(opener.minRevisions, minRevision)
	opener.currents = append(opener.currents, current.NetworkRevision())
	opener.refreshMu.Unlock()
	return opener.Open(ctx, machine, request)
}

func (opener *refreshingSnapshotOpener) refreshes() ([]int64, []int64) {
	opener.refreshMu.Lock()
	defer opener.refreshMu.Unlock()
	return append([]int64(nil), opener.minRevisions...), append([]int64(nil), opener.currents...)
}

func TestStreamServiceRefreshesARevisionWakeToTheAnnouncedRevision(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial, advanced, _ := authorityDeltaSnapshotsFixture(t)
		opener := &refreshingSnapshotOpener{
			streamSnapshotOpener: streamSnapshotOpener{snapshots: []Snapshot{initial, advanced}},
		}
		revisions := newStreamRevisionWatcher()
		service := newStreamServiceWithRevisionsFixture(t, opener, &streamPresenceStore{}, revisions)
		machine, request := authenticatedRequestFixture(t, initial)
		sink := &recordingStreamSink{}
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, sink) }()

		synctest.Wait()
		if minRevisions, _ := opener.refreshes(); len(minRevisions) != 0 {
			t.Fatalf("stream open refreshed %v, want a full Open", minRevisions)
		}

		advanceRevision(t, revisions, initial, advanced)
		synctest.Wait()
		minRevisions, currents := opener.refreshes()
		if len(minRevisions) != 1 || minRevisions[0] != advanced.NetworkRevision() ||
			currents[0] != initial.NetworkRevision() {
			t.Fatalf("Refresh(min=%v from=%v), want min=%d from=%d",
				minRevisions, currents, advanced.NetworkRevision(), initial.NetworkRevision())
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
	})
}
