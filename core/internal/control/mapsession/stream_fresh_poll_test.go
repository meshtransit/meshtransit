package mapsession

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// freshRecordingSink records the stream's MapFresh confirmations.
type freshRecordingSink struct {
	recordingStreamSink
	freshMu   sync.Mutex
	confirmed []time.Time
	revisions []int64
}

func (sink *freshRecordingSink) ConfirmFresh(_ context.Context, current Snapshot, asOf time.Time) error {
	sink.freshMu.Lock()
	defer sink.freshMu.Unlock()
	sink.confirmed = append(sink.confirmed, asOf)
	sink.revisions = append(sink.revisions, current.NetworkRevision())
	return nil
}

func (sink *freshRecordingSink) confirmations() ([]time.Time, []int64) {
	sink.freshMu.Lock()
	defer sink.freshMu.Unlock()
	return append([]time.Time(nil), sink.confirmed...), append([]int64(nil), sink.revisions...)
}

func freshPollService(t *testing.T, opener SnapshotOpener) *StreamService {
	t.Helper()
	options := streamOptionsFixture(t)
	options.ReconcileInterval = 5 * time.Minute
	options.FreshPoll = time.Second
	service, err := NewStreamService(opener, &streamPresenceStore{}, newStreamRevisionWatcher(),
		newStreamConnectivityWatcher(), options)
	if err != nil {
		t.Fatalf("NewStreamService() error = %v", err)
	}
	return service
}

// A gateway's stream whose map carries its peers' access confirms it while
// the Network's revision stands, as of a read a RevisionReadAge back, and
// refreshes to a newer revision instead (K1a3 §5.2, §12.4).
func TestStreamServiceConfirmsAGatewayMapWhileItsRevisionStands(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial, advanced, peer := authorityDeltaSnapshotsFixture(t)
		view := gatewayViewFixture(t, peer.NodeID(), "view", time.Time{})
		initial, advanced = initial.WithKubernetes(view), advanced.WithKubernetes(view)
		opener := &revisionReadingSnapshotOpener{refreshingSnapshotOpener: refreshingSnapshotOpener{
			streamSnapshotOpener: streamSnapshotOpener{snapshots: []Snapshot{initial, advanced}},
		}}
		opener.set(initial.NetworkRevision(), false)
		service := freshPollService(t, opener)
		machine, request := authenticatedRequestFixture(t, initial)
		sink := &freshRecordingSink{}
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, sink) }()

		synctest.Wait()
		started := time.Now()
		time.Sleep(2500 * time.Millisecond)
		synctest.Wait()
		confirmed, revisions := sink.confirmations()
		if len(confirmed) != 2 || revisions[0] != initial.NetworkRevision() ||
			!confirmed[0].Equal(started.Add(time.Second-RevisionReadAge)) {
			t.Fatalf("confirmations %v at %v, started %v", revisions, confirmed, started)
		}
		// A newer revision refreshes instead of confirming.
		opener.set(advanced.NetworkRevision(), false)
		time.Sleep(time.Second)
		synctest.Wait()
		if minRevisions, _ := opener.refreshes(); len(minRevisions) != 1 ||
			minRevisions[0] != advanced.NetworkRevision() {
			t.Fatalf("refreshes %v", minRevisions)
		}
		if confirmed, _ := sink.confirmations(); len(confirmed) != 2 {
			t.Fatalf("a stale map was confirmed: %v", confirmed)
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v", err)
		}
	})
}

// A map without its peers' access, a withheld one included, is never
// confirmed and costs no revision read.
func TestStreamServiceConfirmsNoMapWithoutAccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial, _, _ := authorityDeltaSnapshotsFixture(t)
		opener := &revisionReadingSnapshotOpener{refreshingSnapshotOpener: refreshingSnapshotOpener{
			streamSnapshotOpener: streamSnapshotOpener{snapshots: []Snapshot{initial}},
		}}
		opener.set(initial.NetworkRevision(), false)
		service := freshPollService(t, opener)
		machine, request := authenticatedRequestFixture(t, initial)
		sink := &freshRecordingSink{}
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, sink) }()

		synctest.Wait()
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if confirmed, _ := sink.confirmations(); len(confirmed) != 0 || opener.readCount() != 0 {
			t.Fatalf("confirmed %v after %d reads", confirmed, opener.readCount())
		}
		cancel()
		synctest.Wait()
		<-result
	})
}
