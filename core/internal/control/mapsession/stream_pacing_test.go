package mapsession

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/network"
)

func TestRefreshPacerSpacesOnlyExpensiveRefreshes(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, time.October, 13, 6, 0, 0, 0, time.UTC)
	var pacer refreshPacer
	if pacer.hold(start, 7) {
		t.Fatal("a stream never refreshed held a wakeup")
	}
	pacer.refreshed(start, 100*time.Millisecond)
	if pacer.hold(start.Add(time.Millisecond), 7) {
		t.Fatal("a fast stream held a wakeup")
	}
	for took, spacing := range map[time.Duration]time.Duration{
		250 * time.Millisecond: time.Second,           // the minimum
		time.Second:            3 * time.Second,       // three times the refresh
		20 * time.Second:       refreshSpacingMaximum, // the maximum
	} {
		pacer.refreshed(start, took)
		if pacer.spacing != spacing {
			t.Fatalf("a %v refresh spaces %v, want %v", took, pacer.spacing, spacing)
		}
	}
	pacer.refreshed(start, time.Second)
	if !pacer.hold(start.Add(time.Second), 7) || !pacer.hold(start.Add(2*time.Second), 0) ||
		!pacer.hold(start.Add(2*time.Second), 5) {
		t.Fatal("wakeups within the spacing were not held")
	}
	if due, held := pacer.due(); !held || !due.Equal(start.Add(3*time.Second)) || pacer.pendingRevision != 7 {
		t.Fatalf("due() = %v, %t, revision %d; want the end of the spacing and revision 7", due, held, pacer.pendingRevision)
	}
	if pacer.hold(start.Add(3*time.Second), 9) {
		t.Fatal("a wakeup at the end of the spacing was held")
	}
	pacer.refreshed(start.Add(4*time.Second), time.Second)
	if _, held := pacer.due(); held || pacer.pendingRevision != 0 {
		t.Fatal("a refresh did not clear the held wakeup")
	}
}

// slowRefreshingSnapshotOpener takes delay for each Refresh, as a Device
// re-proving thousands of shares does.
type slowRefreshingSnapshotOpener struct {
	refreshingSnapshotOpener
	delay time.Duration
}

func (opener *slowRefreshingSnapshotOpener) Refresh(
	ctx context.Context,
	machine control.AuthenticatedMachine,
	request Request,
	current Snapshot,
	minRevision int64,
) (Snapshot, error) {
	next, err := opener.refreshingSnapshotOpener.Refresh(ctx, machine, request, current, minRevision)
	time.Sleep(opener.delay)
	return next, err
}

func TestStreamServiceMergesTheWakeupsOfAnExpensiveStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial, advanced, _ := authorityDeltaSnapshotsFixture(t)
		opener := &slowRefreshingSnapshotOpener{delay: time.Second, refreshingSnapshotOpener: refreshingSnapshotOpener{
			streamSnapshotOpener: streamSnapshotOpener{snapshots: []Snapshot{initial, advanced}},
		}}
		revisions := newStreamRevisionWatcher()
		service := newStreamServiceWithRevisionsFixture(t, opener, &streamPresenceStore{}, revisions)
		machine, request := authenticatedRequestFixture(t, initial)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, &recordingStreamSink{}) }()
		synctest.Wait()

		announce := func(revision int64) {
			wakeup, err := network.NewRevisionAdvanced(initial.Scope().NetworkID().String(), revision)
			if err != nil {
				t.Fatal(err)
			}
			revisions.send(t, wakeup)
		}
		announce(advanced.NetworkRevision()) // refreshed at once, taking 1s
		synctest.Wait()
		if minRevisions, _ := opener.refreshes(); len(minRevisions) != 1 {
			t.Fatalf("refreshes = %v, want the first wakeup refreshed at once", minRevisions)
		}
		time.Sleep(time.Second) // the first refresh ends
		synctest.Wait()
		for _, revision := range []int64{advanced.NetworkRevision() + 1, advanced.NetworkRevision() + 3,
			advanced.NetworkRevision() + 2} {
			announce(revision)
		}
		synctest.Wait()
		if minRevisions, _ := opener.refreshes(); len(minRevisions) != 1 {
			t.Fatalf("refreshes = %v, want the next wakeups held for the spacing", minRevisions)
		}
		time.Sleep(3 * time.Second) // the spacing: three times the 1s refresh
		synctest.Wait()
		minRevisions, _ := opener.refreshes()
		if len(minRevisions) != 2 || minRevisions[1] != advanced.NetworkRevision()+3 {
			t.Fatalf("refreshes = %v, want one more, to the highest held revision %d",
				minRevisions, advanced.NetworkRevision()+3)
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
	})
}
