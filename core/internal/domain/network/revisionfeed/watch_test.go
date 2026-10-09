package revisionfeed

import (
	"errors"
	"runtime"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/network"
)

const (
	testNetworkA = "01890f00-0000-7000-8000-000000000201"
	testNetworkB = "01890f00-0000-7000-8000-000000000202"
)

func TestFeedFansOutByNetworkAndCoalescesBackpressure(t *testing.T) {
	t.Parallel()

	subscription := newFakeSubscription()
	feed := mustFeed(t, 3, subscription)
	networkA := parseNetworkID(t, testNetworkA)
	networkB := parseNetworkID(t, testNetworkB)
	updatesA1, releaseA1 := mustWatch(t, feed, networkA)
	updatesA2, releaseA2 := mustWatch(t, feed, networkA)
	updatesB, releaseB := mustWatch(t, feed, networkB)
	defer releaseA1()
	defer releaseA2()
	defer releaseB()

	if _, _, err := feed.WatchNetwork(networkA); !errors.Is(err, ErrFeedUnavailable) {
		t.Fatalf("WatchNetwork(over capacity) error = %v, want ErrFeedUnavailable", err)
	}
	publishRevision(t, subscription, testNetworkA, 1)
	assertRevision(t, updatesA1, testNetworkA, 1)
	assertRevision(t, updatesA2, testNetworkA, 1)
	assertNoRevision(t, updatesB)

	publishRevision(t, subscription, testNetworkA, 2)
	publishRevision(t, subscription, testNetworkA, 3)
	publishRevision(t, subscription, testNetworkB, 4)
	assertRevision(t, updatesB, testNetworkB, 4)
	assertRevision(t, updatesA1, testNetworkA, 3)
	assertRevision(t, updatesA2, testNetworkA, 3)

	snapshot := feed.telemetry.Snapshot()
	if !snapshot.Connected || snapshot.ActiveWatchers != 3 || snapshot.WakeupsTotal != 4 ||
		snapshot.DeliveredTotal != 5 || snapshot.CoalescedTotal != 2 {
		t.Fatalf("fan-out telemetry = %+v", snapshot)
	}

	releaseA1()
	releaseA1()
	if _, open := <-updatesA1; open {
		t.Fatal("released watcher remained open")
	}
	if active := feed.telemetry.Snapshot().ActiveWatchers; active != 2 {
		t.Fatalf("active watchers = %d, want 2", active)
	}
}

func TestFeedKeepsHighestPendingRevision(t *testing.T) {
	t.Parallel()

	subscription := newFakeSubscription()
	feed := mustFeed(t, 1, subscription)
	updates, release := mustWatch(t, feed, parseNetworkID(t, testNetworkA))
	defer release()

	publishRevision(t, subscription, testNetworkA, 5)
	publishRevision(t, subscription, testNetworkA, 4)
	assertWakeupCount(t, feed, 2)
	assertRevision(t, updates, testNetworkA, 5)
	assertNoRevision(t, updates)

	snapshot := feed.telemetry.Snapshot()
	if snapshot.WakeupsTotal != 2 || snapshot.DeliveredTotal != 1 ||
		snapshot.CoalescedTotal != 1 {
		t.Fatalf("latest-wins telemetry = %+v", snapshot)
	}
}

func assertWakeupCount(t *testing.T, feed *Feed, want uint64) {
	t.Helper()
	for feed.telemetry.Snapshot().WakeupsTotal < want {
		select {
		case <-t.Context().Done():
			t.Fatalf("wait for %d wakeups: %v", want, t.Context().Err())
		default:
			runtime.Gosched()
		}
	}
}

func TestFeedRejectsInvalidOrInactiveWatches(t *testing.T) {
	t.Parallel()

	feed := mustUnstartedFeed(t, 1, newFakeSubscription())
	validID := parseNetworkID(t, testNetworkA)
	if _, _, err := feed.WatchNetwork(validID); !errors.Is(err, ErrFeedUnavailable) {
		t.Fatalf("WatchNetwork(before start) error = %v, want ErrFeedUnavailable", err)
	}
	if _, _, err := feed.WatchNetwork(network.ID{}); !errors.Is(err, ErrInvalidFeed) {
		t.Fatalf("WatchNetwork(invalid ID) error = %v, want ErrInvalidFeed", err)
	}
	if _, _, err := (*Feed)(nil).WatchNetwork(validID); !errors.Is(err, ErrInvalidFeed) {
		t.Fatalf("nil WatchNetwork() error = %v, want ErrInvalidFeed", err)
	}
}

func mustWatch(
	t *testing.T,
	feed *Feed,
	networkID network.ID,
) (<-chan network.RevisionAdvanced, func()) {
	t.Helper()
	updates, release, err := feed.WatchNetwork(networkID)
	if err != nil {
		t.Fatalf("WatchNetwork() error = %v", err)
	}
	return updates, release
}

func publishRevision(t *testing.T, subscription *fakeSubscription, networkPublicID string, number int64) {
	t.Helper()
	revision, err := network.NewRevisionAdvanced(networkPublicID, number)
	if err != nil {
		t.Fatalf("network.NewRevisionAdvanced() error = %v", err)
	}
	select {
	case subscription.messages <- revision:
	case <-t.Context().Done():
		t.Fatalf("publish revision: %v", t.Context().Err())
	}
}

func assertRevision(
	t *testing.T,
	updates <-chan network.RevisionAdvanced,
	networkPublicID string,
	number int64,
) {
	t.Helper()
	select {
	case revision, open := <-updates:
		if !open || revision.NetworkPublicID() != networkPublicID || revision.Number() != number {
			t.Fatalf("revision = (%+v, %t), want (%s, %d)", revision, open, networkPublicID, number)
		}
	case <-t.Context().Done():
		t.Fatalf("wait for revision: %v", t.Context().Err())
	}
}

func assertNoRevision(t *testing.T, updates <-chan network.RevisionAdvanced) {
	t.Helper()
	select {
	case revision := <-updates:
		t.Fatalf("unexpected revision: %+v", revision)
	default:
	}
}

func parseNetworkID(t *testing.T, value string) network.ID {
	t.Helper()
	id, err := network.ParseID(value)
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	return id
}
