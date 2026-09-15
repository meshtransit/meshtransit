package connectivityfeed

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
)

func TestFeedFansOutAndCoalescesNetworkConnectivityWakeups(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		subscription := newTestSubscription()
		telemetry := NewTelemetry()
		feed, err := New(
			Options{MaxWatchers: 2, SubscribeTimeout: time.Second},
			func(context.Context) (Subscription, error) { return subscription, nil },
			telemetry,
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if err := feed.Start(t.Context()); err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		first := connectivityChangeFixture(t, "01890f00-0000-7000-8000-000000000701", 1)
		second := connectivityChangeFixture(t, "01890f00-0000-7000-8000-000000000702", 2)
		updates, release, err := feed.WatchNetwork(first.NetworkID())
		if err != nil {
			t.Fatalf("WatchNetwork() error = %v", err)
		}

		subscription.send(first)
		synctest.Wait()
		subscription.send(second)
		synctest.Wait()
		select {
		case got := <-updates:
			if got.Key() != second.Key() {
				t.Fatalf("coalesced wakeup = %+v, want latest %+v", got, second)
			}
		default:
			t.Fatal("watcher received no connectivity wakeup")
		}
		snapshot := telemetry.Snapshot()
		if !snapshot.Connected || snapshot.ActiveWatchers != 1 ||
			snapshot.WakeupsTotal != 2 || snapshot.DeliveredTotal != 1 ||
			snapshot.CoalescedTotal != 1 {
			t.Fatalf("telemetry = %+v, want connected coalesced fanout", snapshot)
		}

		release()
		release()
		if err := feed.Shutdown(t.Context()); err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
		synctest.Wait()
		if err := <-feed.Done(); err != nil {
			t.Fatalf("Done() error = %v", err)
		}
		if subscription.closeCalls() != 1 || telemetry.Snapshot().Connected {
			t.Fatalf("shutdown = closes %d telemetry %+v", subscription.closeCalls(), telemetry.Snapshot())
		}
	})
}

func TestFeedRejectsUnsafeLifecycleAndWatcherInputs(t *testing.T) {
	t.Parallel()

	telemetry := NewTelemetry()
	if _, err := New(Options{}, nil, telemetry); !errors.Is(err, ErrInvalidFeed) {
		t.Fatalf("New(invalid) error = %v, want ErrInvalidFeed", err)
	}
	feed, err := New(
		Options{MaxWatchers: 1, SubscribeTimeout: time.Second},
		func(context.Context) (Subscription, error) { return newTestSubscription(), nil },
		telemetry,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	networkID := connectivityChangeFixture(
		t,
		"01890f00-0000-7000-8000-000000000701",
		1,
	).NetworkID()
	if _, _, err := feed.WatchNetwork(networkID); !errors.Is(err, ErrFeedUnavailable) {
		t.Fatalf("WatchNetwork(before Start) error = %v, want ErrFeedUnavailable", err)
	}
	if err := feed.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	_, release, err := feed.WatchNetwork(networkID)
	if err != nil {
		t.Fatalf("WatchNetwork() error = %v", err)
	}
	if _, _, err := feed.WatchNetwork(networkID); !errors.Is(err, ErrFeedUnavailable) {
		t.Fatalf("WatchNetwork(over capacity) error = %v, want ErrFeedUnavailable", err)
	}
	release()
	if err := feed.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
}

type testSubscription struct {
	updates chan mapsession.ConnectivityChanged
	mu      sync.Mutex
	closed  bool
	closes  int
}

func newTestSubscription() *testSubscription {
	return &testSubscription{updates: make(chan mapsession.ConnectivityChanged)}
}

func (subscription *testSubscription) Receive(
	ctx context.Context,
) (mapsession.ConnectivityChanged, error) {
	select {
	case <-ctx.Done():
		return mapsession.ConnectivityChanged{}, ctx.Err()
	case change := <-subscription.updates:
		return change, nil
	}
}

func (subscription *testSubscription) Close() error {
	subscription.mu.Lock()
	defer subscription.mu.Unlock()
	if !subscription.closed {
		subscription.closed = true
		subscription.closes++
	}
	return nil
}

func (subscription *testSubscription) send(change mapsession.ConnectivityChanged) {
	subscription.updates <- change
}

func (subscription *testSubscription) closeCalls() int {
	subscription.mu.Lock()
	defer subscription.mu.Unlock()
	return subscription.closes
}

func connectivityChangeFixture(
	t testing.TB,
	nodePublicID string,
	generation int64,
) mapsession.ConnectivityChanged {
	t.Helper()
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000201")
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	nodeID, err := node.ParseID(nodePublicID)
	if err != nil {
		t.Fatalf("node.ParseID() error = %v", err)
	}
	change, err := mapsession.NewConnectivityChanged(
		networkID,
		nodeID,
		generation,
		mapsession.ConnectivityChangeEndpoints,
	)
	if err != nil {
		t.Fatalf("mapsession.NewConnectivityChanged() error = %v", err)
	}
	return change
}
