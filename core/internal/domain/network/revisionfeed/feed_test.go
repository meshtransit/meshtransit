package revisionfeed

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/network"
)

func TestNewRejectsInvalidComposition(t *testing.T) {
	t.Parallel()

	validSubscribe := func(context.Context) (Subscription, error) {
		return &fakeSubscription{}, nil
	}
	validOptions := testFeedOptions(1)
	telemetry := NewTelemetry()
	tests := []struct {
		name      string
		options   Options
		subscribe SubscribeFunc
		telemetry *Telemetry
	}{
		{name: "zero watcher bound", options: withMaxWatchers(validOptions, 0), subscribe: validSubscribe, telemetry: telemetry},
		{name: "excessive watcher bound", options: withMaxWatchers(validOptions, maximumWatchers+1), subscribe: validSubscribe, telemetry: telemetry},
		{name: "missing subscribe timeout", options: withSubscribeTimeout(validOptions, 0), subscribe: validSubscribe, telemetry: telemetry},
		{name: "excessive subscribe timeout", options: withSubscribeTimeout(validOptions, maximumSubscribeTimeout+time.Millisecond), subscribe: validSubscribe, telemetry: telemetry},
		{name: "missing reconnect initial", options: withReconnectInitial(validOptions, 0), subscribe: validSubscribe, telemetry: telemetry},
		{name: "reconnect maximum below initial", options: withReconnectMaximum(validOptions, time.Millisecond-time.Nanosecond), subscribe: validSubscribe, telemetry: telemetry},
		{name: "missing subscriber", options: validOptions, telemetry: telemetry},
		{name: "missing telemetry", options: validOptions, subscribe: validSubscribe},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			feed, err := New(test.options, test.subscribe, test.telemetry)
			if !errors.Is(err, ErrInvalidFeed) || feed != nil {
				t.Fatalf("New() = (%v, %v), want (nil, ErrInvalidFeed)", feed, err)
			}
		})
	}
}

func TestFeedBoundsSubscriptionSetup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const timeout = 2 * time.Second
		feed, err := New(
			withSubscribeTimeout(testFeedOptions(1), timeout),
			func(ctx context.Context) (Subscription, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
			NewTelemetry(),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		startedAt := time.Now()
		err = feed.Start(t.Context())
		if !errors.Is(err, ErrSubscribe) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Start() error = %v, want bounded subscribe deadline", err)
		}
		if elapsed := time.Since(startedAt); elapsed != timeout {
			t.Fatalf("subscription setup elapsed = %s, want %s", elapsed, timeout)
		}
	})
}

func TestFeedOwnsOneSubscriptionLifecycle(t *testing.T) {
	t.Parallel()

	subscription := newFakeSubscription()
	var subscribeCalls atomic.Int32
	var sawSubscribeDeadline bool
	feed, err := New(
		testFeedOptions(2),
		func(ctx context.Context) (Subscription, error) {
			subscribeCalls.Add(1)
			_, sawSubscribeDeadline = ctx.Deadline()
			return subscription, nil
		},
		NewTelemetry(),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := feed.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if subscribeCalls.Load() != 1 || !sawSubscribeDeadline ||
		!feed.telemetry.Snapshot().Connected {
		t.Fatalf("started feed = calls %d telemetry %+v", subscribeCalls.Load(), feed.telemetry.Snapshot())
	}
	if err := feed.Start(t.Context()); !errors.Is(err, ErrFeedStarted) {
		t.Fatalf("second Start() error = %v, want ErrFeedStarted", err)
	}

	if err := feed.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if result := receiveFeedResult(t, feed.Done()); result != nil {
		t.Fatalf("Done() result = %v, want nil", result)
	}
	if subscription.closeCalls.Load() != 1 || feed.telemetry.Snapshot().Connected {
		t.Fatalf("stopped feed = close calls %d telemetry %+v", subscription.closeCalls.Load(), feed.telemetry.Snapshot())
	}
	if err := feed.Shutdown(t.Context()); err != nil {
		t.Fatalf("second Shutdown() error = %v", err)
	}
}

func TestFeedClassifiesSubscriptionFailures(t *testing.T) {
	t.Parallel()

	subscribeErr := errors.New("controlled subscribe failure")
	feed, err := New(
		testFeedOptions(1),
		func(context.Context) (Subscription, error) { return nil, subscribeErr },
		NewTelemetry(),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := feed.Start(t.Context()); !errors.Is(err, ErrSubscribe) || !errors.Is(err, subscribeErr) {
		t.Fatalf("Start() error = %v, want classified subscribe failure", err)
	}
	if feed.Done() != nil {
		t.Fatal("Done() is non-nil after failed start")
	}

	var nilSubscription *fakeSubscription
	feed, err = New(
		testFeedOptions(1),
		func(context.Context) (Subscription, error) { return nilSubscription, nil },
		NewTelemetry(),
	)
	if err != nil {
		t.Fatalf("New(typed nil) error = %v", err)
	}
	if err := feed.Start(t.Context()); !errors.Is(err, ErrSubscribe) {
		t.Fatalf("Start(typed nil) error = %v, want ErrSubscribe", err)
	}
}

func TestFeedReceiveFailureReconnectsWithoutClosingWatchers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := newFakeSubscription()
		second := newFakeSubscription()
		var subscribeCalls atomic.Int32
		telemetry := NewTelemetry()
		feed, err := New(
			testFeedOptions(1),
			func(context.Context) (Subscription, error) {
				if subscribeCalls.Add(1) == 1 {
					return first, nil
				}
				return second, nil
			},
			telemetry,
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if err := feed.Start(t.Context()); err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		stopped := false
		defer func() {
			if stopped {
				return
			}
			_ = feed.Shutdown(t.Context())
			<-feed.Done()
		}()
		networkID := parseNetworkID(t, testNetworkA)
		updates, release, err := feed.WatchNetwork(networkID)
		if err != nil {
			t.Fatalf("WatchNetwork() error = %v", err)
		}
		defer release()

		select {
		case first.failures <- errors.New("controlled receive failure"):
		case <-t.Context().Done():
			t.Fatalf("send receive failure: %v", t.Context().Err())
		}
		time.Sleep(2 * time.Millisecond)
		synctest.Wait()
		snapshot := telemetry.Snapshot()
		if !snapshot.Connected || snapshot.ActiveWatchers != 1 ||
			snapshot.ReconnectTotal != 1 || snapshot.RecoveredTotal != 1 {
			t.Fatalf("telemetry after recovery = %+v", snapshot)
		}
		publishRevision(t, second, testNetworkA, 9)
		synctest.Wait()
		assertRevision(t, updates, testNetworkA, 9)
		select {
		case result := <-feed.Done():
			t.Fatalf("feed stopped after recoverable failure: %v", result)
		default:
		}

		if err := feed.Shutdown(t.Context()); err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
		synctest.Wait()
		if result := <-feed.Done(); result != nil {
			t.Fatalf("Done() result = %v, want nil", result)
		}
		stopped = true
	})
}

func TestFeedShutdownCancelsStartup(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	feed, err := New(
		testFeedOptions(1),
		func(ctx context.Context) (Subscription, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		},
		NewTelemetry(),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	startResult := make(chan error, 1)
	go func() { startResult <- feed.Start(t.Context()) }()
	select {
	case <-entered:
	case <-t.Context().Done():
		t.Fatalf("wait for startup: %v", t.Context().Err())
	}
	if err := feed.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if err := <-startResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("Start() error = %v, want context cancellation", err)
	}
	if feed.Done() != nil {
		t.Fatal("Done() is non-nil after canceled startup")
	}
}

func TestFeedRejectsInvalidLifecycleCalls(t *testing.T) {
	t.Parallel()

	feed := mustUnstartedFeed(t, 1, newFakeSubscription())
	if err := feed.Shutdown(t.Context()); !errors.Is(err, ErrFeedNotStarted) {
		t.Fatalf("Shutdown() error = %v, want ErrFeedNotStarted", err)
	}
	if err := (*Feed)(nil).Start(t.Context()); !errors.Is(err, ErrInvalidFeed) {
		t.Fatalf("nil Start() error = %v, want ErrInvalidFeed", err)
	}
	if err := (*Feed)(nil).Shutdown(t.Context()); !errors.Is(err, ErrInvalidFeed) {
		t.Fatalf("nil Shutdown() error = %v, want ErrInvalidFeed", err)
	}
}

func mustFeed(t *testing.T, maxWatchers int, subscription *fakeSubscription) *Feed {
	t.Helper()
	feed := mustUnstartedFeed(t, maxWatchers, subscription)
	if err := feed.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		_ = feed.Shutdown(t.Context())
		if done := feed.Done(); done != nil {
			<-done
		}
	})
	return feed
}

func mustUnstartedFeed(t *testing.T, maxWatchers int, subscription *fakeSubscription) *Feed {
	t.Helper()
	feed, err := New(
		testFeedOptions(maxWatchers),
		func(context.Context) (Subscription, error) { return subscription, nil },
		NewTelemetry(),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return feed
}

func receiveFeedResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-t.Context().Done():
		t.Fatalf("wait for feed result: %v", t.Context().Err())
		return nil
	}
}

func testFeedOptions(maxWatchers int) Options {
	return Options{
		MaxWatchers:      maxWatchers,
		SubscribeTimeout: time.Second,
		ReconnectInitial: time.Millisecond,
		ReconnectMaximum: 4 * time.Millisecond,
	}
}

func withMaxWatchers(options Options, maximum int) Options {
	options.MaxWatchers = maximum
	return options
}

func withSubscribeTimeout(options Options, timeout time.Duration) Options {
	options.SubscribeTimeout = timeout
	return options
}

func withReconnectInitial(options Options, delay time.Duration) Options {
	options.ReconnectInitial = delay
	return options
}

func withReconnectMaximum(options Options, delay time.Duration) Options {
	options.ReconnectMaximum = delay
	return options
}

type fakeSubscription struct {
	messages   chan network.RevisionAdvanced
	failures   chan error
	closeOnce  sync.Once
	closeCalls atomic.Int32
}

func newFakeSubscription() *fakeSubscription {
	return &fakeSubscription{
		messages: make(chan network.RevisionAdvanced),
		failures: make(chan error),
	}
}

func (subscription *fakeSubscription) Receive(
	ctx context.Context,
) (network.RevisionAdvanced, error) {
	select {
	case revision := <-subscription.messages:
		return revision, nil
	case err := <-subscription.failures:
		return network.RevisionAdvanced{}, err
	case <-ctx.Done():
		return network.RevisionAdvanced{}, ctx.Err()
	}
}

func (subscription *fakeSubscription) Close() error {
	subscription.closeOnce.Do(func() { subscription.closeCalls.Add(1) })
	return nil
}
