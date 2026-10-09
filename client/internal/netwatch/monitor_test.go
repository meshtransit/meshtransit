package netwatch

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestNewRejectsEmptyExcludedInterface(t *testing.T) {
	t.Parallel()

	_, err := New(Options{ExcludedInterfaces: []string{" "}})
	if err == nil {
		t.Fatal("New() error = nil")
	}
}

func TestNewCreatesMonitorFromHostSnapshot(t *testing.T) {
	monitor, err := New(Options{ExcludedInterfaces: []string{"mesh0", "meshdns0"}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if monitor.Events() == nil {
		t.Fatal("Events() = nil")
	}
}

func TestMonitorReportsOnlyChangedSnapshots(t *testing.T) {
	source := &testSource{signals: make(chan struct{}, 4)}
	state := &testSnapshotState{tokens: []string{"initial"}}
	monitor := testMonitor(state.read, func(time.Duration) (changeSource, error) {
		return source, nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- monitor.Run(ctx) }()

	source.signals <- struct{}{}
	assertNoEvent(t, monitor.Events())
	state.set([]string{"changed"})
	source.signals <- struct{}{}
	assertEvent(t, monitor.Events())

	state.set([]string{"changed-again"})
	source.signals <- struct{}{}
	assertEvent(t, monitor.Events())
	state.set([]string{"changed-once-more"})
	source.signals <- struct{}{}
	time.Sleep(20 * time.Millisecond)
	if eventCount := len(monitor.events); eventCount != 1 {
		t.Fatalf("coalesced event count = %d, want 1", eventCount)
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation", err)
	}
}

func TestMonitorDetectsChangeBetweenConstructionAndRun(t *testing.T) {
	source := &testSource{signals: make(chan struct{})}
	state := &testSnapshotState{tokens: []string{"changed-before-run"}}
	monitor := testMonitor(state.read, func(time.Duration) (changeSource, error) {
		return source, nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- monitor.Run(ctx) }()

	assertEvent(t, monitor.Events())
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation", err)
	}
}

func TestMonitorFallsBackToPolling(t *testing.T) {
	state := &testSnapshotState{tokens: []string{"initial"}}
	monitor := testMonitor(state.read, func(time.Duration) (changeSource, error) {
		return nil, errors.New("test native source failure")
	})
	monitor.pollInterval = time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- monitor.Run(ctx) }()

	state.set([]string{"changed"})
	assertEvent(t, monitor.Events())
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation", err)
	}
}

func TestMonitorMayOnlyRunOnce(t *testing.T) {
	source := &testSource{signals: make(chan struct{})}
	state := &testSnapshotState{tokens: []string{"initial"}}
	monitor := testMonitor(state.read, func(time.Duration) (changeSource, error) {
		return source, nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- monitor.Run(ctx) }()

	deadline := time.Now().Add(time.Second)
	for !monitor.started.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := monitor.Run(t.Context()); err == nil {
		t.Fatal("second Run() error = nil")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("first Run() error = %v, want context cancellation", err)
	}
}

func TestIsUsableAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		address string
		usable  bool
	}{
		{name: "public ipv4", address: "192.0.2.1", usable: true},
		{name: "private ipv4", address: "10.0.0.1", usable: true},
		{name: "ula ipv6", address: "fd00::1", usable: true},
		{name: "loopback", address: "127.0.0.1", usable: false},
		{name: "link local", address: "fe80::1", usable: false},
		{name: "multicast", address: "ff02::1", usable: false},
		{name: "unspecified", address: "0.0.0.0", usable: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			actual := isUsableAddress(netip.MustParseAddr(test.address))
			if actual != test.usable {
				t.Fatalf("isUsableAddress(%q) = %t, want %t", test.address, actual, test.usable)
			}
		})
	}
}

func testMonitor(snapshot snapshotter, factory sourceFactory) *Monitor {
	return &Monitor{
		events:          make(chan struct{}, 1),
		excluded:        map[string]struct{}{},
		last:            networkSnapshot{tokens: []string{"initial"}},
		snapshot:        snapshot,
		newNativeSource: factory,
		debounce:        time.Millisecond,
		pollInterval:    time.Second,
	}
}

func assertEvent(t *testing.T, events <-chan struct{}) {
	t.Helper()

	select {
	case <-events:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for network change event")
	}
}

func assertNoEvent(t *testing.T, events <-chan struct{}) {
	t.Helper()

	select {
	case <-events:
		t.Fatal("received event for unchanged network state")
	case <-time.After(20 * time.Millisecond):
	}
}

type testSnapshotState struct {
	mu     sync.Mutex
	tokens []string
}

func (s *testSnapshotState) read(map[string]struct{}) (networkSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return networkSnapshot{tokens: slices.Clone(s.tokens)}, nil
}

func (s *testSnapshotState) set(tokens []string) {
	s.mu.Lock()
	s.tokens = slices.Clone(tokens)
	s.mu.Unlock()
}

type testSource struct {
	signals chan struct{}
}

func (s *testSource) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.signals:
		return nil
	}
}

func (s *testSource) Close() error {
	return nil
}
