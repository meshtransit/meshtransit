package corelink

import (
	"context"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// holdingCore holds a poll that names the current ETag until the test
// publishes a new state or the poll's wait ends, like Core's state handler.
type holdingCore struct {
	fakeCore
	waits   atomic.Int64 // polls that asked to wait
	publish chan struct{}
}

func (c *holdingCore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	etag := c.etag
	c.mu.Unlock()
	if seconds, err := strconv.Atoi(r.URL.Query().Get("wait")); err == nil && r.Header.Get("If-None-Match") == etag {
		c.waits.Add(1)
		select {
		case <-c.publish:
		case <-time.After(time.Duration(seconds) * time.Second):
		case <-r.Context().Done():
		}
	}
	c.fakeCore.ServeHTTP(w, r)
}

// TestRunLongPollsAndAppliesRevocationsAtOnce: a revocation Core signs while
// the relay holds a poll reaches the relay without waiting for the interval.
func TestRunLongPollsAndAppliesRevocationsAtOnce(t *testing.T) {
	t.Parallel()
	a := signer(t, 1)
	var now atomic.Int64
	now.Store(t0.UnixMilli())
	var drained atomic.Int32
	core := &holdingCore{publish: make(chan struct{})}
	trusted := mtrp.TrustedKey{Key: a.Public(), NotAfter: t0.Add(time.Hour)}
	core.set(t, state(1, trusted), a, `"1"`)
	l := newLink(t, core, &now, a.Public(), key.RelayPublic{1}, &drained)
	l.cfg.Interval = time.Hour // only the long poll can deliver in time
	l.cfg.LongPoll = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for core.waits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if core.waits.Load() == 0 {
		t.Fatal("the relay never held a long poll")
	}
	node := key.NodePublic{0x42}
	next := state(2, trusted)
	next.Nodes = []mtrp.RevocationID{mtrp.RevocationHash(mtrp.RevokeNode, node[:])}
	core.set(t, next, a, `"2"`)
	published := time.Now()
	close(core.publish)
	for !l.Revoked(mtrp.Ticket{Node: node}) && time.Since(published) < 3*time.Second {
		time.Sleep(5 * time.Millisecond)
	}
	if !l.Revoked(mtrp.Ticket{Node: node}) {
		t.Fatal("revocation not applied")
	}
	if elapsed := time.Since(published); elapsed > time.Second {
		t.Fatalf("revocation took %v", elapsed)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestRunFallsBackWhenCoreDoesNotHold keeps the poll interval against a
// Core that answers a long poll at once, instead of spinning.
func TestRunFallsBackWhenCoreDoesNotHold(t *testing.T) {
	t.Parallel()
	a := signer(t, 1)
	var now atomic.Int64
	now.Store(t0.UnixMilli())
	var drained atomic.Int32
	core := &fakeCore{}
	core.set(t, state(1, mtrp.TrustedKey{Key: a.Public(), NotAfter: t0.Add(time.Hour)}), a, `"1"`)
	l := newLink(t, core, &now, a.Public(), key.RelayPublic{1}, &drained)
	l.cfg.Interval = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	time.Sleep(time.Second)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := core.requests.Load(); got < 3 || got > 15 {
		t.Fatalf("%d requests in one second at a 100 ms interval", got)
	}
}

func TestRetryDelayStartsNearASecond(t *testing.T) {
	t.Parallel()
	for failures, want := range map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 7: time.Minute, 50: time.Minute} {
		if got := retryDelay(10*time.Second, failures); got != want {
			t.Errorf("retryDelay(10s, %d) = %v, want %v", failures, got, want)
		}
	}
	if got := retryDelay(10*time.Millisecond, 1); got != 10*time.Millisecond {
		t.Errorf("retryDelay(10ms, 1) = %v", got)
	}
}
