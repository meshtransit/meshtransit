//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"meshtransit.net/core/internal/adapter/mtcp/mtcptest"
)

// scaleCollector reads every stream on its own goroutine and times the
// first update of each watched stream that satisfies the current watch.
type scaleCollector struct {
	mu         sync.Mutex
	streams    []*mtcptest.MapStream
	closing    bool
	reconnects int
	lastEvent  time.Time
	expected   map[int]bool
	unexpected []error
	current    *scaleWatch
}

type scaleWatch struct {
	collector *scaleCollector
	targets   []int
	match     func(int, mtcptest.MapUpdate) bool
	started   time.Time
	pending   map[int]struct{}
	hits      map[int]time.Duration
	snapshot  int
	done      chan struct{}
}

func newScaleCollector(size int) *scaleCollector {
	return &scaleCollector{streams: make([]*mtcptest.MapStream, size), lastEvent: time.Now(),
		expected: make(map[int]bool)}
}

// read owns stream until it ends. When Core ends it with Lifecycle
// RECONNECT, read opens a new stream for client as a node would, and
// observes its first map like any other update.
func (collector *scaleCollector) read(
	ctx context.Context,
	index int,
	stream *mtcptest.MapStream,
	client *mtcptest.Client,
) {
	collector.setStream(index, stream)
	go func() {
		for {
			update, err := stream.Next(ctx)
			if err == nil {
				collector.observe(index, update, time.Now())
				continue
			}
			if !strings.Contains(err.Error(), "lifecycle RECONNECT") || !collector.noteReconnect() {
				collector.end(index, err)
				return
			}
			var initial mtcptest.MapUpdate
			_, reopenErr := retryScaleShed(ctx, func() error {
				var openErr error
				stream, initial, openErr = client.OpenMapStream(ctx)
				return openErr
			})
			if reopenErr != nil {
				collector.end(index, errors.Join(err, reopenErr))
				return
			}
			collector.setStream(index, stream)
			collector.observe(index, initial, time.Now())
		}
	}()
}

func (collector *scaleCollector) setStream(index int, stream *mtcptest.MapStream) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	collector.streams[index] = stream
	if collector.closing {
		_ = stream.Close()
	}
}

func (collector *scaleCollector) stream(index int) *mtcptest.MapStream {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	return collector.streams[index]
}

func (collector *scaleCollector) size() int { return len(collector.streams) }

// noteReconnect counts a Core-initiated reconnect unless the test is
// closing every stream.
func (collector *scaleCollector) noteReconnect() bool {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.closing {
		return false
	}
	collector.reconnects++
	return true
}

func (collector *scaleCollector) reconnectCount() int {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	return collector.reconnects
}

// closeAll closes every stream; readers then end quietly.
func (collector *scaleCollector) closeAll() {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	collector.closing = true
	for _, stream := range collector.streams {
		if stream != nil {
			_ = stream.Close()
		}
	}
}

func (collector *scaleCollector) observe(index int, update mtcptest.MapUpdate, at time.Time) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	collector.lastEvent = at
	watch := collector.current
	if watch == nil {
		return
	}
	if _, waiting := watch.pending[index]; !waiting || !watch.match(index, update) {
		return
	}
	watch.hits[index] = at.Sub(watch.started)
	if update.Snapshot && index != 0 {
		watch.snapshot++
	}
	delete(watch.pending, index)
	if len(watch.pending) == 0 {
		close(watch.done)
		collector.current = nil
	}
}

func (collector *scaleCollector) end(index int, err error) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.expected[index] || collector.closing {
		delete(collector.expected, index)
		return
	}
	collector.unexpected = append(collector.unexpected, fmt.Errorf("stream %d ended: %w", index, err))
}

func (collector *scaleCollector) expectEnd(index int) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	collector.expected[index] = true
}

// watch starts timing targets from now.
func (collector *scaleCollector) watch(targets []int, match func(int, mtcptest.MapUpdate) bool) *scaleWatch {
	watch := &scaleWatch{collector: collector, targets: targets, match: match, started: time.Now(),
		pending: make(map[int]struct{}, len(targets)), hits: make(map[int]time.Duration, len(targets)),
		done: make(chan struct{})}
	for _, index := range targets {
		watch.pending[index] = struct{}{}
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	collector.current = watch
	return watch
}

func (watch *scaleWatch) snapshots() int {
	watch.collector.mu.Lock()
	defer watch.collector.mu.Unlock()
	return watch.snapshot
}

// await returns each target's latency in target order, failing the test
// when a target missed the update within timeout.
func (collector *scaleCollector) await(
	ctx context.Context,
	t *testing.T,
	running readyControlProcess,
	watch *scaleWatch,
	timeout time.Duration,
	phase string,
) []time.Duration {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-watch.done:
	case <-timer.C:
	case <-ctx.Done():
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if len(watch.pending) != 0 {
		missing := slices.Sorted(func(yield func(int) bool) {
			for index := range watch.pending {
				if !yield(index) {
					return
				}
			}
		})
		running.process.forceStop(t)
		t.Fatalf("%s update missed %d of %d streams after %v (first missing %v); stream errors: %v; stderr: %s",
			phase, len(missing), len(watch.targets), timeout, missing[:min(10, len(missing))],
			collector.unexpected[:min(5, len(collector.unexpected))], scaleTail(running.process.stderr.String()))
	}
	latencies := make([]time.Duration, len(watch.targets))
	for position, index := range watch.targets {
		latencies[position] = watch.hits[index]
	}
	return latencies
}

// quiesce waits until no stream received anything for scaleQuietPeriod,
// or until limit.
func (collector *scaleCollector) quiesce(ctx context.Context, limit time.Duration) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		collector.mu.Lock()
		quiet := time.Since(collector.lastEvent) >= scaleQuietPeriod
		collector.mu.Unlock()
		if quiet {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (collector *scaleCollector) failOnUnexpected(t *testing.T, running readyControlProcess) {
	t.Helper()
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if len(collector.unexpected) != 0 {
		running.process.forceStop(t)
		t.Fatalf("%d scale streams ended unexpectedly, first: %v; stderr: %s", len(collector.unexpected),
			collector.unexpected[:min(5, len(collector.unexpected))], scaleTail(running.process.stderr.String()))
	}
}
