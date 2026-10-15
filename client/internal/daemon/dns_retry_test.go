package daemon

import (
	"sync/atomic"
	"testing"
	"time"
)

// A newer map cancels the retry of an older one, and stop ends retries.
func TestDNSRetryRunsOnlyForTheLatestMap(t *testing.T) {
	t.Parallel()

	var retry dnsRetry
	var stale, latest atomic.Int32
	retry.apply(func() bool { return false })
	retry.schedule(func() bool { stale.Add(1); return true })
	retry.apply(func() bool { return false })
	retry.schedule(func() bool { latest.Add(1); return true })
	deadline := time.Now().Add(3 * time.Second)
	for latest.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if stale.Load() != 0 || latest.Load() != 1 {
		t.Fatalf("retries stale=%d latest=%d, want 0/1", stale.Load(), latest.Load())
	}

	var stopped dnsRetry
	var calls atomic.Int32
	stopped.apply(func() bool { return false })
	stopped.schedule(func() bool { calls.Add(1); return false })
	stopped.stop()
	stopped.schedule(func() bool { calls.Add(1); return false })
	time.Sleep(1500 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatalf("%d retries ran after stop", calls.Load())
	}
}

// Failed retries back off, doubling up to the runtime's longest delay; a new
// map starts again from the shortest.
func TestDNSRetryBacksOff(t *testing.T) {
	t.Parallel()

	var retry dnsRetry
	retry.mu.Lock()
	for _, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
		retry.scheduleLocked(func() bool { return false })
		if retry.delay != want {
			t.Fatalf("delay = %v, want %v", retry.delay, want)
		}
	}
	retry.delay = maxRuntimeRetry
	retry.scheduleLocked(func() bool { return false })
	if retry.delay != maxRuntimeRetry {
		t.Fatalf("delay = %v, want at most %v", retry.delay, maxRuntimeRetry)
	}
	retry.cancelLocked()
	retry.mu.Unlock()
	retry.apply(func() bool { return true })
	if retry.delay != 0 {
		t.Fatalf("a new map kept delay %v", retry.delay)
	}
	retry.stop()
}
