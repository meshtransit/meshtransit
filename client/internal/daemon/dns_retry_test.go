package daemon

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"meshtransit.net/client/internal/dnsconfig"
	"meshtransit.net/client/internal/networkmap"
)

// A newer map cancels the retry of an older one, and stop ends retries.
func TestDNSRetryRunsOnlyForTheLatestMap(t *testing.T) {
	t.Parallel()

	var retry dnsRetry
	var stale, latest atomic.Int32
	retry.apply(differs, func() bool { return false })
	retry.schedule(func() bool { stale.Add(1); return true })
	retry.apply(differs, func() bool { return false })
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
	stopped.apply(differs, func() bool { return false })
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
	retry.apply(differs, func() bool { return true })
	if retry.delay != 0 {
		t.Fatalf("a new map kept delay %v", retry.delay)
	}
	retry.stop()
}

func differs() bool { return false }

// A map whose DNS is the one a pending retry applies keeps that retry and
// its backoff, and adds no retry; one whose DNS changed applies at once
// (TD-CLI-33).
func TestDNSRetryKeepsBackoffForTheSameDNS(t *testing.T) {
	t.Parallel()
	retry := &dnsRetry{}
	defer retry.stop()
	applies := 0
	failing := func() bool { applies++; return false }
	retry.apply(differs, failing)
	retry.schedule(func() bool { return false })
	retry.mu.Lock()
	delay, timer := retry.delay, retry.timer
	retry.mu.Unlock()
	same := func() bool { return true }
	if retry.apply(same, failing) || applies != 1 {
		t.Fatalf("the same DNS applied at once: %d applies", applies)
	}
	retry.mu.Lock()
	kept := retry.delay == delay && retry.timer == timer && retry.pending
	retry.mu.Unlock()
	if !kept {
		t.Fatal("the same DNS reset the backoff or replaced the retry")
	}
	if !retry.apply(differs, failing) || applies != 2 {
		t.Fatalf("changed DNS did not apply at once: %d applies", applies)
	}
}

// After a retry succeeds, a map with the same DNS applies at once: nothing
// is pending any more.
func TestDNSRetryAppliesTheSameDNSAfterRecovering(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		retry := &dnsRetry{}
		defer retry.stop()
		retry.apply(differs, func() bool { return false })
		retry.schedule(func() bool { return true })
		time.Sleep(2 * time.Second)
		synctest.Wait()
		applied := false
		if !retry.apply(func() bool { return true }, func() bool { applied = true; return true }) || !applied {
			t.Fatal("a map after a recovered retry was kept")
		}
	})
}

// Scheduling again replaces the pending retry: one chain at most.
func TestDNSRetryKeepsOneChain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		retry := &dnsRetry{}
		defer retry.stop()
		var attempts int
		attempt := func() bool { attempts++; return false }
		retry.schedule(attempt)
		retry.schedule(attempt)
		retry.schedule(attempt)
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if attempts > 4 {
			t.Fatalf("%d attempts in 10 s: more than one chain", attempts)
		}
	})
}

func retrySnapshot(revision uint64, search string) networkmap.Snapshot {
	return networkmap.Snapshot{
		Revision: revision,
		Self: networkmap.Node{
			ID: 1, Name: "node-a.example.mesh.",
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		},
		DNS: &networkmap.DNSConfig{
			Routes: []networkmap.DNSRoute{
				{Suffix: "example.mesh", Resolvers: []networkmap.DNSResolver{}},
				{Suffix: search, Resolvers: []networkmap.DNSResolver{{Address: netip.MustParseAddrPort("10.0.0.53:53")}}},
			},
			SearchDomains: []string{search},
			Records: []networkmap.DNSRecord{
				{Name: "node-a.example.mesh", Type: networkmap.DNSRecordA, Address: netip.MustParseAddr("100.64.0.1")},
			},
		},
	}
}

// A new map revision with the same DNS is the same DNS; another search
// domain or relay host is not.
func TestSameDNSComparesThePlanAndInfrastructure(t *testing.T) {
	t.Parallel()
	first, next := retrySnapshot(41, "corp.example"), retrySnapshot(42, "corp.example")
	if _, err := dnsconfig.Compile(first); err != nil {
		t.Fatalf("the fixture does not compile: %v", err)
	}
	if !sameDNS(first, next, "https://control.example") {
		t.Fatal("a new revision with the same DNS differs")
	}
	if sameDNS(first, retrySnapshot(42, "lab.example"), "https://control.example") {
		t.Fatal("another search domain is the same DNS")
	}
	moved := retrySnapshot(42, "corp.example")
	moved.Relays = map[int]networkmap.RelayRegion{1: {Nodes: []networkmap.RelayNode{{HostName: "relay.example.net"}}}}
	if sameDNS(first, moved, "https://control.example") {
		t.Fatal("other relay hosts are the same DNS")
	}
}
