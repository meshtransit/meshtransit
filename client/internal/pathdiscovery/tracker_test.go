package pathdiscovery

import (
	"net/netip"
	"testing"
	"time"
)

func TestTrackerRetainsFlappedCandidateUntilExactDeadline(t *testing.T) {
	t.Parallel()

	retention := 10 * time.Second
	tracker := newTracker(retention)
	now := time.Unix(1_000, 0)
	reflexive := mustCandidate(
		t,
		netip.MustParseAddrPort("198.51.100.10:41641"),
		SourceServerReflexive,
	)
	host := mustCandidate(
		t,
		netip.MustParseAddrPort("192.168.1.10:41641"),
		SourceHost,
	)
	initial := mustSet(t, reflexive, host)

	first, err := tracker.Update(now, initial)
	if err != nil {
		t.Fatalf("Update(initial) error = %v", err)
	}
	if !first.Changed || !first.Candidates.Equal(initial) ||
		!first.ExpiresAt.Equal(now.Add(retention)) {
		t.Fatalf("Update(initial) = %#v", first)
	}

	flapped, err := tracker.Update(now.Add(time.Second), mustSet(t, host))
	if err != nil {
		t.Fatalf("Update(flapped) error = %v", err)
	}
	if flapped.Changed || !flapped.Candidates.Equal(initial) {
		t.Fatalf("Update(flapped) = %#v", flapped)
	}

	expired, err := tracker.Expire(now.Add(retention))
	if err != nil {
		t.Fatalf("Expire() error = %v", err)
	}
	if !expired.Changed || !expired.Candidates.Equal(mustSet(t, host)) ||
		!expired.ExpiresAt.IsZero() {
		t.Fatalf("Expire() = %#v", expired)
	}
}

func TestTrackerRefreshExtendsCandidateAndHostRemovalIsImmediate(t *testing.T) {
	t.Parallel()

	retention := 10 * time.Second
	tracker := newTracker(retention)
	now := time.Unix(2_000, 0)
	reflexive := mustCandidate(
		t,
		netip.MustParseAddrPort("198.51.100.20:41641"),
		SourceServerReflexive,
	)
	host := mustCandidate(
		t,
		netip.MustParseAddrPort("192.168.1.20:41641"),
		SourceHost,
	)
	if _, err := tracker.Update(now, mustSet(t, reflexive, host)); err != nil {
		t.Fatalf("Update(initial) error = %v", err)
	}

	refreshedAt := now.Add(5 * time.Second)
	refreshed, err := tracker.Update(refreshedAt, mustSet(t, reflexive))
	if err != nil {
		t.Fatalf("Update(refreshed) error = %v", err)
	}
	if !refreshed.Changed || !refreshed.Candidates.Equal(mustSet(t, reflexive)) ||
		!refreshed.ExpiresAt.Equal(refreshedAt.Add(retention)) {
		t.Fatalf("Update(refreshed) = %#v", refreshed)
	}
	beforeExpiry, err := tracker.Expire(now.Add(retention))
	if err != nil || beforeExpiry.Candidates.Len() != 1 {
		t.Fatalf("Expire(old deadline) = %#v, %v", beforeExpiry, err)
	}
	afterExpiry, err := tracker.Expire(refreshedAt.Add(retention))
	if err != nil || afterExpiry.Candidates.Len() != 0 || !afterExpiry.Changed {
		t.Fatalf("Expire(new deadline) = %#v, %v", afterExpiry, err)
	}
}

func TestTrackerBoundsPortChurnPerAddress(t *testing.T) {
	t.Parallel()

	tracker := newTracker(time.Minute)
	now := time.Unix(3_000, 0)
	address := netip.MustParseAddr("198.51.100.30")
	for index := 0; index < maxTrackedPerAddress+4; index++ {
		candidate := mustCandidate(
			t,
			netip.AddrPortFrom(address, uint16(41000+index)),
			SourceServerReflexive,
		)
		if _, err := tracker.Update(now.Add(time.Duration(index)*time.Second), mustSet(t, candidate)); err != nil {
			t.Fatalf("Update(%d) error = %v", index, err)
		}
	}
	if len(tracker.tracked) != maxTrackedPerAddress {
		t.Fatalf("tracked candidates = %d, want %d", len(tracker.tracked), maxTrackedPerAddress)
	}
	oldest := mustCandidate(
		t,
		netip.AddrPortFrom(address, 41000),
		SourceServerReflexive,
	)
	newest := mustCandidate(
		t,
		netip.AddrPortFrom(address, uint16(41000+maxTrackedPerAddress+3)),
		SourceServerReflexive,
	)
	if _, exists := tracker.tracked[oldest]; exists {
		t.Fatal("tracker retained the oldest candidate after port churn")
	}
	if _, exists := tracker.tracked[newest]; !exists {
		t.Fatal("tracker dropped the newest candidate after port churn")
	}
}

func TestTrackerResetDropsHistory(t *testing.T) {
	t.Parallel()

	tracker := newTracker(time.Minute)
	now := time.Unix(4_000, 0)
	reflexive := mustCandidate(
		t,
		netip.MustParseAddrPort("198.51.100.40:41641"),
		SourceServerReflexive,
	)
	configured := mustCandidate(
		t,
		netip.MustParseAddrPort("192.0.2.40:41641"),
		SourceConfigured,
	)
	if _, err := tracker.Update(now, mustSet(t, reflexive, configured)); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	reset, err := tracker.Reset(now.Add(time.Second), mustSet(t, configured))
	if err != nil {
		t.Fatalf("Reset() error = %v", err)
	}
	if !reset.Changed || !reset.Candidates.Equal(mustSet(t, configured)) ||
		!reset.ExpiresAt.IsZero() || len(tracker.tracked) != 0 {
		t.Fatalf("Reset() = %#v, tracked=%d", reset, len(tracker.tracked))
	}
	if _, err := tracker.Reset(now, mustSet(t, reflexive)); err == nil {
		t.Fatal("Reset(reflexive) error = nil")
	}
}

func TestTrackerRejectsInvalidBoundary(t *testing.T) {
	t.Parallel()

	var tracker *Tracker
	if _, err := tracker.Update(time.Now(), Set{}); err == nil {
		t.Fatal("nil Tracker.Update() error = nil")
	}
	tracker = NewTracker()
	if _, err := tracker.Update(time.Time{}, Set{}); err == nil {
		t.Fatal("Tracker.Update(zero time) error = nil")
	}
}

func mustSet(t *testing.T, candidates ...Candidate) Set {
	t.Helper()

	set, err := NewSet(candidates)
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}

	return set
}

func TestTrackerDropsARemovedPortMappingAtOnce(t *testing.T) {
	t.Parallel()

	tracker := newTracker(10 * time.Second)
	now := time.Unix(2_000, 0)
	reflexive := mustCandidate(t, netip.MustParseAddrPort("198.51.100.20:41641"), SourceServerReflexive)
	mapped := mustCandidate(t, netip.MustParseAddrPort("198.51.100.20:50000"), SourcePortMapping)
	if _, err := tracker.Update(now, mustSet(t, reflexive, mapped)); err != nil {
		t.Fatalf("Update(initial) error = %v", err)
	}
	// The mapper removed the mapping; one STUN round failed too.
	result, err := tracker.Update(now.Add(time.Second), mustSet(t))
	if err != nil {
		t.Fatalf("Update(after removal) error = %v", err)
	}
	if !result.Candidates.Equal(mustSet(t, reflexive)) {
		t.Fatalf("published %v, want only the retained reflexive candidate", result.Candidates.Candidates())
	}
}
