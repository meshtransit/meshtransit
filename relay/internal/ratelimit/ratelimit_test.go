package ratelimit

import (
	"net/netip"
	"testing"
	"time"
)

func TestBucket(t *testing.T) {
	t.Parallel()
	now := time.Unix(0, 0)
	b := NewBucket(10, 2)
	for i, want := range []bool{true, true, false} {
		if got := b.Allow(now, 1); got != want {
			t.Fatalf("take %d: %v, want %v", i, got, want)
		}
	}
	if !b.Allow(now.Add(100*time.Millisecond), 1) {
		t.Fatal("no refill")
	}
	b.SetRate(0, 0)
	if !b.Allow(now, 1000) {
		t.Fatal("zero rate must disable the limit")
	}
}

func TestSourceLimiter(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)
	l := NewSourceLimiter(1, 2, 2, func() time.Time { return now })
	a := netip.MustParseAddr("192.0.2.1")
	for i, want := range []bool{true, true, false} {
		if got := l.Allow(a); got != want {
			t.Fatalf("event %d: %v, want %v", i, got, want)
		}
	}
	// IPv6 addresses in one /64 share an allowance.
	v6a, v6b := netip.MustParseAddr("2001:db8:1:2::1"), netip.MustParseAddr("2001:db8:1:2::ffff")
	if !l.Allow(v6a) || !l.Allow(v6b) || l.Allow(v6a) {
		t.Fatal("/64 not shared")
	}
	// Table full and nobody idle: new sources are refused, not reset.
	if l.Allow(netip.MustParseAddr("192.0.2.3")) {
		t.Fatal("full table admitted a new source")
	}
	if l.Allow(a) {
		t.Fatal("existing source's allowance was reset")
	}
	// Once entries are idle they are pruned (at most once per second).
	now = now.Add(5 * time.Second)
	if !l.Allow(netip.MustParseAddr("192.0.2.3")) {
		t.Fatal("idle entries not pruned")
	}
}
