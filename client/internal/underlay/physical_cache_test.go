//go:build (darwin && !ios) || windows

package underlay

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestPhysicalCacheReusesAnInterfaceBriefly(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 20, 9, 0, 0, 0, time.UTC)
	cache := &physicalCache{now: func() time.Time { return now }, entries: map[netip.Addr]physicalEntry{}}
	reads := 0
	find := func(netip.Addr) (int, error) { reads++; return 4 + reads, nil }
	destination := netip.MustParseAddr("10.35.0.4")
	first, _ := cache.lookup(destination, find)
	second, _ := cache.lookup(destination, find)
	if first != 5 || second != 5 || reads != 1 {
		t.Fatalf("lookups %d, %d with %d reads", first, second, reads)
	}
	now = now.Add(physicalCacheTTL)
	if third, _ := cache.lookup(destination, find); third != 6 || reads != 2 {
		t.Fatalf("an old entry was reused: %d after %d reads", third, reads)
	}
	if _, err := cache.lookup(netip.MustParseAddr("10.35.0.5"), func(netip.Addr) (int, error) {
		return 0, errors.New("no route")
	}); err == nil {
		t.Fatal("a failure was hidden")
	}
	for index := range physicalCacheEntries + 1 {
		_, _ = cache.lookup(netip.AddrFrom4([4]byte{10, 0, byte(index >> 8), byte(index)}), find)
	}
	if len(cache.entries) > physicalCacheEntries {
		t.Fatalf("cache holds %d entries", len(cache.entries))
	}
}
