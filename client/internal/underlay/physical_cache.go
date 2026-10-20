//go:build (darwin && !ios) || windows

package underlay

import (
	"net/netip"
	"sync"
	"time"
)

// physicalCacheTTL is how long the interface found for a destination is
// reused: a burst of dials does not read the whole routing table each time,
// and a network change is seen within this long.
const (
	physicalCacheTTL     = 500 * time.Millisecond
	physicalCacheEntries = 256
)

type physicalEntry struct {
	index int
	at    time.Time
}

// physicalCache remembers, for a short while, the physical interface a
// destination's route leaves by.
type physicalCache struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[netip.Addr]physicalEntry
}

var physicalInterfaces = &physicalCache{now: time.Now, entries: map[netip.Addr]physicalEntry{}}

// lookup returns the cached interface of destination, or finds it with find
// and caches it. A failure is not cached.
func (cache *physicalCache) lookup(destination netip.Addr, find func(netip.Addr) (int, error)) (int, error) {
	now := cache.now()
	cache.mu.Lock()
	entry, cached := cache.entries[destination]
	cache.mu.Unlock()
	if cached && now.Sub(entry.at) >= 0 && now.Sub(entry.at) < physicalCacheTTL {
		return entry.index, nil
	}
	index, err := find(destination)
	if err != nil {
		return 0, err
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if len(cache.entries) >= physicalCacheEntries {
		clear(cache.entries)
	}
	cache.entries[destination] = physicalEntry{index: index, at: now}
	return index, nil
}

// forgetPhysicalInterfaces drops every cached interface, as after a change
// of the host's networks.
func forgetPhysicalInterfaces() {
	physicalInterfaces.mu.Lock()
	defer physicalInterfaces.mu.Unlock()
	clear(physicalInterfaces.entries)
}
