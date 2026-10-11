package mapsession

import (
	"context"
	"sync"
	"time"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
)

// inventoryCacheEntries bounds how many Networks keep a cached inventory.
const inventoryCacheEntries = 4096

// cachedInventory is one Network's inventory as read at one revision.
type cachedInventory struct {
	revision  int64
	readAt    time.Time // PostgreSQL transaction time of the read
	expiresAt time.Time // earliest Device key expiry in the inventory
	inventory appmapsession.NetworkInventory
}

// usableAt reports whether the inventory answers for revision at the
// PostgreSQL time now: same revision, no listed Device expired by now, and
// read within maxAge of now (state changes that do not advance the
// revision, such as an owner suspension, are then picked up as before by
// the reconcile interval). An inventory read after now is usable: it can
// only omit Devices that expired in between, never add one.
func (cached cachedInventory) usableAt(revision int64, now time.Time, maxAge time.Duration) bool {
	age := now.Sub(cached.readAt)
	return cached.inventory.IsValid() && cached.revision == revision &&
		age <= maxAge && age >= -maxAge &&
		(cached.expiresAt.IsZero() || now.Before(cached.expiresAt))
}

// inventoryCache keeps each Network's latest inventory and lets one caller
// read it while concurrent callers for the same Network wait (singleflight).
// It holds no authority of its own: every entry is a PostgreSQL read bound
// to a revision, and a caller uses it only for that exact revision.
type inventoryCache struct {
	mu       sync.Mutex
	entries  map[network.Scope]*inventorySlot
	maxAge   time.Duration
	capacity int
}

type inventorySlot struct {
	current  cachedInventory
	loading  chan struct{} // closed when the in-flight read ends; nil when idle
	lastUsed time.Time
}

func newInventoryCache(maxAge time.Duration) *inventoryCache {
	return &inventoryCache{entries: make(map[network.Scope]*inventorySlot), maxAge: maxAge,
		capacity: inventoryCacheEntries}
}

// inventoryReader reads one Network's inventory in its own transaction.
type inventoryReader func(context.Context) (cachedInventory, error)

// get returns the inventory of scope for revision at PostgreSQL time now,
// reading it at most once across concurrent callers. found is false when no
// usable inventory exists for that exact revision (for example the Network
// already moved on), and the caller then reads its candidates itself.
func (cache *inventoryCache) get(
	ctx context.Context,
	scope network.Scope,
	revision int64,
	now time.Time,
	read inventoryReader,
) (appmapsession.NetworkInventory, bool, error) {
	for attempt := 0; attempt < 2; attempt++ {
		cache.mu.Lock()
		slot := cache.slotLocked(scope)
		if slot.current.usableAt(revision, now, cache.maxAge) {
			slot.lastUsed = time.Now()
			inventory := slot.current.inventory
			cache.mu.Unlock()
			return inventory, true, nil
		}
		if slot.current.revision > revision {
			cache.mu.Unlock()
			return appmapsession.NetworkInventory{}, false, nil // the caller read an older revision
		}
		if wait := slot.loading; wait != nil {
			cache.mu.Unlock()
			select {
			case <-wait:
				continue // re-check what the reader stored
			case <-ctx.Done():
				return appmapsession.NetworkInventory{}, false, ctx.Err()
			}
		}
		done := make(chan struct{})
		slot.loading = done
		cache.mu.Unlock()

		loaded, err := read(ctx)

		cache.mu.Lock()
		if err == nil && loaded.revision >= slot.current.revision {
			slot.current = loaded
			slot.lastUsed = time.Now()
		}
		slot.loading = nil
		close(done)
		cache.mu.Unlock()
		if err != nil {
			return appmapsession.NetworkInventory{}, false, err
		}
		if loaded.usableAt(revision, now, cache.maxAge) {
			return loaded.inventory, true, nil
		}
		return appmapsession.NetworkInventory{}, false, nil
	}
	return appmapsession.NetworkInventory{}, false, nil
}

// slotLocked returns scope's slot, evicting the least recently used idle
// slot when the cache is full. cache.mu is held.
func (cache *inventoryCache) slotLocked(scope network.Scope) *inventorySlot {
	if slot, found := cache.entries[scope]; found {
		return slot
	}
	if len(cache.entries) >= cache.capacity {
		var oldest network.Scope
		var oldestUsed time.Time
		found := false
		for candidate, slot := range cache.entries {
			if slot.loading == nil && (!found || slot.lastUsed.Before(oldestUsed)) {
				oldest, oldestUsed, found = candidate, slot.lastUsed, true
			}
		}
		if found {
			delete(cache.entries, oldest)
		}
	}
	slot := &inventorySlot{lastUsed: time.Now()}
	cache.entries[scope] = slot
	return slot
}
