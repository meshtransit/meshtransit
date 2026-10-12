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
	policy    appmapsession.NetworkPolicy // at the policy revision of the read
	// header: present only while the Deployment, Workspace and Network can
	// serve maps (schema 142).
	serveable     bool
	networkName   network.DisplayName
	recoveryEpoch int64
	// sharing: the Network takes part in a Device share (schema 145). Its
	// Devices' maps depend on state outside the view (aliases, peers across
	// Networks), so they are always read per Device.
	sharing bool
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
) (cachedInventory, bool, error) {
	for attempt := 0; attempt < 2; attempt++ {
		cache.mu.Lock()
		slot := cache.slotLocked(scope)
		if slot.current.usableAt(revision, now, cache.maxAge) {
			slot.lastUsed = time.Now()
			current := slot.current
			cache.mu.Unlock()
			return current, true, nil
		}
		if slot.current.revision > revision {
			cache.mu.Unlock()
			return cachedInventory{}, false, nil // the caller read an older revision
		}
		if wait := slot.loading; wait != nil {
			cache.mu.Unlock()
			select {
			case <-wait:
				continue // re-check what the reader stored
			case <-ctx.Done():
				return cachedInventory{}, false, ctx.Err()
			}
		}
		done := make(chan struct{})
		slot.loading = done
		cache.mu.Unlock()

		loaded, err := read(ctx)

		cache.mu.Lock()
		if err == nil && loaded.revision >= slot.current.revision {
			loaded = keepIdentical(slot.current, loaded)
			slot.current = loaded
			slot.lastUsed = time.Now()
		}
		slot.loading = nil
		close(done)
		cache.mu.Unlock()
		if err != nil {
			return cachedInventory{}, false, err
		}
		if loaded.usableAt(revision, now, cache.maxAge) {
			return loaded, true, nil
		}
		return cachedInventory{}, false, nil
	}
	return cachedInventory{}, false, nil
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

// keepIdentical returns loaded, but with the inventory and policy objects
// of previous when the reread found exactly the same Network (same revision
// and evidence). Streams holding a snapshot built from previous then see
// their view is still the latest by identity, in O(1).
func keepIdentical(previous, loaded cachedInventory) cachedInventory {
	if previous.revision != loaded.revision || previous.serveable != loaded.serveable ||
		previous.networkName != loaded.networkName || previous.recoveryEpoch != loaded.recoveryEpoch ||
		!previous.inventory.Equal(loaded.inventory) || !previous.policy.Equal(loaded.policy) {
		return loaded
	}
	loaded.inventory, loaded.policy = previous.inventory, previous.policy
	return loaded
}

// clockMargin keeps a derived map clear of a deadline across the clock skew
// between this replica and PostgreSQL.
const clockMargin = 2 * time.Second

// freshAt reports whether the inventory, read at PostgreSQL time readAt,
// still describes the Network at local time now: read within maxAge and
// before any listed Device or membership lapses (less the clock margin).
func (cached cachedInventory) freshAt(now time.Time, maxAge time.Duration) bool {
	age := now.Sub(cached.readAt)
	return cached.inventory.IsValid() && age <= maxAge && age >= -maxAge &&
		(cached.expiresAt.IsZero() || now.Add(clockMargin).Before(cached.expiresAt))
}

// latest returns scope's newest inventory of at least minRevision that is
// fresh at local time now, reading it at most once across concurrent
// callers. found is false when even a new read does not reach minRevision.
func (cache *inventoryCache) latest(
	ctx context.Context,
	scope network.Scope,
	minRevision int64,
	now time.Time,
	read inventoryReader,
) (cachedInventory, bool, error) {
	for attempt := 0; attempt < 2; attempt++ {
		cache.mu.Lock()
		slot := cache.slotLocked(scope)
		if slot.current.revision >= minRevision && slot.current.freshAt(now, cache.maxAge) {
			slot.lastUsed = time.Now()
			current := slot.current
			cache.mu.Unlock()
			return current, true, nil
		}
		if wait := slot.loading; wait != nil {
			cache.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return cachedInventory{}, false, ctx.Err()
			}
		}
		done := make(chan struct{})
		slot.loading = done
		cache.mu.Unlock()

		loaded, err := read(ctx)

		cache.mu.Lock()
		if err == nil && loaded.revision >= slot.current.revision {
			loaded = keepIdentical(slot.current, loaded)
			slot.current = loaded
			slot.lastUsed = time.Now()
		}
		slot.loading = nil
		close(done)
		cache.mu.Unlock()
		if err != nil {
			return cachedInventory{}, false, err
		}
		if loaded.revision >= minRevision && loaded.freshAt(now, cache.maxAge) {
			return loaded, true, nil
		}
		return cachedInventory{}, false, nil
	}
	return cachedInventory{}, false, nil
}
