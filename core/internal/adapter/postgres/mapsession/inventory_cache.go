package mapsession

import (
	"context"
	"sync"
	"time"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/identity"
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
	// The Workspace and Network display codes of the Network's DNS zone
	// (schema 169); immutable.
	workspaceCode, networkCode identity.DisplayCode
	// sharingDevices: numeric node identifiers of the Devices a share binds
	// (schema 146). Their maps depend on state outside the view (aliases,
	// peers across Networks), so they are always read per Device.
	sharingDevices map[int64]struct{}
	// directEndpoints: the Network holds a legacy direct share endpoint
	// (schema 154), which every Device of a consumer Network reads, or the
	// database cannot tell.
	directEndpoints bool
	// changeSeq is the Network's change counter (schema 153) the inventory
	// reflects, or -1 when the database tracks no changes; the next read
	// applies the Devices changed after it. fullReadAt is the local time of
	// the last read of the whole Network.
	changeSeq  int64
	fullReadAt time.Time
}

// sharesAbsent reports whether no share reader can return anything for the
// Device numericNodeID: a share binds it neither directly nor through a
// legacy direct endpoint of its Network.
func (cached cachedInventory) sharesAbsent(numericNodeID int64) bool {
	return cached.inventory.IsValid() && !cached.directEndpoints && !cached.sharingBinds(numericNodeID)
}

// sharingBinds reports whether a share binds the Device numericNodeID.
func (cached cachedInventory) sharingBinds(numericNodeID int64) bool {
	_, bound := cached.sharingDevices[numericNodeID]
	return bound
}

// usableAt reports whether the inventory answers for revision at the
// PostgreSQL time now: that revision or a later one, no listed Device
// expired by now, and
// read within maxAge of now (state changes that do not advance the
// revision, such as an owner suspension, are then picked up as before by
// the reconcile interval). An inventory read after now is usable: it can
// only omit Devices that expired in between, never add one.
func (cached cachedInventory) usableAt(revision int64, now time.Time, maxAge time.Duration) bool {
	age := now.Sub(cached.readAt)
	return cached.inventory.IsValid() && cached.revision >= revision &&
		age <= maxAge && age >= -maxAge &&
		(cached.expiresAt.IsZero() || now.Before(cached.expiresAt))
}

// inventoryCache keeps each Network's latest inventory and lets one caller
// read it while concurrent callers for the same Network wait (singleflight).
// It holds no authority of its own: every entry is a PostgreSQL read bound
// to a revision, and a caller uses it for that revision or a later one (the
// caller checks the inventory lists it unchanged and its policy matches).
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

// inventoryReader reads one Network's inventory in its own transaction,
// given the inventory the cache holds (possibly none), which it may bring up
// to date instead of reading the whole Network.
type inventoryReader func(ctx context.Context, previous cachedInventory) (cachedInventory, error)

// get returns an inventory of scope at revision or later, usable at
// PostgreSQL time now, reading it at most once across concurrent callers.
// While Devices join, the Network's revision moves on between a Device's read
// and the inventory read, so an exact revision rarely meets: the later
// inventory answers instead of every Device reading the whole Network itself
// (O(N) each, O(N^2) while a Network fills). found is false when none is
// usable, and the caller then reads its candidates itself.
func (cache *inventoryCache) get(
	ctx context.Context,
	scope network.Scope,
	revision int64,
	now time.Time,
	read inventoryReader,
) (cachedInventory, bool, error) {
	return cache.fetch(ctx, scope, func(cached cachedInventory) bool {
		return cached.usableAt(revision, now, cache.maxAge)
	}, read)
}

// inventoryFetchRounds bounds how often fetch re-checks the cache. A caller
// that waited on a read begun before its own revision existed (round 1)
// joins or starts the next read (round 2), which began after the first one
// ended and so after the caller's revision; round 3 finds it.
const inventoryFetchRounds = 3

// fetch returns scope's cached inventory when usable accepts it, else reads
// one, joining the in-flight read of a concurrent caller instead of reading
// alongside it. Revisions only grow, so a caller that misses a read waits for
// the next shared one rather than reading its Network on its own.
func (cache *inventoryCache) fetch(
	ctx context.Context,
	scope network.Scope,
	usable func(cachedInventory) bool,
	read inventoryReader,
) (cachedInventory, bool, error) {
	for range inventoryFetchRounds {
		cache.mu.Lock()
		slot := cache.slotLocked(scope)
		if usable(slot.current) {
			slot.lastUsed = time.Now()
			current := slot.current
			cache.mu.Unlock()
			return current, true, nil
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
		previous := slot.current
		cache.mu.Unlock()

		loaded, err := read(ctx, previous)

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
		return loaded, usable(loaded), nil
	}
	return cachedInventory{}, false, nil
}

// peek returns scope's cached inventory, whatever its revision or age,
// without reading one.
func (cache *inventoryCache) peek(scope network.Scope) (cachedInventory, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	slot, found := cache.entries[scope]
	if !found || !slot.current.inventory.IsValid() {
		return cachedInventory{}, false
	}
	return slot.current, true
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
	return cache.fetch(ctx, scope, func(cached cachedInventory) bool {
		return cached.revision >= minRevision && cached.freshAt(now, cache.maxAge)
	}, read)
}
