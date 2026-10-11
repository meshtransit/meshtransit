package mapsession

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

const (
	// connectivityChangeLog bounds how many Node changes a Network keeps for
	// streams to catch up from; a stream further behind rereads everything.
	connectivityChangeLog = 16384
	// connectivityHubBatch bounds the wakeups one Network reads in one Redis
	// call, which also coalesces bursts.
	connectivityHubBatch = 512
	// connectivityHubMailbox is the upstream wakeup buffer of one Network.
	connectivityHubMailbox = 4096
	// connectivityResyncBatch bounds one key batch of a resync read.
	connectivityResyncBatch = 1024
)

// ErrInvalidConnectivityHub reports a missing dependency or unsafe option.
var ErrInvalidConnectivityHub = errors.New("map session: invalid connectivity hub")

// BufferedConnectivityWatcher is a ConnectivityWatcher that can give one
// consumer a deeper mailbox (the hub drains a whole Network's wakeups).
type BufferedConnectivityWatcher interface {
	WatchNetworkBuffered(network.ID, int) (<-chan ConnectivityChanged, func(), error)
}

// ConnectivityHubOptions bounds one replica's shared connectivity tables.
type ConnectivityHubOptions struct {
	// ResyncInterval rereads every Node a table holds, repairing lost
	// wakeups (Redis Pub/Sub is best effort).
	ResyncInterval time.Duration
	// ReadTimeout bounds one Redis read.
	ReadTimeout time.Duration
}

func (options ConnectivityHubOptions) isValid() bool {
	return options.ResyncInterval >= time.Second && options.ResyncInterval <= 5*time.Minute &&
		options.ReadTimeout >= time.Millisecond && options.ReadTimeout <= 30*time.Second
}

// ConnectivityHub keeps, per replica and per Network with live streams, one
// versioned table of its Nodes' transient connectivity. A wakeup costs one
// Redis read per replica (not one per stream), and a stream moves from its
// table version to the latest in O(changes × log N) through the change log
// instead of reloading every peer. It grants no authority: snapshots still
// decide which Nodes a stream may see.
type ConnectivityHub struct {
	store   ConnectivityStore
	watcher ConnectivityWatcher
	options ConnectivityHubOptions

	mu       sync.Mutex
	networks map[network.ID]*networkConnectivity

	reads, keysRead, resyncs, overflows atomic.Uint64
}

// ConnectivityHubStats counts a hub's work since start.
type ConnectivityHubStats struct {
	// Networks is how many Networks currently keep a table.
	Networks int
	// Reads and KeysRead count Redis reads and the keys they asked for.
	Reads, KeysRead uint64
	// Resyncs counts full table rereads; Overflows the wakeup bursts that
	// filled a Network's mailbox and forced one.
	Resyncs, Overflows uint64
}

// NewConnectivityHub constructs a hub over the Redis store and wakeup feed.
func NewConnectivityHub(store ConnectivityStore, watcher ConnectivityWatcher,
	options ConnectivityHubOptions) (*ConnectivityHub, error) {
	if isNilDependency(store) || isNilDependency(watcher) || !options.isValid() {
		return nil, ErrInvalidConnectivityHub
	}
	return &ConnectivityHub{store: store, watcher: watcher, options: options,
		networks: make(map[network.ID]*networkConnectivity)}, nil
}

// Stats returns the hub's counters.
func (hub *ConnectivityHub) Stats() ConnectivityHubStats {
	hub.mu.Lock()
	networks := len(hub.networks)
	hub.mu.Unlock()
	return ConnectivityHubStats{Networks: networks, Reads: hub.reads.Load(), KeysRead: hub.keysRead.Load(),
		Resyncs: hub.resyncs.Load(), Overflows: hub.overflows.Load()}
}

// connectivityVersion is one immutable state of a Network's table.
type connectivityVersion struct {
	table   *networkConnectivity // nil for a private, unshared read
	seq     uint64
	entries connectivityMap
}

// networkConnectivity is one Network's table on this replica. It exists
// while at least one stream watches the Network.
type networkConnectivity struct {
	hub     *ConnectivityHub
	id      network.ID
	current atomic.Pointer[connectivityVersion]
	cancel  context.CancelFunc
	release func()
	done    chan struct{}

	mu          sync.Mutex // serializes writes, the log and subscribers
	log         changeRing
	subscribers map[uint64]chan ConnectivityChanged
	next        uint64
	failed      bool

	loading sync.Mutex // one miss read at a time, so a stream-open storm reads once
}

// WatchNetwork implements ConnectivityWatcher for streams: it opens the
// Network's table on first use and forwards each wakeup only after the
// table has read it, so a stream that catches up then sees the change.
func (hub *ConnectivityHub) WatchNetwork(networkID network.ID) (<-chan ConnectivityChanged, func(), error) {
	if hub == nil || !networkID.IsValid() {
		return nil, nil, ErrInvalidConnectivityHub
	}
	hub.mu.Lock()
	defer hub.mu.Unlock()
	table := hub.networks[networkID]
	if table == nil {
		var err error
		if table, err = hub.openTable(networkID); err != nil {
			return nil, nil, err
		}
		hub.networks[networkID] = table
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	if table.failed {
		return nil, nil, ErrStreamUnavailable
	}
	table.next++
	subscriber := table.next
	updates := make(chan ConnectivityChanged, 1)
	table.subscribers[subscriber] = updates
	var once sync.Once
	return updates, func() { once.Do(func() { hub.unsubscribe(table, subscriber) }) }, nil
}

// openTable subscribes to the Network's wakeups and starts its worker.
// hub.mu is held.
func (hub *ConnectivityHub) openTable(networkID network.ID) (*networkConnectivity, error) {
	var upstream <-chan ConnectivityChanged
	var release func()
	var err error
	if buffered, ok := hub.watcher.(BufferedConnectivityWatcher); ok {
		upstream, release, err = buffered.WatchNetworkBuffered(networkID, connectivityHubMailbox)
	} else {
		upstream, release, err = hub.watcher.WatchNetwork(networkID)
	}
	if err != nil || upstream == nil || release == nil {
		if release != nil {
			release()
		}
		return nil, errors.Join(ErrStreamUnavailable, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	table := &networkConnectivity{hub: hub, id: networkID, cancel: cancel, release: release,
		done: make(chan struct{}), subscribers: make(map[uint64]chan ConnectivityChanged)}
	table.current.Store(&connectivityVersion{table: table})
	go table.run(ctx, upstream)
	return table, nil
}

func (hub *ConnectivityHub) unsubscribe(table *networkConnectivity, subscriber uint64) {
	hub.mu.Lock()
	table.mu.Lock()
	updates, found := table.subscribers[subscriber]
	if found {
		delete(table.subscribers, subscriber)
		if !table.failed {
			close(updates)
		}
	}
	last := len(table.subscribers) == 0
	if last && hub.networks[table.id] == table {
		delete(hub.networks, table.id)
	}
	table.mu.Unlock()
	hub.mu.Unlock()
	if last {
		table.cancel()
		<-table.done
		table.release()
	}
}

// run applies the Network's wakeups and resyncs it until the last stream
// leaves or the feed ends.
func (table *networkConnectivity) run(ctx context.Context, upstream <-chan ConnectivityChanged) {
	defer close(table.done)
	resync := time.NewTimer(table.hub.options.ResyncInterval)
	defer resync.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-resync.C:
			table.resync(ctx)
			resync.Reset(table.hub.options.ResyncInterval)
		case change, open := <-upstream:
			if !open {
				table.fail()
				return
			}
			overflow := cap(upstream) > 1 && len(upstream) >= cap(upstream)-1
			batch := []ConnectivityChanged{change}
			for drained := false; !drained && len(batch) < connectivityHubBatch; {
				select {
				case more, ok := <-upstream:
					if !ok {
						table.fail()
						return
					}
					batch = append(batch, more)
				default:
					drained = true
				}
			}
			table.applyWakeups(ctx, batch)
			if overflow {
				table.hub.overflows.Add(1)
				table.resync(ctx)
			}
		}
	}
}

// applyWakeups reads each woken Node once (its newest generation), stores
// what changed and then forwards the wakeups to the streams.
func (table *networkConnectivity) applyWakeups(ctx context.Context, batch []ConnectivityChanged) {
	newest := make(map[node.ID]ConnectivityKey, len(batch))
	for _, change := range batch {
		key := change.Key()
		if change.NetworkID() != table.id {
			continue
		}
		if known, found := newest[key.NodeID()]; !found || key.Generation() > known.Generation() {
			newest[key.NodeID()] = key
		}
	}
	keys := make([]ConnectivityKey, 0, len(newest))
	for _, key := range newest {
		keys = append(keys, key)
	}
	if len(keys) != 0 {
		if values, err := table.read(ctx, keys); err == nil {
			table.apply(values, true)
		}
		// A failed read leaves the table as it was; the resync repairs it.
	}
	table.forward(batch)
}

// resync rereads every Node of the table, in batches, and wakes the streams
// when that repaired anything.
func (table *networkConnectivity) resync(ctx context.Context) {
	table.hub.resyncs.Add(1)
	before := table.current.Load()
	var keys []ConnectivityKey
	before.entries.each(func(value Connectivity) { keys = append(keys, value.key) })
	for offset := 0; offset < len(keys); offset += connectivityResyncBatch {
		batch := keys[offset:min(offset+connectivityResyncBatch, len(keys))]
		values, err := table.read(ctx, batch)
		if err != nil {
			break
		}
		table.apply(values, true)
	}
	if after := table.current.Load(); after != before && len(keys) != 0 {
		wake, err := NewConnectivityChanged(table.id, keys[0].nodeID, keys[0].generation, ConnectivityChangeEndpoints)
		if err == nil {
			table.forward([]ConnectivityChanged{wake})
		}
	}
}

func (table *networkConnectivity) read(ctx context.Context, keys []ConnectivityKey) ([]Connectivity, error) {
	return table.hub.read(ctx, keys)
}

// read loads keys in bounded batches (a map may authorize more peers than
// one store call accepts) and checks every answer.
func (hub *ConnectivityHub) read(ctx context.Context, keys []ConnectivityKey) ([]Connectivity, error) {
	readCtx, cancel := context.WithTimeout(ctx, hub.options.ReadTimeout)
	defer cancel()
	values := make([]Connectivity, 0, len(keys))
	for offset := 0; offset < len(keys); offset += connectivityResyncBatch {
		batch := keys[offset:min(offset+connectivityResyncBatch, len(keys))]
		hub.reads.Add(1)
		hub.keysRead.Add(uint64(len(batch)))
		loaded, err := hub.store.LoadConnectivity(readCtx, batch)
		if err != nil {
			return nil, err
		}
		if len(loaded) != len(batch) {
			return nil, ErrInvalidConnectivity
		}
		for index, value := range loaded {
			if !value.IsValid() || value.Key() != batch[index] {
				return nil, ErrInvalidConnectivity
			}
		}
		values = append(values, loaded...)
	}
	return values, nil
}

// apply stores values and records the Nodes whose state changed. With
// overwrite false it only fills Nodes the table lacks (or holds at an older
// generation), so a read for a newly opened stream never replaces state the
// worker read later. Only the worker overwrites, and it rereads every Node
// it is woken for, so the table converges on Redis.
func (table *networkConnectivity) apply(values []Connectivity, overwrite bool) *connectivityVersion {
	table.mu.Lock()
	defer table.mu.Unlock()
	current := table.current.Load()
	entries := current.entries
	changed := make([]node.ID, 0, len(values))
	for _, value := range values {
		stored, found := entries.get(value.key.nodeID)
		if found && (stored.key.generation > value.key.generation ||
			stored.equal(value) || !overwrite && stored.key.generation == value.key.generation) {
			continue
		}
		entries = entries.set(value)
		changed = append(changed, value.key.nodeID)
	}
	if len(changed) == 0 {
		return current
	}
	next := &connectivityVersion{table: table, seq: current.seq + 1, entries: entries}
	table.log.append(next.seq, changed)
	table.current.Store(next)
	return next
}

// forward wakes each stream of the Network once per batch, latest wins: a
// stream catches up from the change log, not from the wakeup's Node.
func (table *networkConnectivity) forward(batch []ConnectivityChanged) {
	change := batch[len(batch)-1]
	change.batched = true
	table.mu.Lock()
	defer table.mu.Unlock()
	for _, updates := range table.subscribers {
		select {
		case updates <- change:
		default:
			select {
			case <-updates:
			default:
			}
			updates <- change
		}
	}
}

// fail ends every stream of the Network when the feed itself ends, as the
// feed would.
func (table *networkConnectivity) fail() {
	table.mu.Lock()
	defer table.mu.Unlock()
	table.failed = true
	for _, updates := range table.subscribers {
		close(updates)
	}
}

// changesSince returns the Nodes changed after seq (sorted, unique), or
// false when the log no longer reaches back to seq.
func (table *networkConnectivity) changesSince(seq uint64) ([]node.ID, bool) {
	table.mu.Lock()
	defer table.mu.Unlock()
	return table.log.since(seq)
}

// view returns the latest table version holding every key, reading the
// keys the table lacks once. A Network without a table (no stream watches
// it) gets a private version read for this call alone.
func (hub *ConnectivityHub) view(ctx context.Context, networkID network.ID,
	keys []ConnectivityKey) (*connectivityVersion, error) {
	hub.mu.Lock()
	table := hub.networks[networkID]
	hub.mu.Unlock()
	if table == nil {
		return hub.privateView(ctx, keys)
	}
	if version := table.current.Load(); len(missingConnectivity(version, keys)) == 0 {
		return version, nil
	}
	table.loading.Lock()
	defer table.loading.Unlock()
	missing := missingConnectivity(table.current.Load(), keys)
	if len(missing) == 0 {
		return table.current.Load(), nil
	}
	values, err := table.read(ctx, missing)
	if err != nil {
		return nil, err
	}
	return table.apply(values, false), nil
}

func (hub *ConnectivityHub) privateView(ctx context.Context, keys []ConnectivityKey) (*connectivityVersion, error) {
	values, err := hub.read(ctx, keys)
	if err != nil {
		return nil, err
	}
	var entries connectivityMap
	for _, value := range values {
		entries = entries.set(value)
	}
	return &connectivityVersion{entries: entries}, nil
}

// missingConnectivity lists the keys version cannot answer: Nodes it lacks
// or holds at an older generation. A newer stored generation answers an
// older key as offline without endpoints, as Redis would.
func missingConnectivity(version *connectivityVersion, keys []ConnectivityKey) []ConnectivityKey {
	var missing []ConnectivityKey
	for _, key := range keys {
		if stored, found := version.entries.get(key.nodeID); !found || stored.key.generation < key.generation {
			missing = append(missing, key)
		}
	}
	return missing
}

// lookup returns key's connectivity in this version: the stored value at
// the same generation, or offline without endpoints otherwise.
func (version *connectivityVersion) lookup(key ConnectivityKey) Connectivity {
	if stored, found := version.entries.get(key.nodeID); found && stored.key == key {
		return stored
	}
	return Connectivity{key: key}
}

// changesTo returns the Nodes whose state may differ between version and
// next, or false when only a full comparison can tell.
func (version *connectivityVersion) changesTo(next *connectivityVersion) ([]node.ID, bool) {
	if version == next {
		return nil, true
	}
	if version.table == nil || version.table != next.table || next.seq < version.seq {
		return nil, false
	}
	return version.table.changesSince(version.seq)
}

// changeRing is a bounded log of (version, Node) changes.
type changeRing struct {
	seqs  []uint64
	nodes []node.ID
	start int
	count int
	floor uint64 // a reader at or above floor has every later change
}

func (ring *changeRing) append(seq uint64, changed []node.ID) {
	if ring.seqs == nil {
		ring.seqs = make([]uint64, connectivityChangeLog)
		ring.nodes = make([]node.ID, connectivityChangeLog)
	}
	for _, id := range changed {
		if ring.count == len(ring.seqs) {
			ring.floor = ring.seqs[ring.start]
			ring.start = (ring.start + 1) % len(ring.seqs)
			ring.count--
		}
		at := (ring.start + ring.count) % len(ring.seqs)
		ring.seqs[at], ring.nodes[at] = seq, id
		ring.count++
	}
}

func (ring *changeRing) since(seq uint64) ([]node.ID, bool) {
	if seq < ring.floor {
		return nil, false
	}
	var changed []node.ID
	// Entries are in seq order; scan back from the newest.
	for offset := ring.count - 1; offset >= 0; offset-- {
		at := (ring.start + offset) % len(ring.seqs)
		if ring.seqs[at] <= seq {
			break
		}
		changed = append(changed, ring.nodes[at])
	}
	slices.SortFunc(changed, compareNodeIDs)
	return slices.Compact(changed), true
}
