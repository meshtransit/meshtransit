package server

import (
	"sync"
	"time"

	"meshtransit.net/relay/internal/ratelimit"
	"meshtransit.net/shared/mtrp"
)

const (
	// idleNetworkBudget is how long a Network's bucket outlives its last
	// frame; a bucket that full again carries no state worth keeping.
	idleNetworkBudget = time.Minute
	// pruneNetworkBudgets is how often the janitor forgets idle buckets.
	pruneNetworkBudgets = 10 * time.Second
	// networkBudgetShards spreads the buckets over locks, so frames of
	// different Networks from the UDP readers rarely wait for each other.
	networkBudgetShards = 32
)

// networkBudgets bounds the bytes all sessions of one Network forward
// through this relay node (mtrp-v1 §7), so one Network cannot take a
// shared relay's capacity from the others. The Network is the sender's:
// the Network zone of its ticket, even when a Trust Contract authorised
// the route. Relay nodes share no state, so the budget is per node.
type networkBudgets struct {
	rate   float64
	shards [networkBudgetShards]networkBudgetShard

	pruneMu sync.Mutex
	pruned  time.Time
}

type networkBudgetShard struct {
	mu      sync.Mutex
	buckets map[[16]byte]*networkBucket
}

type networkBucket struct {
	bucket ratelimit.Bucket
	used   time.Time
}

func newNetworkBudgets(rate float64) *networkBudgets {
	budgets := &networkBudgets{rate: rate}
	for index := range budgets.shards {
		budgets.shards[index].buckets = make(map[[16]byte]*networkBucket)
	}
	return budgets
}

// shard picks a Network's lock. Network IDs end in random bits (UUIDv7).
func (budgets *networkBudgets) shard(network [16]byte) *networkBudgetShard {
	return &budgets.shards[int(network[15])%networkBudgetShards]
}

// allow charges n bytes of the Network to its budget.
func (budgets *networkBudgets) allow(network [16]byte, n int, now time.Time) bool {
	shard := budgets.shard(network)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	entry := shard.buckets[network]
	if entry == nil {
		entry = &networkBucket{bucket: ratelimit.NewBucket(budgets.rate, budgets.rate)}
		shard.buckets[network] = entry
	}
	entry.used = now
	return entry.bucket.Allow(now, float64(n))
}

// prune forgets the buckets of Networks idle for idleNetworkBudget, at most
// every pruneNetworkBudgets; the janitor runs it. One shard is locked at a
// time, so forwarding waits for a fraction of the scan at most.
func (budgets *networkBudgets) prune(now time.Time) {
	budgets.pruneMu.Lock()
	due := now.Sub(budgets.pruned) >= pruneNetworkBudgets
	if due {
		budgets.pruned = now
	}
	budgets.pruneMu.Unlock()
	if !due {
		return
	}
	for index := range budgets.shards {
		shard := &budgets.shards[index]
		shard.mu.Lock()
		for network, entry := range shard.buckets {
			if now.Sub(entry.used) >= idleNetworkBudget {
				delete(shard.buckets, network)
			}
		}
		shard.mu.Unlock()
	}
}

// networkZone returns the Network a ticket's traffic is charged to: zones
// are sorted by kind, so a Network zone, kind 1, comes first (mtrp-v1 §6).
// Core puts one in every ticket; one without shares the all-zero budget,
// so it is still bounded.
func networkZone(ticket mtrp.Ticket) [16]byte {
	if len(ticket.Zones) == 0 || ticket.Zones[0].Kind != mtrp.ZoneNetwork {
		return [16]byte{}
	}
	return ticket.Zones[0].ID
}
