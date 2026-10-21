package mapsession

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/node"
)

// ExitAssignmentVersion is the assignment of spread pools this Core
// computes (exit node design §16.4); a pool stored with another is served
// as failover.
const ExitAssignmentVersion = 1

// exitSpreadDomain separates spread scores from any other use of the hash.
const exitSpreadDomain = "meshtransit/exit-spread/v1"

// exitSpreadScore is a consumer's rendezvous score for one exit node: the
// first eight bytes, big-endian, of SHA-256 over the domain, the pool's
// salt, the consumer and the exit node.
func exitSpreadScore(salt [16]byte, consumer, exitNode node.ID) uint64 {
	hash := sha256.New()
	hash.Write([]byte(exitSpreadDomain))
	hash.Write(salt[:])
	hash.Write(consumer[:])
	hash.Write(exitNode[:])
	return binary.BigEndian.Uint64(hash.Sum(nil)[:8])
}

// spreadRoute gives a consumer of a spread pool its own exit node: the
// member of the serving set with the highest score among those that can
// serve and whose consumer window holds the consumer, and orders the
// candidates by priority tier, then serving set first, then score. It
// reports false, leaving route unchanged, when no member of the set can take
// the consumer: the pool then serves it as failover.
func (inner *networkPolicy) spreadRoute(route *ExitPoolRoute, entry *exitPoolEntry, self int64,
	now time.Time) bool {
	consumer, known := inner.devices[self]
	if !known || !consumer.NodeID.IsValid() {
		return false
	}
	index := inner.routes
	scores := make(map[node.ID]uint64, len(entry.nodes))
	serving := make(map[node.ID]bool, len(entry.pool.Serving))
	var assigned ExitNode
	var best uint64
	for _, exitNode := range entry.nodes {
		score := exitSpreadScore(entry.pool.Salt, consumer.NodeID, exitNode.NodeID)
		scores[exitNode.NodeID] = score
		if !exitNode.Active || !slices.Contains(entry.pool.Serving, exitNode.Device) {
			continue
		}
		serving[exitNode.NodeID] = true
		position, found := slices.BinarySearch(index.static[exitNode.Device], self)
		if !inner.exitServes(exitNode, now) || !found || position >= index.consumers {
			continue
		}
		if !assigned.NodeID.IsValid() || score > best {
			assigned, best = exitNode, score
		}
	}
	if !assigned.NodeID.IsValid() {
		return false
	}
	priority := make(map[node.ID]int, len(entry.nodes))
	for _, exitNode := range entry.nodes {
		priority[exitNode.NodeID] = exitNode.Priority
	}
	slices.SortFunc(route.Candidates, func(first, second node.ID) int {
		return cmp.Or(cmp.Compare(priority[first], priority[second]),
			-cmp.Compare(boolRank(serving[first]), boolRank(serving[second])),
			-cmp.Compare(scores[first], scores[second]))
	})
	route.Spread, route.Primary, route.Status = true, assigned.NodeID, RouteServed
	return true
}

func boolRank(value bool) int {
	if value {
		return 1
	}
	return 0
}
