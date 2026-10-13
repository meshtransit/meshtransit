package mapsession

import (
	"slices"
	"sync/atomic"

	"meshtransit.net/core/internal/domain/node"
)

// ConnectivityInterest names the Nodes of one Network whose connectivity
// changes wake a stream: every Node, or a few named ones (the stream's self
// and its authorized peers). It is a hint filter, never authority: a stream
// that is not woken for a change keeps what it showed until its next
// refresh, and a stream that changes its interest catches up from the
// table's latest version.
type ConnectivityInterest struct {
	all   bool
	nodes []node.ID // sorted, unique
}

// AllConnectivity wakes a stream for every change of the Network.
func AllConnectivity() ConnectivityInterest { return ConnectivityInterest{all: true} }

// ConnectivityOf wakes a stream for changes of the given Nodes only.
func ConnectivityOf(nodes []node.ID) ConnectivityInterest {
	sorted := slices.Clone(nodes)
	slices.SortFunc(sorted, compareNodeIDs)
	return ConnectivityInterest{nodes: slices.Compact(sorted)}
}

// Equal reports whether both interests wake for the same Nodes.
func (interest ConnectivityInterest) Equal(other ConnectivityInterest) bool {
	return interest.all == other.all && slices.Equal(interest.nodes, other.nodes)
}

// wants reports whether a change of the sorted Nodes changed concerns the
// stream; nil changed stands for an unknown set, which concerns everyone.
func (interest ConnectivityInterest) wants(changed []node.ID) bool {
	if interest.all || changed == nil {
		return true
	}
	for left, right := 0, 0; left < len(interest.nodes) && right < len(changed); {
		switch order := compareNodeIDs(interest.nodes[left], changed[right]); {
		case order == 0:
			return true
		case order < 0:
			left++
		default:
			right++
		}
	}
	return false
}

// streamConnectivityInterest is what the stream of snapshot compares when
// its Network's connectivity changes (connectivityCandidates): self and its
// authorized peers, or, for a map with many peers, every Node.
func streamConnectivityInterest(snapshot Snapshot) ConnectivityInterest {
	if len(snapshot.authorized) >= directConnectivityPeers {
		return AllConnectivity()
	}
	nodes := make([]node.ID, 0, len(snapshot.authorized)+1)
	nodes = append(nodes, snapshot.nodeID)
	for _, peer := range snapshot.authorized {
		nodes = append(nodes, peer.nodeID)
	}
	return ConnectivityOf(nodes)
}

// connectivitySubscriber is one stream's wakeup channel and interest.
type connectivitySubscriber struct {
	updates  chan ConnectivityChanged
	interest atomic.Pointer[ConnectivityInterest]
}

func (subscriber *connectivitySubscriber) setInterest(interest ConnectivityInterest) {
	subscriber.interest.Store(&interest)
}

func (subscriber *connectivitySubscriber) wants(changed []node.ID) bool {
	interest := subscriber.interest.Load()
	return interest == nil || interest.wants(changed)
}
