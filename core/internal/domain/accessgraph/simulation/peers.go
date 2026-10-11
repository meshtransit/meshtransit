package simulation

import (
	"errors"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy/publication"
)

// PeerEstimate is how many peers a policy puts in each Device's map: every
// Device a rule pairs it with, in either direction. It is computed per
// rule side, without expanding group rules into Device pairs, so it works
// for policies far too large to simulate Device by Device. Device rules
// count exactly; a group rule adds the size of its other side, so with
// group rules the counts are upper bounds (a peer two rules both name is
// counted twice).
type PeerEstimate struct {
	bounds map[node.ID]int
	exact  bool
}

// MaxPeers returns the largest count over all Devices.
func (estimate PeerEstimate) MaxPeers() int {
	largest := 0
	for _, bound := range estimate.bounds {
		largest = max(largest, bound)
	}
	return largest
}

// DevicesOver returns how many Devices have more than threshold peers.
func (estimate PeerEstimate) DevicesOver(threshold int) int {
	count := 0
	for _, bound := range estimate.bounds {
		if bound > threshold {
			count++
		}
	}
	return count
}

// Exact reports whether the counts are exact (no group rule took part).
func (estimate PeerEstimate) Exact() bool { return estimate.exact }

// estimatePeers counts each Device's peers under candidate, with group
// membership from members.
func estimatePeers(candidate publication.Candidate, members map[publication.RuleSide][]node.ID) PeerEstimate {
	exactPeers := make(map[node.ID]map[node.ID]struct{})
	pair := func(first, second node.ID) {
		if first == second {
			return
		}
		for _, edge := range [][2]node.ID{{first, second}, {second, first}} {
			if exactPeers[edge[0]] == nil {
				exactPeers[edge[0]] = make(map[node.ID]struct{})
			}
			exactPeers[edge[0]][edge[1]] = struct{}{}
		}
	}
	for _, rule := range candidate.Snapshot().Rules() {
		pair(rule.SourceNodeID(), rule.DestinationNodeID())
	}
	bounds := make(map[node.ID]int, len(exactPeers))
	for device, peers := range exactPeers {
		bounds[device] = len(peers)
	}
	side := func(selected publication.RuleSide) []node.ID {
		if selected.Kind() == publication.SideDevice {
			return []node.ID{node.ID(selected.ID())}
		}
		return members[selected]
	}
	groupRules := candidate.GroupRules()
	for _, groupRule := range groupRules {
		sources, destinations := side(groupRule.Source()), side(groupRule.Destination())
		inDestinations := make(map[node.ID]struct{}, len(destinations))
		for _, destination := range destinations {
			inDestinations[destination] = struct{}{}
		}
		inSources := make(map[node.ID]struct{}, len(sources))
		for _, source := range sources {
			inSources[source] = struct{}{}
			others := len(destinations)
			if _, both := inDestinations[source]; both {
				others-- // never its own peer
			}
			bounds[source] += others
		}
		for _, destination := range destinations {
			others := len(sources)
			if _, both := inSources[destination]; both {
				others--
			}
			bounds[destination] += others
		}
	}
	return PeerEstimate{bounds: bounds, exact: len(groupRules) == 0}
}

// TooLargeError is ErrTooLarge with the peer estimate, which needs no
// Device-by-Device expansion.
type TooLargeError struct {
	Peers PeerEstimate
}

func (*TooLargeError) Error() string { return ErrTooLarge.Error() }

// Is makes errors.Is(err, ErrTooLarge) hold.
func (*TooLargeError) Is(target error) bool { return target == ErrTooLarge }

// PeerEstimateOf returns the estimate an ErrTooLarge carries.
func PeerEstimateOf(err error) (PeerEstimate, bool) {
	var tooLarge *TooLargeError
	if errors.As(err, &tooLarge) {
		return tooLarge.Peers, true
	}
	return PeerEstimate{}, false
}

// withPeerEstimate attaches the estimate to an ErrTooLarge.
func withPeerEstimate(err error, peers PeerEstimate) error {
	if errors.Is(err, ErrTooLarge) {
		return &TooLargeError{Peers: peers}
	}
	return err
}
