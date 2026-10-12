package mapsession

import (
	"cmp"
	"slices"

	"meshtransit.net/core/internal/domain/node"
)

// DefaultPeerLimit bounds how many peers one map carries. A Device whose
// policy authorizes more receives a prioritized subset: no map grows beyond
// what Core and the client can hold, and since packet rules only allow,
// leaving a peer out can never widen access.
const DefaultPeerLimit = 10_000

// LegacyPeerLimit bounds the maps of clients that do not declare large maps
// (MTCP map.large1): those reject, and so lose, a map of more than 256 peers,
// alias peers or shared Devices.
const LegacyPeerLimit = 256

// sessionPeerLimit is the peer bound of one session: the Service's limit,
// and at most LegacyPeerLimit for a client that did not declare large maps.
func (options ServiceOptions) sessionPeerLimit(request Request) int {
	if request.LargeMap() {
		return options.peerLimit()
	}
	return min(options.peerLimit(), LegacyPeerLimit)
}

// withSessionLimit bounds the snapshot to limit peers, shared Devices
// included. Shares come first, oldest contract first (projections are sorted
// by contract ID, a UUIDv7), so an accepted share keeps its place when newer
// ones arrive; peers of the Network fill what remains by peerRank. The map
// reports what it left out.
func (snapshot Snapshot) withSessionLimit(limit int) (Snapshot, error) {
	if limit <= 0 {
		return snapshot, nil
	}
	if len(snapshot.directDeviceProjections) > limit {
		// The shares left out count once, in omittedShares, which survives
		// the rebuilds that recompute the authorized peers.
		params := snapshot.params()
		params.DirectDeviceProjections = params.DirectDeviceProjections[:limit]
		params.OmittedShares = snapshot.omittedShares + len(snapshot.directDeviceProjections) - limit
		next, err := NewSnapshot(params)
		if err != nil {
			return Snapshot{}, err
		}
		next.relayGrant = snapshot.relayGrant
		next.peerLimit = snapshot.peerLimit
		snapshot = next
	}
	return snapshot.withPeerLimit(limit), nil
}

// peerRank orders peers for a limited map: explicit Device shares first,
// then peers online now, then the rest.
func (snapshot Snapshot) peerRank(peer PeerCandidate, shared map[node.ID]struct{}) int {
	if _, explicit := shared[peer.nodeID]; explicit {
		return 0
	}
	if connectivity, found := snapshot.ConnectivityFor(peer.nodeID); found && connectivity.Online() {
		return 1
	}
	return 2
}

// withPeerLimit returns the snapshot with at most limit authorized peers,
// chosen by peerRank and then by stable numeric identifier, so a map does
// not churn between refreshes. It needs connectivity attached (presence
// ranks peers). Zero or a map within the limit returns the snapshot as is.
func (snapshot Snapshot) withPeerLimit(limit int) Snapshot {
	if limit <= 0 || len(snapshot.authorized) <= limit {
		return snapshot
	}
	shared := make(map[node.ID]struct{}, len(snapshot.directDeviceProjections))
	for _, projection := range snapshot.directDeviceProjections {
		shared[projection.Peer().nodeID] = struct{}{}
	}
	type ranked struct {
		peer PeerCandidate
		rank int
	}
	peers := make([]ranked, len(snapshot.authorized))
	for index, peer := range snapshot.authorized {
		peers[index] = ranked{peer: peer, rank: snapshot.peerRank(peer, shared)}
	}
	slices.SortFunc(peers, func(left, right ranked) int {
		return cmp.Or(cmp.Compare(left.rank, right.rank), cmp.Compare(left.peer.numericNodeID, right.peer.numericNodeID))
	})
	selected := make([]PeerCandidate, limit)
	for index := range selected {
		selected[index] = peers[index].peer
	}
	slices.SortFunc(selected, comparePeerCandidates)

	snapshot.authorizedTotal = max(snapshot.authorizedTotal, len(snapshot.authorized))
	snapshot.authorized = selected
	if snapshot.connectivity != nil {
		// A private read keeps only self and the selected peers.
		kept := make([]Connectivity, 0, limit+1)
		for _, value := range snapshot.connectivity {
			if value.key.nodeID == snapshot.nodeID {
				kept = append(kept, value)
				continue
			}
			if _, found := snapshot.authorizedPeer(value.key.nodeID); found {
				kept = append(kept, value)
			}
		}
		snapshot.connectivity = kept
	}
	return snapshot
}

// PeerLimit reports how many peers the map carries and how many the policy
// and the accepted shares authorize, counting each share left out as one
// (shares left out by a store are a lower bound); they differ only for a
// limited map.
func (snapshot Snapshot) PeerLimit() (sent, authorized int) {
	sent = len(snapshot.authorized)
	return sent, max(snapshot.authorizedTotal, sent) + snapshot.omittedShares
}

// SharesInventory reports whether the snapshot's candidates are exactly
// inventory (the same shared object, not merely equal contents).
func (snapshot Snapshot) SharesInventory(inventory NetworkInventory) bool {
	return snapshot.candidates.shared && snapshot.candidates.sharedInventory().Same(inventory)
}

// IsPeerLimited reports whether a peer limit cut the snapshot's peers; such
// a map is rechosen at every full refresh (presence ranks its peers).
func (snapshot Snapshot) IsPeerLimited() bool {
	return snapshot.authorizedTotal > len(snapshot.authorized) || snapshot.omittedShares > 0
}

// sameAuthorizedPeers reports whether two maps carry the same peers: O(1)
// for copies of one snapshot (a connectivity-only move), a full comparison
// otherwise.
func sameAuthorizedPeers(current, next Snapshot) bool {
	if len(current.authorized) != len(next.authorized) {
		return false
	}
	if len(current.authorized) == 0 || &current.authorized[0] == &next.authorized[0] {
		return true
	}
	return equalPeerCandidates(current.authorized, next.authorized)
}
