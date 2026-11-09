// Package networksummary keeps one summary row per Network current, so the
// Console reads a page of Networks in one request instead of six per Network
// (docs/console-load-design.md §5, TD-CON-43/48).
//
// Writers mark a Network dirty (database triggers). The worker claims dirty
// Networks, and Networks whose figures change with time, counts each one in
// a read-only snapshot, and stores the result only if it is newer than the
// stored one.
package networksummary

import (
	"errors"
	"net/netip"
	"time"
)

// ErrInvalidSummary rejects a computed summary that cannot be true.
var ErrInvalidSummary = errors.New("network summary: invalid summary")

// Peer is the shares of one Network with one other side.
type Peer struct {
	Direction string // "outgoing" or "incoming"
	// PeerWorkspaceID and PeerNetworkID are database keys; PeerNetworkID is
	// 0 when the peer is another Workspace as a whole.
	PeerWorkspaceID, PeerNetworkID int64
	Active, Waiting                int
}

// Summary is one Network's figures as of one snapshot. The keys are the
// database's own: a summary never leaves the worker and its store.
type Summary struct {
	WorkspaceID, NetworkID           int64
	NetworkRevision, DirtyGeneration int64
	EvaluatedAt                      time.Time
	IPv4Prefix                       netip.Prefix // zero when the Network has no IPv4 range
	AddressesCapacity                int64
	AddressesInUse, AddressesHeld    int64
	ActiveDevices, RuleCount         int64
	PolicyRevision                   int64
	PolicyPublishedAt                time.Time // zero before the first release
	SharesOutActive, SharesInActive  int
	OffersWaiting, PendingApprovals  int
	Sites, KubernetesClusters        int
	// RecomputeAt is the next instant a figure changes with time; zero
	// when none does.
	RecomputeAt time.Time
	Peers       []Peer
}

// Validate refuses figures no snapshot can produce.
func (summary Summary) Validate() error {
	counts := []int64{summary.AddressesInUse, summary.AddressesHeld, summary.ActiveDevices, summary.RuleCount,
		int64(summary.SharesOutActive), int64(summary.SharesInActive), int64(summary.OffersWaiting),
		int64(summary.PendingApprovals), int64(summary.Sites), int64(summary.KubernetesClusters)}
	for _, count := range counts {
		if count < 0 {
			return ErrInvalidSummary
		}
	}
	if summary.WorkspaceID <= 0 || summary.NetworkID <= 0 || summary.NetworkRevision <= 0 ||
		summary.DirtyGeneration <= 0 || summary.PolicyRevision <= 0 || summary.EvaluatedAt.IsZero() {
		return ErrInvalidSummary
	}
	if summary.IPv4Prefix.IsValid() {
		if !summary.IPv4Prefix.Addr().Is4() || summary.IPv4Prefix.Bits() > 30 ||
			summary.AddressesCapacity != int64(1)<<(32-summary.IPv4Prefix.Bits())-2 ||
			summary.AddressesInUse+summary.AddressesHeld > summary.AddressesCapacity {
			return ErrInvalidSummary
		}
	} else if summary.AddressesCapacity != 0 || summary.AddressesInUse != 0 || summary.AddressesHeld != 0 {
		return ErrInvalidSummary
	}
	if !summary.RecomputeAt.IsZero() && !summary.RecomputeAt.After(summary.EvaluatedAt) {
		return ErrInvalidSummary
	}
	for _, peer := range summary.Peers {
		sameWorkspace := peer.PeerWorkspaceID == summary.WorkspaceID
		validPeer := (peer.Direction == "outgoing" || peer.Direction == "incoming") && peer.PeerWorkspaceID > 0 &&
			peer.Active >= 0 && peer.Waiting >= 0 && peer.Active+peer.Waiting > 0 &&
			(sameWorkspace && peer.PeerNetworkID > 0 && peer.PeerNetworkID != summary.NetworkID ||
				!sameWorkspace && peer.PeerNetworkID == 0)
		if !validPeer {
			return ErrInvalidSummary
		}
	}
	return nil
}
