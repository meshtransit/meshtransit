package distribution

import (
	"time"

	"meshtransit.net/core/internal/domain/node"
)

// MaximumPathPeers bounds the peers one stored path report keeps; the
// busiest peers are kept.
const MaximumPathPeers = 256

// PathKind is how a Device's traffic reaches a peer.
type PathKind string

const (
	// PathDirect sends straight to the peer.
	PathDirect PathKind = "direct"
	// PathRelay sends through a relay.
	PathRelay PathKind = "relay"
	// PathUnknown has no path installed yet.
	PathUnknown PathKind = "unknown"
)

// RelayReason explains a relayed path, as the Device sees it.
type RelayReason string

const (
	// RelayBootstrap means direct candidates are still being probed.
	RelayBootstrap RelayReason = "bootstrap"
	// RelayNoCandidates means the peer offers no direct candidate.
	RelayNoCandidates RelayReason = "no_candidates"
	// RelayNoResponse means direct probes went unanswered (filtered UDP or
	// a hard NAT on either side).
	RelayNoResponse RelayReason = "no_response"
)

// PeerPath is one peer's path over a report interval.
type PeerPath struct {
	PeerID node.ID
	// External marks a peer of another Network (a share): its identity is
	// never shown to this Network's viewers.
	External    bool
	Kind        PathKind
	RelayRegion int
	RelayCode   string // the region's code, when the relay directory names it
	RelayReason RelayReason
	DirectBytes uint64 // sent and received
	RelayBytes  uint64
}

// PathReport is the latest path report of a Device's session.
type PathReport struct {
	ReportedAt time.Time
	Interval   time.Duration
	Peers      []PeerPath
}

// IsValid reports a bounded, self-consistent report.
func (report PathReport) IsValid() bool {
	if report.ReportedAt.IsZero() || report.Interval <= 0 || report.Interval > time.Hour ||
		len(report.Peers) > MaximumPathPeers {
		return false
	}
	for _, peer := range report.Peers {
		switch {
		case !peer.PeerID.IsValid(), len(peer.RelayCode) > 32:
			return false
		case peer.Kind == PathRelay:
			if peer.RelayRegion < 0 || peer.RelayRegion > 65535 {
				return false
			}
		case peer.Kind == PathDirect, peer.Kind == PathUnknown:
			if peer.RelayRegion != 0 || peer.RelayCode != "" || peer.RelayReason != "" {
				return false
			}
		default:
			return false
		}
	}
	return true
}
