package mapsession

import (
	"errors"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

const (
	// MaximumPeerCandidates is the absolute safety ceiling for one unfiltered
	// Network candidate projection. Exceeding it fails the snapshot closed.
	MaximumPeerCandidates = 10_000
)

var (
	// ErrInvalidPeerCandidate reports incomplete or unsafe durable peer evidence.
	ErrInvalidPeerCandidate = errors.New("map session: invalid peer candidate")
	// ErrPeerCandidateLimit reports a candidate set that exceeded its configured bound.
	ErrPeerCandidateLimit = errors.New("map session: peer candidate limit exceeded")
)

// PeerCandidateParams contains durable, protocol-independent facts for one
// same-Network Node that may be considered by a later policy decision.
type PeerCandidateParams struct {
	NumericNodeID  int64
	NumericOwnerID int64
	Scope          network.Scope
	NodeID         node.ID
	OwnerID        identity.PrincipalID
	Hostname       node.Hostname
	// DNSLabel is the first label of the Device's name in its Network's
	// zone; the zero value means the store gave none (no name is published).
	DNSLabel          node.DNSLabel
	MachineKey        node.MachineKey
	NodeKey           node.Key
	SessionGeneration int64
	Addresses         []netip.Prefix
	CreatedAt         time.Time
	KeyExpiry         time.Time
}

// PeerCandidate is immutable durable inventory, not an authorization grant.
// Presence, endpoints, routes, and packet visibility are deliberately absent.
type PeerCandidate struct {
	numericNodeID     int64
	numericOwnerID    int64
	scope             network.Scope
	nodeID            node.ID
	ownerID           identity.PrincipalID
	hostname          node.Hostname
	dnsLabel          node.DNSLabel
	machineKey        node.MachineKey
	nodeKey           node.Key
	sessionGeneration int64
	addresses         []netip.Prefix
	createdAt         time.Time
	keyExpiry         time.Time
}

// NewPeerCandidate validates and copies one same-Network candidate.
func NewPeerCandidate(params PeerCandidateParams) (PeerCandidate, error) {
	if !validPeerCandidateParams(params) {
		return PeerCandidate{}, ErrInvalidPeerCandidate
	}
	return PeerCandidate{
		numericNodeID:     params.NumericNodeID,
		numericOwnerID:    params.NumericOwnerID,
		scope:             params.Scope,
		nodeID:            params.NodeID,
		ownerID:           params.OwnerID,
		hostname:          params.Hostname,
		dnsLabel:          params.DNSLabel,
		machineKey:        params.MachineKey,
		nodeKey:           params.NodeKey,
		sessionGeneration: params.SessionGeneration,
		addresses:         slices.Clone(params.Addresses),
		createdAt:         params.CreatedAt,
		keyExpiry:         params.KeyExpiry,
	}, nil
}

// NumericNodeID returns the stable numeric control-protocol Node identifier.
func (candidate PeerCandidate) NumericNodeID() int64 { return candidate.numericNodeID }

// NumericOwnerID returns the stable numeric control-protocol owner identifier.
func (candidate PeerCandidate) NumericOwnerID() int64 { return candidate.numericOwnerID }

// Scope returns the exact Workspace-qualified Network scope.
func (candidate PeerCandidate) Scope() network.Scope { return candidate.scope }

// NodeID returns the stable public Node identity.
func (candidate PeerCandidate) NodeID() node.ID { return candidate.nodeID }

// OwnerID returns the stable public owner identity.
func (candidate PeerCandidate) OwnerID() identity.PrincipalID { return candidate.ownerID }

// Hostname returns the canonical allocated hostname.
func (candidate PeerCandidate) Hostname() node.Hostname { return candidate.hostname }

// DNSLabel returns the first label of the Device's name in its Network's
// zone, and whether the store gave one.
func (candidate PeerCandidate) DNSLabel() (node.DNSLabel, bool) {
	return candidate.dnsLabel, candidate.dnsLabel.IsValid()
}

// MachineKey returns the active machine-key epoch.
func (candidate PeerCandidate) MachineKey() node.MachineKey { return candidate.machineKey }

// NodeKey returns the active Node-key epoch.
func (candidate PeerCandidate) NodeKey() node.Key { return candidate.nodeKey }

// SessionGeneration returns the durable fence used for transient observations.
func (candidate PeerCandidate) SessionGeneration() int64 { return candidate.sessionGeneration }

// Addresses returns a caller-owned copy of active primary addresses.
func (candidate PeerCandidate) Addresses() []netip.Prefix { return slices.Clone(candidate.addresses) }

// CreatedAt returns the logical Node creation time.
func (candidate PeerCandidate) CreatedAt() time.Time { return candidate.createdAt }

// KeyExpiry returns the exclusive durable authority deadline.
func (candidate PeerCandidate) KeyExpiry() time.Time { return candidate.keyExpiry }

// IsValid reports whether the candidate contains complete durable evidence.
func (candidate PeerCandidate) IsValid() bool {
	return validPeerCandidateParams(candidate.params())
}

func (candidate PeerCandidate) params() PeerCandidateParams {
	return PeerCandidateParams{
		NumericNodeID:     candidate.numericNodeID,
		NumericOwnerID:    candidate.numericOwnerID,
		Scope:             candidate.scope,
		NodeID:            candidate.nodeID,
		OwnerID:           candidate.ownerID,
		Hostname:          candidate.hostname,
		DNSLabel:          candidate.dnsLabel,
		MachineKey:        candidate.machineKey,
		NodeKey:           candidate.nodeKey,
		SessionGeneration: candidate.sessionGeneration,
		Addresses:         slices.Clone(candidate.addresses),
		CreatedAt:         candidate.createdAt,
		KeyExpiry:         candidate.keyExpiry,
	}
}

func validPeerCandidateParams(params PeerCandidateParams) bool {
	return validNumericID(params.NumericNodeID) && validNumericID(params.NumericOwnerID) &&
		params.Scope.IsValid() && params.NodeID.IsValid() && params.OwnerID.IsValid() &&
		params.Hostname.IsValid() && (params.DNSLabel == node.DNSLabel{} || params.DNSLabel.IsValid()) &&
		params.MachineKey.IsValid() && params.NodeKey.IsValid() &&
		params.SessionGeneration > 0 && validSnapshotAddresses(params.Addresses) &&
		!params.CreatedAt.IsZero() && params.KeyExpiry.After(params.CreatedAt)
}

func canonicalPeerCandidates(candidates []PeerCandidate) []PeerCandidate {
	canonical := make([]PeerCandidate, len(candidates))
	copy(canonical, candidates)
	slices.SortFunc(canonical, comparePeerCandidates)
	return canonical
}

func comparePeerCandidates(first, second PeerCandidate) int {
	return compareNodeIDs(first.nodeID, second.nodeID)
}

func equalPeerCandidates(first, second []PeerCandidate) bool {
	return slices.EqualFunc(first, second, func(left, right PeerCandidate) bool {
		return left.numericNodeID == right.numericNodeID &&
			left.numericOwnerID == right.numericOwnerID &&
			left.scope == right.scope && left.nodeID == right.nodeID &&
			left.ownerID == right.ownerID && left.hostname == right.hostname &&
			left.dnsLabel == right.dnsLabel &&
			left.machineKey == right.machineKey && left.nodeKey == right.nodeKey &&
			left.sessionGeneration == right.sessionGeneration &&
			slices.Equal(left.addresses, right.addresses) &&
			left.createdAt.Equal(right.createdAt) && left.keyExpiry.Equal(right.keyExpiry)
	})
}
