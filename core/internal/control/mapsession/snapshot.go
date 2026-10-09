package mapsession

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/relay"
)

const (
	maximumSafeNumericID int64 = 1<<53 - 1
	// MaximumPacketPolicyRules bounds one Node-reduced policy projection.
	MaximumPacketPolicyRules = policy.MaximumRules
)

var (
	// ErrInvalidSnapshot reports incomplete, stale, or unsafe authority evidence.
	ErrInvalidSnapshot = errors.New("map session: invalid snapshot")
	// ErrPacketPolicyLimit reports a Node projection above its configured bound.
	ErrPacketPolicyLimit = errors.New("map session: packet policy limit exceeded")
)

// SnapshotParams contains authoritative facts read in one consistent database snapshot.
type SnapshotParams struct {
	Scope                   network.Scope
	NetworkName             network.DisplayName
	NetworkRevision         int64
	RecoveryEpoch           int64
	SessionGeneration       int64
	NumericNodeID           int64
	NumericOwnerID          int64
	NodeID                  node.ID
	Hostname                node.Hostname
	MachineKey              node.MachineKey
	NodeKey                 node.Key
	Addresses               []netip.Prefix
	CreatedAt               time.Time
	KeyExpiry               time.Time
	PeerCandidates          []PeerCandidate
	DirectDeviceProjections []DirectDeviceProjection
	SharingDependencies     []network.Scope
	PacketPolicy            policy.Snapshot
	Connectivity            []Connectivity
	RelayDirectory          relay.Directory
}

// Snapshot is immutable authorization evidence for the first response of a map session.
type Snapshot struct {
	scope                   network.Scope
	networkName             network.DisplayName
	networkRevision         int64
	recoveryEpoch           int64
	sessionGeneration       int64
	numericNodeID           int64
	numericOwnerID          int64
	nodeID                  node.ID
	hostname                node.Hostname
	machineKey              node.MachineKey
	nodeKey                 node.Key
	addresses               []netip.Prefix
	createdAt               time.Time
	keyExpiry               time.Time
	peerCandidates          []PeerCandidate
	directDeviceProjections []DirectDeviceProjection
	sharingDependencies     []network.Scope
	packetPolicy            policy.Snapshot
	connectivity            []Connectivity
	relayDirectory          relay.Directory
	relayGrant              RelayGrant // set by the stream service, never by the store
}

// NewSnapshot validates and copies one authoritative map snapshot.
func NewSnapshot(params SnapshotParams) (Snapshot, error) {
	if len(params.PeerCandidates) > MaximumPeerCandidates {
		return Snapshot{}, errors.Join(ErrInvalidSnapshot, ErrPeerCandidateLimit)
	}
	params.PeerCandidates = canonicalPeerCandidates(params.PeerCandidates)
	params.DirectDeviceProjections = slices.Clone(params.DirectDeviceProjections)
	params.SharingDependencies = slices.Clone(params.SharingDependencies)
	slices.SortFunc(params.SharingDependencies, compareSharingScopes)
	slices.SortFunc(params.DirectDeviceProjections, compareDirectDeviceProjections)
	params.Connectivity = canonicalConnectivity(params.Connectivity)
	if !validSnapshotParams(params) {
		return Snapshot{}, ErrInvalidSnapshot
	}
	return Snapshot{
		scope:                   params.Scope,
		networkName:             params.NetworkName,
		networkRevision:         params.NetworkRevision,
		recoveryEpoch:           params.RecoveryEpoch,
		sessionGeneration:       params.SessionGeneration,
		numericNodeID:           params.NumericNodeID,
		numericOwnerID:          params.NumericOwnerID,
		nodeID:                  params.NodeID,
		hostname:                params.Hostname,
		machineKey:              params.MachineKey,
		nodeKey:                 params.NodeKey,
		addresses:               slices.Clone(params.Addresses),
		createdAt:               params.CreatedAt,
		keyExpiry:               params.KeyExpiry,
		peerCandidates:          params.PeerCandidates,
		directDeviceProjections: params.DirectDeviceProjections,
		sharingDependencies:     params.SharingDependencies,
		packetPolicy:            params.PacketPolicy,
		connectivity:            params.Connectivity,
		relayDirectory:          params.RelayDirectory,
	}, nil
}

// Scope returns the exact Workspace-qualified Network scope.
func (snapshot Snapshot) Scope() network.Scope { return snapshot.scope }

// NetworkName returns the presentation-only name of the authorized Network.
func (snapshot Snapshot) NetworkName() network.DisplayName { return snapshot.networkName }

// NetworkRevision returns the authoritative revision used to build this snapshot.
func (snapshot Snapshot) NetworkRevision() int64 { return snapshot.networkRevision }

// RecoveryEpoch returns the deployment recovery fence for this session.
func (snapshot Snapshot) RecoveryEpoch() int64 { return snapshot.recoveryEpoch }

// SessionGeneration returns the Node session-generation fence.
func (snapshot Snapshot) SessionGeneration() int64 { return snapshot.sessionGeneration }

// NumericNodeID returns the stable numeric control-protocol Node identifier.
func (snapshot Snapshot) NumericNodeID() int64 { return snapshot.numericNodeID }

// NumericOwnerID returns the stable numeric control-protocol owner identifier.
func (snapshot Snapshot) NumericOwnerID() int64 { return snapshot.numericOwnerID }

// NodeID returns the globally stable public Node identity.
func (snapshot Snapshot) NodeID() node.ID { return snapshot.nodeID }

// Hostname returns the canonical allocated hostname.
func (snapshot Snapshot) Hostname() node.Hostname { return snapshot.hostname }

// MachineKey returns the active machine key epoch.
func (snapshot Snapshot) MachineKey() node.MachineKey { return snapshot.machineKey }

// NodeKey returns the active Node key epoch.
func (snapshot Snapshot) NodeKey() node.Key { return snapshot.nodeKey }

// Addresses returns a caller-owned copy of active primary addresses.
func (snapshot Snapshot) Addresses() []netip.Prefix { return slices.Clone(snapshot.addresses) }

// CreatedAt returns the Node creation time.
func (snapshot Snapshot) CreatedAt() time.Time { return snapshot.createdAt }

// KeyExpiry returns the authority validity deadline for this Node key.
func (snapshot Snapshot) KeyExpiry() time.Time { return snapshot.keyExpiry }

// PeerCandidates returns a caller-owned, deterministically ordered copy of
// same-Network inventory. Candidates are not authorized peers.
func (snapshot Snapshot) PeerCandidates() []PeerCandidate {
	return slices.Clone(snapshot.peerCandidates)
}

// PacketPolicy returns the immutable exact-revision product policy snapshot.
func (snapshot Snapshot) PacketPolicy() policy.Snapshot { return snapshot.packetPolicy }

// RelayDirectory returns complete validated routing metadata. It grants no
// peer visibility, route, packet-policy, or Network membership authority.
func (snapshot Snapshot) RelayDirectory() relay.Directory { return snapshot.relayDirectory }

// ConnectivityFor returns transient state only for self or a policy-authorized
// peer in this exact snapshot. A miss is normal and grants no routing authority.
func (snapshot Snapshot) ConnectivityFor(nodeID node.ID) (Connectivity, bool) {
	index, found := slices.BinarySearchFunc(
		snapshot.connectivity,
		nodeID,
		func(value Connectivity, target node.ID) int {
			return strings.Compare(value.key.nodeID.String(), target.String())
		},
	)
	if !found {
		return Connectivity{}, false
	}
	return snapshot.connectivity[index], true
}

// WithConnectivity validates and returns a copy with non-authoritative routing
// state attached. Durable authority fields remain unchanged.
func (snapshot Snapshot) WithConnectivity(values []Connectivity) (Snapshot, error) {
	params := snapshot.params()
	params.Connectivity = values
	return NewSnapshot(params)
}

// AuthorizedPeers returns only candidates required by an explicit packet rule
// in either direction. Candidate inventory and same-Network membership alone
// never grant visibility.
func (snapshot Snapshot) AuthorizedPeers() []PeerCandidate {
	if !snapshot.IsValid() {
		return []PeerCandidate{}
	}
	peers := make([]PeerCandidate, 0, min(len(snapshot.peerCandidates), 64))
	for _, candidate := range snapshot.peerCandidates {
		if snapshot.packetPolicy.AllowsPeer(snapshot.nodeID, candidate.nodeID) {
			peers = append(peers, candidate)
		}
	}
	seen := make(map[node.ID]struct{}, len(peers))
	for _, peer := range peers {
		seen[peer.NodeID()] = struct{}{}
	}
	deadlines := make(map[node.ID]time.Time, len(snapshot.directDeviceProjections))
	for _, projection := range snapshot.directDeviceProjections {
		peer := projection.Peer()
		if _, exists := seen[peer.NodeID()]; !exists {
			peers = append(peers, peer)
			seen[peer.NodeID()] = struct{}{}
		}
		deadline, exists := deadlines[peer.NodeID()]
		if !exists || projection.ExpiresAt().Before(deadline) {
			deadlines[peer.NodeID()] = projection.ExpiresAt()
		}
	}
	for index, peer := range peers {
		if deadline, exists := deadlines[peer.NodeID()]; exists && deadline.Before(peer.keyExpiry) {
			peers[index].keyExpiry = deadline
		}
	}
	slices.SortFunc(peers, comparePeerCandidates)
	return peers
}

// IsValid reports whether the snapshot contains complete authority evidence.
func (snapshot Snapshot) IsValid() bool { return validSnapshotParams(snapshot.params()) }

func (snapshot Snapshot) params() SnapshotParams {
	return SnapshotParams{
		Scope:                   snapshot.scope,
		NetworkName:             snapshot.networkName,
		NetworkRevision:         snapshot.networkRevision,
		RecoveryEpoch:           snapshot.recoveryEpoch,
		SessionGeneration:       snapshot.sessionGeneration,
		NumericNodeID:           snapshot.numericNodeID,
		NumericOwnerID:          snapshot.numericOwnerID,
		NodeID:                  snapshot.nodeID,
		Hostname:                snapshot.hostname,
		MachineKey:              snapshot.machineKey,
		NodeKey:                 snapshot.nodeKey,
		Addresses:               slices.Clone(snapshot.addresses),
		CreatedAt:               snapshot.createdAt,
		KeyExpiry:               snapshot.keyExpiry,
		PeerCandidates:          slices.Clone(snapshot.peerCandidates),
		DirectDeviceProjections: slices.Clone(snapshot.directDeviceProjections),
		SharingDependencies:     slices.Clone(snapshot.sharingDependencies),
		PacketPolicy:            snapshot.packetPolicy,
		Connectivity:            slices.Clone(snapshot.connectivity),
		RelayDirectory:          snapshot.relayDirectory,
	}
}

func validSnapshotParams(params SnapshotParams) bool {
	return params.Scope.IsValid() && params.NetworkName.IsValid() && params.NetworkRevision > 0 &&
		params.RecoveryEpoch > 0 &&
		params.SessionGeneration > 0 && validNumericID(params.NumericNodeID) &&
		validNumericID(params.NumericOwnerID) && params.NodeID.IsValid() &&
		params.Hostname.IsValid() && params.MachineKey.IsValid() && params.NodeKey.IsValid() &&
		validSnapshotAddresses(params.Addresses) && !params.CreatedAt.IsZero() &&
		params.KeyExpiry.After(params.CreatedAt) && validSnapshotPeerCandidates(
		params.PeerCandidates,
		params.Scope,
		params.NodeID,
		params.NumericNodeID,
		params.MachineKey,
		params.NodeKey,
	) && params.PacketPolicy.IsValid() && params.PacketPolicy.Scope() == params.Scope &&
		validSharingDependencies(params) && validDirectDeviceProjections(params) && validSnapshotConnectivity(params) && params.RelayDirectory.IsValid()
}

func validSnapshotConnectivity(params SnapshotParams) bool {
	if params.Connectivity == nil || len(params.Connectivity) > len(params.PeerCandidates)+len(params.DirectDeviceProjections)+1 {
		return params.Connectivity == nil
	}
	allowed := map[node.ID]int64{params.NodeID: params.SessionGeneration}
	for _, candidate := range params.PeerCandidates {
		if params.PacketPolicy.AllowsPeer(params.NodeID, candidate.NodeID()) {
			allowed[candidate.NodeID()] = candidate.SessionGeneration()
		}
	}
	for _, projection := range params.DirectDeviceProjections {
		peer := projection.Peer()
		allowed[peer.NodeID()] = peer.SessionGeneration()
	}
	for index, connectivity := range params.Connectivity {
		if !connectivity.IsValid() || allowed[connectivity.key.nodeID] != connectivity.key.generation ||
			index > 0 && params.Connectivity[index-1].key.nodeID.String() >= connectivity.key.nodeID.String() {
			return false
		}
	}
	return true
}

func validNumericID(value int64) bool { return value > 0 && value <= maximumSafeNumericID }

func validSnapshotAddresses(addresses []netip.Prefix) bool {
	if len(addresses) == 0 || len(addresses) > 2 {
		return false
	}
	seenIPv4 := false
	seenIPv6 := false
	for _, prefix := range addresses {
		address := prefix.Addr()
		if !prefix.IsValid() || !address.IsValid() || address.IsUnspecified() ||
			prefix.Bits() != address.BitLen() {
			return false
		}
		if address.Is4() {
			if seenIPv4 {
				return false
			}
			seenIPv4 = true
			continue
		}
		if seenIPv6 {
			return false
		}
		seenIPv6 = true
	}
	return true
}
