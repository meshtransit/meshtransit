package mapsession

import (
	"errors"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/identity"
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
	Scope             network.Scope
	NetworkName       network.DisplayName
	NetworkRevision   int64
	RecoveryEpoch     int64
	SessionGeneration int64
	NumericNodeID     int64
	NumericOwnerID    int64
	NodeID            node.ID
	Hostname          node.Hostname
	// DNSLabel and the Workspace and Network display codes name the Device
	// <label>.<workspace code>.<network code>.<suffix>. Zero values mean the
	// store gave none: the map then publishes no Device names.
	DNSLabel      node.DNSLabel
	WorkspaceCode identity.DisplayCode
	NetworkCode   identity.DisplayCode
	MachineKey    node.MachineKey
	NodeKey       node.Key
	Addresses     []netip.Prefix
	CreatedAt     time.Time
	KeyExpiry     time.Time
	// PeerCandidates lists the other Devices of the Network. When it is nil,
	// Inventory (the whole Network, self included) provides them instead and
	// is shared, not copied.
	PeerCandidates          []PeerCandidate
	Inventory               NetworkInventory
	DirectDeviceProjections []DirectDeviceProjection
	SharingDependencies     []network.Scope
	PacketPolicy            policy.Snapshot
	// Routes are the Device's subnet routes, expanded from its Network's
	// policy with PacketPolicy; the zero value carries none.
	Routes RouteView
	// Kubernetes is, for a cluster gateway, its peers' Kubernetes access,
	// computed from the policy PacketPolicy was expanded from; the zero
	// value carries none (K1a3b).
	Kubernetes KubernetesView
	// routeCapabilities carry the session's route capabilities through
	// rebuilds (withRouteCapabilities).
	routeCapabilities      RouteCapabilities
	routeCapabilitiesKnown bool
	Connectivity           []Connectivity
	RelayDirectory         relay.Directory
	// OmittedShares is a lower bound on the shares a store left out of the
	// snapshot to stay within its bounds; such a map reports itself limited.
	OmittedShares int
	// DatabaseReadAt is the PostgreSQL clock's time of the read the snapshot
	// comes from, and ReadAtLocal this host's clock (with its monotonic
	// reading) taken before that read began; zero ReadAtLocal means now. The
	// stream measures the key and projection deadlines, which the database
	// clock set, from them instead of from this host's wall clock; taking
	// ReadAtLocal before the read makes deadlines come early, never late. A
	// zero DatabaseReadAt falls back to this host's clock.
	DatabaseReadAt time.Time
	ReadAtLocal    time.Time
}

// Snapshot is immutable authorization evidence for the first response of a map session.
type Snapshot struct {
	databaseReadAt          time.Time
	readAtLocal             time.Time
	scope                   network.Scope
	networkName             network.DisplayName
	networkRevision         int64
	recoveryEpoch           int64
	sessionGeneration       int64
	numericNodeID           int64
	numericOwnerID          int64
	nodeID                  node.ID
	hostname                node.Hostname
	dnsLabel                node.DNSLabel
	workspaceCode           identity.DisplayCode
	networkCode             identity.DisplayCode
	machineKey              node.MachineKey
	nodeKey                 node.Key
	addresses               []netip.Prefix
	createdAt               time.Time
	keyExpiry               time.Time
	candidates              snapshotCandidates
	directDeviceProjections []DirectDeviceProjection
	sharingDependencies     []network.Scope
	packetPolicy            policy.Snapshot
	routes                  RouteView
	kubernetes              KubernetesView
	connectivity            []Connectivity
	// sharedConnectivity, when set, replaces connectivity: a version of the
	// replica's table for the Network, read through self and the authorized
	// peers (see ConnectivityFor).
	sharedConnectivity *connectivityVersion
	relayDirectory     relay.Directory
	relayGrant         RelayGrant // set by the stream service, never by the store
	// authorized and valid are computed once by NewSnapshot; the snapshot is
	// immutable, so readers never repeat the O(candidates) work.
	authorized []PeerCandidate
	// authorizedTotal is how many peers the policy authorizes when a peer
	// limit cut authorized down (zero otherwise).
	authorizedTotal int
	// omittedShares is a lower bound on shares left out, by the store or
	// by the session limit.
	omittedShares int
	// peerLimit is the session's bound on peers, set by the Service from
	// the request (zero: the Service's own limit).
	peerLimit int
	// relayZones is set by the Service for a session that declared
	// relay.zones2: its relay ticket may name every share.
	relayZones bool
	// routeCapabilities are the session's route capabilities, set by the
	// Service (withRouteCapabilities).
	routeCapabilities      RouteCapabilities
	routeCapabilitiesKnown bool
	valid                  bool
}

// NewSnapshot validates and copies one authoritative map snapshot.
func NewSnapshot(params SnapshotParams) (Snapshot, error) {
	if len(params.PeerCandidates) > MaximumPeerCandidates {
		return Snapshot{}, errors.Join(ErrInvalidSnapshot, ErrPeerCandidateLimit)
	}
	candidates, ok := snapshotCandidatesOf(params)
	if !ok {
		return Snapshot{}, ErrInvalidSnapshot
	}
	if candidates.len() > candidates.limit() {
		return Snapshot{}, errors.Join(ErrInvalidSnapshot, ErrPeerCandidateLimit)
	}
	if params.OmittedShares < 0 {
		return Snapshot{}, ErrInvalidSnapshot
	}
	params.PeerCandidates = nil
	params.DirectDeviceProjections = slices.Clone(params.DirectDeviceProjections)
	params.SharingDependencies = slices.Clone(params.SharingDependencies)
	slices.SortFunc(params.SharingDependencies, compareSharingScopes)
	slices.SortFunc(params.DirectDeviceProjections, compareDirectDeviceProjections)
	params.Connectivity = canonicalConnectivity(params.Connectivity)
	if !validSnapshotCore(params) || !validDirectDeviceProjections(params, candidates) {
		return Snapshot{}, ErrInvalidSnapshot
	}
	authorized := authorizedPeers(params, candidates)
	if !validSnapshotConnectivity(params, candidates, authorized) {
		return Snapshot{}, ErrInvalidSnapshot
	}
	readAtLocal := params.ReadAtLocal
	if readAtLocal.IsZero() {
		readAtLocal = time.Now()
	}
	return Snapshot{
		databaseReadAt:          params.DatabaseReadAt.UTC(),
		readAtLocal:             readAtLocal,
		scope:                   params.Scope,
		networkName:             params.NetworkName,
		networkRevision:         params.NetworkRevision,
		recoveryEpoch:           params.RecoveryEpoch,
		sessionGeneration:       params.SessionGeneration,
		numericNodeID:           params.NumericNodeID,
		numericOwnerID:          params.NumericOwnerID,
		nodeID:                  params.NodeID,
		hostname:                params.Hostname,
		dnsLabel:                params.DNSLabel,
		workspaceCode:           params.WorkspaceCode,
		networkCode:             params.NetworkCode,
		machineKey:              params.MachineKey,
		nodeKey:                 params.NodeKey,
		addresses:               slices.Clone(params.Addresses),
		createdAt:               params.CreatedAt,
		keyExpiry:               params.KeyExpiry,
		candidates:              candidates,
		directDeviceProjections: params.DirectDeviceProjections,
		sharingDependencies:     params.SharingDependencies,
		packetPolicy:            params.PacketPolicy,
		routes:                  params.Routes,
		kubernetes:              params.Kubernetes,
		routeCapabilities:       params.routeCapabilities,
		routeCapabilitiesKnown:  params.routeCapabilitiesKnown,
		connectivity:            params.Connectivity,
		relayDirectory:          params.RelayDirectory,
		authorized:              authorized,
		omittedShares:           params.OmittedShares,
		valid:                   true,
	}, nil
}

// snapshotCandidatesOf binds self into the candidate source of params: the
// given list (a private inventory, which must not list self) or the shared
// Network inventory.
func snapshotCandidatesOf(params SnapshotParams) (snapshotCandidates, bool) {
	self := selfIdentity{
		scope: params.Scope, nodeID: params.NodeID, numericID: params.NumericNodeID,
		machineKey: params.MachineKey, nodeKey: params.NodeKey,
	}
	if params.PeerCandidates == nil && params.Inventory.IsValid() {
		return bindCandidates(params.Inventory.inner, self, true)
	}
	inventory, err := newNetworkInventory(params.Scope, params.PeerCandidates)
	if err != nil {
		return snapshotCandidates{}, false
	}
	return bindCandidates(inventory, self, false)
}

// authorizedPeers lists the candidates an explicit rule pairs with self,
// found through the policy's own peer list (O(rules)) instead of testing
// every candidate, plus the peers of direct projections.
func authorizedPeers(params SnapshotParams, candidates snapshotCandidates) []PeerCandidate {
	policyPeers := params.PacketPolicy.PeersOf(params.NodeID)
	peers := make([]PeerCandidate, 0, len(policyPeers)+len(params.DirectDeviceProjections))
	for _, peerID := range policyPeers {
		if candidate, found := candidates.lookup(peerID); found {
			peers = append(peers, candidate)
		}
	}
	seen := make(map[node.ID]struct{}, len(peers))
	for _, peer := range peers {
		seen[peer.NodeID()] = struct{}{}
	}
	// Routes add the routers of a consumer's Sites and a router's consumers.
	for _, peerID := range params.Routes.Peers() {
		if _, exists := seen[peerID]; exists {
			continue
		}
		if candidate, found := candidates.lookup(peerID); found {
			peers = append(peers, candidate)
			seen[peerID] = struct{}{}
		}
	}
	deadlines := make(map[node.ID]time.Time, len(params.DirectDeviceProjections))
	for _, projection := range params.DirectDeviceProjections {
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

// Scope returns the exact Workspace-qualified Network scope.
func (snapshot Snapshot) Scope() network.Scope { return snapshot.scope }

// Routes returns the Device's subnet routes (mtcp-v1 §7.6).
func (snapshot Snapshot) Routes() RouteView { return snapshot.routes }

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

// DNSLabel returns the first label of the Device's name, and whether the
// store gave one.
func (snapshot Snapshot) DNSLabel() (node.DNSLabel, bool) {
	return snapshot.dnsLabel, snapshot.dnsLabel.IsValid()
}

// DisplayCodes returns the Workspace and Network display codes of the
// Network's DNS zone, and whether the store gave them.
func (snapshot Snapshot) DisplayCodes() (identity.DisplayCode, identity.DisplayCode, bool) {
	return snapshot.workspaceCode, snapshot.networkCode,
		snapshot.workspaceCode.IsValid() && snapshot.networkCode.IsValid()
}

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
	return snapshot.candidates.list()
}

// PacketPolicy returns the immutable exact-revision product policy snapshot.
func (snapshot Snapshot) PacketPolicy() policy.Snapshot { return snapshot.packetPolicy }

// RelayDirectory returns complete validated routing metadata. It grants no
// peer visibility, route, packet-policy, or Network membership authority.
func (snapshot Snapshot) RelayDirectory() relay.Directory { return snapshot.relayDirectory }

// ConnectivityFor returns transient state only for self or a policy-authorized
// peer in this exact snapshot. A miss is normal and grants no routing authority.
func (snapshot Snapshot) ConnectivityFor(nodeID node.ID) (Connectivity, bool) {
	if shared := snapshot.sharedConnectivity; shared != nil {
		generation, found := snapshot.connectivityGeneration(nodeID)
		if !found {
			return Connectivity{}, false
		}
		value := shared.lookup(ConnectivityKey{nodeID: nodeID, generation: generation})
		if relayID, present := value.PreferredRelay(); present && relayID > 0 &&
			!usableRelayPreference(snapshot, relayID) {
			value.preferredRelay, value.preferredRelayPresent = 0, false
		}
		return value, true
	}
	index, found := slices.BinarySearchFunc(
		snapshot.connectivity,
		nodeID,
		func(value Connectivity, target node.ID) int { return compareNodeIDs(value.key.nodeID, target) },
	)
	if !found {
		return Connectivity{}, false
	}
	return snapshot.connectivity[index], true
}

// connectivityGeneration returns the session generation a map shows nodeID
// at: self's own, or an authorized peer's.
func (snapshot Snapshot) connectivityGeneration(nodeID node.ID) (int64, bool) {
	if nodeID == snapshot.nodeID {
		return snapshot.sessionGeneration, true
	}
	peer, found := snapshot.authorizedPeer(nodeID)
	return peer.sessionGeneration, found
}

// authorizedPeer finds one authorized peer in O(log N).
func (snapshot Snapshot) authorizedPeer(nodeID node.ID) (PeerCandidate, bool) {
	index, found := slices.BinarySearchFunc(snapshot.authorized, nodeID,
		func(peer PeerCandidate, target node.ID) int { return compareNodeIDs(peer.nodeID, target) })
	if !found {
		return PeerCandidate{}, false
	}
	return snapshot.authorized[index], true
}

// withSharedConnectivity returns a copy reading connectivity from version
// (O(1): nothing per peer is copied). Maps with direct projections keep
// their own reads, as their peers belong to other Networks.
func (snapshot Snapshot) withSharedConnectivity(version *connectivityVersion) (Snapshot, error) {
	if !snapshot.valid || version == nil || len(snapshot.directDeviceProjections) != 0 {
		return Snapshot{}, ErrInvalidSnapshot
	}
	snapshot.connectivity, snapshot.sharedConnectivity = nil, version
	return snapshot, nil
}

// WithConnectivity validates and returns a copy with non-authoritative routing
// state attached. Durable authority fields remain unchanged.
func (snapshot Snapshot) WithConnectivity(values []Connectivity) (Snapshot, error) {
	params := snapshot.params()
	params.Connectivity = values
	next, err := NewSnapshot(params)
	if err != nil {
		return Snapshot{}, err
	}
	// The grant belongs to the stream, not the store; the stream re-checks
	// it against the new connectivity (a changed disco key is re-granted).
	next.relayGrant = snapshot.relayGrant
	return next, nil
}

// AuthorizedPeers returns only candidates required by an explicit packet rule
// in either direction. Candidate inventory and same-Network membership alone
// never grant visibility.
func (snapshot Snapshot) AuthorizedPeers() []PeerCandidate {
	if !snapshot.valid {
		return []PeerCandidate{}
	}
	return slices.Clone(snapshot.authorized)
}

// IsValid reports whether the snapshot contains complete authority evidence.
func (snapshot Snapshot) IsValid() bool { return snapshot.valid }

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
		DNSLabel:                snapshot.dnsLabel,
		WorkspaceCode:           snapshot.workspaceCode,
		NetworkCode:             snapshot.networkCode,
		MachineKey:              snapshot.machineKey,
		NodeKey:                 snapshot.nodeKey,
		Addresses:               slices.Clone(snapshot.addresses),
		CreatedAt:               snapshot.createdAt,
		KeyExpiry:               snapshot.keyExpiry,
		PeerCandidates:          snapshot.candidates.privateList(),
		Inventory:               snapshot.candidates.sharedInventory(),
		DirectDeviceProjections: slices.Clone(snapshot.directDeviceProjections),
		SharingDependencies:     slices.Clone(snapshot.sharingDependencies),
		PacketPolicy:            snapshot.packetPolicy,
		Routes:                  snapshot.routes,
		Kubernetes:              snapshot.kubernetes,
		routeCapabilities:       snapshot.routeCapabilities,
		routeCapabilitiesKnown:  snapshot.routeCapabilitiesKnown,
		Connectivity:            slices.Clone(snapshot.connectivity),
		RelayDirectory:          snapshot.relayDirectory,
		OmittedShares:           snapshot.omittedShares,
	}
}

// validSnapshotCore checks every field but the candidates, direct
// projections and connectivity, which NewSnapshot checks against the bound
// candidate view.
func validSnapshotCore(params SnapshotParams) bool {
	return params.Scope.IsValid() && params.NetworkName.IsValid() && params.NetworkRevision > 0 &&
		params.RecoveryEpoch > 0 &&
		params.SessionGeneration > 0 && validNumericID(params.NumericNodeID) &&
		validNumericID(params.NumericOwnerID) && params.NodeID.IsValid() &&
		params.Hostname.IsValid() && params.MachineKey.IsValid() && params.NodeKey.IsValid() &&
		validSnapshotNaming(params) && validSnapshotAddresses(params.Addresses) && !params.CreatedAt.IsZero() &&
		params.KeyExpiry.After(params.CreatedAt) &&
		params.PacketPolicy.IsValid() && params.PacketPolicy.Scope() == params.Scope &&
		validSharingDependencies(params) && params.RelayDirectory.IsValid()
}

func validSnapshotConnectivity(params SnapshotParams, candidates snapshotCandidates, authorized []PeerCandidate) bool {
	if params.Connectivity == nil || len(params.Connectivity) > candidates.len()+len(params.DirectDeviceProjections)+1 {
		return params.Connectivity == nil
	}
	allowed := make(map[node.ID]int64, len(authorized)+1)
	allowed[params.NodeID] = params.SessionGeneration
	for _, peer := range authorized {
		allowed[peer.NodeID()] = peer.SessionGeneration()
	}
	for index, connectivity := range params.Connectivity {
		if !connectivity.IsValid() || allowed[connectivity.key.nodeID] != connectivity.key.generation ||
			index > 0 && compareNodeIDs(params.Connectivity[index-1].key.nodeID, connectivity.key.nodeID) >= 0 {
			return false
		}
	}
	return true
}

// validSnapshotNaming accepts absent naming facts or valid ones; the codes
// come together.
func validSnapshotNaming(params SnapshotParams) bool {
	return (params.DNSLabel == node.DNSLabel{} || params.DNSLabel.IsValid()) &&
		(params.WorkspaceCode == "") == (params.NetworkCode == "") &&
		(params.WorkspaceCode == "" || params.WorkspaceCode.IsValid() && params.NetworkCode.IsValid())
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

// untilDeadline returns how long until deadline on the database clock: the
// deadline's distance from the snapshot's database read time, less the time
// elapsed since that read on this host's monotonic clock. Skew between this
// host's wall clock and the database's does not change it. Without a
// database read time it falls back to this host's clock.
func (snapshot Snapshot) untilDeadline(deadline time.Time) time.Duration {
	if snapshot.databaseReadAt.IsZero() || snapshot.readAtLocal.IsZero() {
		return time.Until(deadline)
	}
	return deadline.Sub(snapshot.databaseReadAt) - time.Since(snapshot.readAtLocal)
}

// deadlinePassed reports whether deadline has passed on the database clock.
func (snapshot Snapshot) deadlinePassed(deadline time.Time) bool {
	return snapshot.untilDeadline(deadline) <= 0
}
