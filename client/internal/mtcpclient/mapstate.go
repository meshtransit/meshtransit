package mtcpclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/overlayframe"
	"meshtransit.net/shared/internet"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
	"meshtransit.net/shared/mtrp"
	"meshtransit.net/shared/policydigest"
)

// Bounds of what one map may hold; networkmap validates the rest.
const (
	maxMapPeers    = 100_000
	maxPeerPatches = 100_000
)

// errMapGap reports a delta that does not follow the node's view: the node
// asks for a resync (mtcp-v1 §7.1).
var errMapGap = errors.New("mtcp: map delta does not follow the current view")

// mapState is the node's view of its map: the last snapshot with every
// delta applied in order, the signing keys of its relay grant and its
// relay ticket.
type mapState struct {
	ready  bool
	epoch  uint64
	seq    uint64
	self   *mtcpv1.Device
	peers  map[string]*mtcpv1.Device
	filter *mtcpv1.PacketFilter
	dns    *mtcpv1.DnsConfig
	routes *mtcpv1.RouteConfig
	// takesRoutes: the node declared routes.subnet.v1; otherwise it ignores
	// routes, as it ignores any field it did not ask for.
	takesRoutes bool
	// takesKubernetes: the node is a gateway that declared gateway.kube.v1;
	// any other ignores peers' Kubernetes access.
	takesKubernetes bool
	// takesProfiles: the gateway declared gateway.kube.v2 too, so it reads
	// the scope table and peers' scoped grants (§7.12); without it, as a v1
	// gateway, it ignores them. scopes is the table the map holds.
	takesProfiles bool
	scopes        *mtcpv1.KubernetesScopeTable
	// compiled is scopes compiled, for the table compiledFrom: a snapshot or
	// a delta that carries a table replaces the pointer, so it is compiled
	// once per table, not on every build.
	compiled     compiledScopes
	compiledFrom *mtcpv1.KubernetesScopeTable
	compiledOnce bool
	served       *mtcpv1.ServedRoutes
	// takesServed: the node declared router.subnet.v1.
	takesServed bool
	servedExits *mtcpv1.ServedExits
	// takesKubernetesCA: the node is a gateway that declared gateway.cert1;
	// its own entry may name its cluster's CAs (§7.10).
	takesKubernetesCA bool
	// takesServedExits: the node declared router.exit.v1.
	takesServedExits bool
	exits            *mtcpv1.ExitConfig
	// takesExits: the node declared routes.exit.v1.
	takesExits bool
	// takesClusters: the node declared kube.ca1, so its map names the
	// clusters it holds (§7.11); clustersNegotiated: Core offered it too, so
	// every snapshot carries them. kubeClusters is the stream's hold, which
	// outlives the session; clock dates it.
	takesClusters      bool
	clustersNegotiated bool
	kubeClusters       *kubeClusterHold
	clock              func() time.Time
	relayMap           []byte
	revisions          []*mtcpv1.NetworkRevision

	signingKeys []mtrp.TrustedKey
	ticket      []byte
	ticketUntil time.Time
	ticketZones []byte // MTT2 only
	// fallbackTicket is the MTT1 ticket beside an MTT2 one.
	fallbackTicket []byte
}

func newMapState(takesRoutes bool) *mapState {
	return &mapState{peers: make(map[string]*mtcpv1.Device), takesRoutes: takesRoutes}
}

// applySnapshot replaces the view.
func (state *mapState) applySnapshot(snapshot *mtcpv1.MapSnapshot) error {
	view := snapshot.GetView()
	if view.GetEpoch() == 0 || view.GetSeq() != 1 || snapshot.GetSelf() == nil || len(snapshot.GetPeers()) > maxMapPeers {
		return fmt.Errorf("%w: malformed snapshot", controlplane.ErrNetmapInvalid)
	}
	if state.ready && view.GetEpoch() <= state.epoch {
		return fmt.Errorf("%w: snapshot epoch went back", controlplane.ErrNetmapInvalid)
	}
	clusters, err := state.nextKubeClusters(snapshot.GetKubernetesClusters(), true)
	if err != nil {
		return err
	}
	peers := make(map[string]*mtcpv1.Device, len(snapshot.GetPeers()))
	for _, peer := range snapshot.GetPeers() {
		if peer.GetDeviceId() == "" {
			return fmt.Errorf("%w: peer without a Device ID", controlplane.ErrNetmapInvalid)
		}
		if _, duplicate := peers[peer.GetDeviceId()]; duplicate {
			return fmt.Errorf("%w: duplicate peer", controlplane.ErrNetmapInvalid)
		}
		peers[peer.GetDeviceId()] = peer
	}
	state.ready, state.epoch, state.seq = true, view.GetEpoch(), 1
	state.self, state.peers = snapshot.GetSelf(), peers
	state.filter, state.dns = snapshot.GetPacketFilter(), snapshot.GetDns()
	// A snapshot without routes means none (mtcp-v1 §7.6).
	state.routes, state.served = snapshot.GetRoutes(), snapshot.GetServed()
	state.servedExits, state.exits = snapshot.GetServedExits(), snapshot.GetExits()
	state.relayMap = bytes.Clone(snapshot.GetRelayMap())
	state.revisions = snapshot.GetNetworkRevisions()
	// A snapshot without a table holds none (§7.12).
	state.scopes = snapshot.GetKubernetesScopes()
	state.holdKubeClusters(clusters)
	return nil
}

// applyDelta applies the next delta of the current epoch.
func (state *mapState) applyDelta(delta *mtcpv1.MapDelta) error {
	view := delta.GetView()
	if !state.ready || view.GetEpoch() != state.epoch || view.GetSeq() != state.seq+1 {
		return errMapGap
	}
	if len(delta.GetPeersUpsert()) > maxMapPeers || len(delta.GetPeerPatches()) > maxPeerPatches {
		return fmt.Errorf("%w: delta exceeds its bounds", controlplane.ErrNetmapInvalid)
	}
	peers := make(map[string]*mtcpv1.Device, len(state.peers))
	for id, peer := range state.peers {
		peers[id] = peer
	}
	for _, id := range delta.GetPeersRemove() {
		delete(peers, id)
	}
	for _, peer := range delta.GetPeersUpsert() {
		if peer.GetDeviceId() == "" {
			return fmt.Errorf("%w: peer without a Device ID", controlplane.ErrNetmapInvalid)
		}
		peers[peer.GetDeviceId()] = peer
	}
	for _, patch := range delta.GetPeerPatches() {
		current, found := peers[patch.GetDeviceId()]
		if !found {
			return errMapGap // the node lost a peer Core thinks it has
		}
		peers[patch.GetDeviceId()] = patchPeer(current, patch)
	}
	if len(peers) > maxMapPeers {
		return fmt.Errorf("%w: too many peers", controlplane.ErrNetmapInvalid)
	}
	clusters, err := state.nextKubeClusters(delta.GetKubernetesClusters(), false)
	if err != nil {
		return err
	}
	state.seq = view.GetSeq()
	state.peers = peers
	if delta.GetSelf() != nil {
		state.self = delta.GetSelf()
	}
	if delta.GetPacketFilter() != nil {
		state.filter = delta.GetPacketFilter()
	}
	if delta.GetDns() != nil {
		state.dns = delta.GetDns()
	}
	// A present routes message replaces them all; a present, empty one
	// clears them.
	if delta.GetRoutes() != nil {
		state.routes = delta.GetRoutes()
	}
	if delta.GetServed() != nil {
		state.served = delta.GetServed()
	}
	if delta.GetServedExits() != nil {
		state.servedExits = delta.GetServedExits()
	}
	if delta.GetExits() != nil {
		state.exits = delta.GetExits()
	}
	if len(delta.GetRelayMap()) != 0 {
		state.relayMap = bytes.Clone(delta.GetRelayMap())
	}
	if len(delta.GetNetworkRevisions()) != 0 {
		state.revisions = delta.GetNetworkRevisions()
	}
	// A present table replaces the whole of it (§7.12).
	if delta.GetKubernetesScopes() != nil {
		state.scopes = delta.GetKubernetesScopes()
	}
	state.holdKubeClusters(clusters)
	return nil
}

// patchPeer returns a copy of peer with the patch's present fields.
func patchPeer(peer *mtcpv1.Device, patch *mtcpv1.PeerPatch) *mtcpv1.Device {
	next, _ := proto.Clone(peer).(*mtcpv1.Device)
	if patch.DiscoKey != nil {
		next.DiscoKey = bytes.Clone(patch.GetDiscoKey())
	}
	if patch.GetEndpoints() != nil {
		next.Endpoints = patch.GetEndpoints().GetItems()
	}
	if patch.HomeRelay != nil {
		next.HomeRelay = patch.GetHomeRelay()
	}
	if patch.Online != nil {
		online := patch.GetOnline()
		next.Online = &online
	}
	if patch.LastSeenMs != nil {
		next.LastSeenMs = patch.GetLastSeenMs()
	}
	if patch.GetNat() != nil {
		next.Nat = patch.GetNat()
	}
	return next
}

// setKeys records the relay signing keys of a KeyUpdate.
func (state *mapState) setKeys(update *mtcpv1.KeyUpdate) error {
	keys := make([]mtrp.TrustedKey, 0, len(update.GetSigningKeys()))
	for _, signing := range update.GetSigningKeys() {
		if len(signing.GetKey()) != len(key.SigningPublic{}) || signing.GetNotAfterMs() <= 0 {
			return fmt.Errorf("%w: malformed signing key", controlplane.ErrNetmapInvalid)
		}
		keys = append(keys, mtrp.TrustedKey{
			Key:      key.SigningPublic(signing.GetKey()),
			NotAfter: time.UnixMilli(signing.GetNotAfterMs()),
		})
	}
	state.signingKeys = keys
	return nil
}

// setTicket records a relay ticket. An MTT2 ticket must come with the zone
// list it commits to, checked here so relays are only ever handed a list
// that completes the ticket.
func (state *mapState) setTicket(ticket *mtcpv1.RelayTicket) error {
	if len(ticket.GetTicket()) == 0 || len(ticket.GetTicket()) > mtrp.MaxTicketSize || ticket.GetNotAfterMs() <= 0 {
		return fmt.Errorf("%w: malformed relay ticket", controlplane.ErrNetmapInvalid)
	}
	if len(ticket.GetZones()) != 0 || isMTT2(ticket.GetTicket()) {
		if _, err := mtrp.CompleteTicket(ticket.GetTicket(), ticket.GetZones()); err != nil {
			return fmt.Errorf("%w: relay ticket zones: %w", controlplane.ErrNetmapInvalid, err)
		}
	}
	if fallback := ticket.GetFallbackTicket(); len(fallback) != 0 {
		if len(fallback) > mtrp.MaxTicketSize || mtrp.CheckFallbackTicket(ticket.GetTicket(), fallback) != nil {
			return fmt.Errorf("%w: relay fallback ticket", controlplane.ErrNetmapInvalid)
		}
	}
	state.ticket, state.ticketUntil = bytes.Clone(ticket.GetTicket()), time.UnixMilli(ticket.GetNotAfterMs())
	state.ticketZones = bytes.Clone(ticket.GetZones())
	state.fallbackTicket = bytes.Clone(ticket.GetFallbackTicket())
	return nil
}

// isMTT2 reports whether ticket claims the MTT2 format.
func isMTT2(ticket []byte) bool { return len(ticket) >= 4 && string(ticket[:4]) == "MTT2" }

// snapshotInput carries what a product snapshot needs besides the view.
type snapshotInput struct {
	revision    uint64
	controlTime time.Time
	now         time.Time
}

// build returns the validated product snapshot of the view.
func (state *mapState) build(input snapshotInput) (networkmap.Snapshot, error) {
	if !state.ready {
		return networkmap.Snapshot{}, fmt.Errorf("%w: no map yet", controlplane.ErrNetmapInvalid)
	}
	self, err := convertDevice(state.self, true, input.now)
	if err != nil {
		return networkmap.Snapshot{}, err
	}
	ids := make([]string, 0, len(state.peers))
	for id := range state.peers {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	// References resolve against the whole map as it stands (§7.12).
	var scopes compiledScopes
	if state.takesKubernetes && state.takesProfiles {
		if !state.compiledOnce || state.compiledFrom != state.scopes {
			state.compiled, state.compiledFrom, state.compiledOnce = compileKubernetesScopes(state.scopes), state.scopes, true
		}
		scopes = state.compiled
	}
	peers := make([]networkmap.Node, 0, len(ids))
	for _, id := range ids {
		peer, err := convertDevice(state.peers[id], false, input.now)
		if err != nil {
			return networkmap.Snapshot{}, err
		}
		if peer.Kubernetes != nil && state.takesProfiles && !scopes.withheld {
			access := state.peers[id].GetKubernetes()
			scoped, ordered := scopedKubernetesGrants(access.GetScopedGrants(), scopes.scopes)
			if !ordered || len(access.GetGrants())+len(access.GetScopedGrants()) > sharedmtcp.KubernetesPeerGrantsMaximum {
				peer.Kubernetes = nil
			} else {
				peer.Kubernetes.Scoped = scoped
			}
		}
		// A peer's malformed access costs that peer its access, never the
		// gateway its map (fail closed for one peer); an unusable table costs
		// every peer theirs.
		if !state.takesKubernetes || peer.Alias != nil || scopes.withheld ||
			networkmap.CheckKubernetesAccess(peer.Kubernetes) != nil {
			peer.Kubernetes = nil
		}
		if peer.Alias != nil {
			peer.Alias.SelfKey, peer.Alias.PeerKey = self.PublicKey, peer.PublicKey
		}
		peers = append(peers, peer)
	}
	policy, err := convertFilter(state.filter)
	if err != nil {
		return networkmap.Snapshot{}, err
	}
	dns, err := convertDNS(state.dns)
	if err != nil {
		return networkmap.Snapshot{}, err
	}
	snapshot := networkmap.Snapshot{
		Revision: input.revision, ControlTime: input.controlTime, Self: self, Peers: peers, Policy: policy, DNS: dns,
		Relays: map[int]networkmap.RelayRegion{}, KubernetesScopes: scopes.scopes, KubernetesWithheld: scopes.withheld,
	}
	if state.takesRoutes {
		if snapshot.Routes, err = convertRoutes(state.routes); err != nil {
			return networkmap.Snapshot{}, err
		}
	}
	if state.takesServed {
		if snapshot.Served, err = convertServed(state.served); err != nil {
			return networkmap.Snapshot{}, err
		}
	}
	if state.takesServedExits {
		if snapshot.ServedExits, err = convertServedExits(state.servedExits); err != nil {
			return networkmap.Snapshot{}, err
		}
	}
	if state.takesExits {
		if snapshot.Exits, err = convertExits(state.exits); err != nil {
			return networkmap.Snapshot{}, err
		}
	}
	if interchange, regions, ok := state.interchange(input.now); ok {
		snapshot.Interchange, snapshot.Relays = interchange, regions
	}
	if state.takesKubernetesCA {
		snapshot.KubernetesCA = state.kubernetesCA()
	}
	if state.takesClusters && state.kubeClusters != nil {
		snapshot.KubernetesClusters = state.kubeClusters.clusters(input.now)
		snapshot.KubernetesClustersAuthoritative = state.kubeClusters.authoritativeAt(input.now)
		snapshot.KubernetesClustersNegotiated = state.clustersNegotiated
	}
	// A share whose alias cannot be used now (expired, invalid, colliding,
	// or a clock ahead of Core's) is left out, not the whole map.
	usable, dropped := networkmap.WithoutUnusableAliases(networkmap.WithUsableEndpoints(snapshot), input.now)
	usable.DroppedAliasPeers = dropped
	return networkmap.ValidateAndClone(usable, input.now)
}

// kubernetesCA is the gateway's cluster's CAs its own entry names, with the
// map's revision of its Network; nil when absent or malformed (a malformed
// one never costs the gateway its map: it keeps its certificate).
func (state *mapState) kubernetesCA() *networkmap.KubernetesCA {
	named := state.self.GetKubernetesCa()
	if named == nil {
		return nil
	}
	ca := &networkmap.KubernetesCA{
		Root: bytes.Clone(named.GetRootFingerprint()), Signing: bytes.Clone(named.GetSigningFingerprint()),
	}
	// A gateway belongs to one Network: the map lists its revision only.
	for _, revision := range state.revisions {
		ca.MapRevision = max(ca.MapRevision, revision.GetRevision())
	}
	if networkmap.CheckKubernetesCA(ca) != nil {
		return nil
	}
	return ca
}

// interchange verifies the relay map with the grant's signing keys and
// pairs it with the ticket (MTRP v1 §9). Without a complete grant there are
// no relays yet.
func (state *mapState) interchange(now time.Time) (*networkmap.Interchange, map[int]networkmap.RelayRegion, bool) {
	if len(state.signingKeys) == 0 || len(state.relayMap) == 0 || len(state.ticket) == 0 ||
		!now.Before(state.ticketUntil) {
		return nil, nil, false
	}
	grant := mtrp.InterchangeGrant{
		SigningKeys: state.signingKeys, RelayMap: state.relayMap, Ticket: state.ticket,
		TicketNotAfter: state.ticketUntil,
	}
	relayMap, err := grant.OpenRelayMap(now)
	if err != nil {
		return nil, nil, false
	}
	ticket, err := mtrp.ParseTicketUnverified(state.ticket)
	if err != nil {
		return nil, nil, false
	}
	regions := make(map[int]networkmap.RelayRegion, len(relayMap.Regions))
	for _, r := range relayMap.Regions {
		region := networkmap.RelayRegion{ID: int(r.ID), Code: r.Code, Name: r.Name, Preferred: r.Preferred}
		for _, n := range r.Nodes {
			relay := networkmap.RelayNode{
				Name: n.Name, HostName: n.HostName, STUNPort: int(n.STUNPort),
				RelayPort: int(n.TLSPort), RelayKey: n.Key, UDPPort: int(n.UDPPort),
			}
			if n.IPv4.IsValid() {
				relay.IPv4 = n.IPv4.String()
			}
			if n.IPv6.IsValid() {
				relay.IPv6 = n.IPv6.String()
			}
			region.Nodes = append(region.Nodes, relay)
		}
		regions[region.ID] = region
	}
	return &networkmap.Interchange{
		Ticket: bytes.Clone(state.ticket), TicketNotAfter: state.ticketUntil,
		TicketZones: bytes.Clone(state.ticketZones), FallbackTicket: bytes.Clone(state.fallbackTicket),
		TicketDisco: ticket.Disco, MapVersion: relayMap.Version, MapExpiresAt: relayMap.ExpiresAt,
	}, regions, true
}

// nodeID derives the product's numeric node identity from the Device ID:
// Core's internal identifiers never reach nodes.
func nodeID(deviceID string) uint64 {
	digest := sha256.Sum256([]byte("meshtransit/node-id/v1\x00" + deviceID))
	id := binary.BigEndian.Uint64(digest[:8]) &^ (1 << 63)
	if id == 0 {
		return 1
	}
	return id
}

func convertDevice(device *mtcpv1.Device, self bool, now time.Time) (networkmap.Node, error) {
	invalid := func(what string) (networkmap.Node, error) {
		return networkmap.Node{}, fmt.Errorf("%w: device %s", controlplane.ErrNetmapInvalid, what)
	}
	if device == nil || device.GetDeviceId() == "" || len(device.GetNodeKey()) != key.Size {
		return invalid("identity")
	}
	node := networkmap.Node{
		ID: nodeID(device.GetDeviceId()), StableID: device.GetDeviceId(), Name: device.GetName(),
		PublicKey: "nodekey:" + hex.EncodeToString(device.GetNodeKey()), HomeRelay: int(device.GetHomeRelay()),
		MachineAuthorized: true,
	}
	if disco := device.GetDiscoKey(); len(disco) != 0 {
		if len(disco) != key.Size {
			return invalid("disco key")
		}
		node.DiscoveryKey = "discokey:" + hex.EncodeToString(disco)
	}
	for _, raw := range device.GetAddresses() {
		address, ok := netip.AddrFromSlice(raw)
		if !ok {
			return invalid("address")
		}
		address = address.Unmap()
		node.Addresses = append(node.Addresses, netip.PrefixFrom(address, address.BitLen()))
	}
	for _, raw := range device.GetAllowedPrefixes() {
		prefix, err := sharedmtcp.ParsePrefix(raw)
		if err != nil {
			return invalid("allowed prefix")
		}
		node.AllowedIPs = append(node.AllowedIPs, prefix)
	}
	if len(node.AllowedIPs) == 0 {
		node.AllowedIPs = slices.Clone(node.Addresses)
	}
	for _, endpoint := range device.GetEndpoints() {
		address, ok := netip.AddrFromSlice(endpoint.GetIp())
		if !ok || endpoint.GetPort() == 0 || endpoint.GetPort() > 65535 {
			return invalid("endpoint")
		}
		node.Endpoints = append(node.Endpoints, netip.AddrPortFrom(address.Unmap(), uint16(endpoint.GetPort()))) //nolint:gosec // G115: checked above
	}
	if expiry := device.GetKeyExpiryMs(); expiry > 0 {
		node.KeyExpiry = time.UnixMilli(expiry).UTC()
		node.Expired = !node.KeyExpiry.After(now)
	}
	if !self && device.Online != nil {
		// Absent means Core has no connectivity for the peer: unknown, so the
		// node still probes it.
		node.OnlineKnown, node.Online = true, device.GetOnline()
	}
	if alias := device.GetAlias(); alias != nil {
		binding, err := convertAlias(alias)
		if err != nil {
			return networkmap.Node{}, err
		}
		node.Alias = binding
	}
	// Self never holds access (mtcp-v1 §7.8): any sent is ignored.
	if access := device.GetKubernetes(); access != nil && !self {
		node.Kubernetes = convertKubernetesAccess(access, device.GetOwner().GetRef())
	}
	return node, nil
}

// convertKubernetesAccess decodes a peer's access in a gateway's map
// (mtcp-v1 §7.8); networkmap validates it. A deadline of 0, which Core never
// sends, stays zero and is refused there.
func convertKubernetesAccess(access *mtcpv1.KubernetesAccess, owner string) *networkmap.KubernetesAccess {
	converted := &networkmap.KubernetesAccess{
		OwnerRef: owner,
		Grants:   make([]networkmap.KubernetesGrant, 0, len(access.GetGrants())),
	}
	if changed := access.GetOwnerChangedMs(); changed > 0 {
		converted.OwnerChangedAt = time.UnixMilli(changed).UTC()
	}
	for _, grant := range access.GetGrants() {
		converted.Grants = append(converted.Grants, networkmap.KubernetesGrant{Group: grant.GetGroup()})
		if until := grant.GetValidUntilMs(); until > 0 {
			converted.Grants[len(converted.Grants)-1].ValidUntil = time.UnixMilli(until).UTC()
		}
	}
	return converted
}

func convertAlias(alias *mtcpv1.AliasGrant) (*networkmap.AliasBinding, error) {
	role := networkmap.AliasProvider
	switch alias.GetRole() {
	case mtcpv1.AliasGrant_CONSUMER:
		role = networkmap.AliasConsumer
	case mtcpv1.AliasGrant_PROVIDER:
	default:
		return nil, fmt.Errorf("%w: alias role", controlplane.ErrNetmapInvalid)
	}
	binding := &networkmap.AliasBinding{
		ContractID: alias.GetContractId(), EndpointID: alias.GetEndpointId(), Generation: alias.GetGeneration(),
		GrantRevision: alias.GetGrantRevision(), RecoveryEpoch: alias.GetRecoveryEpoch(), Role: role,
		ExpiresAt: time.UnixMilli(alias.GetExpiresMs()).UTC(),
	}
	for _, raw := range [][]byte{alias.GetMasqueradeV4(), alias.GetMasqueradeV6()} {
		if len(raw) == 0 {
			continue
		}
		address, ok := netip.AddrFromSlice(raw)
		if !ok {
			return nil, fmt.Errorf("%w: alias address", controlplane.ErrNetmapInvalid)
		}
		if address.Unmap().Is4() {
			binding.SelfIPv4 = address.Unmap()
		} else {
			binding.SelfIPv6 = address
		}
	}
	for _, service := range alias.GetServices() {
		if service.GetProtocol() > 255 || service.GetPortFrom() > 65535 || service.GetPortTo() > 65535 {
			return nil, fmt.Errorf("%w: alias service", controlplane.ErrNetmapInvalid)
		}
		binding.Services = append(binding.Services, networkmap.AliasService{
			Protocol: uint8(service.GetProtocol()),  //nolint:gosec // G115: checked above
			PortFrom: uint16(service.GetPortFrom()), //nolint:gosec // G115: checked above
			PortTo:   uint16(service.GetPortTo()),   //nolint:gosec // G115: checked above
		})
	}
	return binding, nil
}

// convertFilter reads the packet filter through the same rules Core
// digests (shared/mtcp), so the enforced policy digest matches Core's.
func convertFilter(filter *mtcpv1.PacketFilter) ([]networkmap.Rule, error) {
	if filter == nil {
		return nil, nil
	}
	rules, err := sharedmtcp.PolicyRules(filter)
	if err != nil {
		return nil, fmt.Errorf("%w: packet filter: %w", controlplane.ErrNetmapInvalid, err)
	}
	converted := make([]networkmap.Rule, 0, len(rules))
	for _, rule := range rules {
		next := networkmap.Rule{Protocols: slices.Clone(rule.Protocols)}
		for _, source := range rule.Sources {
			selector, err := convertSelector(source)
			if err != nil {
				return nil, err
			}
			next.Sources = append(next.Sources, selector)
		}
		for _, destination := range rule.Destinations {
			selector, err := convertSelector(destination.Selector)
			if err != nil {
				return nil, err
			}
			next.Destinations = append(next.Destinations, networkmap.Destination{
				Selector: selector,
				PortFrom: destination.PortFrom, PortTo: destination.PortTo,
			})
		}
		converted = append(converted, next)
	}
	return converted, nil
}

func convertSelector(selector policydigest.Selector) (networkmap.Selector, error) {
	switch selector.Kind {
	case policydigest.KindAny:
		return networkmap.Selector{Kind: networkmap.SelectorAny}, nil
	case policydigest.KindPrefix:
		return networkmap.Selector{Kind: networkmap.SelectorPrefix, Prefix: selector.Prefix}, nil
	case policydigest.KindRange:
		return networkmap.Selector{
			Kind: networkmap.SelectorRange, RangeStart: selector.RangeStart,
			RangeEnd: selector.RangeEnd,
		}, nil
	default:
		return networkmap.Selector{}, fmt.Errorf("%w: unsupported filter selector", controlplane.ErrNetmapInvalid)
	}
}

// convertDNS keeps classic IP resolvers and drops URL resolvers, which the
// product's DNS model does not run yet. A resolver's port 0 is 53; only a
// route's resolver in the mesh (dns.forward1) may use another port, 1024 or
// above, and any other is dropped. A route of a forward zone whose resolvers
// were all dropped, or that says it is unavailable, is kept unavailable, so
// its names follow its failure mode instead of the host's DNS, and one odd
// route never stops the map.
func convertDNS(config *mtcpv1.DnsConfig) (*networkmap.DNSConfig, error) {
	if config == nil {
		return nil, nil
	}
	out := &networkmap.DNSConfig{}
	resolvers := func(raw []*mtcpv1.Resolver, route bool) []networkmap.DNSResolver {
		converted := []networkmap.DNSResolver{}
		for _, resolver := range raw {
			address, ok := netip.AddrFromSlice(resolver.GetIp())
			if !ok || resolver.GetUrl() != "" {
				continue
			}
			address = address.Unmap()
			port := resolver.GetPort()
			if port == 0 {
				port = 53
			}
			if port != 53 && (!route || port < 1024 || port > 65535 ||
				!overlayframe.Contains(netip.PrefixFrom(address, address.BitLen()))) {
				continue
			}
			converted = append(converted, networkmap.DNSResolver{
				Address: netip.AddrPortFrom(address, uint16(port)),
			})
		}
		return converted
	}
	out.Resolvers = resolvers(config.GetResolvers(), false)
	for _, route := range config.GetRoutes() {
		// The root zone (dns.root1, DNS design D1b): every name no other
		// route holds. It has no labels to canonicalize.
		suffix := "."
		if route.GetSuffix() != "." {
			var err error
			if suffix, err = canonicalDNSName(route.GetSuffix()); err != nil {
				return nil, err
			}
		}
		routeResolvers := resolvers(route.GetResolvers(), true)
		unavailable := route.GetUnavailable() || (len(route.GetResolvers()) != 0 && len(routeResolvers) == 0)
		if unavailable {
			routeResolvers = []networkmap.DNSResolver{}
		}
		out.Routes = append(out.Routes, networkmap.DNSRoute{
			Suffix: suffix, Resolvers: routeResolvers,
			Unavailable: unavailable, FailOpen: route.GetFailOpen(),
		})
	}
	// A name the node cannot read is left out: only a root zone uses them,
	// and its other names go to its resolvers anyway.
	for _, raw := range config.GetInfrastructureNames() {
		name, err := canonicalDNSName(raw)
		if err != nil || len(out.InfrastructureNames) == maxInfrastructureNames ||
			slices.Contains(out.InfrastructureNames, name) {
			continue
		}
		out.InfrastructureNames = append(out.InfrastructureNames, name)
	}
	for _, domain := range config.GetSearchDomains() {
		canonical, err := canonicalDNSName(domain)
		if err != nil {
			return nil, err
		}
		out.SearchDomains = append(out.SearchDomains, canonical)
	}
	for _, record := range config.GetRecords() {
		name, err := canonicalDNSName(record.GetName())
		if err != nil {
			return nil, err
		}
		if record.GetType() == mtcpv1.DnsRecord_CNAME {
			target, err := canonicalDNSName(record.GetTarget())
			if err != nil || len(record.GetValue()) != 0 {
				return nil, fmt.Errorf("%w: dns cname record", controlplane.ErrNetmapInvalid)
			}
			out.Records = append(out.Records, networkmap.DNSRecord{
				Name: name, Type: networkmap.DNSRecordCNAME,
				Target: target,
			})
			continue
		}
		if record.GetType() != mtcpv1.DnsRecord_A && record.GetType() != mtcpv1.DnsRecord_AAAA {
			return nil, fmt.Errorf("%w: dns record type", controlplane.ErrNetmapInvalid)
		}
		address, ok := netip.AddrFromSlice(record.GetValue())
		if !ok {
			return nil, fmt.Errorf("%w: dns record address", controlplane.ErrNetmapInvalid)
		}
		address = address.Unmap()
		recordType := networkmap.DNSRecordAAAA
		if record.GetType() == mtcpv1.DnsRecord_A {
			recordType = networkmap.DNSRecordA
		}
		if (recordType == networkmap.DNSRecordA) != address.Is4() {
			return nil, fmt.Errorf("%w: dns record type and address differ", controlplane.ErrNetmapInvalid)
		}
		out.Records = append(out.Records, networkmap.DNSRecord{Name: name, Type: recordType, Address: address})
	}
	return out, nil
}

// canonicalDNSName lowercases a DNS name and drops one trailing dot.
func canonicalDNSName(raw string) (string, error) {
	trimmed := strings.TrimSuffix(raw, ".")
	if trimmed == "" || len(trimmed) > 253 || strings.TrimSpace(raw) != raw {
		return "", fmt.Errorf("%w: dns name", controlplane.ErrNetmapInvalid)
	}
	for label := range strings.SplitSeq(trimmed, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("%w: dns label", controlplane.ErrNetmapInvalid)
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return "", fmt.Errorf("%w: dns label", controlplane.ErrNetmapInvalid)
			}
		}
	}
	return strings.ToLower(trimmed), nil
}

// convertRoutes reads the Sites of routes (mtcp-v1 §7.6). Prefixes must be
// canonical as sent: host bits or an IPv4-mapped address make the map
// malformed rather than being masked. networkmap validates the rest.
func convertRoutes(config *mtcpv1.RouteConfig) ([]networkmap.SiteRoute, error) {
	sites := config.GetSites()
	routes := make([]networkmap.SiteRoute, 0, len(sites))
	for _, site := range sites {
		route := networkmap.SiteRoute{
			Ref: site.GetSiteRef(), Name: networkmap.SiteName(site.GetName()),
			Candidates: slices.Clone(site.GetCandidates()),
			Primary:    site.GetPrimary(), Generation: site.GetGeneration(),
		}
		switch site.GetStatus() {
		case mtcpv1.SiteRoute_SERVED:
			route.Status = networkmap.RouteServed
		case mtcpv1.SiteRoute_UNSERVED:
			route.Status = networkmap.RouteUnserved
		case mtcpv1.SiteRoute_CONFLICT:
			route.Status = networkmap.RouteConflict
		case mtcpv1.SiteRoute_CAPACITY:
			route.Status = networkmap.RouteCapacity
		default:
			return nil, fmt.Errorf("%w: unknown route status", controlplane.ErrNetmapInvalid)
		}
		for _, encoded := range site.GetPrefixes() {
			prefix, err := exactPrefix(encoded)
			if err != nil {
				return nil, err
			}
			route.Prefixes = append(route.Prefixes, prefix)
		}
		routes = append(routes, route)
	}
	return routes, nil
}

// convertServed reads the Sites the node forwards to (mtcp-v1 §7.6); as with
// routes, prefixes must be canonical as sent and networkmap validates the
// rest.
func convertServed(config *mtcpv1.ServedRoutes) ([]networkmap.ServedSite, error) {
	sites := config.GetSites()
	served := make([]networkmap.ServedSite, 0, len(sites))
	for _, site := range sites {
		converted := networkmap.ServedSite{Ref: site.GetSiteRef(), Masquerade: site.GetMasquerade()}
		for _, encoded := range site.GetPrefixes() {
			prefix, err := exactPrefix(encoded)
			if err != nil {
				return nil, err
			}
			converted.Prefixes = append(converted.Prefixes, prefix)
		}
		for _, probe := range site.GetProbes() {
			address, ok := netip.AddrFromSlice(probe.GetIp())
			kind := probe.GetKind()
			if !ok || address.Is4In6() || probe.GetPort() > 65535 ||
				(kind != mtcpv1.RouteProbe_ICMP && kind != mtcpv1.RouteProbe_TCP) {
				return nil, fmt.Errorf("%w: malformed route probe", controlplane.ErrNetmapInvalid)
			}
			converted.Probes = append(converted.Probes, networkmap.RouteProbe{
				Address: address, TCP: kind == mtcpv1.RouteProbe_TCP, Port: uint16(probe.GetPort()), //nolint:gosec // G115: checked above
			})
		}
		served = append(served, converted)
	}
	return served, nil
}

// convertExits reads the Exit Pools the node may use (mtcp-v1 §7.7);
// networkmap validates the rest.
func convertExits(config *mtcpv1.ExitConfig) ([]networkmap.ExitPool, error) {
	pools := config.GetPools()
	exits := make([]networkmap.ExitPool, 0, len(pools))
	for _, pool := range pools {
		converted := networkmap.ExitPool{
			Ref: pool.GetPoolRef(), Name: pool.GetName(), Primary: pool.GetPrimary(),
			Generation: pool.GetGeneration(), Managed: pool.GetManaged(),
			Spread: pool.GetMode() == mtcpv1.ExitPool_SPREAD, CaptiveOff: pool.GetCaptiveOff(),
		}
		switch pool.GetStatus() {
		case mtcpv1.ExitPool_SERVED:
			converted.Status = networkmap.ExitServed
		case mtcpv1.ExitPool_UNSERVED:
			converted.Status = networkmap.ExitUnserved
		case mtcpv1.ExitPool_CAPACITY:
			converted.Status = networkmap.ExitCapacity
		default:
			return nil, fmt.Errorf("%w: unknown exit pool status", controlplane.ErrNetmapInvalid)
		}
		for _, candidate := range pool.GetCandidates() {
			next := networkmap.ExitCandidate{DeviceID: candidate.GetDeviceId(), Draining: candidate.GetDraining()}
			switch candidate.GetState() {
			case mtcpv1.ExitCandidate_STATE_UNSPECIFIED:
			case mtcpv1.ExitCandidate_OK:
				next.State = networkmap.ExitStateOK
			case mtcpv1.ExitCandidate_DEGRADED:
				next.State = networkmap.ExitStateDegraded
			case mtcpv1.ExitCandidate_FAILED:
				next.State = networkmap.ExitStateFailed
			default:
				return nil, fmt.Errorf("%w: unknown exit candidate state", controlplane.ErrNetmapInvalid)
			}
			switch candidate.GetFamilies() {
			case mtcpv1.ExitCandidate_FAMILIES_UNSPECIFIED:
			case mtcpv1.ExitCandidate_V4:
				next.IPv4 = true
			case mtcpv1.ExitCandidate_V6:
				next.IPv6 = true
			case mtcpv1.ExitCandidate_BOTH:
				next.IPv4, next.IPv6 = true, true
			default:
				return nil, fmt.Errorf("%w: unknown exit candidate families", controlplane.ErrNetmapInvalid)
			}
			for _, raw := range [][]byte{candidate.GetDnsIpv4(), candidate.GetDnsIpv6()} {
				if len(raw) == 0 {
					continue
				}
				address, ok := netip.AddrFromSlice(raw)
				if !ok || address.Is4In6() {
					return nil, fmt.Errorf("%w: malformed exit DNS address", controlplane.ErrNetmapInvalid)
				}
				if address.Is4() {
					next.DNS4 = address
				} else {
					next.DNS6 = address
				}
			}
			converted.Candidates = append(converted.Candidates, next)
		}
		exits = append(exits, converted)
	}
	return exits, nil
}

// maxInfrastructureNames bounds the infrastructure names a map carries
// (mtcp-v1 §7.3).
const maxInfrastructureNames = 64

// relayTargetsOf reads relay targets, leaving out and counting those that
// are malformed, off the Internet or listed before.
func relayTargetsOf(raw [][]byte) (targets []netip.Addr, dropped int) {
	for _, encoded := range raw {
		address, ok := netip.AddrFromSlice(encoded)
		if !ok || address.Is4In6() || !internet.Contains(address) || slices.Contains(targets, address) {
			dropped++
			continue
		}
		targets = append(targets, address)
	}
	return targets, dropped
}

// convertServedExits reads the Exit Pool the node serves (mtcp-v1 §7.7);
// networkmap validates the rest. Its rules are read as the packet filter's.
func convertServedExits(config *mtcpv1.ServedExits) ([]networkmap.ServedExit, error) {
	pools := config.GetPools()
	served := make([]networkmap.ServedExit, 0, len(pools))
	for _, pool := range pools {
		converted := networkmap.ServedExit{
			Ref: pool.GetPoolRef(), SMTPAllowed: pool.GetSmtpAllowed(),
			ConntrackPerConsumer: int(min(pool.GetConntrackPerConsumer(), 1<<30)),
		}
		for _, probe := range pool.GetProbes() {
			address, ok := netip.AddrFromSlice(probe.GetIp())
			if !ok || address.Is4In6() || probe.GetPort() == 0 || probe.GetPort() > 65535 {
				return nil, fmt.Errorf("%w: malformed exit probe", controlplane.ErrNetmapInvalid)
			}
			converted.Probes = append(converted.Probes, netip.AddrPortFrom(address, uint16(probe.GetPort()))) //nolint:gosec // checked
		}
		for _, raw := range pool.GetDnsUpstreams() {
			address, ok := netip.AddrFromSlice(raw)
			if !ok || address.Is4In6() {
				return nil, fmt.Errorf("%w: malformed exit resolver", controlplane.ErrNetmapInvalid)
			}
			converted.DNSUpstreams = append(converted.DNSUpstreams, address)
		}
		// A relay target this client does not take (off the Internet as it
		// sees it, or listed twice) is left out alone: the pool and the
		// other targets stay (TD-CLI-72).
		var dropped int
		converted.DNSRelayTargets, dropped = relayTargetsOf(pool.GetDnsRelayTargets())
		converted.DroppedRelayTargets += dropped
		for _, scope := range pool.GetDnsRelayScopes() {
			next := networkmap.RelayScope{}
			next.Targets, dropped = relayTargetsOf(scope.GetTargets())
			converted.DroppedRelayTargets += dropped
			for _, encoded := range scope.GetSources() {
				source, err := exactPrefix(encoded)
				if err != nil {
					return nil, err
				}
				next.Sources = append(next.Sources, source)
			}
			if len(next.Targets) != 0 {
				converted.DNSRelayScopes = append(converted.DNSRelayScopes, next)
			}
		}
		rules, err := convertFilter(&mtcpv1.PacketFilter{Rules: pool.GetRules()})
		if err != nil {
			return nil, err
		}
		converted.Rules = rules
		served = append(served, converted)
	}
	return served, nil
}

// exactPrefix reads a prefix that must already be canonical.
func exactPrefix(encoded *mtcpv1.Prefix) (netip.Prefix, error) {
	raw := encoded.GetIp()
	address, ok := netip.AddrFromSlice(raw)
	if !ok || (len(raw) != 4 && len(raw) != 16) || address.Is4In6() || int(encoded.GetBits()) > address.BitLen() {
		return netip.Prefix{}, fmt.Errorf("%w: malformed route prefix", controlplane.ErrNetmapInvalid)
	}
	prefix := netip.PrefixFrom(address, int(encoded.GetBits()))
	if prefix != prefix.Masked() {
		return netip.Prefix{}, fmt.Errorf("%w: route prefix has host bits", controlplane.ErrNetmapInvalid)
	}
	return prefix, nil
}

// nextKubeClusters checks a message's clusters field and returns the hold
// after it, nil when it changes nothing. A snapshot on a session that
// negotiated kube.ca1 must carry it (§7.11); a field Core sends unasked is
// ignored, as any other.
func (state *mapState) nextKubeClusters(field *mtcpv1.KubernetesClusters, snapshot bool) (*kubeClusterHold, error) {
	if !state.clustersNegotiated || state.kubeClusters == nil {
		return nil, nil
	}
	if field == nil {
		if snapshot {
			return nil, fmt.Errorf("%w: snapshot without Kubernetes clusters", controlplane.ErrNetmapInvalid)
		}
		return nil, nil
	}
	if err := checkKubeClusters(field); err != nil {
		return nil, err
	}
	now := time.Now
	if state.clock != nil {
		now = state.clock
	}
	next := state.kubeClusters.apply(field, now())
	return &next, nil
}

// holdKubeClusters keeps a hold nextKubeClusters returned, once the
// message is otherwise applied.
func (state *mapState) holdKubeClusters(next *kubeClusterHold) {
	if next != nil {
		*state.kubeClusters = *next
	}
}
