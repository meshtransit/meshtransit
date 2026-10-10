package mtcptest

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// FullMap is the comparable evidence of a node's current map: its self
// entry and the size of everything else. View and Network revisions are
// left out, so maps of different sessions and revisions compare equal when
// the node's projection did not change; MapUpdate carries them.
type FullMap struct {
	DeviceID        string
	Name            string
	DisplayName     string
	NodeKey         [32]byte
	DiscoveryKey    [32]byte // zero while Core holds no endpoint report
	Addresses       []netip.Prefix
	AllowedPrefixes []netip.Prefix
	Endpoints       []netip.AddrPort
	HomeRelay       uint32
	KeyExpiry       time.Time
	PeerCount       int
	FilterRules     int
	DenyAll         bool // the packet filter allows nothing inbound
	DNSRecords      int
}

// MapUpdate is one applied map message and the map after it.
type MapUpdate struct {
	Snapshot         bool // a MapSnapshot replaced the whole state
	SelfChanged      bool
	PeersUpserted    []string
	PeersRemoved     []string
	PeersPatched     []string
	FilterReplaced   bool
	DNSReplaced      bool
	NetworkRevisions map[string]uint64 // by Network ID, as listed by the message
	Map              FullMap
}

// mapState applies MapSnapshot and MapDelta messages (mtcp-v1 §7.1).
type mapState struct {
	epoch, seq uint64
	self       *mtcpv1.Device
	peers      map[string]*mtcpv1.Device
	filter     *mtcpv1.PacketFilter
	dns        *mtcpv1.DnsConfig
}

func newMapState() *mapState { return &mapState{peers: make(map[string]*mtcpv1.Device)} }

func (state *mapState) view() *mtcpv1.View { return &mtcpv1.View{Epoch: state.epoch, Seq: state.seq} }

// applySnapshot replaces the state. A snapshot starts a newer epoch at seq 1.
func (state *mapState) applySnapshot(snapshot *mtcpv1.MapSnapshot) (MapUpdate, error) {
	view := snapshot.GetView()
	if view.GetSeq() != 1 || view.GetEpoch() <= state.epoch {
		return MapUpdate{}, errors.Join(ErrMap, errors.New("snapshot does not start a newer epoch"))
	}
	if snapshot.GetSelf() == nil || snapshot.GetPacketFilter() == nil || snapshot.GetDns() == nil {
		return MapUpdate{}, errors.Join(ErrMap, errors.New("snapshot is incomplete"))
	}
	peers := make(map[string]*mtcpv1.Device, len(snapshot.GetPeers()))
	previous := ""
	for _, peer := range snapshot.GetPeers() {
		if peer.GetDeviceId() == "" || peer.GetDeviceId() <= previous {
			return MapUpdate{}, errors.Join(ErrMap, errors.New("snapshot peers are not sorted by device ID"))
		}
		previous = peer.GetDeviceId()
		peers[peer.GetDeviceId()] = peer
	}
	next := &mapState{epoch: view.GetEpoch(), seq: 1, self: snapshot.GetSelf(), peers: peers,
		filter: snapshot.GetPacketFilter(), dns: snapshot.GetDns()}
	full, err := next.fullMap()
	if err != nil {
		return MapUpdate{}, err
	}
	*state = *next
	return MapUpdate{Snapshot: true, SelfChanged: true, PeersUpserted: sortedKeys(peers), FilterReplaced: true,
		DNSReplaced: true, NetworkRevisions: networkRevisions(snapshot.GetNetworkRevisions()), Map: full}, nil
}

// applyDelta applies a delta of the current epoch atomically. A delta of
// another epoch predates the latest snapshot and is dropped (applied is
// false); a gap in seq is an error, since this client never resyncs.
func (state *mapState) applyDelta(delta *mtcpv1.MapDelta) (_ MapUpdate, applied bool, _ error) {
	view := delta.GetView()
	if state.epoch == 0 || view.GetEpoch() != state.epoch {
		return MapUpdate{}, false, nil
	}
	if view.GetSeq() != state.seq+1 {
		return MapUpdate{}, false, errors.Join(ErrMap, fmt.Errorf("map gap: seq %d after %d", view.GetSeq(), state.seq))
	}
	next := &mapState{epoch: state.epoch, seq: view.GetSeq(), self: state.self, peers: maps.Clone(state.peers),
		filter: state.filter, dns: state.dns}
	update := MapUpdate{NetworkRevisions: networkRevisions(delta.GetNetworkRevisions())}
	if self := delta.GetSelf(); self != nil {
		if self.GetDeviceId() != state.self.GetDeviceId() {
			return MapUpdate{}, false, errors.Join(ErrMap, errors.New("delta replaces self with another Device"))
		}
		next.self, update.SelfChanged = self, true
	}
	if err := next.applyPeers(delta, &update); err != nil {
		return MapUpdate{}, false, err
	}
	if delta.GetPacketFilter() != nil {
		next.filter, update.FilterReplaced = delta.GetPacketFilter(), true
	}
	if delta.GetDns() != nil {
		next.dns, update.DNSReplaced = delta.GetDns(), true
	}
	full, err := next.fullMap()
	if err != nil {
		return MapUpdate{}, false, err
	}
	*state = *next
	update.Map = full
	return update, true, nil
}

// applyPeers applies upserts, removals and patches; a device ID appears at
// most once across them and patches name known peers (mtcp-v1 §7.3). The
// test map keeps only the peer count, so a patch is validated, not applied.
func (state *mapState) applyPeers(delta *mtcpv1.MapDelta, update *MapUpdate) error {
	seen := make(map[string]struct{})
	claim := func(deviceID string) error {
		if _, duplicate := seen[deviceID]; deviceID == "" || duplicate {
			return errors.Join(ErrMap, errors.New("delta names a peer twice"))
		}
		seen[deviceID] = struct{}{}
		return nil
	}
	for _, peer := range delta.GetPeersUpsert() {
		if err := claim(peer.GetDeviceId()); err != nil {
			return err
		}
		state.peers[peer.GetDeviceId()] = peer
		update.PeersUpserted = append(update.PeersUpserted, peer.GetDeviceId())
	}
	for _, deviceID := range delta.GetPeersRemove() {
		if err := claim(deviceID); err != nil {
			return err
		}
		if _, known := state.peers[deviceID]; !known {
			return errors.Join(ErrMap, errors.New("delta removes an unknown peer"))
		}
		delete(state.peers, deviceID)
		update.PeersRemoved = append(update.PeersRemoved, deviceID)
	}
	for _, patch := range delta.GetPeerPatches() {
		if err := claim(patch.GetDeviceId()); err != nil {
			return err
		}
		if _, known := state.peers[patch.GetDeviceId()]; !known {
			return errors.Join(ErrMap, errors.New("delta patches an unknown peer"))
		}
		update.PeersPatched = append(update.PeersPatched, patch.GetDeviceId())
	}
	return nil
}

// fullMap decodes the self entry and summarizes the rest.
func (state *mapState) fullMap() (FullMap, error) {
	self := state.self
	invalid := func(what string) (FullMap, error) {
		return FullMap{}, errors.Join(ErrMap, fmt.Errorf("self entry has %s", what))
	}
	if self.GetDeviceId() == "" || len(self.GetNodeKey()) != 32 {
		return invalid("no device ID or node key")
	}
	full := FullMap{
		DeviceID: self.GetDeviceId(), Name: self.GetName(), DisplayName: self.GetDisplayName(),
		NodeKey: [32]byte(self.GetNodeKey()), HomeRelay: self.GetHomeRelay(), PeerCount: len(state.peers),
		FilterRules: len(state.filter.GetRules()), DenyAll: len(state.filter.GetRules()) == 0,
		DNSRecords: len(state.dns.GetRecords()),
	}
	switch len(self.GetDiscoKey()) {
	case 0:
	case 32:
		full.DiscoveryKey = [32]byte(self.GetDiscoKey())
	default:
		return invalid("a malformed disco key")
	}
	if self.GetKeyExpiryMs() != 0 {
		full.KeyExpiry = time.UnixMilli(self.GetKeyExpiryMs()).UTC()
	}
	for _, raw := range self.GetAddresses() {
		address, ok := netip.AddrFromSlice(raw)
		if !ok {
			return invalid("a malformed address")
		}
		address = address.Unmap()
		full.Addresses = append(full.Addresses, netip.PrefixFrom(address, address.BitLen()))
	}
	for _, encoded := range self.GetAllowedPrefixes() {
		prefix, err := sharedmtcp.ParsePrefix(encoded)
		if err != nil {
			return invalid("a malformed allowed prefix")
		}
		full.AllowedPrefixes = append(full.AllowedPrefixes, prefix)
	}
	for _, endpoint := range self.GetEndpoints() {
		address, ok := netip.AddrFromSlice(endpoint.GetIp())
		if !ok || endpoint.GetPort() == 0 || endpoint.GetPort() > 65535 {
			return invalid("a malformed endpoint")
		}
		full.Endpoints = append(full.Endpoints,
			netip.AddrPortFrom(address.Unmap(), uint16(endpoint.GetPort()))) //nolint:gosec // G115: checked above
	}
	return full, nil
}

func networkRevisions(listed []*mtcpv1.NetworkRevision) map[string]uint64 {
	revisions := make(map[string]uint64, len(listed))
	for _, revision := range listed {
		revisions[revision.GetNetworkId()] = revision.GetRevision()
	}
	return revisions
}

func sortedKeys(peers map[string]*mtcpv1.Device) []string {
	return slices.Sorted(maps.Keys(peers))
}
