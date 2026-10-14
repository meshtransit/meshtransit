package mtcpclient

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
	"meshtransit.net/shared/mtrp"
)

func device(id string, seed byte, address string) *mtcpv1.Device {
	ip := netip.MustParseAddr(address)
	return &mtcpv1.Device{
		DeviceId: id, Name: id + ".", NodeKey: bytes.Repeat([]byte{seed}, 32),
		DiscoKey: bytes.Repeat([]byte{seed + 100}, 32), Addresses: [][]byte{ip.AsSlice()},
		KeyExpiryMs: time.Now().Add(24 * time.Hour).UnixMilli(), Online: proto.Bool(true),
	}
}

func filterFixture() *mtcpv1.PacketFilter {
	return &mtcpv1.PacketFilter{Rules: []*mtcpv1.FilterRule{{
		Sources: []*mtcpv1.Prefix{sharedmtcp.AppendPrefix(netip.MustParsePrefix("100.64.0.2/32"))},
		Destinations: []*mtcpv1.Destination{{
			Prefix: sharedmtcp.AppendPrefix(netip.MustParsePrefix("100.64.0.1/32")),
			Ports:  []*mtcpv1.PortRange{{First: 22, Last: 22}, {First: 443, Last: 443}},
		}},
		Protocols: []uint32{6},
	}, {
		Sources:      []*mtcpv1.Prefix{sharedmtcp.AppendPrefix(netip.MustParsePrefix("100.64.0.3/32"))},
		Destinations: []*mtcpv1.Destination{{Prefix: sharedmtcp.AppendPrefix(netip.MustParsePrefix("100.64.0.1/32"))}},
		Protocols:    []uint32{1},
	}}}
}

func snapshotMessage(epoch uint64) *mtcpv1.MapSnapshot {
	return &mtcpv1.MapSnapshot{
		View:         &mtcpv1.View{Epoch: epoch, Seq: 1},
		Self:         device("self", 1, "100.64.0.1"),
		Peers:        []*mtcpv1.Device{device("peer-a", 2, "100.64.0.2"), device("peer-b", 3, "100.64.0.3")},
		PacketFilter: filterFixture(),
		Dns: &mtcpv1.DnsConfig{Records: []*mtcpv1.DnsRecord{{
			Name: "Laptop.Example.", Type: mtcpv1.DnsRecord_A,
			Value: netip.MustParseAddr("198.18.0.5").AsSlice(),
		}}},
	}
}

func build(t *testing.T, state *mapState) networkmap.Snapshot {
	t.Helper()
	snapshot, err := state.build(snapshotInput{revision: 1, controlTime: time.Now(), now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestMapStateBuildsTheProductSnapshot(t *testing.T) {
	t.Parallel()
	state := newMapState()
	if err := state.applySnapshot(snapshotMessage(7)); err != nil {
		t.Fatal(err)
	}
	snapshot := build(t, state)
	if snapshot.Self.StableID != "self" || !snapshot.Self.MachineAuthorized || snapshot.Self.ID == 0 ||
		snapshot.Self.PublicKey != "nodekey:"+bytesHex(1) || snapshot.Self.Addresses[0] != netip.MustParsePrefix("100.64.0.1/32") {
		t.Fatalf("self %+v", snapshot.Self)
	}
	if len(snapshot.Peers) != 2 || snapshot.Peers[0].StableID != "peer-a" || !snapshot.Peers[0].Online ||
		snapshot.Peers[0].DiscoveryKey != "discokey:"+bytesHex(102) || nodeID("peer-a") == nodeID("peer-b") {
		t.Fatalf("peers %+v", snapshot.Peers)
	}
	unknown := snapshotMessage(8)
	unknown.Peers[1].Online = nil
	if err := state.applySnapshot(unknown); err != nil {
		t.Fatal(err)
	}
	if peers := build(t, state).Peers; peers[1].OnlineKnown || !peers[0].OnlineKnown {
		t.Fatal("a peer without connectivity must be unknown, not offline")
	}
	if snapshot.DNS == nil || len(snapshot.DNS.Records) != 1 || snapshot.DNS.Records[0].Name != "laptop.example" {
		t.Fatalf("dns %+v", snapshot.DNS)
	}
	// The client enforces exactly what Core delivered: digests match.
	want, wantGrants, err := sharedmtcp.FilterDigest(filterFixture())
	if err != nil {
		t.Fatal(err)
	}
	got, grants, err := networkmap.PolicyDigest(snapshot.Policy)
	if err != nil || got != want || grants != wantGrants {
		t.Fatalf("policy digest %s (%d), Core's %s (%d): %v", got, grants, want, wantGrants, err)
	}
	if snapshot.Interchange != nil || len(snapshot.Relays) != 0 {
		t.Fatal("relays without a grant")
	}
}

func bytesHex(seed byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i := range 32 {
		out[2*i], out[2*i+1] = digits[seed>>4], digits[seed&15]
	}
	return string(out)
}

func TestMapStateAppliesDeltasInOrder(t *testing.T) {
	t.Parallel()
	state := newMapState()
	if err := state.applySnapshot(snapshotMessage(7)); err != nil {
		t.Fatal(err)
	}
	offline := false
	err := state.applyDelta(&mtcpv1.MapDelta{
		View:        &mtcpv1.View{Epoch: 7, Seq: 2},
		PeersRemove: []string{"peer-b"}, PeersUpsert: []*mtcpv1.Device{device("peer-c", 4, "100.64.0.4")},
		PeerPatches: []*mtcpv1.PeerPatch{{
			DeviceId: "peer-a", Online: &offline,
			Endpoints: &mtcpv1.EndpointList{Items: []*mtcpv1.Endpoint{{
				Ip:   netip.MustParseAddr("198.51.100.7").AsSlice(),
				Port: 41641, Kind: mtcpv1.Endpoint_SERVER_REFLEXIVE,
			}}},
		}},
		PacketFilter: &mtcpv1.PacketFilter{},
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := build(t, state)
	if len(snapshot.Peers) != 2 || snapshot.Peers[0].StableID != "peer-a" || snapshot.Peers[0].Online ||
		len(snapshot.Peers[0].Endpoints) != 1 || snapshot.Peers[1].StableID != "peer-c" || len(snapshot.Policy) != 0 {
		t.Fatalf("after delta: %+v policy %d", snapshot.Peers, len(snapshot.Policy))
	}
	if snapshot.DNS == nil || len(snapshot.DNS.Records) != 1 {
		t.Fatal("an absent DNS must keep the previous one")
	}
	for name, delta := range map[string]*mtcpv1.MapDelta{
		"skipped seq":   {View: &mtcpv1.View{Epoch: 7, Seq: 4}},
		"old epoch":     {View: &mtcpv1.View{Epoch: 6, Seq: 3}},
		"unknown patch": {View: &mtcpv1.View{Epoch: 7, Seq: 3}, PeerPatches: []*mtcpv1.PeerPatch{{DeviceId: "ghost"}}},
	} {
		if err := state.applyDelta(delta); !errors.Is(err, errMapGap) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := state.applySnapshot(snapshotMessage(6)); !errors.Is(err, controlplane.ErrNetmapInvalid) {
		t.Fatalf("an older snapshot epoch: %v", err)
	}
}

func TestMapStateVerifiesTheRelayGrant(t *testing.T) {
	t.Parallel()
	signer, _ := key.NewSigningPrivate(nil)
	now := time.Now()
	payload, err := mtrp.RelayMap{Version: 3, ExpiresAt: now.Add(24 * time.Hour), Regions: []mtrp.RelayRegion{{
		ID: 1, Code: "sgp", Name: "Singapore", Nodes: []mtrp.RelayNode{{
			Name:     "sgp1",
			HostName: "relay-sgp1.example.com", IPv4: netip.MustParseAddr("192.0.2.10"), Key: key.RelayPublic{0x18},
			UDPPort: 3479, TLSPort: 443, STUNPort: 3478, Weight: 100,
		}},
	}}}.Payload(now)
	if err != nil {
		t.Fatal(err)
	}
	relayMap, _ := mtrp.SignDocument(mtrp.DocumentRelayMap, payload, signer)
	disco := key.DiscoPublic{0xd1}
	ticket, _ := mtrp.Ticket{
		ID: [16]byte{1}, IssuedAtMS: now.UnixMilli(), NotAfterMS: now.Add(15 * time.Minute).UnixMilli(),
		Node: key.NodePublic{1}, Disco: disco, Deployment: [16]byte{1},
		Zones: []mtrp.Zone{{Kind: mtrp.ZoneNetwork, ID: [16]byte{2}}},
	}.Sign(signer)
	state := newMapState()
	message := snapshotMessage(1)
	message.RelayMap = relayMap
	if err := state.applySnapshot(message); err != nil {
		t.Fatal(err)
	}
	signerPublic := signer.Public()
	if err := state.setKeys(&mtcpv1.KeyUpdate{SigningKeys: []*mtcpv1.KeyUpdate_SigningKey{{
		Key:        signerPublic[:],
		NotAfterMs: now.Add(time.Hour).UnixMilli(),
	}}}); err != nil {
		t.Fatal(err)
	}
	if snapshot := build(t, state); snapshot.Interchange != nil {
		t.Fatal("relays before the ticket")
	}
	if err := state.setTicket(&mtcpv1.RelayTicket{Ticket: ticket, NotAfterMs: now.Add(15 * time.Minute).UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	snapshot := build(t, state)
	if snapshot.Interchange == nil || snapshot.Interchange.MapVersion != 3 || snapshot.Interchange.TicketDisco != disco ||
		len(snapshot.Relays) != 1 || snapshot.Relays[1].Nodes[0].RelayKey != (key.RelayPublic{0x18}) {
		t.Fatalf("interchange %+v relays %+v", snapshot.Interchange, snapshot.Relays)
	}
	// A relay map signed by another key is not trusted.
	other, _ := key.NewSigningPrivate(nil)
	forged, _ := mtrp.SignDocument(mtrp.DocumentRelayMap, payload, other)
	state.relayMap = forged
	if snapshot := build(t, state); snapshot.Interchange != nil || len(snapshot.Relays) != 0 {
		t.Fatal("a relay map with an untrusted signature was used")
	}
}

// TestConvertDeviceCarriesTheAliasGrant checks the device alias v1 grant
// (docs/protocol/device-alias-v1.md) reaches the product model unchanged.
func TestConvertDeviceCarriesTheAliasGrant(t *testing.T) {
	peer := device("01890f00-0000-7000-8000-000000000702", 2, "100.64.0.2")
	expires := time.Now().Add(time.Hour).Truncate(time.Millisecond).UTC()
	peer.Alias = &mtcpv1.AliasGrant{
		ContractId: "01890f00-0000-7000-8000-000000000a01", EndpointId: "01890f00-0000-7000-8000-000000000a02",
		Generation: 3, GrantRevision: 4, RecoveryEpoch: 5, Role: mtcpv1.AliasGrant_CONSUMER,
		ExpiresMs:    expires.UnixMilli(),
		Services:     []*mtcpv1.AliasService{{Protocol: 6, PortFrom: 22, PortTo: 22}, {Protocol: 1}},
		MasqueradeV4: netip.MustParseAddr("198.18.0.7").AsSlice(),
		MasqueradeV6: netip.MustParseAddr("fd02:48de:ec1b:1::7").AsSlice(),
	}
	node, err := convertDevice(peer, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := node.Alias
	if got == nil || got.ContractID != peer.Alias.ContractId || got.EndpointID != peer.Alias.EndpointId ||
		got.Generation != 3 || got.GrantRevision != 4 || got.RecoveryEpoch != 5 ||
		got.Role != networkmap.AliasConsumer || !got.ExpiresAt.Equal(expires) ||
		got.SelfIPv4 != netip.MustParseAddr("198.18.0.7") || got.SelfIPv6 != netip.MustParseAddr("fd02:48de:ec1b:1::7") ||
		len(got.Services) != 2 || got.Services[0] != (networkmap.AliasService{Protocol: 6, PortFrom: 22, PortTo: 22}) ||
		got.Services[1] != (networkmap.AliasService{Protocol: 1}) {
		t.Fatalf("alias = %+v", got)
	}

	for name, mutate := range map[string]func(*mtcpv1.AliasGrant){
		"no role":      func(grant *mtcpv1.AliasGrant) { grant.Role = mtcpv1.AliasGrant_ROLE_UNSPECIFIED },
		"bad address":  func(grant *mtcpv1.AliasGrant) { grant.MasqueradeV4 = []byte{1, 2, 3} },
		"bad protocol": func(grant *mtcpv1.AliasGrant) { grant.Services[0].Protocol = 256 },
		"bad port":     func(grant *mtcpv1.AliasGrant) { grant.Services[0].PortTo = 65536 },
	} {
		broken, _ := proto.Clone(peer).(*mtcpv1.Device)
		mutate(broken.Alias)
		if _, err := convertDevice(broken, false, time.Now()); !errors.Is(err, controlplane.ErrNetmapInvalid) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

// TestMapStateChecksMTT2Zones: an MTT2 ticket is kept only with the zone
// list it commits to, which reaches the product snapshot; a ticket without
// it, a list for another ticket, or a list with an MTT1 ticket is rejected.
func TestMapStateChecksMTT2Zones(t *testing.T) {
	t.Parallel()
	signer, _ := key.NewSigningPrivate(nil)
	now := time.Now()
	zones := []mtrp.Zone{{Kind: mtrp.ZoneNetwork, ID: [16]byte{2}}}
	for i := range 40 {
		zones = append(zones, mtrp.Zone{Kind: mtrp.ZoneTrustContract, ID: [16]byte{3, byte(i), 15: 1}})
	}
	base := mtrp.Ticket{
		ID: [16]byte{1}, IssuedAtMS: now.UnixMilli(), NotAfterMS: now.Add(15 * time.Minute).UnixMilli(),
		Node: key.NodePublic{1}, Disco: key.DiscoPublic{0xd1}, Deployment: [16]byte{1}, Zones: zones,
	}
	ticket, list, err := base.SignZones(signer)
	if err != nil {
		t.Fatal(err)
	}
	other := base
	other.Zones = append(append([]mtrp.Zone(nil), zones[:40]...), mtrp.Zone{Kind: mtrp.ZoneTrustContract, ID: [16]byte{4, 15: 1}})
	_, otherList, _ := other.SignZones(signer)
	v1 := base
	v1.Zones = zones[:1]
	mtt1, _ := v1.Sign(signer)
	until := now.Add(15 * time.Minute).UnixMilli()
	for name, message := range map[string]*mtcpv1.RelayTicket{
		"MTT2 without zones": {Ticket: ticket, NotAfterMs: until},
		"another zone list":  {Ticket: ticket, NotAfterMs: until, Zones: otherList},
		"truncated zones":    {Ticket: ticket, NotAfterMs: until, Zones: list[:len(list)-17]},
		"MTT1 with zones":    {Ticket: mtt1, NotAfterMs: until, Zones: list},
	} {
		if err := newMapState().setTicket(message); !errors.Is(err, controlplane.ErrNetmapInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	inline := base
	inline.ID[0] = 7
	inline.Zones = zones[:mtrp.MaxZones]
	fallback, _ := inline.Sign(signer)
	otherNode := inline
	otherNode.Node = key.NodePublic{9}
	foreign, _ := otherNode.Sign(signer)
	withForeign := &mtcpv1.RelayTicket{Ticket: ticket, NotAfterMs: until, Zones: list, FallbackTicket: foreign}
	if err := newMapState().setTicket(withForeign); !errors.Is(err, controlplane.ErrNetmapInvalid) {
		t.Errorf("a fallback for another node: %v", err)
	}
	state := newMapState()
	withFallback := &mtcpv1.RelayTicket{Ticket: ticket, NotAfterMs: until, Zones: list, FallbackTicket: fallback}
	if err := state.setTicket(withFallback); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(state.ticketZones, list) || !bytes.Equal(state.fallbackTicket, fallback) {
		t.Fatal("zone list or fallback not kept")
	}
	if err := state.setTicket(&mtcpv1.RelayTicket{Ticket: mtt1, NotAfterMs: until}); err != nil || state.ticketZones != nil {
		t.Fatalf("an MTT1 ticket kept the old zone list: %v", err)
	}
}

// TestMapStateDropsEndpointsANodeMustNotProbe keeps a peer whose map entry
// names an overlay address as an endpoint, as an older Core may send, and
// drops only that endpoint.
func TestMapStateDropsEndpointsANodeMustNotProbe(t *testing.T) {
	t.Parallel()
	state := newMapState()
	if err := state.applySnapshot(snapshotMessage(7)); err != nil {
		t.Fatal(err)
	}
	endpoint := func(address string) *mtcpv1.Endpoint {
		return &mtcpv1.Endpoint{
			Ip: netip.MustParseAddr(address).AsSlice(), Port: 41641,
			Kind: mtcpv1.Endpoint_SERVER_REFLEXIVE,
		}
	}
	err := state.applyDelta(&mtcpv1.MapDelta{
		View: &mtcpv1.View{Epoch: 7, Seq: 2},
		PeerPatches: []*mtcpv1.PeerPatch{{DeviceId: "peer-a", Endpoints: &mtcpv1.EndpointList{
			Items: []*mtcpv1.Endpoint{endpoint("100.64.0.4"), endpoint("198.51.100.7"), endpoint("127.0.0.1")},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := build(t, state)
	if got := snapshot.Peers[0].Endpoints; len(got) != 1 || got[0] != netip.MustParseAddrPort("198.51.100.7:41641") {
		t.Fatalf("peer endpoints = %v, want only the public one", got)
	}
}
