package ts2021

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshd/internal/networkmap"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
)

func TestNewMapRequest_OmitsNetworkSelector(t *testing.T) {
	t.Parallel()

	request := newMapRequest(key.NewNode(), key.NewDisco().Public(), NetmapOptions{
		Hostname:          "node-a",
		Version:           "meshd/dev",
		PinnedFingerprint: "sha256:" + strings.Repeat("a", 64),
	}, true)
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, forbidden := range []string{"network_id", `"Tailnet"`} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("netmap request contains forbidden field %q: %s", forbidden, encoded)
		}
	}
	if !request.Stream || !request.KeepAlive || request.Version != tailcfg.CurrentCapabilityVersion {
		t.Fatalf("map request flags = %#v, want streaming capability %d", request, tailcfg.CurrentCapabilityVersion)
	}
}

func TestNewMapRequest_EndpointUpdateIsNonStreaming(t *testing.T) {
	t.Parallel()

	endpoint := netip.MustParseAddrPort("203.0.113.10:41641")
	request := newMapRequest(key.NewNode(), key.NewDisco().Public(), NetmapOptions{
		Hostname:          "node-a",
		Version:           "meshd/dev",
		PinnedFingerprint: "sha256:" + strings.Repeat("a", 64),
		Endpoints:         []netip.AddrPort{endpoint},
	}, false)
	if request.Stream || !request.OmitPeers {
		t.Fatalf("endpoint request stream=%t omitPeers=%t", request.Stream, request.OmitPeers)
	}
	if len(request.Endpoints) != 1 || request.Endpoints[0] != endpoint ||
		len(request.EndpointTypes) != 1 ||
		request.EndpointTypes[0] != tailcfg.EndpointExplicitConf {
		t.Fatalf("endpoint request = %#v", request)
	}
}

func TestMapAccumulator_FullAndDelta(t *testing.T) {
	t.Parallel()

	self := testWireNode(1, 1)
	peer := testWireNode(2, 2)
	accumulator := newMapAccumulator()
	now := time.Now()
	snapshot, changed, err := accumulator.apply(tailcfg.MapResponse{
		Node:   self,
		Peers:  []*tailcfg.Node{peer},
		Domain: "example.mesh",
		PacketFilter: []tailcfg.FilterRule{{
			SrcIPs: []string{"100.64.0.2"},
			DstPorts: []tailcfg.NetPortRange{{
				IP:    "100.64.0.1",
				Ports: tailcfg.PortRange{First: 22, Last: 22},
			}},
			IPProto: []int{6},
		}},
		DERPMap: &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "sgp",
				RegionName: "Singapore",
				Nodes: []*tailcfg.DERPNode{{
					Name:     "1a",
					HostName: "relay.example.com",
				}},
			},
		}},
		DNSConfig: &tailcfg.DNSConfig{
			FallbackResolvers: []*dnstype.Resolver{{Addr: "1.1.1.1"}},
			Routes: map[string][]*dnstype.Resolver{
				"EXAMPLE.mesh.":       {},
				"64.100.in-addr.arpa": {},
			},
			Domains: []string{"example.mesh"},
			Proxied: true,
			ExtraRecords: []tailcfg.DNSRecord{{
				Name:  "Service.Example.Mesh.",
				Value: "100.64.0.10",
			}},
		},
	}, now)
	if err != nil || !changed {
		t.Fatalf("initial apply() = changed %t, error %v", changed, err)
	}
	if snapshot.Revision != 1 || len(snapshot.Peers) != 1 || len(snapshot.Policy) != 1 {
		t.Fatalf("initial snapshot = %#v", snapshot)
	}
	if snapshot.DNS == nil || !snapshot.DNS.Proxied ||
		len(snapshot.DNS.FallbackResolvers) != 1 ||
		len(snapshot.DNS.Routes) != 2 ||
		snapshot.DNS.Routes[1].Suffix != "example.mesh" ||
		len(snapshot.DNS.Records) != 1 ||
		snapshot.DNS.Records[0].Type != networkmap.DNSRecordA ||
		snapshot.DNS.Records[0].Name != "service.example.mesh" {
		t.Fatalf("initial dns snapshot = %#v", snapshot.DNS)
	}

	online := true
	delta, changed, err := accumulator.apply(tailcfg.MapResponse{
		PeersChangedPatch: []*tailcfg.PeerChange{{
			NodeID:     peer.ID,
			DERPRegion: 2,
			Online:     &online,
			Endpoints:  []netip.AddrPort{netip.MustParseAddrPort("203.0.113.2:41641")},
		}},
	}, now)
	if err != nil || !changed {
		t.Fatalf("delta apply() = changed %t, error %v", changed, err)
	}
	if delta.Revision != 2 || delta.Peers[0].HomeRelay != 2 ||
		!delta.Peers[0].OnlineKnown || !delta.Peers[0].Online {
		t.Fatalf("delta peer = %#v", delta.Peers[0])
	}
	if delta.DNS == nil || !delta.DNS.Proxied || len(delta.DNS.Routes) != 2 {
		t.Fatalf("delta did not preserve dns = %#v", delta.DNS)
	}
}

func TestMapAccumulator_DNSReplacementIsAtomic(t *testing.T) {
	t.Parallel()

	accumulator := newMapAccumulator()
	initial, _, err := accumulator.apply(tailcfg.MapResponse{
		Node:  testWireNode(1, 1),
		Peers: []*tailcfg.Node{},
		DNSConfig: &tailcfg.DNSConfig{
			Routes:  map[string][]*dnstype.Resolver{"example.mesh": {}},
			Domains: []string{"example.mesh"},
			Proxied: true,
		},
	}, time.Now())
	if err != nil {
		t.Fatalf("initial apply() error = %v", err)
	}
	if _, _, err := accumulator.apply(tailcfg.MapResponse{
		DNSConfig: &tailcfg.DNSConfig{
			Resolvers: []*dnstype.Resolver{{Addr: "https://resolver.example/dns-query"}},
		},
	}, time.Now()); !errors.Is(err, ErrNetmapInvalid) {
		t.Fatalf("unsupported dns apply() error = %v, want ErrNetmapInvalid", err)
	}
	preserved, _, err := accumulator.apply(tailcfg.MapResponse{}, time.Now())
	if err != nil {
		t.Fatalf("post-rejection apply() error = %v", err)
	}
	if preserved.Revision != initial.Revision+1 || preserved.DNS == nil ||
		!preserved.DNS.Proxied || preserved.DNS.SearchDomains[0] != "example.mesh" {
		t.Fatalf("dns changed after rejected update: %#v", preserved.DNS)
	}
}

func TestMapAccumulator_AcceptsScopedAuditCredentials(t *testing.T) {
	t.Parallel()

	self := testWireNode(11, 1)
	self.CapMap = tailcfg.NodeCapMap{meshDataPlaneAuditLogs: nil}
	self.DataPlaneAuditLogID = testProtocolAuditToken(7, 11)
	snapshot, changed, err := newMapAccumulator().apply(tailcfg.MapResponse{
		Node:                      self,
		Peers:                     []*tailcfg.Node{},
		DomainDataPlaneAuditLogID: testProtocolAuditToken(7, 0),
	}, time.Now())
	if err != nil || !changed {
		t.Fatalf("apply() = changed %t, error %v", changed, err)
	}
	if !snapshot.Audit.Enabled() || snapshot.Audit.NetworkID() != 7 || snapshot.Audit.NodeID() != 11 {
		t.Fatalf("audit credentials scope = network %d node %d", snapshot.Audit.NetworkID(), snapshot.Audit.NodeID())
	}
}

func TestMapAccumulator_RejectsUnscopedAuditCredentials(t *testing.T) {
	t.Parallel()

	self := testWireNode(11, 1)
	self.CapMap = tailcfg.NodeCapMap{meshDataPlaneAuditLogs: nil}
	self.DataPlaneAuditLogID = testProtocolAuditToken(7, 12)
	if _, _, err := newMapAccumulator().apply(tailcfg.MapResponse{
		Node:                      self,
		Peers:                     []*tailcfg.Node{},
		DomainDataPlaneAuditLogID: testProtocolAuditToken(7, 0),
	}, time.Now()); !errors.Is(err, ErrNetmapInvalid) {
		t.Fatalf("apply() error = %v, want ErrNetmapInvalid", err)
	}
}

func testProtocolAuditToken(networkID, nodeID uint64) string {
	var token [32]byte
	binary.BigEndian.PutUint64(token[0:8], networkID)
	binary.BigEndian.PutUint64(token[8:16], nodeID)
	for index := 16; index < len(token); index++ {
		token[index] = byte(index)
	}

	return hex.EncodeToString(token[:])
}

func TestMapAccumulator_InvalidDeltaIsAtomic(t *testing.T) {
	t.Parallel()

	accumulator := newMapAccumulator()
	now := time.Now()
	initial, _, err := accumulator.apply(tailcfg.MapResponse{
		Node:  testWireNode(1, 1),
		Peers: []*tailcfg.Node{testWireNode(2, 2)},
	}, now)
	if err != nil {
		t.Fatalf("initial apply() error = %v", err)
	}
	badPeer := testWireNode(2, 2)
	badPeer.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}
	badPeer.AllowedIPs = append([]netip.Prefix(nil), badPeer.Addresses...)
	if _, _, err := accumulator.apply(tailcfg.MapResponse{
		PeersChanged: []*tailcfg.Node{badPeer},
	}, now); !errors.Is(err, ErrNetmapInvalid) {
		t.Fatalf("invalid delta error = %v, want ErrNetmapInvalid", err)
	}
	if accumulator.revision != initial.Revision || accumulator.peers[2].Addresses[0] != netip.MustParsePrefix("100.64.0.2/32") {
		t.Fatalf("accumulator mutated after rejected delta: %#v", accumulator)
	}
}

func TestMapAccumulator_RejectsDuplicateWirePeerIDs(t *testing.T) {
	t.Parallel()

	accumulator := newMapAccumulator()
	peer := testWireNode(2, 2)
	if _, _, err := accumulator.apply(tailcfg.MapResponse{
		Node:  testWireNode(1, 1),
		Peers: []*tailcfg.Node{peer, testWireNode(2, 3)},
	}, time.Now()); !errors.Is(err, ErrNetmapInvalid) {
		t.Fatalf("duplicate peer error = %v, want ErrNetmapInvalid", err)
	}
	if accumulator.initialized || accumulator.revision != 0 {
		t.Fatalf("accumulator mutated after duplicate peer rejection: %#v", accumulator)
	}
}

func TestMapAccumulator_ReconnectRequiresAndReplacesFullState(t *testing.T) {
	t.Parallel()

	accumulator := newMapAccumulator()
	if _, _, err := accumulator.apply(tailcfg.MapResponse{
		Node:  testWireNode(1, 1),
		Peers: []*tailcfg.Node{testWireNode(2, 2)},
	}, time.Now()); err != nil {
		t.Fatalf("initial apply() error = %v", err)
	}
	accumulator.resetSession()
	if _, _, err := accumulator.apply(tailcfg.MapResponse{
		PeersChanged: []*tailcfg.Node{testWireNode(3, 3)},
	}, time.Now()); !errors.Is(err, ErrNetmapInvalid) {
		t.Fatalf("delta-first reconnect error = %v, want ErrNetmapInvalid", err)
	}
	reconnected, _, err := accumulator.apply(tailcfg.MapResponse{
		Node:  testWireNode(1, 1),
		Peers: []*tailcfg.Node{},
	}, time.Now())
	if err != nil {
		t.Fatalf("full reconnect apply() error = %v", err)
	}
	if reconnected.Revision != 2 || len(reconnected.Peers) != 0 {
		t.Fatalf("reconnected snapshot = %#v, want revision 2 with no stale peers", reconnected)
	}
}

func TestReadMapFrame_Bounds(t *testing.T) {
	t.Parallel()

	body := []byte(`{"KeepAlive":true}`)
	encoded := make([]byte, 4, 4+len(body))
	binary.LittleEndian.PutUint32(
		encoded,
		uint32(len(body)), //nolint:gosec // The body is a small compile-time test fixture.
	)
	encoded = append(encoded, body...)
	got, err := readMapFrame(bytes.NewReader(encoded))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("readMapFrame() = %q, %v", got, err)
	}

	oversized := make([]byte, 4)
	binary.LittleEndian.PutUint32(oversized, maxNetmapFrameBytes+1)
	if _, err := readMapFrame(bytes.NewReader(oversized)); err == nil {
		t.Fatal("readMapFrame() oversized error = nil")
	}
}

func TestParseSelectorAndProtocolValidation(t *testing.T) {
	t.Parallel()

	selector, err := parseSelector("100.64.0.2", nil, true)
	if err != nil || selector.Kind != networkmap.SelectorPrefix ||
		selector.Prefix != netip.MustParsePrefix("100.64.0.2/32") {
		t.Fatalf("parseSelector() = %#v, %v", selector, err)
	}
	if _, err := parseSelector("cap:admin", nil, false); err == nil {
		t.Fatal("destination capability selector accepted")
	}
	if _, err := convertProtocols([]int{999}); err == nil {
		t.Fatal("out-of-range protocol accepted")
	}
}

func TestJitteredReconnectDelay_Bounds(t *testing.T) {
	t.Parallel()

	for range 100 {
		delay := jitteredReconnectDelay(10 * time.Second)
		if delay < 5*time.Second || delay >= 10*time.Second {
			t.Fatalf("jittered delay = %s, want [5s, 10s)", delay)
		}
	}
}

func FuzzParseSelector(f *testing.F) {
	for _, seed := range []string{
		"*",
		"100.64.0.1",
		"100.64.0.0/10",
		"fd7a:115c:a1e0::/48",
		"100.64.0.1-100.64.0.9",
		"cap:example",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4_096 {
			t.Skip()
		}
		_, _ = parseSelector(raw, nil, true)
	})
}

func testWireNode(id tailcfg.NodeID, addressByte byte) *tailcfg.Node {
	address := netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, addressByte}), 32)
	stableID := tailcfg.StableNodeID(fmt.Sprintf("node-%d", id))

	return &tailcfg.Node{
		ID:                id,
		StableID:          stableID,
		Name:              string(stableID) + ".example.mesh.",
		Key:               key.NewNode().Public(),
		DiscoKey:          key.NewDisco().Public(),
		Addresses:         []netip.Prefix{address},
		AllowedIPs:        []netip.Prefix{address},
		MachineAuthorized: true,
	}
}
