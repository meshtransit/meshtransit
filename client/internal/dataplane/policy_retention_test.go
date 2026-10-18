package dataplane

import (
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/packetmeta"
)

const (
	tcpSYN    = 0x02
	tcpPSHACK = 0x18
)

// retentionFixture opens one TCP flow from self (100.64.0.3) to the peer
// (100.64.0.4) and returns a mid-stream reply, which can never re-create the
// flow on its own.
func retentionFixture(t *testing.T) (*policyFilter, networkmap.Snapshot, []byte, *time.Time) {
	t.Helper()
	now := time.Date(2026, time.October, 18, 0, 0, 0, 0, time.UTC)
	filter := newPolicyFilter()
	filter.clock = func() time.Time { return now }
	snapshot := testPolicySnapshot()
	snapshot.Self.ID, snapshot.Self.PublicKey = 1, "nodekey:self"
	snapshot.Peers[0].ID, snapshot.Peers[0].PublicKey = 2, "nodekey:peer"
	snapshot.Peers[0].KeyExpiry = now.Add(time.Hour)
	filter.UpdateNetwork(snapshot)
	syn := testIPv4TransportPacket([4]byte{100, 64, 0, 3}, [4]byte{100, 64, 0, 4}, 48326, 22, packetmeta.ProtocolTCP, tcpSYN)
	if !filter.Allow(PacketOutbound, syn) {
		t.Fatal("outbound SYN denied")
	}
	reply := testIPv4TransportPacket([4]byte{100, 64, 0, 4}, [4]byte{100, 64, 0, 3}, 22, 48326, packetmeta.ProtocolTCP, tcpPSHACK)
	if !filter.Allow(PacketInbound, reply) {
		t.Fatal("mid-stream reply denied before any map change")
	}
	return filter, snapshot, reply, &now
}

func otherPeer() networkmap.Node {
	return networkmap.Node{ID: 3, PublicKey: "nodekey:other", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.5/32")}}
}

func TestPolicyFilterRetainsFlowsTheNewMapStillAuthorizes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*networkmap.Snapshot)
	}{
		{"unrelated peer added", func(s *networkmap.Snapshot) { s.Peers = append(s.Peers, otherPeer()) }},
		{"local rules changed", func(s *networkmap.Snapshot) { s.Policy = nil }},
		{"peer expiry extended", func(s *networkmap.Snapshot) { s.Peers[0].KeyExpiry = s.Peers[0].KeyExpiry.Add(time.Hour) }},
		{"peer endpoints changed", func(s *networkmap.Snapshot) {
			s.Peers[0].Endpoints = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:41641")}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			filter, snapshot, reply, _ := retentionFixture(t)
			changed := snapshot
			changed.Peers = append([]networkmap.Node{}, snapshot.Peers...)
			test.change(&changed)
			filter.UpdateNetwork(changed)
			if !filter.Allow(PacketInbound, reply) {
				t.Fatal("established flow lost on a map change that keeps its authority")
			}
		})
	}
}

func TestPolicyFilterDropsFlowsTheNewMapNoLongerAuthorizes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*networkmap.Snapshot, time.Time)
	}{
		{"peer key rotated", func(s *networkmap.Snapshot, _ time.Time) { s.Peers[0].PublicKey = "nodekey:rotated" }},
		{"address moved to another node", func(s *networkmap.Snapshot, _ time.Time) { s.Peers[0].ID = 9 }},
		{"peer expired", func(s *networkmap.Snapshot, now time.Time) { s.Peers[0].KeyExpiry = now }},
		{"peer removed", func(s *networkmap.Snapshot, _ time.Time) { s.Peers = []networkmap.Node{otherPeer()} }},
		{"self address changed", func(s *networkmap.Snapshot, _ time.Time) {
			s.Self.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.30/32")}
		}},
		{"self key rotated", func(s *networkmap.Snapshot, _ time.Time) { s.Self.PublicKey = "nodekey:self-rotated" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			filter, snapshot, reply, now := retentionFixture(t)
			changed := snapshot
			changed.Peers = append([]networkmap.Node{}, snapshot.Peers...)
			test.change(&changed, *now)
			filter.UpdateNetwork(changed)
			filter.UpdateNetwork(snapshot) // restoring the old map must not revive the flow
			if filter.Allow(PacketInbound, reply) {
				t.Fatal("flow survived a map change that removed its authority")
			}
		})
	}
}

func TestAliasProviderFlowFollowsLocalRules(t *testing.T) {
	t.Parallel()
	vector := aliasRoundtripVectors(t)[0]
	for _, test := range []struct {
		name   string
		change func(*networkmap.Snapshot)
		keep   bool
	}{
		{"unrelated peer added", nil, true},
		{"local rules changed", func(s *networkmap.Snapshot) {
			s.Policy = append(s.Policy, networkmap.Rule{
				Sources:      []networkmap.Selector{{Kind: networkmap.SelectorAny}},
				Destinations: []networkmap.Destination{{Selector: networkmap.Selector{Kind: networkmap.SelectorAny}, PortFrom: 1, PortTo: 1}},
			})
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot, now := aliasPolicySnapshot(networkmap.AliasProvider)
			filter := newPolicyFilter()
			filter.clock = func() time.Time { return now }
			filter.UpdateNetwork(snapshot)
			assertAliasPacket(t, filter, PacketInbound, aliasPacket(t, vector.ConsumerWire), vector.ProviderKernel)
			changed := snapshot
			changed.Peers = append([]networkmap.Node{}, snapshot.Peers...)
			if test.change == nil {
				changed.Peers = append(changed.Peers, ordinaryPeer(t, now))
			} else {
				test.change(&changed)
			}
			filter.UpdateNetwork(changed)
			if kept := filter.ProcessPacket(PacketOutbound, aliasPacket(t, vector.ProviderReply)); kept != test.keep {
				t.Fatalf("provider reply allowed = %v, want %v", kept, test.keep)
			}
		})
	}
}

func TestPolicyFilterBoundsPurgeWorkWhenFull(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 18, 0, 0, 0, 0, time.UTC)
	filter := newPolicyFilter()
	filter.clock = func() time.Time { return now }
	filter.maximumFlows = 2
	snapshot := testPolicySnapshot()
	snapshot.Policy = nil
	filter.UpdateNetwork(snapshot)
	open := func(port uint16) bool {
		return filter.Allow(PacketOutbound, testIPv4TransportPacket([4]byte{100, 64, 0, 3}, [4]byte{100, 64, 0, 4}, port, 53, packetmeta.ProtocolUDP, 0))
	}
	open(40001)
	open(40002)
	now = now.Add(udpFlowTimeout + time.Second)
	open(40003) // full of expired flows: one purge frees room
	if len(filter.flows) != 1 {
		t.Fatalf("flows = %d after purge, want 1", len(filter.flows))
	}
	if defaultMaximumTrackedFlows < 32768 {
		t.Fatalf("default flow capacity %d is below 32768", defaultMaximumTrackedFlows)
	}
}

// A local server's UDP reply creates a flow from a self address, but the
// exchange was admitted by a local rule: revoking the rule must end it.
func TestPolicyFilterRuleRevocationEndsRuleAdmittedUDPExchange(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 18, 0, 0, 0, 0, time.UTC)
	filter := newPolicyFilter()
	filter.clock = func() time.Time { return now }
	snapshot := testPolicySnapshotFor(netip.MustParsePrefix("100.64.0.3/32"), netip.MustParsePrefix("100.64.0.4/32"),
		packetmeta.ProtocolUDP, 53, 53)
	filter.UpdateNetwork(snapshot)
	request := testIPv4TransportPacket([4]byte{100, 64, 0, 4}, [4]byte{100, 64, 0, 3}, 40000, 53, packetmeta.ProtocolUDP, 0)
	if !filter.Allow(PacketInbound, request) || !filter.Allow(PacketOutbound, reverseTestPacket(request)) {
		t.Fatal("rule-admitted UDP exchange denied")
	}
	revoked := snapshot
	revoked.Policy = nil
	filter.UpdateNetwork(revoked)
	if filter.Allow(PacketInbound, request) {
		t.Fatal("revoked rule still admits the peer through the reply flow")
	}
}

// A flow from before this node's own key lapsed stays dead when the next map
// extends the key.
func TestPolicyFilterSelfLapseEndsFlows(t *testing.T) {
	t.Parallel()
	filter, snapshot, reply, now := retentionFixture(t)
	snapshot.Self.KeyExpiry = now.Add(time.Minute)
	filter.UpdateNetwork(snapshot)
	if !filter.Allow(PacketInbound, reply) {
		t.Fatal("flow lost when the self key gained an expiry")
	}
	*now = now.Add(2 * time.Minute)
	snapshot.Self.KeyExpiry = now.Add(time.Hour)
	filter.UpdateNetwork(snapshot)
	if filter.Allow(PacketInbound, reply) {
		t.Fatal("flow survived a lapsed self key")
	}
}

// A wall clock that steps backwards must not stop the full-table purge.
func TestPolicyFilterPurgesAfterClockStepsBack(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 18, 0, 0, 0, 0, time.UTC)
	filter := newPolicyFilter()
	filter.clock = func() time.Time { return now }
	filter.maximumFlows = 1
	snapshot := testPolicySnapshot()
	snapshot.Policy = nil
	filter.UpdateNetwork(snapshot)
	open := func(port uint16) {
		filter.Allow(PacketOutbound, testIPv4TransportPacket([4]byte{100, 64, 0, 3}, [4]byte{100, 64, 0, 4}, port, 53, packetmeta.ProtocolUDP, 0))
	}
	open(40001)
	now = now.Add(time.Hour)
	open(40002) // purges at the later time
	now = now.Add(-30 * time.Minute)
	filter.flows = map[flowKey]flowState{{protocol: packetmeta.ProtocolUDP}: {expiresAt: now.Add(-time.Second)}}
	open(40003)
	if _, ok := filter.flows[flowKey{protocol: packetmeta.ProtocolUDP}]; ok {
		t.Fatal("expired flow kept after the clock stepped back")
	}
}

// With allow-all rules the reverse of an outbound SYN is also allowed; a rule
// change must still keep a TCP flow this node opened.
func TestPolicyFilterKeepsOwnTCPFlowUnderAllowAllRules(t *testing.T) {
	t.Parallel()
	filter, snapshot, reply, _ := retentionFixture(t)
	allowAll := []networkmap.Rule{{
		Sources:      []networkmap.Selector{{Kind: networkmap.SelectorAny}},
		Destinations: []networkmap.Destination{{Selector: networkmap.Selector{Kind: networkmap.SelectorAny}, PortTo: 65535}},
	}}
	snapshot.Policy = allowAll
	filter.UpdateNetwork(snapshot)
	syn := testIPv4TransportPacket([4]byte{100, 64, 0, 3}, [4]byte{100, 64, 0, 4}, 48400, 22, packetmeta.ProtocolTCP, tcpSYN)
	if !filter.Allow(PacketOutbound, syn) {
		t.Fatal("outbound SYN denied")
	}
	snapshot.Policy = append(append([]networkmap.Rule{}, allowAll...), testPolicySnapshot().Policy...)
	filter.UpdateNetwork(snapshot)
	later := testIPv4TransportPacket([4]byte{100, 64, 0, 4}, [4]byte{100, 64, 0, 3}, 22, 48400, packetmeta.ProtocolTCP, tcpPSHACK)
	if !filter.Allow(PacketInbound, later) || !filter.Allow(PacketInbound, reply) {
		t.Fatal("rule change dropped TCP flows this node opened")
	}
}
