package dataplane

import (
	"bytes"
	"net/netip"
	"sync"
	"testing"
	"time"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/client/internal/flowcount"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/packetmeta"
)

var (
	flowSelf6 = netip.MustParseAddr("fd07:d4de:9d87::3")
	flowPeer6 = netip.MustParseAddr("fd07:d4de:9d87::4")
)

// openSnapshot lets every peer reach every port of this node, both ways.
func openSnapshot() networkmap.Snapshot {
	snapshot := meshFlowSnapshot()
	snapshot.Self.Addresses = append(snapshot.Self.Addresses, netip.PrefixFrom(flowSelf6, 128))
	snapshot.Peers[0].Addresses = append(snapshot.Peers[0].Addresses, netip.PrefixFrom(flowPeer6, 128))
	snapshot.Policy = []networkmap.Rule{{
		Sources:      []networkmap.Selector{{Kind: networkmap.SelectorAny}},
		Destinations: []networkmap.Destination{{Selector: networkmap.Selector{Kind: networkmap.SelectorAny}, PortTo: 65535}},
	}}
	return snapshot
}

type flowStep struct {
	direction PacketDirection
	packet    []byte
}

func runSteps(t *testing.T, filter *policyFilter, steps ...flowStep) {
	t.Helper()
	for index, step := range steps {
		if !filter.ProcessPacket(step.direction, step.packet) {
			t.Fatalf("step %d denied", index)
		}
	}
}

// A UDP query this node sends under a rule that also admits the reverse is
// still its own outbound flow, keyed by the server's port.
func TestFlowObserveUDPOpenedHereUnderAllowAll(t *testing.T) {
	t.Parallel()
	filter, counter := countingFilter(openSnapshot())
	query := testIPv4TransportPacket(flowSelf, flowPeer, 41000, 53, packetmeta.ProtocolUDP, 0)
	runSteps(t, filter, flowStep{PacketOutbound, query}, flowStep{PacketInbound, reverseTestPacket(query)},
		flowStep{PacketOutbound, query})
	record := onlyRecord(t, counter)
	if record.GetDirection() != flowlogv1.FlowRecord_OUTBOUND || record.GetPrimary() || record.GetDestinationPort() != 53 ||
		record.GetPacketsOut() != 2 || record.GetPacketsIn() != 1 {
		t.Fatalf("record %v", record)
	}
	// And a query a peer sends here is the peer's.
	inbound := testIPv4TransportPacket(flowPeer, flowSelf, 42000, 53, packetmeta.ProtocolUDP, 0)
	runSteps(t, filter, flowStep{PacketInbound, inbound}, flowStep{PacketOutbound, reverseTestPacket(inbound)})
	record = onlyRecord(t, counter)
	if record.GetDirection() != flowlogv1.FlowRecord_INBOUND || !record.GetPrimary() || record.GetDestinationPort() != 53 ||
		record.GetPacketsIn() != 1 {
		t.Fatalf("inbound record %v", record)
	}
}

// A consumer's DNS question to the exit node's forwarder is one inbound
// record at the exit node, over UDP and TCP.
func TestFlowObserveExitDNS(t *testing.T) {
	t.Parallel()
	snapshot := testRouterSnapshot()
	snapshot.Peers[0].StableID = testPeerUUID
	filter, counter := countingFilter(snapshot)
	filter.SetExitInstalled(testPoolUUID, testExitRules(), nil, 2)
	udp := testIPv4TransportPacket(flowPeer, flowSelf, 40000, 53, packetmeta.ProtocolUDP, 0)
	tcp := testIPv4TransportPacket(flowPeer, flowSelf, 40001, 53, packetmeta.ProtocolTCP, 0x02)
	tcpAnswer := reverseTestPacket(tcp)
	tcpAnswer[33] = 0x12
	runSteps(t, filter, flowStep{PacketInbound, udp}, flowStep{PacketOutbound, reverseTestPacket(udp)},
		flowStep{PacketInbound, udp}, flowStep{PacketInbound, tcp}, flowStep{PacketOutbound, tcpAnswer})
	records := flowRecords(t, counter)
	if len(records) != 2 {
		t.Fatalf("records %v", records)
	}
	for _, record := range records {
		if record.GetClass() != flowlogv1.FlowRecord_MESH || record.GetDirection() != flowlogv1.FlowRecord_INBOUND ||
			!record.GetPrimary() || record.GetDestinationPort() != 53 || record.GetPacketsIn() != 1 {
			t.Errorf("DNS record %v", record)
		}
	}
}

// Echo both ways and IPv6 ULA peers count; neighbour discovery does not.
func TestFlowObserveICMPAndIPv6(t *testing.T) {
	t.Parallel()
	filter, counter := countingFilter(openSnapshot())
	runSteps(t, filter,
		flowStep{PacketOutbound, testIPv4ICMPPacket(flowSelf, flowPeer, 8, 7)},
		flowStep{PacketInbound, testIPv4ICMPPacket(flowPeer, flowSelf, 0, 7)},
		flowStep{PacketInbound, testIPv6ICMPPacket(flowPeer6, flowSelf6, 128, 9)},
		flowStep{PacketOutbound, testIPv6ICMPPacket(flowSelf6, flowPeer6, 129, 9)},
		flowStep{PacketOutbound, testIPv6TransportPacket(flowSelf6, flowPeer6, 41000, 443, packetmeta.ProtocolTCP, 0x02)},
	)
	filter.ProcessPacket(PacketOutbound, testIPv6ICMPPacket(flowSelf6, netip.MustParseAddr("ff02::2"), 133, 0))
	filter.ProcessPacket(PacketInbound, testIPv6ICMPPacket(flowPeer6, flowSelf6, 135, 0))
	records := flowRecords(t, counter)
	if len(records) != 3 {
		t.Fatalf("records %v", records)
	}
	directions := map[flowlogv1.FlowRecord_Direction]int{}
	for _, record := range records {
		directions[record.GetDirection()]++
		if record.GetPacketsOut()+record.GetPacketsIn() == 0 || len(record.GetSourceIp()) == 0 {
			t.Errorf("record %v", record)
		}
	}
	if directions[flowlogv1.FlowRecord_OUTBOUND] != 2 || directions[flowlogv1.FlowRecord_INBOUND] != 1 {
		t.Fatalf("directions %v", directions)
	}
}

// A consumer's Internet traffic through the exit node is an exit record
// with no address; without the exit route it is a denial.
func TestFlowObserveExitConsumer(t *testing.T) {
	t.Parallel()
	snapshot := withExitRoute(meshFlowSnapshot(), false)
	snapshot.Exits[0].Ref, snapshot.ExitRoute.Pool = testPoolUUID, testPoolUUID
	filter, counter := countingFilter(snapshot)
	out := testIPv4TransportPacket(flowSelf, [4]byte{8, 8, 8, 8}, 40000, 443, packetmeta.ProtocolTCP, 0x02)
	reply := reverseTestPacket(out)
	reply[33] = 0x12
	if filter.ProcessPacket(PacketOutbound, out) {
		t.Fatal("the Internet was reached without the exit route")
	}
	if records := flowRecords(t, counter); len(records) != 0 {
		t.Fatalf("an Internet packet with no exit route in use counted: %v", records)
	}
	filter.SetExitRouted(true)
	runSteps(t, filter, flowStep{PacketOutbound, out}, flowStep{PacketInbound, reply})
	record := onlyRecord(t, counter)
	if record.GetClass() != flowlogv1.FlowRecord_EXIT || record.GetDirection() != flowlogv1.FlowRecord_OUTBOUND ||
		record.GetPrimary() || len(record.GetSourceIp()) != 0 || len(record.GetDestinationIp()) != 0 ||
		record.GetPacketsIn() != 1 || !bytes.Equal(record.GetExitPoolId(), idBytes(testPoolUUID)) {
		t.Fatalf("record %v", record)
	}
	snapshot.Peers[0].Expired = true
	filter.UpdateNetwork(snapshot)
	if filter.ProcessPacket(PacketOutbound, out) {
		t.Fatal("an expired exit node was used")
	}
	if record = onlyRecord(t, counter); record.GetDenyReason() != flowlogv1.FlowRecord_ROUTE_NOT_INSTALLED ||
		len(record.GetDestinationIp()) != 0 {
		t.Fatalf("denial %v", record)
	}
}

// A router's own services are mesh records; its LAN address through a
// Site prefix is noise.
func TestFlowObserveRouterOwnTraffic(t *testing.T) {
	t.Parallel()
	snapshot := testRouterSnapshot()
	snapshot.Peers[0].StableID = testPeerUUID
	snapshot.Policy = append(snapshot.Policy, openSnapshot().Policy...)
	filter, counter := countingFilter(snapshot)
	routerLAN := [4]byte{10, 35, 0, 2}
	filter.SetServedInstalled(nil, []netip.Addr{netip.AddrFrom4(routerLAN)})
	runSteps(t, filter, flowStep{PacketInbound, testIPv4TransportPacket(flowPeer, flowSelf, 40000, 22, packetmeta.ProtocolTCP, 0x02)})
	filter.ProcessPacket(PacketInbound, testIPv4TransportPacket(flowPeer, routerLAN, 40000, 443, packetmeta.ProtocolTCP, 0x02))
	record := onlyRecord(t, counter)
	if record.GetClass() != flowlogv1.FlowRecord_MESH || record.GetDirection() != flowlogv1.FlowRecord_INBOUND {
		t.Fatalf("record %v", record)
	}
}

// A late answer after this node reset its flow is noise, not a denial.
func TestFlowObserveLateAnswerAfterReset(t *testing.T) {
	t.Parallel()
	filter, counter := countingFilter(meshFlowSnapshot())
	runSteps(t, filter,
		flowStep{PacketOutbound, testIPv4TransportPacket(flowSelf, flowPeer, 41000, 22, packetmeta.ProtocolTCP, 0x02)},
		flowStep{PacketOutbound, testIPv4TransportPacket(flowSelf, flowPeer, 41000, 22, packetmeta.ProtocolTCP, 0x04)},
	)
	if filter.ProcessPacket(PacketInbound, testIPv4TransportPacket(flowPeer, flowSelf, 22, 41000, packetmeta.ProtocolTCP, 0x10)) {
		t.Fatal("an answer after a reset was admitted")
	}
	for _, record := range flowRecords(t, counter) {
		if record.GetKind() == flowlogv1.FlowRecord_DENY {
			t.Fatalf("a late answer was a denial: %v", record)
		}
	}
}

// An exit node's consumer limit is its capacity, not the pool's rules.
func TestFlowObserveExitCapacity(t *testing.T) {
	t.Parallel()
	snapshot := testRouterSnapshot()
	second := snapshot.Peers[0]
	second.ID, second.StableID, second.PublicKey = 5, "01890f00-0000-7000-8000-0000000000a5", "nodekey:second"
	second.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.5/32")}
	snapshot.Peers = append(snapshot.Peers, second)
	filter, counter := countingFilter(snapshot)
	rules := testExitRules()
	rules[0].Sources[0].Prefix = netip.MustParsePrefix("100.64.0.0/10")
	filter.SetExitInstalled(testPoolUUID, rules, nil, 1)
	runSteps(t, filter, flowStep{PacketInbound, testIPv4TransportPacket(flowPeer, [4]byte{8, 8, 8, 8}, 40000, 443,
		packetmeta.ProtocolTCP, 0x02)})
	if filter.ProcessPacket(PacketInbound, testIPv4TransportPacket([4]byte{100, 64, 0, 5}, [4]byte{8, 8, 8, 8}, 40000, 443,
		packetmeta.ProtocolTCP, 0x02)) {
		t.Fatal("a consumer past the limit was forwarded")
	}
	var denial *flowlogv1.FlowRecord
	for _, record := range flowRecords(t, counter) {
		if record.GetKind() == flowlogv1.FlowRecord_DENY {
			denial = record
		}
	}
	if denial == nil || denial.GetDenyReason() != flowlogv1.FlowRecord_CAPACITY {
		t.Fatalf("denial %v", denial)
	}
}

// A share outside its services is SHARE_SERVICE (an ICMP error is noise);
// a share the map left out is not in the map.
func TestFlowObserveShareDenials(t *testing.T) {
	t.Parallel()
	services := 0
	for _, vector := range aliasRoundtripVectors(t) {
		consumer := newAliasFilter(t, networkmap.AliasConsumer)
		counter := flowcount.NewCounter(flowcount.DeviceKeys, flowcount.DeviceDenyKeys, consumer.clock())
		consumer.SetFlowCounter(counter)
		if consumer.ProcessPacket(PacketOutbound, aliasPacket(t, vector.DeniedConsumerKernel)) {
			t.Fatalf("%s: a packet outside the share was sent", vector.Name)
		}
		for _, record := range counter.Drain(consumer.clock(), flowcount.ID{}).Records {
			if record.GetDenyReason() != flowlogv1.FlowRecord_SHARE_SERVICE {
				t.Errorf("%s: denial %v", vector.Name, record)
			}
			services++
		}
		// A map whose provider's key lapses before the grant leaves the
		// share out: the alias address is then not in the map.
		snapshot, now := aliasPolicySnapshot(networkmap.AliasConsumer)
		snapshot.Peers[0].KeyExpiry = now.Add(30 * time.Second)
		consumer.UpdateNetwork(snapshot)
		if consumer.ProcessPacket(PacketOutbound, aliasPacket(t, vector.ConsumerKernel)) {
			t.Fatalf("%s: a share left out of the map was reached", vector.Name)
		}
		records := counter.Drain(consumer.clock(), flowcount.ID{}).Records
		if len(records) != 1 || records[0].GetDenyReason() != flowlogv1.FlowRecord_NOT_IN_MAP ||
			len(records[0].GetDestinationDeviceId()) != 0 {
			t.Errorf("%s: denial %v", vector.Name, records)
		}
	}
	if services == 0 {
		t.Fatal("no vector was a service denial")
	}
}

// Counting never changes a decision or a packet's bytes.
func TestFlowObserveDecisionsUnchanged(t *testing.T) {
	t.Parallel()
	for _, vector := range aliasRoundtripVectors(t) {
		for _, role := range []networkmap.AliasRole{networkmap.AliasConsumer, networkmap.AliasProvider} {
			plain, counted := newAliasFilter(t, role), newAliasFilter(t, role)
			counted.SetFlowCounter(flowcount.NewCounter(flowcount.DeviceKeys, flowcount.DeviceDenyKeys, counted.clock()))
			for _, step := range []struct {
				direction PacketDirection
				hex       string
			}{
				{PacketOutbound, vector.ConsumerKernel},
				{PacketInbound, vector.ConsumerKernel},
				{PacketOutbound, vector.ProviderReply},
				{PacketInbound, vector.ProviderReply},
				{PacketOutbound, vector.DeniedConsumerKernel},
				{PacketOutbound, vector.SpoofedConsumerKernel},
				{PacketInbound, vector.ReverseConsumerWire},
				{PacketOutbound, vector.ReverseProviderKernel},
			} {
				first, second := aliasPacket(t, step.hex), aliasPacket(t, step.hex)
				if plain.ProcessPacket(step.direction, first) != counted.ProcessPacket(step.direction, second) ||
					!bytes.Equal(first, second) {
					t.Fatalf("%s %s: counting changed a decision", vector.Name, role)
				}
			}
		}
	}
	plain, _ := countingFilter(openSnapshot())
	plain.SetFlowCounter(nil)
	counted, _ := countingFilter(openSnapshot())
	for _, step := range []flowStep{
		{PacketOutbound, testIPv4TransportPacket(flowSelf, flowPeer, 41000, 53, packetmeta.ProtocolUDP, 0)},
		{PacketInbound, testIPv4TransportPacket(flowPeer, flowSelf, 53, 41000, packetmeta.ProtocolUDP, 0)},
		{PacketOutbound, testIPv4TransportPacket(flowSelf, [4]byte{100, 64, 0, 9}, 1, 2, packetmeta.ProtocolTCP, 0x02)},
		{PacketInbound, testIPv4ICMPPacket(flowPeer, flowSelf, 0, 1)},
	} {
		if plain.ProcessPacket(step.direction, bytes.Clone(step.packet)) != counted.ProcessPacket(step.direction, bytes.Clone(step.packet)) {
			t.Fatal("counting changed a decision")
		}
	}
}

// Counters can be swapped while packets flow (run with -race).
func TestFlowObserveCounterSwap(t *testing.T) {
	t.Parallel()
	filter, _ := countingFilter(openSnapshot())
	var group sync.WaitGroup
	for worker := range uint16(4) {
		group.Go(func() {
			for index := range uint16(2000) {
				packet := testIPv4TransportPacket(flowSelf, flowPeer, 40000+worker, index%100+1,
					packetmeta.ProtocolTCP, 0x02)
				filter.ProcessPacket(PacketOutbound, packet)
			}
		})
	}
	for range 50 {
		filter.SetFlowCounter(flowcount.NewCounter(flowcount.DeviceKeys, flowcount.DeviceDenyKeys, flowStart))
		filter.SetFlowCounter(nil)
	}
	group.Wait()
}

// A late TCP packet of a share's ended flow is noise, not capacity; a full
// flow table is capacity.
func TestFlowObserveShareStaleAndFull(t *testing.T) {
	t.Parallel()
	for _, vector := range aliasRoundtripVectors(t) {
		request := aliasPacket(t, vector.ConsumerKernel)
		header, err := packetmeta.Parse(request)
		if err != nil || header.Protocol != packetmeta.ProtocolTCP {
			continue
		}
		consumer := newAliasFilter(t, networkmap.AliasConsumer)
		counter := flowcount.NewCounter(flowcount.DeviceKeys, flowcount.DeviceDenyKeys, consumer.clock())
		consumer.SetFlowCounter(counter)
		consumer.maximumFlows = 0
		if consumer.ProcessPacket(PacketOutbound, bytes.Clone(request)) {
			t.Fatalf("%s: a flow past the table's limit was opened", vector.Name)
		}
		records := counter.Drain(consumer.clock(), flowcount.ID{}).Records
		if len(records) != 1 || records[0].GetDenyReason() != flowlogv1.FlowRecord_CAPACITY {
			t.Fatalf("%s: full table %v", vector.Name, records)
		}
		// The request as a bare ACK, on no tracked flow: what the filter
		// denies after a share's flow ended.
		fresh := newAliasFilter(t, networkmap.AliasConsumer)
		fresh.maximumFlows = 0 // even a full table: stale is never capacity
		header.TCPFlags = 0x10
		fresh.mu.Lock()
		grant := fresh.aliases[header.Destination]
		observation := fresh.aliasObservationLocked(PacketOutbound, header, grant, false, false, fresh.clock())
		fresh.mu.Unlock()
		if observation.Deny != flowcount.DenyNoise {
			t.Errorf("%s: a stale ACK was %v", vector.Name, observation.Deny)
		}
	}
}

// A UDP server on a high port is one inbound record, its answers included.
func TestFlowObserveUDPServerOnHighPort(t *testing.T) {
	t.Parallel()
	filter, counter := countingFilter(openSnapshot())
	query := testIPv4TransportPacket(flowPeer, flowSelf, 40000, 51820, packetmeta.ProtocolUDP, 0)
	runSteps(t, filter, flowStep{PacketInbound, query}, flowStep{PacketOutbound, reverseTestPacket(query)},
		flowStep{PacketInbound, query})
	record := onlyRecord(t, counter)
	if record.GetDirection() != flowlogv1.FlowRecord_INBOUND || record.GetDestinationPort() != 51820 ||
		record.GetPacketsOut() != 2 || record.GetPacketsIn() != 1 {
		t.Fatalf("record %v", record)
	}
}
