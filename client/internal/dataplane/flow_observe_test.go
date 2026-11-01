package dataplane

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/client/internal/flowcount"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/packetmeta"
	"meshtransit.net/shared/routedigest"
)

const (
	testPeerUUID = "01890f00-0000-7000-8000-0000000000a4"
	testSiteUUID = "01890f00-0000-7000-8000-0000000000b1"
	testPoolUUID = "01890f00-0000-7000-8000-000000000e01"
)

var flowStart = time.UnixMilli(1_800_000_000_000)

// countingFilter is a filter over snapshot whose decisions are counted.
func countingFilter(snapshot networkmap.Snapshot) (*policyFilter, *flowcount.Counter) {
	filter := newPolicyFilter()
	filter.UpdateNetwork(snapshot)
	counter := flowcount.NewCounter(flowcount.ForwarderKeys, flowcount.ForwarderDenyKeys, flowStart)
	filter.SetFlowCounter(counter)
	return filter, counter
}

func flowRecords(t *testing.T, counter *flowcount.Counter) []*flowlogv1.FlowRecord {
	t.Helper()
	return counter.Drain(flowStart.Add(time.Minute), flowcount.ID{}).Records
}

func onlyRecord(t *testing.T, counter *flowcount.Counter) *flowlogv1.FlowRecord {
	t.Helper()
	records := flowRecords(t, counter)
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1: %v", len(records), records)
	}
	return records[0]
}

func idBytes(text string) []byte {
	id := flowcount.ParseID(text)
	return id[:]
}

func meshFlowSnapshot() networkmap.Snapshot {
	snapshot := testPolicySnapshot()
	snapshot.Peers[0].ID, snapshot.Peers[0].StableID = 4, testPeerUUID
	return snapshot
}

var (
	flowSelf = [4]byte{100, 64, 0, 3}
	flowPeer = [4]byte{100, 64, 0, 4}
)

// A connection this node opens and the peer's answers are one outbound
// record naming the peer; a connection the peer opens is the receiver's,
// primary record.
func TestFlowObserveMeshDirections(t *testing.T) {
	t.Parallel()
	filter, counter := countingFilter(meshFlowSnapshot())
	request := testIPv4TransportPacket(flowSelf, flowPeer, 41000, 22, packetmeta.ProtocolTCP, 0x02)
	answer := testIPv4TransportPacket(flowPeer, flowSelf, 22, 41000, packetmeta.ProtocolTCP, 0x12)
	if !filter.ProcessPacket(PacketOutbound, request) || !filter.ProcessPacket(PacketInbound, answer) {
		t.Fatal("an opened flow was denied")
	}
	record := onlyRecord(t, counter)
	if record.GetDirection() != flowlogv1.FlowRecord_OUTBOUND || record.GetPrimary() || record.GetPacketsOut() != 1 ||
		record.GetPacketsIn() != 1 || !bytes.Equal(record.GetDestinationDeviceId(), idBytes(testPeerUUID)) {
		t.Fatalf("outbound record %v", record)
	}

	opening := testIPv4TransportPacket(flowPeer, flowSelf, 42000, 18080, packetmeta.ProtocolTCP, 0x02)
	accepting := testIPv4TransportPacket(flowSelf, flowPeer, 18080, 42000, packetmeta.ProtocolTCP, 0x12)
	if !filter.ProcessPacket(PacketInbound, opening) || !filter.ProcessPacket(PacketOutbound, accepting) {
		t.Fatal("an allowed inbound flow was denied")
	}
	record = onlyRecord(t, counter)
	if record.GetDirection() != flowlogv1.FlowRecord_INBOUND || !record.GetPrimary() || record.GetPacketsOut() != 1 ||
		record.GetPacketsIn() != 1 || record.GetDestinationPort() != 18080 ||
		!bytes.Equal(record.GetSourceDeviceId(), idBytes(testPeerUUID)) {
		t.Fatalf("inbound record %v", record)
	}
}

// Denials carry the deciding side's reason.
func TestFlowObserveDenyReasons(t *testing.T) {
	t.Parallel()
	snapshot := meshFlowSnapshot()
	filter, counter := countingFilter(snapshot)
	for _, packet := range []struct {
		direction PacketDirection
		packet    []byte
	}{
		{PacketInbound, testIPv4TransportPacket(flowPeer, flowSelf, 42000, 18081, packetmeta.ProtocolTCP, 0x02)},
		{PacketOutbound, testIPv4TransportPacket(flowSelf, [4]byte{100, 64, 0, 9}, 42000, 22, packetmeta.ProtocolTCP, 0x02)},
		{PacketOutbound, testIPv4TransportPacket(flowSelf, [4]byte{224, 0, 0, 251}, 5353, 5353, packetmeta.ProtocolUDP, 0)},
	} {
		if filter.ProcessPacket(packet.direction, packet.packet) {
			t.Fatal("a packet to deny was allowed")
		}
	}
	reasons := map[flowlogv1.FlowRecord_DenyReason]*flowlogv1.FlowRecord{}
	for _, record := range flowRecords(t, counter) {
		reasons[record.GetDenyReason()] = record
	}
	if len(reasons) != 2 || reasons[flowlogv1.FlowRecord_PORT_NOT_ALLOWED] == nil ||
		reasons[flowlogv1.FlowRecord_NOT_IN_MAP] == nil {
		t.Fatalf("reasons %v", reasons)
	}
	if !bytes.Equal(reasons[flowlogv1.FlowRecord_PORT_NOT_ALLOWED].GetSourceDeviceId(), idBytes(testPeerUUID)) {
		t.Errorf("the denied peer is not named")
	}

	snapshot.Peers[0].Expired = true
	filter.UpdateNetwork(snapshot)
	if filter.ProcessPacket(PacketOutbound, testIPv4TransportPacket(flowSelf, flowPeer, 42000, 22, packetmeta.ProtocolTCP, 0x02)) {
		t.Fatal("an expired peer was reached")
	}
	if record := onlyRecord(t, counter); record.GetDenyReason() != flowlogv1.FlowRecord_PEER_UNUSABLE {
		t.Fatalf("expired peer %v", record)
	}
}

// A router's forwarded flows are Site records naming the Site; the Site's
// answers count into them.
func TestFlowObserveRouter(t *testing.T) {
	t.Parallel()
	snapshot := testRouterSnapshot()
	snapshot.Peers[0].StableID = testPeerUUID
	filter, counter := countingFilter(snapshot)
	filter.SetServedInstalled([]routedigest.Entry{
		{SiteRef: testSiteUUID, Prefix: netip.MustParsePrefix("10.35.0.0/17"), Masquerade: true},
	}, []netip.Addr{netip.AddrFrom4([4]byte{10, 35, 0, 2})})
	toTarget := testIPv4TransportPacket(flowPeer, [4]byte{10, 35, 0, 4}, 40000, 443, packetmeta.ProtocolTCP, 0x02)
	if !filter.ProcessPacket(PacketInbound, toTarget) || !filter.ProcessPacket(PacketOutbound, reverseTestPacket(toTarget)) {
		t.Fatal("a forwarded flow was denied")
	}
	if filter.ProcessPacket(PacketInbound, testIPv4TransportPacket(flowPeer, [4]byte{10, 35, 0, 4}, 40000, 22,
		packetmeta.ProtocolTCP, 0x02)) {
		t.Fatal("a port the rules deny was forwarded")
	}
	var flow, denial *flowlogv1.FlowRecord
	for _, record := range flowRecords(t, counter) {
		if record.GetKind() == flowlogv1.FlowRecord_DENY {
			denial = record
		} else {
			flow = record
		}
	}
	if flow == nil || flow.GetClass() != flowlogv1.FlowRecord_SITE || !flow.GetPrimary() ||
		flow.GetDirection() != flowlogv1.FlowRecord_FORWARDED || flow.GetPacketsIn() != 1 ||
		!bytes.Equal(flow.GetSiteId(), idBytes(testSiteUUID)) || !bytes.Equal(flow.GetSourceDeviceId(), idBytes(testPeerUUID)) {
		t.Fatalf("forwarded record %v", flow)
	}
	if denial == nil || denial.GetDenyReason() != flowlogv1.FlowRecord_PORT_NOT_ALLOWED ||
		!bytes.Equal(denial.GetSiteId(), idBytes(testSiteUUID)) {
		t.Fatalf("denial %v", denial)
	}
}

// An exit node's records keep only pool, protocol and port.
func TestFlowObserveExitNode(t *testing.T) {
	t.Parallel()
	snapshot := testRouterSnapshot()
	snapshot.Peers[0].StableID = testPeerUUID
	filter, counter := countingFilter(snapshot)
	filter.SetExitInstalled(testPoolUUID, testExitRules(), nil, 2)
	toInternet := testIPv4TransportPacket(flowPeer, [4]byte{8, 8, 8, 8}, 40000, 443, packetmeta.ProtocolTCP, 0x02)
	if !filter.ProcessPacket(PacketInbound, toInternet) || !filter.ProcessPacket(PacketOutbound, reverseTestPacket(toInternet)) {
		t.Fatal("an exit flow was denied")
	}
	if filter.ProcessPacket(PacketInbound, testIPv4TransportPacket(flowPeer, [4]byte{8, 8, 8, 8}, 40000, 80,
		packetmeta.ProtocolTCP, 0x02)) {
		t.Fatal("a port the pool denies was forwarded")
	}
	records := flowRecords(t, counter)
	if len(records) != 2 {
		t.Fatalf("records %v", records)
	}
	for _, record := range records {
		if record.GetClass() != flowlogv1.FlowRecord_EXIT || len(record.GetSourceIp()) != 0 ||
			len(record.GetDestinationIp()) != 0 || len(record.GetSourceDeviceId()) != 0 ||
			!bytes.Equal(record.GetExitPoolId(), idBytes(testPoolUUID)) {
			t.Errorf("exit record %v", record)
		}
	}
}

// A consumer's traffic to a Site is a Site record; a Site without its route
// is a denial.
func TestFlowObserveSiteConsumer(t *testing.T) {
	t.Parallel()
	snapshot := testRoutedSnapshot()
	snapshot.Routes[0].Ref = testSiteUUID
	filter, counter := countingFilter(snapshot)
	filter.SetRoutedInstalled([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("10.30.0.0/16")})
	toSite := testIPv4TransportPacket(flowSelf, [4]byte{10, 20, 0, 5}, 40000, 443, packetmeta.ProtocolTCP, 0x02)
	reply := reverseTestPacket(toSite)
	reply[33] = 0x12
	if !filter.ProcessPacket(PacketOutbound, toSite) || !filter.ProcessPacket(PacketInbound, reply) {
		t.Fatal("a Site flow was denied")
	}
	if filter.ProcessPacket(PacketOutbound, testIPv4TransportPacket(flowSelf, [4]byte{10, 30, 0, 5}, 40000, 443,
		packetmeta.ProtocolTCP, 0x02)) {
		t.Fatal("an unserved Site was reached")
	}
	var flow, denial *flowlogv1.FlowRecord
	for _, record := range flowRecords(t, counter) {
		if record.GetKind() == flowlogv1.FlowRecord_DENY {
			denial = record
		} else {
			flow = record
		}
	}
	if flow == nil || flow.GetClass() != flowlogv1.FlowRecord_SITE || flow.GetPrimary() || flow.GetPacketsIn() != 1 ||
		!bytes.Equal(flow.GetSiteId(), idBytes(testSiteUUID)) {
		t.Fatalf("consumer record %v", flow)
	}
	if denial == nil || denial.GetDenyReason() != flowlogv1.FlowRecord_ROUTE_NOT_INSTALLED {
		t.Fatalf("denial %v", denial)
	}
}

// A share's records on either side name the contract and no Device; an
// expired grant is its own reason.
func TestFlowObserveShare(t *testing.T) {
	t.Parallel()
	contract := idBytes("00000000-0000-4000-8000-000000000001")
	for _, vector := range aliasRoundtripVectors(t) {
		consumer, provider := newAliasFilter(t, networkmap.AliasConsumer), newAliasFilter(t, networkmap.AliasProvider)
		now := consumer.clock()
		consumerCounter := flowcount.NewCounter(flowcount.DeviceKeys, flowcount.DeviceDenyKeys, now)
		providerCounter := flowcount.NewCounter(flowcount.DeviceKeys, flowcount.DeviceDenyKeys, now)
		consumer.SetFlowCounter(consumerCounter)
		provider.SetFlowCounter(providerCounter)
		request := aliasPacket(t, vector.ConsumerKernel)
		reply := aliasPacket(t, vector.ProviderReply)
		if !consumer.ProcessPacket(PacketOutbound, request) || !provider.ProcessPacket(PacketInbound, request) ||
			!provider.ProcessPacket(PacketOutbound, reply) || !consumer.ProcessPacket(PacketInbound, reply) {
			t.Fatalf("%s: a share flow was denied", vector.Name)
		}
		for side, counter := range map[string]*flowcount.Counter{"consumer": consumerCounter, "provider": providerCounter} {
			records := counter.Drain(now, flowcount.ID{}).Records
			if len(records) != 1 {
				t.Fatalf("%s %s: records %v", vector.Name, side, records)
			}
			record := records[0]
			if record.GetClass() != flowlogv1.FlowRecord_SHARE || !record.GetPrimary() || record.GetPacketsOut() != 1 ||
				record.GetPacketsIn() != 1 || !bytes.Equal(record.GetTrustContractId(), contract) ||
				len(record.GetSourceDeviceId()) != 0 || len(record.GetDestinationDeviceId()) != 0 {
				t.Errorf("%s %s: record %v", vector.Name, side, record)
			}
		}
		consumer.clock = func() time.Time { return now.Add(2 * time.Minute) }
		if consumer.ProcessPacket(PacketOutbound, aliasPacket(t, vector.ConsumerKernel)) {
			t.Fatalf("%s: an expired share was reached", vector.Name)
		}
		if record := consumerCounter.Drain(now, flowcount.ID{}).Records; len(record) != 1 ||
			record[0].GetDenyReason() != flowlogv1.FlowRecord_SHARE_EXPIRED {
			t.Errorf("%s: expired share %v", vector.Name, record)
		}
	}
}

// Without a counter nothing is counted, and turning it off stops counting.
func TestFlowObserveOff(t *testing.T) {
	t.Parallel()
	filter, counter := countingFilter(meshFlowSnapshot())
	filter.SetFlowCounter(nil)
	if !filter.ProcessPacket(PacketOutbound, testIPv4TransportPacket(flowSelf, flowPeer, 41000, 22, packetmeta.ProtocolTCP, 0x02)) {
		t.Fatal("denied")
	}
	if records := flowRecords(t, counter); len(records) != 0 {
		t.Fatalf("counted while off: %v", records)
	}
}

func BenchmarkProcessPacketForwarded(b *testing.B) {
	for _, counting := range []bool{false, true} {
		name := "off"
		if counting {
			name = "counting"
		}
		b.Run(name, func(b *testing.B) {
			snapshot := testRouterSnapshot()
			snapshot.Peers[0].StableID = testPeerUUID
			filter := newPolicyFilter()
			filter.UpdateNetwork(snapshot)
			filter.SetServedInstalled([]routedigest.Entry{
				{SiteRef: testSiteUUID, Prefix: netip.MustParsePrefix("10.35.0.0/17"), Masquerade: true},
			}, nil)
			if counting {
				filter.SetFlowCounter(flowcount.NewCounter(flowcount.ForwarderKeys, flowcount.ForwarderDenyKeys, flowStart))
			}
			packet := testIPv4TransportPacket(flowPeer, [4]byte{10, 35, 0, 4}, 40000, 443, packetmeta.ProtocolTCP, 0x10)
			b.ReportAllocs()
			for b.Loop() {
				if !filter.ProcessPacket(PacketInbound, packet) {
					b.Fatal("denied")
				}
			}
		})
	}
}
