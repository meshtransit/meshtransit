package flowcount

import (
	"bytes"
	"net/netip"
	"sync"
	"testing"
	"time"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/client/internal/packetmeta"
)

var (
	start  = time.UnixMilli(1_800_000_000_000)
	self   = netip.MustParseAddr("100.64.0.1")
	remote = netip.MustParseAddr("100.64.0.2")
	peerID = ID{2}
	poolID = ID{7}
)

func tcp(source, destination netip.Addr, sourcePort, destinationPort uint16, flags uint8) packetmeta.Header {
	return packetmeta.Header{
		Source: source, Destination: destination, SourcePort: sourcePort, DestinationPort: destinationPort,
		Protocol: packetmeta.ProtocolTCP, TCPFlags: flags, Length: 100,
	}
}

func drainOne(t *testing.T, counter *Counter) *flowlogv1.FlowRecord {
	t.Helper()
	window := counter.Drain(start.Add(time.Minute), ID{})
	if len(window.Records) != 1 {
		t.Fatalf("records = %d, want 1: %v", len(window.Records), window.Records)
	}
	checkRecord(t, window.Records[0])
	return window.Records[0]
}

// checkRecord holds a record to the receiver's refusals (flowlog-v1 §6).
func checkRecord(t *testing.T, record *flowlogv1.FlowRecord) {
	t.Helper()
	for _, ip := range [][]byte{record.GetSourceIp(), record.GetDestinationIp()} {
		if len(ip) != 0 && len(ip) != 4 && len(ip) != 16 {
			t.Errorf("IP of %d bytes", len(ip))
		}
		if address, ok := netip.AddrFromSlice(ip); ok && !isPrivate(address) {
			t.Errorf("public IP %v left the node", address)
		}
	}
	for _, id := range [][]byte{
		record.GetSourceDeviceId(), record.GetDestinationDeviceId(), record.GetTrustContractId(),
		record.GetSiteId(), record.GetExitPoolId(), record.GetClusterId(), record.GetFlowId(),
	} {
		if len(id) != 0 && len(id) != 16 {
			t.Errorf("ID of %d bytes", len(id))
		}
	}
	if record.GetLastSeenMs() < record.GetFirstSeenMs() || record.GetKind() == 0 || record.GetClass() == 0 ||
		record.GetDirection() == 0 {
		t.Errorf("record %v", record)
	}
	deny := record.GetKind() == flowlogv1.FlowRecord_DENY
	if deny != (record.GetDenyReason() != 0) || (!deny && (record.GetDistinctPorts() != 0 || len(record.GetSamplePorts()) != 0)) ||
		len(record.GetSamplePorts()) > MaxSamplePorts || len(record.GetSamplePorts()) > int(record.GetDistinctPorts()) && deny {
		t.Errorf("deny fields of %v", record)
	}
}

// A connection this node opens is one record: source first, its ephemeral
// port collapsed, replies counted in, the peer named, not primary.
func TestOutboundConnection(t *testing.T) {
	t.Parallel()
	counter := NewCounter(DeviceKeys, DeviceDenyKeys, start)
	outbound := Observation{Class: ClassMesh, Direction: DirectionOutbound, Peer: peerID}
	for _, step := range []struct {
		header packetmeta.Header
		reply  bool
	}{
		{tcp(self, remote, 50000, 22, tcpSYN), false},
		{tcp(remote, self, 22, 50000, tcpSYN|tcpACK), true},
		{tcp(self, remote, 50000, 22, tcpACK), false},
		{tcp(remote, self, 22, 50000, tcpACK), true},
		{tcp(self, remote, 50000, 22, tcpFIN|tcpACK), false},
	} {
		observation := outbound
		observation.Header, observation.Reply = step.header, step.reply
		counter.Observe(observation, start.Add(time.Second))
	}
	record := drainOne(t, counter)
	if !bytes.Equal(record.GetSourceIp(), self.AsSlice()) || !bytes.Equal(record.GetDestinationIp(), remote.AsSlice()) ||
		record.GetSourcePort() != 0 || record.GetDestinationPort() != 22 {
		t.Errorf("endpoints %v", record)
	}
	if record.GetPacketsOut() != 3 || record.GetPacketsIn() != 2 || record.GetBytesOut() != 300 ||
		record.GetConnections() != 1 || !record.GetEnded() || record.GetTcpState() != flowlogv1.FlowRecord_CLOSING {
		t.Errorf("counts %v", record)
	}
	if record.GetPrimary() || !bytes.Equal(record.GetDestinationDeviceId(), peerID[:]) ||
		record.GetDirection() != flowlogv1.FlowRecord_OUTBOUND {
		t.Errorf("identity %v", record)
	}
}

// Two connections from different ephemeral ports merge; the receiving node's
// record is primary and names the sender.
func TestInboundConnectionsMerge(t *testing.T) {
	t.Parallel()
	counter := NewCounter(DeviceKeys, DeviceDenyKeys, start)
	for _, port := range []uint16{40000, 40001} {
		counter.Observe(Observation{
			Header: tcp(remote, self, port, 443, tcpSYN), Class: ClassMesh,
			Direction: DirectionInbound, Peer: peerID,
		}, start)
	}
	record := drainOne(t, counter)
	if record.GetConnections() != 2 || !record.GetPrimary() || !bytes.Equal(record.GetSourceDeviceId(), peerID[:]) {
		t.Errorf("record %v", record)
	}
}

// An exit node keeps only pool, protocol and destination port; an Internet
// address never leaves the node in any class.
func TestInternetAddressesStayHome(t *testing.T) {
	t.Parallel()
	internet := netip.MustParseAddr("93.184.216.34")
	counter := NewCounter(ForwarderKeys, ForwarderDenyKeys, start)
	counter.Observe(Observation{
		Header: tcp(remote, internet, 41000, 443, tcpSYN), Class: ClassExit,
		Direction: DirectionForwarded, Peer: peerID, Scope: poolID,
	}, start)
	counter.Observe(Observation{
		Header: tcp(remote, internet, 41001, 443, tcpSYN), Class: ClassExit,
		Direction: DirectionForwarded, Peer: ID{3}, Scope: poolID,
	}, start)
	record := drainOne(t, counter)
	if len(record.GetSourceIp()) != 0 || len(record.GetDestinationIp()) != 0 || len(record.GetSourceDeviceId()) != 0 ||
		record.GetDestinationPort() != 443 || !bytes.Equal(record.GetExitPoolId(), poolID[:]) ||
		!record.GetPrimary() || record.GetConnections() != 2 {
		t.Errorf("exit record %v", record)
	}
	counter.Observe(Observation{
		Header: tcp(self, internet, 41002, 80, tcpSYN), Class: ClassMesh,
		Direction: DirectionOutbound, Deny: DenyRouteNotInstalled,
	}, start)
	record = drainOne(t, counter)
	if len(record.GetDestinationIp()) != 0 || !bytes.Equal(record.GetSourceIp(), self.AsSlice()) {
		t.Errorf("deny record %v", record)
	}
}

func TestNoiseIsNotCounted(t *testing.T) {
	t.Parallel()
	counter := NewCounter(DeviceKeys, DeviceDenyKeys, start)
	for _, destination := range []string{"224.0.0.251", "ff02::fb", "255.255.255.255", "169.254.1.1", "fe80::1", "0.0.0.0"} {
		header := packetmeta.Header{
			Source: self, Destination: netip.MustParseAddr(destination),
			Protocol: packetmeta.ProtocolUDP, DestinationPort: 5353, Length: 80,
		}
		if header.Destination.Is6() {
			header.Source = netip.MustParseAddr("fd7a::1")
		}
		counter.Observe(Observation{
			Header: header, Class: ClassMesh, Direction: DirectionOutbound,
			Deny: DenyNotInMap,
		}, start)
	}
	counter.Observe(Observation{
		Header: tcp(self, remote, 1, 2, tcpSYN), Class: ClassMesh,
		Direction: DirectionOutbound, Deny: DenyNoise,
	}, start)
	if window := counter.Drain(start, ID{}); len(window.Records) != 0 || window.Overflow != (Overflow{}) {
		t.Fatalf("noise counted: %v", window)
	}
}

// A port scan is one denial record with an estimated port count and at most
// eight sample ports.
func TestPortScanIsOneDenial(t *testing.T) {
	t.Parallel()
	counter := NewCounter(DeviceKeys, DeviceDenyKeys, start)
	for port := range uint16(2000) {
		counter.Observe(Observation{
			Header: tcp(remote, self, 40000, port+1, tcpSYN), Class: ClassMesh,
			Direction: DirectionInbound, Deny: DenyPortNotAllowed, Peer: peerID,
		}, start)
	}
	record := drainOne(t, counter)
	if record.GetPacketsOut() != 2000 || len(record.GetSamplePorts()) != MaxSamplePorts ||
		record.GetDenyReason() != flowlogv1.FlowRecord_PORT_NOT_ALLOWED || !record.GetPrimary() {
		t.Errorf("record %v", record)
	}
	if distinct := record.GetDistinctPorts(); distinct < 1700 || distinct > 2300 {
		t.Errorf("distinct ports %d, want about 2000", distinct)
	}
}

// Keys past the cap are counted as overflow, and a drain frees the cap.
func TestCapOverflowsAndDrainFrees(t *testing.T) {
	t.Parallel()
	counter := NewCounter(2, 1, start)
	for port := range uint16(4) {
		counter.Observe(Observation{
			Header: tcp(self, remote, 1, port+1, tcpSYN), Class: ClassMesh,
			Direction: DirectionOutbound,
		}, start)
	}
	counter.Observe(Observation{
		Header: tcp(remote, self, 1, 9, tcpSYN), Class: ClassMesh,
		Direction: DirectionInbound, Deny: DenyPortNotAllowed,
	}, start)
	counter.Observe(Observation{
		Header: tcp(netip.MustParseAddr("100.64.0.3"), self, 1, 9, tcpSYN),
		Class:  ClassMesh, Direction: DirectionInbound, Deny: DenyPortNotAllowed,
	}, start)
	window := counter.Drain(start.Add(time.Minute), ID{})
	if len(window.Records) != 3 || window.Overflow != (Overflow{Keys: 3, Packets: 3, Bytes: 300}) {
		t.Fatalf("records %d, overflow %+v", len(window.Records), window.Overflow)
	}
	if window.StartMS != start.UnixMilli() || window.EndMS != start.Add(time.Minute).UnixMilli() {
		t.Errorf("window %d..%d", window.StartMS, window.EndMS)
	}
	counter.Observe(Observation{
		Header: tcp(self, remote, 1, 4, tcpSYN), Class: ClassMesh,
		Direction: DirectionOutbound,
	}, start)
	if next := counter.Drain(start.Add(2*time.Minute), ID{}); len(next.Records) != 1 || next.Overflow != (Overflow{}) {
		t.Fatalf("after a drain: %d records, %+v", len(next.Records), next.Overflow)
	}
}

// A key keeps its flow ID across windows; another key gets another.
func TestFlowIDStable(t *testing.T) {
	t.Parallel()
	counter := NewCounter(DeviceKeys, DeviceDenyKeys, start)
	observation := Observation{Header: tcp(self, remote, 1, 22, tcpACK), Class: ClassMesh, Direction: DirectionOutbound}
	counter.Observe(observation, start)
	first := drainOne(t, counter).GetFlowId()
	counter.Observe(observation, start)
	second := drainOne(t, counter).GetFlowId()
	observation.Header.DestinationPort = 23
	counter.Observe(observation, start)
	other := drainOne(t, counter).GetFlowId()
	if !bytes.Equal(first, second) || bytes.Equal(first, other) {
		t.Fatalf("flow IDs %x %x %x", first, second, other)
	}
}

func TestShareAndClusterIDs(t *testing.T) {
	t.Parallel()
	counter := NewCounter(DeviceKeys, DeviceDenyKeys, start)
	contract := ID{9}
	counter.Observe(Observation{
		Header: tcp(self, remote, 1, 443, tcpSYN), Class: ClassShare,
		Direction: DirectionOutbound, Scope: contract,
	}, start)
	window := counter.Drain(start, ID{8})
	record := window.Records[0]
	checkRecord(t, record)
	if !record.GetPrimary() || !bytes.Equal(record.GetTrustContractId(), contract[:]) ||
		!bytes.Equal(record.GetClusterId(), []byte{8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("record %v", record)
	}
}

// Observe and Drain run concurrently (run with -race).
func TestConcurrentObserveAndDrain(t *testing.T) {
	t.Parallel()
	counter := NewCounter(DeviceKeys, DeviceDenyKeys, start)
	var group sync.WaitGroup
	var total uint64
	for worker := range uint16(8) {
		group.Go(func() {
			for port := range uint16(1000) {
				counter.Observe(Observation{
					Header: tcp(self, remote, 1, port%50+worker, tcpACK),
					Class:  ClassMesh, Direction: DirectionOutbound,
				}, start)
			}
		})
	}
	done := make(chan struct{})
	var mu sync.Mutex
	go func() {
		defer close(done)
		for range 20 {
			window := counter.Drain(start, ID{})
			mu.Lock()
			for _, record := range window.Records {
				total += record.GetPacketsOut()
			}
			mu.Unlock()
		}
	}()
	group.Wait()
	<-done
	for _, record := range counter.Drain(start, ID{}).Records {
		total += record.GetPacketsOut()
	}
	if total != 8000 {
		t.Fatalf("counted %d packets, want 8000", total)
	}
}

func BenchmarkObserveKnownKey(b *testing.B) {
	counter := NewCounter(ForwarderKeys, ForwarderDenyKeys, start)
	b.RunParallel(func(pb *testing.PB) {
		port := uint16(0)
		for pb.Next() {
			port++
			counter.Observe(Observation{
				Header: tcp(self, remote, 50000, port%64, tcpACK), Class: ClassMesh,
				Direction: DirectionOutbound, Peer: peerID,
			}, start)
		}
	})
}

func BenchmarkObserveManyKeys(b *testing.B) {
	counter := NewCounter(ForwarderKeys, ForwarderDenyKeys, start)
	b.RunParallel(func(pb *testing.PB) {
		port := uint16(0)
		for pb.Next() {
			port++
			destination := netip.AddrFrom4([4]byte{10, 0, byte(port >> 8), byte(port)})
			counter.Observe(Observation{
				Header: tcp(self, destination, 50000, 443, tcpACK), Class: ClassSite,
				Direction: DirectionOutbound,
			}, start)
		}
	})
}

func TestAddressClasses(t *testing.T) {
	t.Parallel()
	for address, private := range map[string]bool{
		"10.1.2.3": true, "172.16.0.1": true, "172.31.255.255": true, "172.32.0.1": false, "192.168.1.1": true,
		"100.64.0.1": true, "100.127.255.255": true, "100.128.0.1": false, "fd7a::1": true, "fc00::1": true,
		"8.8.8.8": false, "2001:db8::1": false, "::ffff:10.0.0.1": true,
	} {
		if got := isPrivate(netip.MustParseAddr(address)); got != private {
			t.Errorf("isPrivate(%s) = %t", address, got)
		}
	}
	for address, noise := range map[string]bool{
		"224.0.0.251": true, "239.255.255.250": true, "255.255.255.255": true, "169.254.9.9": true,
		"127.0.0.1": true, "0.0.0.0": true, "ff02::2": true, "fe80::1": true, "febf::1": true, "::1": true,
		"::": true, "100.64.0.1": false, "fec0::1": false, "8.8.8.8": false,
	} {
		if got := noiseAddress(netip.MustParseAddr(address)); got != noise {
			t.Errorf("noiseAddress(%s) = %t", address, got)
		}
	}
	if !noiseAddress(netip.Addr{}) {
		t.Error("an invalid address is noise")
	}
}

// Packets observed out of time order (two goroutines, a clock step) never
// give last_seen before first_seen, and the window covers its records.
func TestTimesOutOfOrder(t *testing.T) {
	t.Parallel()
	counter := NewCounter(DeviceKeys, DeviceDenyKeys, start)
	flow := Observation{Header: tcp(self, remote, 1, 22, tcpACK), Class: ClassMesh, Direction: DirectionOutbound}
	deny := Observation{
		Header: tcp(remote, self, 1, 23, tcpSYN), Class: ClassMesh, Direction: DirectionInbound,
		Deny: DenyPortNotAllowed,
	}
	for _, at := range []time.Duration{time.Second, 0, -time.Minute, 2 * time.Minute} {
		counter.Observe(flow, start.Add(at))
		counter.Observe(deny, start.Add(at))
	}
	window := counter.Drain(start.Add(time.Minute), ID{})
	for _, record := range window.Records {
		checkRecord(t, record)
		if record.GetFirstSeenMs() != start.Add(-time.Minute).UnixMilli() ||
			record.GetLastSeenMs() != start.Add(2*time.Minute).UnixMilli() {
			t.Errorf("seen %d..%d", record.GetFirstSeenMs(), record.GetLastSeenMs())
		}
		if record.GetFirstSeenMs() < window.StartMS || record.GetLastSeenMs() > window.EndMS {
			t.Errorf("record outside its window %d..%d", window.StartMS, window.EndMS)
		}
	}
	// A clock stepped back still gives a window that ends after it starts.
	if empty := counter.Drain(start.Add(-time.Hour), ID{}); empty.EndMS <= empty.StartMS {
		t.Errorf("window %d..%d", empty.StartMS, empty.EndMS)
	}
}

// A window never holds more records than a batch takes.
func TestWindowFitsABatch(t *testing.T) {
	t.Parallel()
	if ForwarderKeys+ForwarderDenyKeys > MaxWindowRecords || DeviceKeys+DeviceDenyKeys > MaxWindowRecords {
		t.Fatal("caps exceed a batch")
	}
	counter := NewCounter(ForwarderKeys, ForwarderDenyKeys, start)
	for index := range ForwarderKeys + ForwarderDenyKeys + 100 {
		destination := netip.AddrFrom4([4]byte{10, byte(index >> 16), byte(index >> 8), byte(index)})
		counter.Observe(Observation{
			Header: tcp(self, destination, 1, 22, tcpACK), Class: ClassSite,
			Direction: DirectionOutbound,
		}, start)
		counter.Observe(Observation{
			Header: tcp(destination, self, 1, 22, tcpSYN), Class: ClassSite,
			Direction: DirectionInbound, Deny: DenyPortNotAllowed,
		}, start)
	}
	window := counter.Drain(start, ID{})
	if len(window.Records) != MaxWindowRecords {
		t.Fatalf("records = %d, want %d", len(window.Records), MaxWindowRecords)
	}
	// Every key past each cap is refused; the key estimate saturates near
	// 34,000.
	keys := ForwarderKeys + ForwarderDenyKeys + 100
	refused := uint64(keys-ForwarderKeys) + uint64(keys-ForwarderDenyKeys)
	if window.Overflow.Packets != refused || window.Overflow.Keys < 30000 || window.Overflow.Keys > 36000 {
		t.Errorf("overflow %+v for %d refused keys", window.Overflow, refused)
	}
}

// A share never names the other Workspace's Device, and an exit node's
// denials keep no consumer.
func TestShareAndExitDenialsNameNoDevice(t *testing.T) {
	t.Parallel()
	counter := NewCounter(ForwarderKeys, ForwarderDenyKeys, start)
	counter.Observe(Observation{
		Header: tcp(remote, self, 1, 443, tcpSYN), Class: ClassShare,
		Direction: DirectionInbound, Peer: peerID, Scope: ID{9},
	}, start)
	counter.Observe(Observation{
		Header: tcp(remote, self, 1, 444, tcpSYN), Class: ClassShare,
		Direction: DirectionInbound, Deny: DenyShareService, Peer: peerID, Scope: ID{9},
	}, start)
	counter.Observe(Observation{
		Header: tcp(remote, netip.MustParseAddr("1.1.1.1"), 1, 25, tcpSYN),
		Class:  ClassExit, Direction: DirectionForwarded, Deny: DenyPeerUnusable, Peer: peerID, Scope: poolID,
	}, start)
	for _, record := range counter.Drain(start, ID{}).Records {
		checkRecord(t, record)
		if len(record.GetSourceDeviceId()) != 0 || len(record.GetDestinationDeviceId()) != 0 {
			t.Errorf("a Device named: %v", record)
		}
		if record.GetClass() == flowlogv1.FlowRecord_EXIT && len(record.GetSourceIp()) != 0 {
			t.Errorf("exit consumer kept: %v", record)
		}
	}
}

// The final ACKs of a close keep the close; a new SYN opens again.
func TestTCPStateAfterClose(t *testing.T) {
	t.Parallel()
	counter := NewCounter(DeviceKeys, DeviceDenyKeys, start)
	observe := func(flags uint8, reply bool) {
		header := tcp(self, remote, 1, 22, flags)
		if reply {
			header = tcp(remote, self, 22, 1, flags)
		}
		counter.Observe(Observation{Header: header, Class: ClassMesh, Direction: DirectionOutbound, Reply: reply}, start)
	}
	observe(tcpACK, false)
	observe(tcpFIN|tcpACK, false)
	observe(tcpFIN|tcpACK, true)
	observe(tcpACK, false)
	record := drainOne(t, counter)
	if record.GetTcpState() != flowlogv1.FlowRecord_CLOSING || !record.GetEnded() || record.GetConnections() != 0 {
		t.Errorf("after close: %v", record)
	}
	observe(tcpRST, true)
	observe(tcpACK, false)
	if record = drainOne(t, counter); record.GetTcpState() != flowlogv1.FlowRecord_RESET {
		t.Errorf("after reset: %v", record)
	}
	observe(tcpRST, false)
	observe(tcpSYN, false)
	observe(tcpSYN, false)
	if record = drainOne(t, counter); record.GetTcpState() != flowlogv1.FlowRecord_SYN || record.GetConnections() != 2 {
		t.Errorf("after a new SYN: %v", record)
	}
}

// Observations a record may not carry are dropped, not counted.
func TestInvalidObservationsDropped(t *testing.T) {
	t.Parallel()
	counter := NewCounter(DeviceKeys, DeviceDenyKeys, start)
	header := tcp(self, remote, 1, 22, tcpSYN)
	for _, observation := range []Observation{
		{Header: header},
		{Header: header, Class: ClassMesh},
		{Header: header, Direction: DirectionOutbound},
		{Header: header, Class: ClassExit + 1, Direction: DirectionOutbound},
		{Header: header, Class: ClassMesh, Direction: DirectionForwarded + 1},
		{Header: header, Class: ClassMesh, Direction: DirectionOutbound, Deny: DenyNoise + 1},
	} {
		counter.Observe(observation, start)
	}
	var none *Counter
	none.Observe(Observation{Header: header, Class: ClassMesh, Direction: DirectionOutbound}, start)
	if window := counter.Drain(start, ID{}); len(window.Records) != 0 || window.Overflow != (Overflow{}) {
		t.Fatalf("counted: %v", window)
	}
}

func TestIPv6AndMappedAddresses(t *testing.T) {
	t.Parallel()
	counter := NewCounter(DeviceKeys, DeviceDenyKeys, start)
	ula := netip.MustParseAddr("fd7a:115c:a1e0::2")
	counter.Observe(Observation{
		Header: tcp(netip.MustParseAddr("fd7a:115c:a1e0::1"), ula, 1, 22, tcpSYN),
		Class:  ClassMesh, Direction: DirectionOutbound,
	}, start)
	record := drainOne(t, counter)
	if !bytes.Equal(record.GetDestinationIp(), ula.AsSlice()) {
		t.Errorf("IPv6 destination %x", record.GetDestinationIp())
	}
	mapped := netip.AddrFrom16(remote.As16())
	counter.Observe(Observation{
		Header: tcp(self, mapped, 1, 22, tcpSYN), Class: ClassMesh,
		Direction: DirectionOutbound,
	}, start)
	if record = drainOne(t, counter); len(record.GetDestinationIp()) != 4 {
		t.Errorf("a mapped address left as %d bytes", len(record.GetDestinationIp()))
	}
}

// While Observe and Drain race, no window holds more keys than its caps.
func TestCapsHoldUnderConcurrentDrain(t *testing.T) {
	t.Parallel()
	const flows, denials = 500, 50
	counter := NewCounter(flows, denials, start)
	stop := make(chan struct{})
	var group sync.WaitGroup
	for worker := range byte(8) {
		group.Go(func() {
			for index := 0; ; index++ {
				select {
				case <-stop:
					return
				default:
				}
				destination := netip.AddrFrom4([4]byte{10, worker, byte(index >> 8), byte(index)})
				observation := Observation{
					Header: tcp(self, destination, 1, 22, tcpACK), Class: ClassSite,
					Direction: DirectionOutbound,
				}
				if index%5 == 0 {
					observation.Deny = DenyRouteNotInstalled
				}
				counter.Observe(observation, start)
			}
		})
	}
	for range 200 {
		window := counter.Drain(start, ID{})
		flowRecords, denyRecords := 0, 0
		for _, record := range window.Records {
			if record.GetKind() == flowlogv1.FlowRecord_DENY {
				denyRecords++
			} else {
				flowRecords++
			}
		}
		if flowRecords > flows || denyRecords > denials {
			t.Errorf("window held %d flows and %d denials", flowRecords, denyRecords)
		}
	}
	close(stop)
	group.Wait()
}

func TestCapsAboveABatchPanic(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	NewCounter(MaxWindowRecords, 1, start)
}

// Overflow.Keys estimates the distinct refused keys, not the packets.
func TestOverflowKeysEstimate(t *testing.T) {
	t.Parallel()
	counter := NewCounter(0, 0, start)
	for index := range 3000 {
		destination := netip.AddrFrom4([4]byte{10, 1, byte(index >> 8), byte(index)})
		for range 3 {
			counter.Observe(Observation{
				Header: tcp(self, destination, 1, 22, tcpACK), Class: ClassSite,
				Direction: DirectionOutbound,
			}, start)
		}
	}
	window := counter.Drain(start, ID{})
	if window.Overflow.Packets != 9000 || window.Overflow.Keys < 2700 || window.Overflow.Keys > 3300 {
		t.Fatalf("overflow %+v for 3,000 keys", window.Overflow)
	}
}
