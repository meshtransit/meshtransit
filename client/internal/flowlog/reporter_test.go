package flowlog

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/packetmeta"
)

func TestReporterUploadsEstablishedTCPFlowWithoutPayload(t *testing.T) {
	t.Parallel()

	received := make(chan struct {
		body          nativeBatch
		authorization string
		networkToken  string
	}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body nativeBatch
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			http.Error(writer, "bad body", http.StatusBadRequest)
			return
		}
		received <- struct {
			body          nativeBatch
			authorization string
			networkToken  string
		}{
			body:          body,
			authorization: request.Header.Get("Authorization"),
			networkToken:  request.Header.Get("X-MeshTransit-Network-Token"),
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	nodeToken := testToken(7, 11)
	networkToken := testToken(7, 0)
	credentials, err := networkmap.NewAuditCredentials(nodeToken, networkToken, 11)
	if err != nil {
		t.Fatalf("NewAuditCredentials() error = %v", err)
	}
	reporter, err := New(Config{
		BaseURL:    server.URL,
		Interval:   time.Second,
		Timeout:    time.Second,
		HTTPClient: server.Client(),
		Logger:     slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	reporter.UpdateNetwork(testSnapshot(credentials))
	ctx, cancel := context.WithCancel(t.Context())
	runDone := make(chan error, 1)
	go func() { runDone <- reporter.Run(ctx) }()

	reporter.ObservePacket(
		dataplane.PacketOutbound,
		testIPv4TCPPacket([4]byte{100, 64, 0, 3}, [4]byte{100, 64, 0, 4}, 48326, 18080, 0x02, []byte("secret-one")),
	)
	reporter.ObservePacket(
		dataplane.PacketInbound,
		testIPv4TCPPacket([4]byte{100, 64, 0, 4}, [4]byte{100, 64, 0, 3}, 18080, 48326, 0x12, []byte("secret-two")),
	)
	reporter.ObservePacket(
		dataplane.PacketOutbound,
		testIPv4TCPPacket([4]byte{100, 64, 0, 3}, [4]byte{100, 64, 0, 4}, 48326, 18080, 0x10, []byte("secret-three")),
	)

	select {
	case got := <-received:
		if got.authorization != "Bearer "+nodeToken || got.networkToken != networkToken {
			t.Fatal("upload credentials are missing")
		}
		if len(got.body.Flows) != 1 {
			t.Fatalf("flow count = %d", len(got.body.Flows))
		}
		flow := got.body.Flows[0]
		if flow.Source != "100.64.0.3:48326" || flow.Destination != "100.64.0.4:18080" ||
			flow.Initiator != "reporter" || flow.State != "established" ||
			flow.SourceToDestinationPackets != 2 || flow.DestinationToSourcePackets != 1 {
			t.Fatalf("flow = %#v", flow)
		}
		encoded, _ := json.Marshal(got.body)
		for _, forbidden := range []string{"secret-one", "secret-two", "secret-three", nodeToken, networkToken} {
			if stringContains(string(encoded), forbidden) {
				t.Fatalf("uploaded body contains %q", forbidden)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for flow upload")
	}
	cancel()
	<-runDone
}

func TestParsePacketHeaderRejectsTruncationAndNonInitialFragments(t *testing.T) {
	t.Parallel()

	if _, err := parsePacketHeader([]byte{0x45}); err == nil {
		t.Fatal("truncated packet error = nil")
	}
	packet := testIPv4TCPPacket([4]byte{100, 64, 0, 3}, [4]byte{100, 64, 0, 4}, 1, 2, 0x02, nil)
	binary.BigEndian.PutUint16(packet[6:8], 1)
	if _, err := parsePacketHeader(packet); err == nil {
		t.Fatal("non-initial fragment error = nil")
	}
}

func TestTCPStateDoesNotDowngradeTerminalState(t *testing.T) {
	t.Parallel()

	flow := &aggregate{state: "closing", sawHandshake: true}
	updateTCPState(flow, packetHeader{tcpFlags: 0x10})
	if flow.state != "closing" {
		t.Fatalf("ACK downgraded closing state to %q", flow.state)
	}
	updateTCPState(flow, packetHeader{tcpFlags: 0x14})
	if flow.state != "reset" {
		t.Fatalf("RST state = %q", flow.state)
	}
	updateTCPState(flow, packetHeader{tcpFlags: 0x10})
	if flow.state != "reset" {
		t.Fatalf("ACK downgraded reset state to %q", flow.state)
	}
}

func testSnapshot(credentials networkmap.AuditCredentials) networkmap.Snapshot {
	selfAddress := netip.MustParsePrefix("100.64.0.3/32")
	peerAddress := netip.MustParsePrefix("100.64.0.4/32")

	return networkmap.Snapshot{
		Revision: 1,
		Self: networkmap.Node{
			ID:        11,
			Name:      "poc-a.mesh.",
			Addresses: []netip.Prefix{selfAddress},
		},
		Peers: []networkmap.Node{{
			ID:        12,
			Name:      "poc-b.mesh.",
			Addresses: []netip.Prefix{peerAddress},
		}},
		Audit: credentials,
	}
}

func testIPv4TCPPacket(
	source, destination [4]byte,
	sourcePort, destinationPort uint16,
	flags byte,
	payload []byte,
) []byte {
	packet := make([]byte, 40+len(payload))
	if len(packet) > 65535 {
		panic("test packet exceeds IPv4 length")
	}
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet))) //nolint:gosec // length is bounded above.
	packet[8] = 64
	packet[9] = protocolTCP
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	packet[32] = 0x50
	packet[33] = flags
	copy(packet[40:], payload)

	return packet
}

func testToken(networkID, nodeID uint64) string {
	var token [32]byte
	binary.BigEndian.PutUint64(token[0:8], networkID)
	binary.BigEndian.PutUint64(token[8:16], nodeID)
	for index := 16; index < len(token); index++ {
		token[index] = byte(index)
	}

	return hex.EncodeToString(token[:])
}

func stringContains(value, target string) bool {
	for index := 0; index+len(target) <= len(value); index++ {
		if value[index:index+len(target)] == target {
			return true
		}
	}

	return false
}

func TestReporterUploadsCanonicalAliasFlowMetadata(t *testing.T) {
	t.Parallel()
	received := make(chan nativeBatch, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body nativeBatch
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			http.Error(writer, "bad body", http.StatusBadRequest)
			return
		}
		received <- body
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	credentials, err := networkmap.NewAuditCredentials(testToken(7, 11), testToken(7, 0), 11)
	if err != nil {
		t.Fatal(err)
	}
	reporter, err := New(Config{BaseURL: server.URL, Interval: time.Second, Timeout: time.Second, HTTPClient: server.Client(), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testSnapshot(credentials)
	snapshot.Peers[0].Addresses = []netip.Prefix{netip.MustParsePrefix("100.96.0.1/32")}
	reporter.UpdateNetwork(snapshot)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- reporter.Run(ctx) }()
	defer func() { cancel(); <-done }()
	packet := testIPv4TCPPacket([4]byte{100, 64, 0, 3}, [4]byte{100, 96, 0, 1}, 48326, 18080, 0x02, []byte("alias-private-payload"))
	header, err := packetmeta.Parse(packet)
	if err != nil {
		t.Fatal(err)
	}
	// The admitted outbound header remains in TUN coordinates. Local source
	// aliases, wrong directions and unrelated sources cannot identify self.
	localAlias := header
	localAlias.Source = netip.MustParseAddr("100.96.0.2")
	reporter.ObservePacketMetadata(dataplane.PacketOutbound, localAlias)
	reporter.ObservePacketMetadata(dataplane.PacketInbound, header)
	reporter.ObservePacketMetadata(dataplane.PacketDirection(99), header)
	reporter.ObservePacketMetadata(dataplane.PacketOutbound, header)
	reporter.ObservePacket(dataplane.PacketInbound, testIPv4TCPPacket([4]byte{100, 96, 0, 1}, [4]byte{100, 64, 0, 3}, 18080, 48326, 0x12, nil))
	select {
	case body := <-received:
		if len(body.Flows) != 1 {
			t.Fatalf("flow count = %d", len(body.Flows))
		}
		flow := body.Flows[0]
		if flow.Source != "100.64.0.3:48326" || flow.Destination != "100.96.0.1:18080" || flow.SourceToDestinationPackets != 1 || flow.DestinationToSourcePackets != 1 {
			t.Fatalf("invalid alias flow coordinates or widened identity: %+v", flow)
		}
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		if stringContains(string(encoded), "alias-private-payload") || stringContains(string(encoded), "100.96.0.2") {
			t.Fatal("upload exposed payload or local translation alias")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for alias metadata upload")
	}
}

func TestReporterUploadsIPv6AliasUDPMetadata(t *testing.T) {
	t.Parallel()
	received := make(chan nativeBatch, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body nativeBatch
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			http.Error(writer, "bad body", http.StatusBadRequest)
			return
		}
		received <- body
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	credentials, err := networkmap.NewAuditCredentials(testToken(7, 11), testToken(7, 0), 11)
	if err != nil {
		t.Fatal(err)
	}
	reporter, err := New(Config{BaseURL: server.URL, Interval: time.Second, Timeout: time.Second, HTTPClient: server.Client(), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testSnapshot(credentials)
	snapshot.Self.Addresses = []netip.Prefix{netip.MustParsePrefix("fd00:1::1/128")}
	snapshot.Peers[0].Addresses = []netip.Prefix{netip.MustParsePrefix("fd00:2::1/128")}
	reporter.UpdateNetwork(snapshot)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- reporter.Run(ctx) }()
	defer func() { cancel(); <-done }()
	header := packetmeta.Header{Source: netip.MustParseAddr("fd00:1::1"), Destination: netip.MustParseAddr("fd00:2::1"), Length: 48, Protocol: packetmeta.ProtocolUDP, SourcePort: 42000, DestinationPort: 53}
	reporter.ObservePacketMetadata(dataplane.PacketOutbound, header)
	reply := header
	reply.Source, reply.Destination = header.Destination, header.Source
	reply.SourcePort, reply.DestinationPort = header.DestinationPort, header.SourcePort
	reporter.ObservePacketMetadata(dataplane.PacketInbound, reply)
	select {
	case body := <-received:
		if len(body.Flows) != 1 {
			t.Fatalf("flow count = %d", len(body.Flows))
		}
		flow := body.Flows[0]
		if flow.Protocol != packetmeta.ProtocolUDP || flow.Source != "[fd00:1::1]:42000" || flow.Destination != "[fd00:2::1]:53" || flow.SourceToDestinationPackets != 1 || flow.DestinationToSourcePackets != 1 || flow.SourceToDestinationBytes != 48 || flow.DestinationToSourceBytes != 48 {
			t.Fatalf("IPv6 metadata serialization/aggregation = %+v", flow)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for IPv6 alias upload")
	}
}
