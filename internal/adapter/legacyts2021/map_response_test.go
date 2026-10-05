package legacyts2021

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/util/zstdframe"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
)

func TestEncodeFullMapResponseClearsInheritedAuthority(t *testing.T) {
	t.Parallel()

	encoded, err := EncodeFullMapResponse(mapSnapshotWithCandidateFixture(t), 142)
	if err != nil {
		t.Fatalf("EncodeFullMapResponse() error = %v", err)
	}
	if len(encoded) < 5 || int(binary.LittleEndian.Uint32(encoded[:4])) != len(encoded)-4 {
		t.Fatalf("encoded frame length = %d with header %v", len(encoded), encoded[:min(len(encoded), 4)])
	}
	document, err := zstdframe.AppendDecode(nil, encoded[4:], zstdframe.MaxDecodedSize(maxMapResponseBytes))
	if err != nil {
		t.Fatalf("decode zstd map response: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(document, &fields); err != nil {
		t.Fatalf("decode map response fields: %v", err)
	}
	for _, name := range []string{"Domain", "Node", "Peers", "PacketFilter", "DERPMap"} {
		if _, ok := fields[name]; !ok {
			t.Fatalf("map response omitted required field %q: %s", name, document)
		}
	}
	if string(fields["Peers"]) != "[]" || string(fields["PacketFilter"]) != "[]" {
		t.Fatalf("map response did not explicitly clear peers and policy: %s", document)
	}

	var response tailcfg.MapResponse
	if err := json.Unmarshal(document, &response); err != nil {
		t.Fatalf("decode typed map response: %v", err)
	}
	if response.Domain != "Development Mesh" {
		t.Fatalf("map response Domain = %q, want %q", response.Domain, "Development Mesh")
	}
	if response.DERPMap == nil {
		t.Fatal("map response DERPMap is nil")
	}
	region := response.DERPMap.Regions[1]
	if !response.DERPMap.OmitDefaultRegions || len(response.DERPMap.Regions) != 1 || region == nil ||
		region.RegionID != 1 || region.RegionCode != "sin" || region.RegionName != "Singapore" ||
		len(region.Nodes) != 2 || region.Nodes[0].Name != "1a" || region.Nodes[0].RegionID != 1 ||
		region.Nodes[0].HostName != "relay-sin.example.com" ||
		region.Nodes[0].CertName != "relay-cert-sin.example.com" ||
		region.Nodes[0].IPv4 != "192.0.2.10" || region.Nodes[0].IPv6 != "2001:db8::10" ||
		region.Nodes[0].STUNPort != 3478 || region.Nodes[0].DERPPort != 443 ||
		!region.Nodes[1].STUNOnly || region.Nodes[1].HostName != "stun-sin.example.com" ||
		region.Nodes[1].DERPPort != 0 {
		t.Fatalf("map response DERPMap = %+v, want one complete replacement", response.DERPMap)
	}
	if response.Node == nil || response.Node.ID != 701 ||
		string(response.Node.StableID) != "01890f00-0000-7000-8000-000000000701" ||
		response.Node.Name != "node-one.example." || !response.Node.MachineAuthorized ||
		response.Node.Cap != 142 || len(response.Node.Addresses) != 1 ||
		len(response.Node.AllowedIPs) != 1 {
		t.Fatalf("map response Node = %+v, want authoritative self Node", response.Node)
	}
}

func TestEncodeFullMapResponseRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	if _, err := EncodeFullMapResponse(mapSnapshotFixture(t), 0); err == nil {
		t.Fatal("EncodeFullMapResponse(zero capability) error = nil")
	}
}

func TestEncodeAuthorityWithdrawalClearsRuntimeAuthority(t *testing.T) {
	t.Parallel()

	snapshot := mapSnapshotWithCandidateFixture(t)
	encoded, err := encodeAuthorityWithdrawalMapResponse(
		snapshot,
		142,
		mapResponseCompressionZstd,
	)
	if err != nil {
		t.Fatalf("encodeAuthorityWithdrawalMapResponse() error = %v", err)
	}
	document, err := zstdframe.AppendDecode(
		nil,
		encoded[4:],
		zstdframe.MaxDecodedSize(maxMapResponseBytes),
	)
	if err != nil {
		t.Fatalf("decode authority withdrawal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(document, &fields); err != nil {
		t.Fatalf("decode authority withdrawal fields: %v", err)
	}
	if len(fields) != 4 || string(fields["Peers"]) != "[]" ||
		string(fields["PacketFilter"]) != "[]" || string(fields["DNSConfig"]) != "{}" {
		t.Fatalf("authority withdrawal fields = %s", document)
	}
	var response tailcfg.MapResponse
	if err := json.Unmarshal(document, &response); err != nil {
		t.Fatalf("decode typed authority withdrawal: %v", err)
	}
	if response.Node == nil || response.Node.ID != tailcfg.NodeID(snapshot.NumericNodeID()) ||
		!response.Node.Expired || response.Node.MachineAuthorized ||
		!response.Node.DiscoKey.IsZero() || len(response.Node.Endpoints) != 0 ||
		response.Peers == nil || len(response.Peers) != 0 ||
		response.PacketFilter == nil || len(response.PacketFilter) != 0 {
		t.Fatalf("authority withdrawal = %+v", response)
	}
	full := decodeFullMapResponseFixture(t, snapshot)
	if response.Node.Key != full.Node.Key {
		t.Fatalf("withdrawal self key = %s, want %s", response.Node.Key, full.Node.Key)
	}
}

func TestEncodeAuthorityWithdrawalRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	if _, err := encodeAuthorityWithdrawalMapResponse(
		mapSnapshotFixture(t),
		0,
		mapResponseCompressionZstd,
	); !errors.Is(err, ErrMapResponse) {
		t.Fatalf("encodeAuthorityWithdrawalMapResponse() error = %v, want ErrMapResponse", err)
	}
}

func TestEncodeFullMapResponseProjectsAuthorizedPeerWithoutInboundAuthority(t *testing.T) {
	t.Parallel()

	response := decodeFullMapResponseFixture(
		t,
		mapSnapshotWithAuthorizedCandidateFixture(t),
	)
	if len(response.Peers) != 1 || response.Peers[0].ID != 702 ||
		string(response.Peers[0].StableID) != "01890f00-0000-7000-8000-000000000702" ||
		response.Peers[0].Name != "node-two.example." || response.Peers[0].User != 11 ||
		!response.Peers[0].MachineAuthorized || len(response.Peers[0].Addresses) != 1 ||
		len(response.Peers[0].AllowedIPs) != 1 {
		t.Fatalf("map response Peers = %+v, want one complete authorized peer", response.Peers)
	}
	if len(response.PacketFilter) != 0 {
		t.Fatalf(
			"map response PacketFilter = %+v, want no inbound authority from outbound-only rule",
			response.PacketFilter,
		)
	}
}

func TestEncodeFullMapResponseDropsRuleForUnavailablePeer(t *testing.T) {
	t.Parallel()

	params := mapSnapshotParams(mapSnapshotWithInboundPolicyFixture(t))
	params.PeerCandidates = nil
	snapshot, err := mapsession.NewSnapshot(params)
	if err != nil {
		t.Fatalf("mapsession.NewSnapshot() error = %v", err)
	}
	response := decodeFullMapResponseFixture(t, snapshot)
	if len(response.Peers) != 0 || len(response.PacketFilter) != 0 {
		t.Fatalf("expired peer retained map authority: peers=%d rules=%d", len(response.Peers), len(response.PacketFilter))
	}
}

func TestEncodeFullMapResponseProjectsGenerationFencedConnectivity(t *testing.T) {
	t.Parallel()

	snapshot := mapSnapshotWithAuthorizedCandidateFixture(t)
	peers := snapshot.AuthorizedPeers()
	if len(peers) != 1 {
		t.Fatalf("AuthorizedPeers() = %+v, want one fixture peer", peers)
	}
	self := mapConnectivityWithPreferredRelayFixture(
		t,
		snapshot.NodeID(),
		snapshot.SessionGeneration(),
		3,
		"198.51.100.1:41641",
		1,
		true,
	)
	peer := mapConnectivityWithPreferredRelayFixture(
		t,
		peers[0].NodeID(),
		peers[0].SessionGeneration(),
		4,
		"198.51.100.2:41641",
		1,
		true,
	)
	enriched, err := snapshot.WithConnectivity([]mapsession.Connectivity{peer, self})
	if err != nil {
		t.Fatalf("WithConnectivity() error = %v", err)
	}
	response := decodeFullMapResponseFixture(t, enriched)
	if response.Node == nil || response.Node.DiscoKey.IsZero() || response.Node.HomeDERP != 1 ||
		!reflect.DeepEqual(response.Node.Endpoints, []netip.AddrPort{
			netip.MustParseAddrPort("198.51.100.1:41641"),
		}) {
		t.Fatalf("self connectivity = %+v, want discovery key and endpoint", response.Node)
	}
	if len(response.Peers) != 1 || response.Peers[0].DiscoKey.IsZero() ||
		response.Peers[0].HomeDERP != 1 ||
		response.Peers[0].Online == nil || !*response.Peers[0].Online ||
		!reflect.DeepEqual(response.Peers[0].Endpoints, []netip.AddrPort{
			netip.MustParseAddrPort("198.51.100.2:41641"),
		}) {
		t.Fatalf("peer connectivity = %+v, want online discovery endpoint", response.Peers)
	}
}

func TestEncodeFullMapResponseProjectsOnlyNodeReducedInboundPolicy(t *testing.T) {
	t.Parallel()

	response := decodeFullMapResponseFixture(t, mapSnapshotWithInboundPolicyFixture(t))
	if len(response.Peers) != 1 {
		t.Fatalf("map response Peers = %+v, want one authorized peer", response.Peers)
	}
	if len(response.PacketFilter) != 2 {
		t.Fatalf(
			"map response PacketFilter = %+v, want TCP and ICMP inbound rules",
			response.PacketFilter,
		)
	}
	tcp := response.PacketFilter[0]
	if !reflect.DeepEqual(tcp.SrcIPs, []string{"100.64.0.2"}) ||
		!reflect.DeepEqual(tcp.IPProto, []int{6}) || len(tcp.DstPorts) != 2 ||
		tcp.DstPorts[0].IP != "100.64.0.1" || tcp.DstPorts[0].Ports.First != 80 ||
		tcp.DstPorts[0].Ports.Last != 81 || tcp.DstPorts[1].IP != "100.64.0.1" ||
		tcp.DstPorts[1].Ports.First != 443 || tcp.DstPorts[1].Ports.Last != 443 {
		t.Fatalf("TCP packet filter = %+v, want peer-to-self ports 80-81 and 443", tcp)
	}
	icmp := response.PacketFilter[1]
	if !reflect.DeepEqual(icmp.SrcIPs, []string{"100.64.0.2"}) ||
		!reflect.DeepEqual(icmp.IPProto, []int{1}) || len(icmp.DstPorts) != 1 ||
		icmp.DstPorts[0].IP != "100.64.0.1" || icmp.DstPorts[0].Ports != tailcfg.PortRangeAny {
		t.Fatalf("ICMP packet filter = %+v, want bounded IPv4 peer-to-self rule", icmp)
	}
}

func TestEncodeFullMapResponseProjectsTCPAndUDPPortRanges(t *testing.T) {
	t.Parallel()

	response := decodeFullMapResponseFixture(t, mapSnapshotWithInboundTransportPolicyFixture(t))
	if len(response.PacketFilter) != 3 {
		t.Fatalf("PacketFilter = %+v, want three inbound rules", response.PacketFilter)
	}
	udp := response.PacketFilter[2]
	if !reflect.DeepEqual(udp.SrcIPs, []string{"100.64.0.2"}) ||
		!reflect.DeepEqual(udp.IPProto, []int{17}) || len(udp.DstPorts) != 2 ||
		udp.DstPorts[0].IP != "100.64.0.1" || udp.DstPorts[0].Ports.First != 53 ||
		udp.DstPorts[0].Ports.Last != 53 || udp.DstPorts[1].IP != "100.64.0.1" ||
		udp.DstPorts[1].Ports.First != 5353 || udp.DstPorts[1].Ports.Last != 5354 {
		t.Fatalf("UDP packet filter = %+v, want peer-to-self ports 53 and 5353-5354", udp)
	}
}

func TestEncodeFullMapResponseIsDeterministicForEquivalentPolicyInput(t *testing.T) {
	t.Parallel()

	first := mapSnapshotWithInboundTransportPolicyFixture(t)
	rules := first.PacketPolicy().Rules()
	slices.Reverse(rules)
	reorderedPolicy, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: first.Scope(), Revision: first.PacketPolicy().Revision(), Rules: rules,
	})
	if err != nil {
		t.Fatalf("policy.NewSnapshot() error = %v", err)
	}
	params := mapSnapshotParams(first)
	params.PacketPolicy = reorderedPolicy
	second, err := mapsession.NewSnapshot(params)
	if err != nil {
		t.Fatalf("mapsession.NewSnapshot() error = %v", err)
	}
	firstEncoded, err := EncodeFullMapResponse(first, 142)
	if err != nil {
		t.Fatalf("EncodeFullMapResponse(first) error = %v", err)
	}
	secondEncoded, err := EncodeFullMapResponse(second, 142)
	if err != nil {
		t.Fatalf("EncodeFullMapResponse(second) error = %v", err)
	}
	if !bytes.Equal(firstEncoded, secondEncoded) {
		t.Fatal("equivalent policy input produced different map bytes")
	}
}

func decodeFullMapResponseFixture(t *testing.T, snapshot mapsession.Snapshot) tailcfg.MapResponse {
	t.Helper()
	encoded, err := EncodeFullMapResponse(snapshot, 142)
	if err != nil {
		t.Fatalf("EncodeFullMapResponse() error = %v", err)
	}
	document, err := zstdframe.AppendDecode(
		nil,
		encoded[4:],
		zstdframe.MaxDecodedSize(maxMapResponseBytes),
	)
	if err != nil {
		t.Fatalf("decode zstd map response: %v", err)
	}
	var response tailcfg.MapResponse
	if err := json.Unmarshal(document, &response); err != nil {
		t.Fatalf("decode typed map response: %v", err)
	}
	return response
}

func TestEncodeKeepAliveMapResponseIsNonEmptyFramedMessage(t *testing.T) {
	t.Parallel()

	encoded, err := EncodeKeepAliveMapResponse()
	if err != nil {
		t.Fatalf("EncodeKeepAliveMapResponse() error = %v", err)
	}
	if len(encoded) < 5 || int(binary.LittleEndian.Uint32(encoded[:4])) != len(encoded)-4 {
		t.Fatalf("encoded keepalive frame length = %d", len(encoded))
	}
	document, err := zstdframe.AppendDecode(nil, encoded[4:], zstdframe.MaxDecodedSize(maxMapResponseBytes))
	if err != nil {
		t.Fatalf("decode zstd keepalive: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(document, &fields); err != nil {
		t.Fatalf("decode keepalive fields: %v", err)
	}
	if len(fields) != 1 || string(fields["KeepAlive"]) != "true" {
		t.Fatalf("keepalive document = %s, want only KeepAlive=true", document)
	}
}

func mapConnectivityFixture(
	t testing.TB,
	nodeID node.ID,
	generation int64,
	keyByte byte,
	address string,
	online bool,
) mapsession.Connectivity {
	return mapConnectivityFixtureWithPreference(
		t,
		nodeID,
		generation,
		keyByte,
		address,
		0,
		false,
		online,
	)
}

func mapConnectivityWithPreferredRelayFixture(
	t testing.TB,
	nodeID node.ID,
	generation int64,
	keyByte byte,
	address string,
	preferredRelay int,
	online bool,
) mapsession.Connectivity {
	return mapConnectivityFixtureWithPreference(
		t,
		nodeID,
		generation,
		keyByte,
		address,
		preferredRelay,
		true,
		online,
	)
}

func mapConnectivityFixtureWithPreference(
	t testing.TB,
	nodeID node.ID,
	generation int64,
	keyByte byte,
	address string,
	preferredRelay int,
	preferredRelayPresent bool,
	online bool,
) mapsession.Connectivity {
	t.Helper()
	key, err := mapsession.NewConnectivityKey(nodeID, generation)
	if err != nil {
		t.Fatalf("mapsession.NewConnectivityKey() error = %v", err)
	}
	discoveryKey, err := node.NewDiscoveryKey([32]byte{keyByte})
	if err != nil {
		t.Fatalf("node.NewDiscoveryKey() error = %v", err)
	}
	endpoint, err := node.NewEndpoint(
		netip.MustParseAddrPort(address),
		node.EndpointSourceSTUN,
	)
	if err != nil {
		t.Fatalf("node.NewEndpoint() error = %v", err)
	}
	set, err := node.NewEndpointSet(discoveryKey, []node.Endpoint{endpoint})
	if err != nil {
		t.Fatalf("node.NewEndpointSet() error = %v", err)
	}
	connectivity, err := mapsession.NewConnectivity(mapsession.ConnectivityParams{
		Key:                   key,
		EndpointSet:           set,
		EndpointSetPresent:    true,
		PreferredRelay:        preferredRelay,
		PreferredRelayPresent: preferredRelayPresent,
		Online:                online,
	})
	if err != nil {
		t.Fatalf("mapsession.NewConnectivity() error = %v", err)
	}
	return connectivity
}
