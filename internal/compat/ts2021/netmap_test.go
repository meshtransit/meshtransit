package ts2021

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshd/internal/networkmap"
	"github.com/meshtransit/meshd/internal/pathdiscovery"
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
	if request.Hostinfo.NetInfo != nil {
		t.Fatalf("map request published unknown relay state: %#v", request.Hostinfo.NetInfo)
	}
}

func TestNewMapRequest_EndpointUpdateIsNonStreaming(t *testing.T) {
	t.Parallel()

	candidate, err := pathdiscovery.NewCandidate(
		netip.MustParseAddrPort("203.0.113.10:41641"),
		pathdiscovery.SourceServerReflexive,
	)
	if err != nil {
		t.Fatalf("NewCandidate() error = %v", err)
	}
	candidates, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{candidate})
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}
	request := newMapRequest(key.NewNode(), key.NewDisco().Public(), NetmapOptions{
		Hostname:          "node-a",
		Version:           "meshd/dev",
		PinnedFingerprint: "sha256:" + strings.Repeat("a", 64),
		Candidates:        candidates,
		PreferredRelay:    7,
		HasPreferredRelay: true,
	}, false)
	if request.Stream || !request.OmitPeers {
		t.Fatalf("endpoint request stream=%t omitPeers=%t", request.Stream, request.OmitPeers)
	}
	if len(request.Endpoints) != 1 || request.Endpoints[0] != candidate.Endpoint() ||
		len(request.EndpointTypes) != 1 ||
		request.EndpointTypes[0] != tailcfg.EndpointSTUN {
		t.Fatalf("endpoint request = %#v", request)
	}
	if request.Hostinfo.NetInfo == nil || request.Hostinfo.NetInfo.PreferredDERP != 7 {
		t.Fatalf("endpoint request netinfo = %#v", request.Hostinfo.NetInfo)
	}
}

func TestMarshalMapRequestPreservesEndpointWithdrawal(t *testing.T) {
	t.Parallel()

	request := newMapRequest(
		key.NewNode(),
		key.NewDisco().Public(),
		NetmapOptions{},
		false,
	)
	encoded, err := marshalMapRequest(request)
	if err != nil {
		t.Fatalf("marshalMapRequest() error = %v", err)
	}
	if !bytes.Contains(encoded, []byte(`"Endpoints":[]`)) {
		t.Fatalf("endpoint withdrawal omitted from request: %s", encoded)
	}
	decoded := tailcfg.MapRequest{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if decoded.Endpoints == nil || len(decoded.Endpoints) != 0 {
		t.Fatalf("decoded endpoint withdrawal = %#v", decoded.Endpoints)
	}
}

func TestParseNetmapOptionsRequiresCanonicalPeerProbeKey(t *testing.T) {
	t.Parallel()

	validKey := "discokey:" + strings.Repeat("01", 32)
	validOptions := NetmapOptions{
		Hostname:           "node-a",
		Version:            "meshd/test",
		PinnedFingerprint:  "sha256:" + strings.Repeat("a", 64),
		PeerProbePublicKey: validKey,
	}
	parsed, err := parseNetmapOptions(validOptions)
	if err != nil || parsed.String() != validKey {
		t.Fatalf("parseNetmapOptions() = %v, %v", parsed, err)
	}

	tests := []struct {
		name  string
		value string
	}{
		{name: "missing"},
		{name: "wrong prefix", value: "nodekey:" + strings.Repeat("01", 32)},
		{name: "uppercase", value: strings.ToUpper(validKey)},
		{name: "zero", value: "discokey:" + strings.Repeat("00", 32)},
		{name: "short", value: "discokey:01"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			options := validOptions
			options.PeerProbePublicKey = test.value
			if _, err := parseNetmapOptions(options); !errors.Is(err, ErrInvalidMaterial) {
				t.Fatalf("parseNetmapOptions() error = %v, want ErrInvalidMaterial", err)
			}
		})
	}
}

func TestParseNetmapOptionsRejectsInvalidPreferredRelay(t *testing.T) {
	t.Parallel()

	base := NetmapOptions{
		Hostname:           "node-a",
		Version:            "meshd/test",
		PinnedFingerprint:  "sha256:" + strings.Repeat("a", 64),
		PeerProbePublicKey: "discokey:" + strings.Repeat("01", 32),
	}
	tests := []struct {
		name     string
		regionID int
		isSet    bool
	}{
		{name: "positive unknown", regionID: 1},
		{name: "negative", regionID: -1, isSet: true},
		{name: "outside wire range", regionID: 65_536, isSet: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := base
			options.PreferredRelay = test.regionID
			options.HasPreferredRelay = test.isSet
			if _, err := parseNetmapOptions(options); !errors.Is(err, ErrInvalidMaterial) {
				t.Fatalf("parseNetmapOptions() error = %v, want ErrInvalidMaterial", err)
			}
		})
	}
}

func TestProtocolEndpointType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		source pathdiscovery.Source
		want   tailcfg.EndpointType
	}{
		{source: pathdiscovery.SourceHost, want: tailcfg.EndpointLocal},
		{source: pathdiscovery.SourceServerReflexive, want: tailcfg.EndpointSTUN},
		{source: pathdiscovery.SourcePortMapping, want: tailcfg.EndpointPortmapped},
		{source: pathdiscovery.SourceConfigured, want: tailcfg.EndpointExplicitConf},
		{source: pathdiscovery.SourceUnknown, want: tailcfg.EndpointUnknownType},
	}
	for _, test := range tests {
		if got := protocolEndpointType(test.source); got != test.want {
			t.Fatalf("protocolEndpointType(%v) = %v, want %v", test.source, got, test.want)
		}
	}
}

func TestEndpointStateRetainsLatestSetAcrossReconnect(t *testing.T) {
	t.Parallel()

	initial := mustProtocolCandidateSet(
		t,
		"192.0.2.70:41641",
		pathdiscovery.SourceConfigured,
	)
	state := newEndpointState(EndpointUpdate{
		Candidates:        initial,
		PreferredRelay:    1,
		HasPreferredRelay: true,
	})
	if got, shouldSend := state.snapshot(); !shouldSend ||
		!got.Candidates.Equal(initial) || got.PreferredRelay != 1 ||
		!got.HasPreferredRelay {
		t.Fatalf("initial endpoint state = %#v, %t", got, shouldSend)
	}
	dynamic := mustProtocolCandidateSet(
		t,
		"198.51.100.70:41641",
		pathdiscovery.SourceServerReflexive,
	)
	dynamicUpdate := EndpointUpdate{
		Candidates:        dynamic,
		PreferredRelay:    2,
		HasPreferredRelay: true,
	}
	if !state.set(dynamicUpdate) || state.set(dynamicUpdate) {
		t.Fatal("endpoint state change detection is incorrect")
	}
	if got, shouldSend := state.snapshot(); !shouldSend ||
		!got.Candidates.Equal(dynamic) || got.PreferredRelay != 2 ||
		!got.HasPreferredRelay {
		t.Fatalf("dynamic endpoint state = %#v, %t", got, shouldSend)
	}
	if !state.set(EndpointUpdate{}) {
		t.Fatal("endpoint withdrawal was not recorded")
	}
	if got, shouldSend := state.snapshot(); !shouldSend ||
		got.Candidates.Len() != 0 || got.PreferredRelay != 0 {
		t.Fatalf("withdrawn endpoint state = %#v, %t", got, shouldSend)
	}
}

func TestEndpointStateStartsWithExplicitWithdrawal(t *testing.T) {
	t.Parallel()

	state := newEndpointState(EndpointUpdate{})
	got, shouldSend := state.snapshot()
	if !shouldSend || got.Candidates.Len() != 0 || got.PreferredRelay != 0 {
		t.Fatalf("initial endpoint state = %#v, %t", got, shouldSend)
	}
}

func TestEndpointUpdaterRejectsClosedChannel(t *testing.T) {
	t.Parallel()

	updates := make(chan EndpointUpdate)
	close(updates)
	client := newWithHTTPClient(http.DefaultClient)
	options := NetmapOptions{
		EndpointUpdates: updates,
	}
	err := client.runEndpointUpdates(
		t.Context(),
		"https://control.example.com",
		key.NewMachine(),
		key.NewNode(),
		key.NewMachine().Public(),
		key.NewDisco().Public(),
		options,
		newEndpointState(EndpointUpdate{}),
	)
	if !errors.Is(err, ErrEndpointUpdate) {
		t.Fatalf("runEndpointUpdates() error = %v, want ErrEndpointUpdate", err)
	}
}

func mustProtocolCandidateSet(
	t *testing.T,
	endpoint string,
	source pathdiscovery.Source,
) pathdiscovery.Set {
	t.Helper()

	candidate, err := pathdiscovery.NewCandidate(netip.MustParseAddrPort(endpoint), source)
	if err != nil {
		t.Fatalf("NewCandidate() error = %v", err)
	}
	set, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{candidate})
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}

	return set
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
	preserved, changed, err := accumulator.apply(tailcfg.MapResponse{}, time.Now())
	if err != nil {
		t.Fatalf("post-rejection apply() error = %v", err)
	}
	if changed {
		t.Fatal("empty delta published an unchanged snapshot")
	}
	if preserved.Revision != 0 {
		t.Fatalf("empty delta snapshot revision = %d, want zero unpublished value", preserved.Revision)
	}
	if accumulator.revision != initial.Revision || accumulator.dns == nil ||
		!accumulator.dns.Proxied || accumulator.dns.SearchDomains[0] != "example.mesh" {
		t.Fatalf("dns changed after rejected update: %#v", accumulator.dns)
	}
}

func TestMapAccumulator_EquivalentDeltaDoesNotAdvanceRevision(t *testing.T) {
	t.Parallel()

	self := testWireNode(1, 1)
	peer := testWireNode(2, 2)
	peer.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.2:41641")}
	online := true
	peer.Online = &online
	accumulator := newMapAccumulator()
	initial, changed, err := accumulator.apply(tailcfg.MapResponse{
		Node:  self,
		Peers: []*tailcfg.Node{peer},
	}, time.Now())
	if err != nil || !changed {
		t.Fatalf("initial apply() = changed %t, error %v", changed, err)
	}

	responses := []tailcfg.MapResponse{
		{},
		{OnlineChange: map[tailcfg.NodeID]bool{peer.ID: true}},
		{PeersChangedPatch: []*tailcfg.PeerChange{{
			NodeID:    peer.ID,
			Online:    &online,
			Endpoints: append([]netip.AddrPort(nil), peer.Endpoints...),
		}}},
	}
	for index, response := range responses {
		snapshot, changed, err := accumulator.apply(response, time.Now())
		if err != nil {
			t.Fatalf("equivalent apply %d error = %v", index, err)
		}
		if changed || snapshot.Revision != 0 {
			t.Fatalf(
				"equivalent apply %d = changed %t revision %d, want unpublished",
				index,
				changed,
				snapshot.Revision,
			)
		}
		if accumulator.revision != initial.Revision {
			t.Fatalf(
				"equivalent apply %d advanced revision to %d, want %d",
				index,
				accumulator.revision,
				initial.Revision,
			)
		}
	}
}

func TestMapAccumulator_ControlTimeChangeAdvancesRevision(t *testing.T) {
	t.Parallel()

	accumulator := newMapAccumulator()
	initialTime := time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)
	initial, _, err := accumulator.apply(tailcfg.MapResponse{
		Node:        testWireNode(1, 1),
		Peers:       []*tailcfg.Node{},
		ControlTime: &initialTime,
	}, initialTime)
	if err != nil {
		t.Fatalf("initial apply() error = %v", err)
	}
	updatedTime := initialTime.Add(time.Second)
	updated, changed, err := accumulator.apply(tailcfg.MapResponse{
		ControlTime: &updatedTime,
	}, updatedTime)
	if err != nil || !changed {
		t.Fatalf("control-time apply() = changed %t, error %v", changed, err)
	}
	if updated.Revision != initial.Revision+1 || !updated.ControlTime.Equal(updatedTime) {
		t.Fatalf("updated snapshot = %#v", updated)
	}
}

func TestMapAccumulator_EquivalentReconnectPublishesNewGeneration(t *testing.T) {
	t.Parallel()

	self := testWireNode(1, 1)
	peer := testWireNode(2, 2)
	accumulator := newMapAccumulator()
	initial, _, err := accumulator.apply(tailcfg.MapResponse{
		Node:  self,
		Peers: []*tailcfg.Node{peer},
	}, time.Now())
	if err != nil {
		t.Fatalf("initial apply() error = %v", err)
	}
	accumulator.resetSession()
	reconnected, changed, err := accumulator.apply(tailcfg.MapResponse{
		Node:  self,
		Peers: []*tailcfg.Node{peer},
	}, time.Now())
	if err != nil || !changed {
		t.Fatalf("reconnect apply() = changed %t, error %v", changed, err)
	}
	if reconnected.Revision != initial.Revision+1 {
		t.Fatalf(
			"reconnect revision = %d, want %d",
			reconnected.Revision,
			initial.Revision+1,
		)
	}
	if len(reconnected.Peers) != 1 || reconnected.Peers[0].ID != 2 {
		t.Fatalf("reconnected snapshot changed peers: %#v", reconnected.Peers)
	}
}

func TestMapAccumulator_AuthorityRevocationIsTerminalAndAtomic(t *testing.T) {
	t.Parallel()

	self := testWireNode(1, 1)
	peer := testWireNode(2, 2)
	accumulator := newMapAccumulator()
	initial, changed, err := accumulator.apply(tailcfg.MapResponse{
		Node:  self,
		Peers: []*tailcfg.Node{peer},
		PacketFilter: []tailcfg.FilterRule{{
			SrcIPs: []string{"100.64.0.2"},
			DstPorts: []tailcfg.NetPortRange{{
				IP:    "100.64.0.1",
				Ports: tailcfg.PortRange{First: 22, Last: 22},
			}},
		}},
	}, time.Now())
	if err != nil || !changed {
		t.Fatalf("initial apply() = changed %t, error %v", changed, err)
	}

	revoked := *self
	revoked.Expired = true
	revoked.MachineAuthorized = false
	if _, changed, err := accumulator.apply(tailcfg.MapResponse{
		Node:         &revoked,
		Peers:        []*tailcfg.Node{},
		PacketFilter: []tailcfg.FilterRule{},
	}, time.Now()); !errors.Is(err, ErrNetmapAuthorityRevoked) || changed {
		t.Fatalf("revocation apply() = changed %t, error %v", changed, err)
	}
	if accumulator.revision != initial.Revision || accumulator.self.Expired ||
		!accumulator.self.MachineAuthorized || len(accumulator.peers) != 1 ||
		len(accumulator.namedPolicies["base"]) != 1 {
		t.Fatalf("accumulator mutated after revocation: %#v", accumulator)
	}
}

func TestMapAccumulator_RejectsMalformedAuthorityRevocation(t *testing.T) {
	t.Parallel()

	self := testWireNode(1, 1)
	tests := []struct {
		name   string
		mutate func(*tailcfg.MapResponse)
	}{
		{
			name: "wrong self id",
			mutate: func(response *tailcfg.MapResponse) {
				response.Node.ID++
			},
		},
		{
			name: "wrong self key",
			mutate: func(response *tailcfg.MapResponse) {
				response.Node.Key = key.NewNode().Public()
			},
		},
		{
			name: "peers omitted",
			mutate: func(response *tailcfg.MapResponse) {
				response.Peers = nil
			},
		},
		{
			name: "policy omitted",
			mutate: func(response *tailcfg.MapResponse) {
				response.PacketFilter = nil
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			accumulator := newMapAccumulator()
			if _, _, err := accumulator.apply(tailcfg.MapResponse{
				Node:  self,
				Peers: []*tailcfg.Node{testWireNode(2, 2)},
			}, time.Now()); err != nil {
				t.Fatalf("initial apply() error = %v", err)
			}
			revoked := *self
			revoked.Expired = true
			revoked.MachineAuthorized = false
			response := tailcfg.MapResponse{
				Node:         &revoked,
				Peers:        []*tailcfg.Node{},
				PacketFilter: []tailcfg.FilterRule{},
			}
			test.mutate(&response)

			if _, changed, err := accumulator.apply(response, time.Now()); !errors.Is(err, ErrNetmapInvalid) ||
				errors.Is(err, ErrNetmapAuthorityRevoked) || changed {
				t.Fatalf("malformed revocation apply() = changed %t, error %v", changed, err)
			}
			if accumulator.revision != 1 || len(accumulator.peers) != 1 {
				t.Fatalf("accumulator mutated after malformed revocation: %#v", accumulator)
			}
		})
	}
}

func TestMapAccumulator_EquivalentDeltaRevalidatesExpiry(t *testing.T) {
	t.Parallel()

	expiresAt := time.Date(2026, time.September, 11, 12, 0, 1, 0, time.UTC)
	self := testWireNode(1, 1)
	self.KeyExpiry = expiresAt
	accumulator := newMapAccumulator()
	if _, _, err := accumulator.apply(tailcfg.MapResponse{
		Node:  self,
		Peers: []*tailcfg.Node{},
	}, expiresAt.Add(-time.Second)); err != nil {
		t.Fatalf("initial apply() error = %v", err)
	}

	if _, _, err := accumulator.apply(
		tailcfg.MapResponse{},
		expiresAt,
	); !errors.Is(err, ErrNetmapInvalid) {
		t.Fatalf("expired equivalent apply() error = %v, want ErrNetmapInvalid", err)
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

func TestReadMapFrameWithWatchdog(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"KeepAlive":true}`)
	encoded := make([]byte, 4, 4+len(body))
	binary.LittleEndian.PutUint32(
		encoded,
		uint32(len(body)), //nolint:gosec // The body is a small compile-time test fixture.
	)
	encoded = append(encoded, body...)
	connection := &recordingDeadlineSetter{}
	frame, err := readMapFrameWithWatchdog(connection, bytes.NewReader(encoded), now)
	if err != nil || !bytes.Equal(frame, body) {
		t.Fatalf("readMapFrameWithWatchdog() = %q, %v", frame, err)
	}
	if want := now.Add(netmapReadTimeout); !connection.deadline.Equal(want) {
		t.Fatalf("watchdog deadline = %s, want %s", connection.deadline, want)
	}

	readErr := errors.New("test watchdog timeout")
	if _, err := readMapFrameWithWatchdog(
		connection,
		errorReader{err: readErr},
		now,
	); !errors.Is(err, readErr) {
		t.Fatalf("watchdog read error = %v, want wrapped read error", err)
	}
	deadlineErr := errors.New("test deadline failure")
	connection.err = deadlineErr
	if _, err := readMapFrameWithWatchdog(
		connection,
		bytes.NewReader(encoded),
		now,
	); !errors.Is(err, deadlineErr) {
		t.Fatalf("watchdog setup error = %v, want wrapped deadline error", err)
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

func TestRunNetmapReconnectLoop_BacksOffAcrossFlappingMaps(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)
	polls := 0
	waits := make([]time.Duration, 0, 3)
	err := runNetmapReconnectLoop(
		t.Context(),
		func(context.Context) (bool, error) {
			polls++
			now = now.Add(time.Second)
			if polls == 4 {
				return false, ErrNetmapInvalid
			}

			return true, io.ErrUnexpectedEOF
		},
		func() time.Time { return now },
		func(delay time.Duration) time.Duration { return delay },
		func(_ context.Context, delay time.Duration) error {
			waits = append(waits, delay)

			return nil
		},
	)
	if !errors.Is(err, ErrNetmapInvalid) {
		t.Fatalf("runNetmapReconnectLoop() error = %v, want ErrNetmapInvalid", err)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	if !slices.Equal(waits, want) {
		t.Fatalf("reconnect waits = %v, want %v", waits, want)
	}
}

func TestRunNetmapReconnectLoop_ResetsAfterStableSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)
	polls := 0
	waits := make([]time.Duration, 0, 2)
	err := runNetmapReconnectLoop(
		t.Context(),
		func(context.Context) (bool, error) {
			polls++
			switch polls {
			case 1:
				now = now.Add(time.Second)
			case 2:
				now = now.Add(reconnectResetAfter)
			default:
				return false, ErrControlKeyChanged
			}

			return true, io.ErrUnexpectedEOF
		},
		func() time.Time { return now },
		func(delay time.Duration) time.Duration { return delay },
		func(_ context.Context, delay time.Duration) error {
			waits = append(waits, delay)

			return nil
		},
	)
	if !errors.Is(err, ErrControlKeyChanged) {
		t.Fatalf("runNetmapReconnectLoop() error = %v, want ErrControlKeyChanged", err)
	}
	want := []time.Duration{time.Second, time.Second}
	if !slices.Equal(waits, want) {
		t.Fatalf("reconnect waits = %v, want %v", waits, want)
	}
}

func TestRunNetmapReconnectLoop_CapsBackoff(t *testing.T) {
	t.Parallel()

	polls := 0
	waits := make([]time.Duration, 0, 7)
	err := runNetmapReconnectLoop(
		t.Context(),
		func(context.Context) (bool, error) {
			polls++
			if polls == 8 {
				return false, ErrNetmapRejected
			}

			return false, io.ErrUnexpectedEOF
		},
		time.Now,
		func(delay time.Duration) time.Duration { return delay },
		func(_ context.Context, delay time.Duration) error {
			waits = append(waits, delay)

			return nil
		},
	)
	if !errors.Is(err, ErrNetmapRejected) {
		t.Fatalf("runNetmapReconnectLoop() error = %v, want ErrNetmapRejected", err)
	}
	want := []time.Duration{
		time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		maxReconnectDelay,
		maxReconnectDelay,
	}
	if !slices.Equal(waits, want) {
		t.Fatalf("reconnect waits = %v, want %v", waits, want)
	}
}

func TestRunNetmapReconnectLoop_CancelsReconnectWait(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	waits := 0
	err := runNetmapReconnectLoop(
		ctx,
		func(context.Context) (bool, error) { return false, io.ErrUnexpectedEOF },
		time.Now,
		func(delay time.Duration) time.Duration { return delay },
		func(waitCtx context.Context, _ time.Duration) error {
			waits++
			cancel()

			return waitForReconnect(waitCtx, time.Hour)
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runNetmapReconnectLoop() error = %v, want context cancellation", err)
	}
	if waits != 1 {
		t.Fatalf("reconnect wait calls = %d, want 1", waits)
	}
}

func TestRunNetmapReconnectLoop_DoesNotRetryAuthorityRevocation(t *testing.T) {
	t.Parallel()

	polls := 0
	waits := 0
	err := runNetmapReconnectLoop(
		t.Context(),
		func(context.Context) (bool, error) {
			polls++

			return true, ErrNetmapAuthorityRevoked
		},
		time.Now,
		func(delay time.Duration) time.Duration { return delay },
		func(context.Context, time.Duration) error {
			waits++

			return nil
		},
	)
	if !errors.Is(err, ErrNetmapAuthorityRevoked) {
		t.Fatalf("runNetmapReconnectLoop() error = %v, want ErrNetmapAuthorityRevoked", err)
	}
	if polls != 1 || waits != 0 {
		t.Fatalf("reconnect calls = polls %d waits %d, want 1 and 0", polls, waits)
	}
}

func TestEndpointUpdateErrorIsTransientUnlessTrustChanged(t *testing.T) {
	t.Parallel()

	if isPermanentNetmapError(ErrEndpointUpdate) {
		t.Fatal("endpoint transport failure was classified as permanent")
	}
	trustFailure := fmt.Errorf("%w: %w", ErrEndpointUpdate, ErrControlKeyChanged)
	if !isPermanentNetmapError(trustFailure) {
		t.Fatal("control key change inside endpoint update was classified as transient")
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

type recordingDeadlineSetter struct {
	deadline time.Time
	err      error
}

func (s *recordingDeadlineSetter) SetReadDeadline(deadline time.Time) error {
	s.deadline = deadline

	return s.err
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
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
