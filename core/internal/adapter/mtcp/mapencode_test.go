package mtcp

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/sharing"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

func TestEncodeSnapshot(t *testing.T) {
	snapshot := snapshotFixture(t, 7)
	message, err := encodeSnapshot(snapshot, &mtcpv1.View{Epoch: 9, Seq: 1}, false)
	if err != nil {
		t.Fatal(err)
	}
	self, peers := message.GetSelf(), message.GetPeers()
	if self.GetDeviceId() != "01890f00-0000-7000-8000-000000000701" || self.GetName() != "node-one.example." ||
		len(self.GetAddresses()) != 1 || len(self.GetAddresses()[0]) != 4 || len(peers) != 1 ||
		peers[0].GetDeviceId() != "01890f00-0000-7000-8000-000000000702" || peers[0].GetDisplayName() == "" {
		t.Fatalf("devices = %v / %v", self, peers)
	}
	if revisions := message.GetNetworkRevisions(); len(revisions) != 1 || revisions[0].GetRevision() != 7 ||
		revisions[0].GetNetworkId() != snapshot.Scope().NetworkID().String() {
		t.Fatalf("network revisions = %v", revisions)
	}
	rules := message.GetPacketFilter().GetRules()
	if len(rules) != 3 {
		t.Fatalf("filter has %d rules, want TCP, ICMP and UDP inbound only", len(rules))
	}
	for _, rule := range rules {
		source, _ := sharedmtcp.ParsePrefix(rule.GetSources()[0])
		destination, _ := sharedmtcp.ParsePrefix(rule.GetDestinations()[0].GetPrefix())
		if source != netip.MustParsePrefix("100.64.0.2/32") || destination != netip.MustParsePrefix("100.64.0.1/32") {
			t.Fatalf("rule %v is not peer-to-self", rule)
		}
	}
	if message.GetDns() == nil || message.GetSettings().GetEndpointReportS() != endpointReportSeconds {
		t.Fatal("snapshot without DNS or settings")
	}
}

// TestPacketFilterDigestCoversTheEncodedFilter checks the digest Core keeps
// against the filter the map carries, for growing peer sets.
func TestPacketFilterDigestCoversTheEncodedFilter(t *testing.T) {
	scope := snapshotFixture(t, 1).Scope()
	peers := []string{"100.64.0.2", "100.64.0.3", "100.64.0.4"}
	for count := 1; count <= len(peers); count++ {
		list := make([]mapsession.PeerCandidate, 0, count)
		for index := range count {
			list = append(list, peerFixture(t, scope, "01890f00-0000-7000-8000-00000000070"+string(rune('2'+index)),
				int64(702+index), peers[index], byte(2+index)))
		}
		snapshot := snapshotFixture(t, 7, list...)
		filter, err := encodePacketFilter(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		want, grants, err := sharedmtcp.FilterDigest(filter)
		if err != nil {
			t.Fatal(err)
		}
		got, err := PacketFilterDigest(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if got.Digest() != want || got.Grants() != grants {
			t.Fatalf("%d peers: digest %s (%d), want %s (%d)", count, got.Digest(), got.Grants(), want, grants)
		}
	}
	if _, err := PacketFilterDigest(mapsession.Snapshot{}); !errors.Is(err, ErrFilterDigest) {
		t.Fatalf("invalid snapshot error = %v", err)
	}
}

// TestEncodeAliasCarriesTheGrant checks the device alias v1 grant as MTCP
// typed fields (docs/protocol/device-alias-v1.md, mtcp-v1 §7.4).
func TestEncodeAliasCarriesTheGrant(t *testing.T) {
	contract, err := sharing.ParseContractID("01890f00-0000-7000-8000-000000000a01")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := sharing.ParsePrivateEndpointID("01890f00-0000-7000-8000-000000000a02")
	if err != nil {
		t.Fatal(err)
	}
	ports, _ := policy.NewPortRange(22, 22)
	tcp, err := sharing.NewTrafficConstraint(sharing.TrafficConstraintParams{
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{ports},
	})
	if err != nil {
		t.Fatal(err)
	}
	icmp, err := sharing.NewTrafficConstraint(sharing.TrafficConstraintParams{Protocol: policy.ProtocolICMP})
	if err != nil {
		t.Fatal(err)
	}
	traffic, err := sharing.NewTrafficSet([]sharing.TrafficConstraint{tcp, icmp})
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour).Truncate(time.Millisecond)
	grant := mapsession.DeviceAliasGrant{
		ContractID: contract, EndpointID: endpoint, Generation: 3, GrantRevision: 4, RecoveryEpoch: 5,
		IsConsumer: true, ExpiresAt: expires, Traffic: traffic,
		LocalAddresses: []netip.Prefix{
			netip.MustParsePrefix("198.18.0.7/32"), netip.MustParsePrefix("fd02:48de:ec1b:1::7/128"),
		},
	}
	alias, err := encodeAlias(grant)
	if err != nil {
		t.Fatal(err)
	}
	if alias.GetContractId() != contract.String() || alias.GetEndpointId() != endpoint.String() ||
		alias.GetGeneration() != 3 || alias.GetGrantRevision() != 4 || alias.GetRecoveryEpoch() != 5 ||
		alias.GetRole() != mtcpv1.AliasGrant_CONSUMER || alias.GetExpiresMs() != expires.UnixMilli() ||
		!bytes.Equal(alias.GetMasqueradeV4(), netip.MustParseAddr("198.18.0.7").AsSlice()) ||
		!bytes.Equal(alias.GetMasqueradeV6(), netip.MustParseAddr("fd02:48de:ec1b:1::7").AsSlice()) {
		t.Fatalf("alias = %v", alias)
	}
	// ICMP becomes one echo grant per local family, sorted with TCP.
	var services []string
	for _, service := range alias.GetServices() {
		services = append(services, fmt.Sprintf("%d:%d-%d", service.GetProtocol(), service.GetPortFrom(), service.GetPortTo()))
	}
	if strings.Join(services, ",") != "1:0-0,6:22-22,58:0-0" {
		t.Fatalf("services = %v", services)
	}

	grant.IsConsumer = false
	if provider, err := encodeAlias(grant); err != nil || provider.GetRole() != mtcpv1.AliasGrant_PROVIDER {
		t.Fatalf("provider role = %v, %v", provider.GetRole(), err)
	}
}
