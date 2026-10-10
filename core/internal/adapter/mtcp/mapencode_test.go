package mtcp

import (
	"net/netip"
	"testing"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/adapter/legacyts2021"
	"meshtransit.net/core/internal/control/mapsession"
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

// TestFilterDigestMatchesTS2021 keeps enforcement evidence comparable while
// nodes move from TS2021 to MTCP: both encodings digest the same.
func TestFilterDigestMatchesTS2021(t *testing.T) {
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
		got, grants, err := sharedmtcp.FilterDigest(filter)
		if err != nil {
			t.Fatal(err)
		}
		want, err := legacyts2021.PacketFilterDigest(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if got != want.Digest() || grants != want.Grants() {
			t.Fatalf("%d peers: MTCP digest %s (%d) differs from TS2021 %s (%d)", count, got, grants,
				want.Digest(), want.Grants())
		}
	}
}
