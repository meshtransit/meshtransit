package mapsession

import (
	"net/netip"
	"slices"
	"testing"

	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
)

func TestSharedDNSRecordsNameConsumerAliasesOnly(t *testing.T) {
	t.Parallel()
	provider, consumer, evidence := deviceAliasFixture(t)
	for _, self := range []Snapshot{provider, consumer} {
		projection, err := NewDirectDeviceProjection(deviceAliasProjectionParams(t, self, provider, consumer, evidence))
		if err != nil {
			t.Fatal(err)
		}
		mapped, err := self.WithDirectDeviceProjections([]DirectDeviceProjection{projection})
		if err != nil {
			t.Fatal(err)
		}
		records, err := mapped.SharedDNSRecords()
		if err != nil {
			t.Fatal(err)
		}
		if self.Scope() == provider.Scope() {
			if len(records) != 0 {
				t.Fatalf("provider map received consumer names: %+v", records)
			}
			continue
		}
		want := []netip.Addr{netip.MustParseAddr("100.96.0.1"), netip.MustParseAddr("fd00:feed::1")}
		if len(records) != 1 || records[0].Name != evidence.Authority.Endpoint.AccessName().String() ||
			!slices.Equal(records[0].Addresses, want) {
			t.Fatalf("consumer records = %+v, want access name to Resource Aliases %v", records, want)
		}
		records[0].Addresses[0] = netip.MustParseAddr("100.96.9.9")
		again, err := mapped.SharedDNSRecords()
		if err != nil || again[0].Addresses[0] != want[0] {
			t.Fatal("records are not caller-owned copies")
		}
	}
}

func TestSharedDNSRecordsUseCanonicalAddressForDirectShares(t *testing.T) {
	t.Parallel()
	provider, consumer, evidence := directDeviceFixture(t, policy.ProtocolTCP, []policy.PortRange{mustDirectPort(t, 443, 443)})
	projection, err := NewDirectDeviceProjection(directDeviceParams(t, consumer, provider, consumer, evidence))
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := consumer.WithDirectDeviceProjections([]DirectDeviceProjection{projection})
	if err != nil {
		t.Fatal(err)
	}
	records, err := mapped.SharedDNSRecords()
	if err != nil {
		t.Fatal(err)
	}
	want := make([]netip.Addr, 0, 2)
	for _, prefix := range projection.Peer().Addresses() {
		want = append(want, prefix.Addr())
	}
	if len(records) != 1 || !slices.Equal(records[0].Addresses, want) {
		t.Fatalf("direct records = %+v, want %v", records, want)
	}
}

func TestSharedDNSRecordsEmptyWithoutShares(t *testing.T) {
	t.Parallel()
	records, err := snapshotFixture(t).SharedDNSRecords()
	if err != nil || len(records) != 0 {
		t.Fatalf("records = %+v error = %v, want none", records, err)
	}
}

func TestImportedPeerNameIsConsumerSideOnly(t *testing.T) {
	t.Parallel()
	provider, consumer, evidence := deviceAliasFixture(t)
	for _, self := range []Snapshot{provider, consumer} {
		projection, err := NewDirectDeviceProjection(deviceAliasProjectionParams(t, self, provider, consumer, evidence))
		if err != nil {
			t.Fatal(err)
		}
		mapped, err := self.WithDirectDeviceProjections([]DirectDeviceProjection{projection})
		if err != nil {
			t.Fatal(err)
		}
		peer := projection.Peer().NodeID()
		name, found := mapped.ImportedPeerName(peer)
		if self.Scope() == provider.Scope() {
			if found || name != "" {
				t.Fatalf("provider map names its consumer peer %q", name)
			}
			continue
		}
		if !found || name != evidence.Authority.Endpoint.AccessName().String() {
			t.Fatalf("ImportedPeerName = %q, %v", name, found)
		}
		if _, found := mapped.ImportedPeerName(self.NodeID()); found {
			t.Fatal("self is not an imported peer")
		}
	}
}

// Two rules from one Device to one share give two projections of the same
// contract: the share keeps one name, and the map keeps building (TD-CORE-80).
func TestSharedDNSRecordsNameEachShareOnceAcrossRules(t *testing.T) {
	t.Parallel()
	provider, consumer, evidence := deviceAliasFixture(t)
	first := must(NewDirectDeviceProjection(deviceAliasProjectionParams(t, consumer, provider, consumer, evidence)))
	params := deviceAliasProjectionParams(t, consumer, provider, consumer, evidence)
	ruleID := must(policy.ParseRuleID("01890f00-0000-7000-8000-00000000a0a2"))
	params.ConsumerRule = must(publication.NewImportedResourceDestination(publication.ImportedResourceDestinationParams{
		RuleID: ruleID, SourceNodeID: evidence.Rule.SourceNodeID(), Resolution: evidence.Rule.Resolution(),
		Protocol: evidence.Rule.Protocol(), DestinationPortRanges: evidence.Rule.DestinationPortRanges(),
	}))
	second := must(NewDirectDeviceProjection(params))
	if first.ConsumerRuleID() == second.ConsumerRuleID() || first.ContractID() != second.ContractID() {
		t.Fatal("fixture is not two rules of one contract")
	}
	mapped := must(consumer.WithDirectDeviceProjections([]DirectDeviceProjection{first, second}))
	records, err := mapped.SharedDNSRecords()
	if err != nil {
		t.Fatalf("two rules to one share failed the names: %v", err)
	}
	if len(records) != 1 || records[0].Name != evidence.Authority.Endpoint.AccessName().String() {
		t.Fatalf("records = %+v, want the share once", records)
	}
	if _, err := mapped.DNSView(dnsname.Default()); err != nil {
		t.Fatalf("two rules to one share failed the map's DNS: %v", err)
	}
	peers := mapped.AuthorizedPeers()
	if len(peers) != 1 {
		t.Fatalf("two rules to one share listed %d peers, want 1", len(peers))
	}
	if _, ok := mapped.DeviceAliasFor(peers[0].NodeID()); !ok {
		t.Fatal("two rules to one share lost the alias grant")
	}
}
