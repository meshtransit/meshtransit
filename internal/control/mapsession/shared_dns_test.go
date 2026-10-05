package mapsession

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/meshtransit/meshtransit/internal/policy"
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
