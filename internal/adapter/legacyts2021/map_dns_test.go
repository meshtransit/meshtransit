package legacyts2021

import (
	"encoding/json"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/util/zstdframe"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/policy"
)

func TestFullMapNamesImportedSharesOnConsumerOnly(t *testing.T) {
	t.Parallel()
	provider, consumer, _ := aliasMapSnapshots(t, policy.ProtocolICMP, nil, 7)
	consumerWire := decodeFullMapResponseFixture(t, consumer)
	if consumerWire.DNSConfig == nil {
		t.Fatal("full map omitted DNS, so a revoked name could survive")
	}
	grant, ok := consumer.DeviceAliasFor(consumer.AuthorizedPeers()[0].NodeID())
	if !ok {
		t.Fatal("missing consumer grant")
	}
	records, err := consumer.SharedDNSRecords()
	if err != nil || len(records) != 1 {
		t.Fatalf("shared records = %+v error = %v", records, err)
	}
	want := []tailcfg.DNSRecord{
		{Name: records[0].Name, Type: "A", Value: grant.RemoteAddresses[0].Addr().String()},
		{Name: records[0].Name, Type: "AAAA", Value: grant.RemoteAddresses[1].Addr().String()},
	}
	if !equalDNSRecords(consumerWire.DNSConfig.ExtraRecords, want) || consumerWire.DNSConfig.Proxied ||
		len(consumerWire.DNSConfig.Resolvers) != 0 || len(consumerWire.DNSConfig.Routes) != 0 {
		t.Fatalf("consumer DNS = %+v, want only %+v", consumerWire.DNSConfig, want)
	}
	providerWire := decodeFullMapResponseFixture(t, provider)
	if providerWire.DNSConfig == nil || len(providerWire.DNSConfig.ExtraRecords) != 0 {
		t.Fatalf("provider DNS = %+v, want explicit empty configuration", providerWire.DNSConfig)
	}
}

func TestFullMapWithoutSharesClearsDNS(t *testing.T) {
	t.Parallel()
	wire := decodeFullMapResponseFixture(t, mapSnapshotFixture(t))
	if wire.DNSConfig == nil || len(wire.DNSConfig.ExtraRecords) != 0 {
		t.Fatalf("DNS = %+v, want explicit empty configuration", wire.DNSConfig)
	}
}

func TestAuthorityDeltaCarriesCompleteDNS(t *testing.T) {
	t.Parallel()
	// The fixture advances the provider's revision, so this delta belongs to
	// the provider map: its complete DNS configuration is explicitly empty.
	current, _, _ := aliasMapSnapshots(t, policy.ProtocolICMP, nil, 7)
	next, _, _ := aliasMapSnapshots(t, policy.ProtocolICMP, nil, 8)
	delta, err := mapsession.NewAuthorityDelta(current, next)
	if err != nil {
		t.Fatal(err)
	}
	fields, wire := decodeAuthorityDeltaFixture(t, delta)
	if _, present := fields["DNSConfig"]; !present || wire.DNSConfig == nil || len(wire.DNSConfig.ExtraRecords) != 0 {
		t.Fatalf("authority delta DNS = %+v, want the complete (empty) configuration", wire.DNSConfig)
	}
}

func TestAuthorityWithdrawalClearsDNS(t *testing.T) {
	t.Parallel()
	_, consumer, _ := aliasMapSnapshots(t, policy.ProtocolICMP, nil, 7)
	encoded, err := encodeAuthorityWithdrawalMapResponse(consumer, 142, mapResponseCompressionZstd)
	if err != nil {
		t.Fatal(err)
	}
	document, err := zstdframe.AppendDecode(nil, encoded[4:], zstdframe.MaxDecodedSize(maxMapResponseBytes))
	if err != nil {
		t.Fatal(err)
	}
	var wire tailcfg.MapResponse
	if err := json.Unmarshal(document, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.DNSConfig == nil || len(wire.DNSConfig.ExtraRecords) != 0 {
		t.Fatalf("withdrawal DNS = %+v, want explicit empty configuration", wire.DNSConfig)
	}
}

func equalDNSRecords(left, right []tailcfg.DNSRecord) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
