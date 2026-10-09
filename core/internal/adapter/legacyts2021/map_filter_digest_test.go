package legacyts2021

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"tailscale.com/tailcfg"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/shared/policydigest"
)

// TestPacketFilterDigestMatchesSharedVector reads the wire test vector that
// meshd's tests also read, so Core and meshd agree on every PacketFilter.
func TestPacketFilterDigestMatchesSharedVector(t *testing.T) {
	encoded, err := os.ReadFile("../../../../shared/policydigest/testdata/packet-filter-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		PacketFilter []tailcfg.FilterRule `json:"packet_filter"`
		Digest       policydigest.Digest  `json:"digest"`
		Grants       int                  `json:"grants"`
	}
	if err := json.Unmarshal(encoded, &vector); err != nil {
		t.Fatal(err)
	}
	rules, err := digestRules(vector.PacketFilter)
	if err != nil {
		t.Fatal(err)
	}
	digest, grants, err := policydigest.Compute(rules)
	if err != nil || digest != vector.Digest || grants != vector.Grants {
		t.Fatalf("digest = %s (%d grants), %v; want %s (%d)", digest, grants, err, vector.Digest, vector.Grants)
	}
}

// TestPacketFilterDigestCoversTheEncodedFilter checks the digest against the
// PacketFilter the full map actually carries.
func TestPacketFilterDigestCoversTheEncodedFilter(t *testing.T) {
	for name, snapshot := range map[string]mapsession.Snapshot{
		"no rules":  mapSnapshotFixture(t),
		"icmp":      mapSnapshotWithInboundPolicyFixture(t),
		"transport": mapSnapshotWithInboundTransportPolicyFixture(t),
	} {
		t.Run(name, func(t *testing.T) {
			filter, err := PacketFilterDigest(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			response := decodeFullMapResponseFixture(t, snapshot)
			rules, err := digestRules(response.PacketFilter)
			if err != nil {
				t.Fatal(err)
			}
			digest, grants, err := policydigest.Compute(rules)
			if err != nil || digest != filter.Digest() || grants != filter.Grants() {
				t.Fatalf("encoded filter digest %s (%d) differs from %s (%d)", digest, grants,
					filter.Digest(), filter.Grants())
			}
		})
	}
	if _, err := PacketFilterDigest(mapsession.Snapshot{}); !errors.Is(err, ErrFilterDigest) {
		t.Fatalf("invalid snapshot error = %v", err)
	}
}

func TestDigestRulesRejectsSelectorsCoreNeverWrites(t *testing.T) {
	bits := 24
	for name, rule := range map[string]tailcfg.FilterRule{
		"prefix source": {SrcIPs: []string{"100.64.0.0/10"}, DstPorts: []tailcfg.NetPortRange{{IP: "100.64.0.1"}}},
		"legacy bits": {SrcIPs: []string{"100.64.0.2"},
			DstPorts: []tailcfg.NetPortRange{{IP: "100.64.0.1", Bits: &bits}}},
		"protocol": {SrcIPs: []string{"100.64.0.2"}, DstPorts: []tailcfg.NetPortRange{{IP: "100.64.0.1"}},
			IPProto: []int{256}},
	} {
		if _, err := digestRules([]tailcfg.FilterRule{rule}); !errors.Is(err, ErrFilterDigest) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}
