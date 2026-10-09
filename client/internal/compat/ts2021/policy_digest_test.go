package ts2021

import (
	"encoding/json"
	"os"
	"testing"

	"tailscale.com/tailcfg"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/policydigest"
)

// TestPolicyDigestMatchesSharedVector parses the wire test vector that Core's
// tests also read, as meshd parses a map, so both sides agree on the digest.
func TestPolicyDigestMatchesSharedVector(t *testing.T) {
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
	rules, err := convertFilterRules(vector.PacketFilter)
	if err != nil {
		t.Fatal(err)
	}
	digest, grants, err := networkmap.PolicyDigest(rules)
	if err != nil || digest != vector.Digest || grants != vector.Grants {
		t.Fatalf("digest = %s (%d grants), %v; want %s (%d)", digest, grants, err, vector.Digest, vector.Grants)
	}
}
