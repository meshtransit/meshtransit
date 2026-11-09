package postgres

import (
	"reflect"
	"strings"
	"testing"
)

// The JSON compute_network_summary_v1 returns, as PostgreSQL writes it.
const computedNetworkSummary = `{"workspace_id": 103, "network_id": 203, "network_revision": 7,
 "dirty_generation": 3, "evaluated_at": "2026-11-09T08:00:00.123456+00:00", "ipv4_prefix": "100.80.0.0/24",
 "addresses_capacity": 254, "addresses_in_use": 10, "addresses_held": 2, "active_devices": 9,
 "rule_count": 4, "policy_revision": 2, "policy_published_at": "2026-11-08T08:00:00+00:00",
 "shares_out_active": 1, "shares_in_active": 0, "offers_waiting": 1, "pending_approvals": 0, "sites": 1,
 "kubernetes_clusters": 0, "recompute_at": "2026-11-09T09:00:00+00:00",
 "peers": [{"direction": "outgoing", "peer_workspace_id": 103, "peer_network_id": 204, "active": 1, "waiting": 0},
  {"direction": "incoming", "peer_workspace_id": 104, "peer_network_id": 0, "active": 0, "waiting": 1}]}`

func TestNetworkSummaryDecodesWhatTheDatabaseComputes(t *testing.T) {
	t.Parallel()
	summary, err := decodeNetworkSummary(computedNetworkSummary)
	if err != nil {
		t.Fatal(err)
	}
	if summary.IPv4Prefix.String() != "100.80.0.0/24" || summary.AddressesCapacity != 254 || len(summary.Peers) != 2 ||
		summary.RecomputeAt.IsZero() || summary.PolicyPublishedAt.IsZero() {
		t.Fatalf("decoded %+v", summary)
	}
	encoded, err := encodeNetworkSummary(summary)
	if err != nil {
		t.Fatal(err)
	}
	again, err := decodeNetworkSummary(string(encoded))
	if err != nil || !reflect.DeepEqual(again, summary) {
		t.Fatalf("round trip changed the summary: %v\n%+v\n%+v", err, again, summary)
	}
}

func TestNetworkSummaryDecodeRefusesWhatCannotBeTrue(t *testing.T) {
	t.Parallel()
	for name, broken := range map[string]string{
		"unknown field":         strings.Replace(computedNetworkSummary, `"sites": 1,`, `"sites": 1, "extra": 1,`, 1),
		"range without room":    strings.Replace(computedNetworkSummary, `"addresses_capacity": 254`, `"addresses_capacity": null`, 1),
		"host bits in range":    strings.Replace(computedNetworkSummary, `"100.80.0.0/24"`, `"100.80.0.1/24"`, 1),
		"negative count":        strings.Replace(computedNetworkSummary, `"active_devices": 9`, `"active_devices": -1`, 1),
		"foreign Network named": strings.Replace(computedNetworkSummary, `"peer_workspace_id": 104, "peer_network_id": 0`, `"peer_workspace_id": 104, "peer_network_id": 9`, 1),
	} {
		if _, err := decodeNetworkSummary(broken); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
