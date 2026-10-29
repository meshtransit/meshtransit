package cli

import (
	"encoding/json"
	"testing"

	"meshtransit.net/client/internal/cli/localapi"
)

// Status names each cluster with its state, and keeps the daemon's field
// through its JSON form (meshctl --json status re-encodes it).
func TestKubernetesClustersInStatus(t *testing.T) {
	t.Parallel()
	if got := formatKubernetesClusters(nil); got != "none" {
		t.Fatalf("no clusters: %q", got)
	}
	var status localapi.Status
	if err := json.Unmarshal([]byte(`{"kubernetes_clusters":[{"id":"a","name":"kinda-k1","state":"trusted",`+
		`"root_fingerprints":["17ff"]},{"id":"b","name":"abc","state":"pending"}]}`), &status); err != nil {
		t.Fatal(err)
	}
	if got := formatKubernetesClusters(status.KubernetesClusters); got != "kinda-k1 trusted, abc pending" {
		t.Fatalf("clusters: %q", got)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	var again struct {
		Clusters []struct {
			State string   `json:"state"`
			Roots []string `json:"root_fingerprints"`
		} `json:"kubernetes_clusters"`
	}
	if err := json.Unmarshal(encoded, &again); err != nil || len(again.Clusters) != 2 ||
		again.Clusters[0].State != "trusted" || len(again.Clusters[0].Roots) != 1 {
		t.Fatalf("re-encoded status lost the clusters: %s", encoded)
	}
}
