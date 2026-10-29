package daemon

import (
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
)

// A cluster held past HeldUntil shows unavailable when status is read, though
// no map came since; the views never carry DER.
func TestKubernetesClustersAt(t *testing.T) {
	t.Parallel()
	now := time.Now()
	views := kubernetesClusterViews([]networkmap.KubernetesCluster{
		{ID: "a", Name: "alpha", State: networkmap.KubernetesClusterTrusted, RootFingerprints: [][32]byte{{1}},
			Roots: [][]byte{[]byte("der")}, HeldUntil: now.Add(-time.Minute)},
		{ID: "b", Name: "beta", State: networkmap.KubernetesClusterTrusted},
	})
	current := kubernetesClustersAt(views, now)
	if current[0].State != "unavailable" || current[1].State != "trusted" || views[0].State != "trusted" ||
		len(current[0].RootFingerprints) != 1 || current[0].RootFingerprints[0][:2] != "01" {
		t.Fatalf("views = %+v", current)
	}
	if kubernetesClusterViews(nil) != nil || kubernetesClustersAt(nil, now) != nil {
		t.Fatal("a node that takes no clusters shows some")
	}
}
