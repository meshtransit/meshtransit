package mapsession

import (
	"crypto/sha256"
	"testing"

	"meshtransit.net/core/internal/domain/kubecluster"
)

func testClusterTrust(t *testing.T, id, name string, roots ...[32]byte) KubernetesClusterTrust {
	t.Helper()
	parsedID, err := kubecluster.ParseID(id)
	if err != nil {
		t.Fatal(err)
	}
	parsedName, err := kubecluster.ParseName(name)
	if err != nil {
		t.Fatal(err)
	}
	cluster := KubernetesClusterTrust{ID: parsedID, Name: parsedName, Roots: roots}
	if len(roots) > 0 {
		cluster.TLSName = name + ".kube.example"
	}
	return cluster
}

// The trust keeps what the inventory read and refuses what a client could
// be misled by (K1a4d design §3.1).
func TestNewKubernetesTrust(t *testing.T) {
	t.Parallel()
	rootA, rootB := []byte("root a"), []byte("root b")
	printA, printB := sha256.Sum256(rootA), sha256.Sum256(rootB)
	const first, second = "01890f00-0000-7000-8000-000000000901", "01890f00-0000-7000-8000-000000000902"
	trust, ok := NewKubernetesTrust([]KubernetesClusterTrust{
		testClusterTrust(t, first, "alpha", printA, printB),
		testClusterTrust(t, second, "beta"),
	}, map[[32]byte][]byte{printA: rootA})
	if !ok || trust.Availability() != KubernetesTrustAvailable || trust.Len() != 2 {
		t.Fatalf("a valid trust: %v %v", ok, trust.Availability())
	}
	alpha, found := trust.Cluster("alpha")
	if !found || len(alpha.Roots) != 2 || alpha.TLSName != "alpha.kube.example" {
		t.Fatalf("alpha = %+v", alpha)
	}
	if der, held := trust.Root(printA); !held || string(der) != "root a" {
		t.Fatal("root a not held")
	}
	if _, held := trust.Root(printB); held {
		t.Fatal("root b held without its DER")
	}
	pending, _ := trust.Cluster("beta")
	if pending.TLSName != "" || len(pending.Roots) != 0 {
		t.Fatalf("a cluster without a CA: %+v", pending)
	}
	for name, test := range map[string]struct {
		clusters []KubernetesClusterTrust
		roots    map[[32]byte][]byte
	}{
		"duplicate name": {clusters: []KubernetesClusterTrust{
			testClusterTrust(t, first, "alpha"), testClusterTrust(t, second, "alpha"),
		}},
		"duplicate id": {clusters: []KubernetesClusterTrust{
			testClusterTrust(t, first, "alpha"), testClusterTrust(t, first, "beta"),
		}},
		"duplicate root": {clusters: []KubernetesClusterTrust{testClusterTrust(t, first, "alpha", printA, printA)}},
		"four roots": {clusters: []KubernetesClusterTrust{
			testClusterTrust(t, first, "alpha", printA, printB, [32]byte{1}, [32]byte{2}),
		}},
		"TLS name without a root": {clusters: []KubernetesClusterTrust{func() KubernetesClusterTrust {
			cluster := testClusterTrust(t, first, "alpha")
			cluster.TLSName = "alpha.kube.example"
			return cluster
		}()}},
		"DER of another fingerprint": {
			clusters: []KubernetesClusterTrust{testClusterTrust(t, first, "alpha", printA)},
			roots:    map[[32]byte][]byte{printA: rootB},
		},
		"DER of a root no cluster names": {
			clusters: []KubernetesClusterTrust{testClusterTrust(t, first, "alpha", printA)},
			roots:    map[[32]byte][]byte{printB: rootB},
		},
		"no id": {clusters: []KubernetesClusterTrust{{Name: "alpha"}}},
	} {
		if _, ok := NewKubernetesTrust(test.clusters, test.roots); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	if UnavailableKubernetesTrust(KubernetesTrustRestore).Availability() != KubernetesTrustRestore ||
		UnavailableKubernetesTrust(KubernetesTrustAvailable).Availability() != KubernetesTrustUnread ||
		(KubernetesTrust{}).Availability() != KubernetesTrustUnread {
		t.Fatal("an unavailable trust is never available")
	}
}
