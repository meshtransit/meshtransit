package mapsession

import (
	"crypto/sha256"
	"testing"

	"meshtransit.net/core/internal/domain/dnsname"
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

// A map names each cluster with a replica among its peers, once, in ID
// order, with its zone name; only an available trust names any, and only a
// kube.ca1 session keeps it (§7.11).
func TestSnapshotKubernetesClusters(t *testing.T) {
	t.Parallel()
	base := snapshotFixture(t)
	snapshot := clusterSnapshot(t, false,
		replicaParams(t, base, 5, "", "beta", false),
		replicaParams(t, base, 6, "", "alpha", false),
		replicaParams(t, base, 7, "", "alpha", false),
		replicaParams(t, base, 8, "web", "", false))
	rootA, rootB := sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))
	trust, ok := NewKubernetesTrust([]KubernetesClusterTrust{
		testClusterTrust(t, "01890f00-0000-7000-8000-000000000902", "alpha", rootA),
		testClusterTrust(t, "01890f00-0000-7000-8000-000000000901", "beta", rootB),
		testClusterTrust(t, "01890f00-0000-7000-8000-000000000903", "gamma"),
	}, nil)
	if !ok {
		t.Fatal("trust")
	}
	if clusters, _ := snapshot.KubernetesClusters(dnsname.Default()); clusters != nil {
		t.Fatalf("an unread trust names %+v", clusters)
	}
	snapshot = snapshot.WithKubernetes(snapshot.Kubernetes().WithTrust(trust))
	clusters, dropped := snapshot.KubernetesClusters(dnsname.Default())
	if dropped != 0 || len(clusters) != 2 || clusters[0].Name != "beta" || clusters[1].Name != "alpha" ||
		clusters[1].DNSName != "alpha.kube."+kubernetesTestZone || len(clusters[1].Roots) != 1 {
		t.Fatalf("clusters %+v, dropped %d", clusters, dropped)
	}
	without := snapshot.withKubernetesCapability(Request{})
	with := snapshot.withKubernetesCapability(Request{}.WithKubernetesClusters())
	if without.Kubernetes().Trust().Availability() != KubernetesTrustUnread ||
		!with.Kubernetes().Trust().Equal(trust) || !with.Kubernetes().TrustChanged(without.Kubernetes()) ||
		!with.Kubernetes().Equal(without.Kubernetes()) || !with.Kubernetes().TrustTaken() {
		t.Fatal("the trust stays only for kube.ca1")
	}
	// Another trust compares unequal; the same contents compare equal.
	again, _ := NewKubernetesTrust([]KubernetesClusterTrust{
		testClusterTrust(t, "01890f00-0000-7000-8000-000000000902", "alpha", rootA),
		testClusterTrust(t, "01890f00-0000-7000-8000-000000000901", "beta", rootB),
		testClusterTrust(t, "01890f00-0000-7000-8000-000000000903", "gamma"),
	}, nil)
	held, _ := NewKubernetesTrust([]KubernetesClusterTrust{
		testClusterTrust(t, "01890f00-0000-7000-8000-000000000902", "alpha", rootA),
		testClusterTrust(t, "01890f00-0000-7000-8000-000000000901", "beta", rootB),
		testClusterTrust(t, "01890f00-0000-7000-8000-000000000903", "gamma"),
	}, map[[32]byte][]byte{rootA: []byte("a")})
	if !again.Equal(trust) || held.Equal(trust) || EmptyKubernetesTrust().Equal(trust) {
		t.Fatal("trust equality")
	}
}

// The clusters' trust read again at the same revision (a read that failed,
// a root's DER found) reaches a kube.ca1 session as an authority delta, so
// the encoder's epoch rules hold, never as a snapshot (review d2 H2).
func TestTrustAloneChangesTheMapByADelta(t *testing.T) {
	t.Parallel()
	_, authorized, _ := authorityDeltaSnapshotsFixture(t)
	request := Request{}.WithKubernetesClusters()
	root := sha256.Sum256([]byte("root"))
	cluster := testClusterTrust(t, "01890f00-0000-7000-8000-000000000901", "alpha", root)
	missing, _ := NewKubernetesTrust([]KubernetesClusterTrust{cluster}, nil)
	held, _ := NewKubernetesTrust([]KubernetesClusterTrust{cluster}, map[[32]byte][]byte{root: []byte("root")})
	for name, test := range map[string]struct{ current, next KubernetesTrust }{
		"read again":  {UnavailableKubernetesTrust(KubernetesTrustUnread), missing},
		"DER found":   {missing, held},
		"read failed": {held, UnavailableKubernetesTrust(KubernetesTrustUnread)},
	} {
		current := authorized.WithKubernetes(KubernetesView{}.WithTrust(test.current)).withKubernetesCapability(request)
		next := authorized.WithKubernetes(KubernetesView{}.WithTrust(test.next)).withKubernetesCapability(request)
		if !streamSnapshotChanged(current, next) {
			t.Fatalf("%s: unchanged", name)
		}
		sink := &recordingStreamSink{}
		if _, err := (&StreamService{}).deliver(t.Context(), sink, current, next); err != nil {
			t.Fatal(err)
		}
		if snapshots, _ := sink.state(); len(snapshots) != 0 || len(sink.authorityDeltas) != 1 {
			t.Fatalf("%s: sent %d snapshots, %d deltas", name, len(snapshots), len(sink.authorityDeltas))
		}
	}
	// A session without kube.ca1 sees no change at all.
	current := authorized.WithKubernetes(KubernetesView{}.WithTrust(missing)).withKubernetesCapability(Request{})
	next := authorized.WithKubernetes(KubernetesView{}.WithTrust(held)).withKubernetesCapability(Request{})
	if streamSnapshotChanged(current, next) {
		t.Fatal("a session without kube.ca1 changed")
	}
}
