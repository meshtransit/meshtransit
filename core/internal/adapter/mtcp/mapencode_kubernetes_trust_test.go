package mtcp

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
)

const testTrustClusterID = "01890f00-0000-7000-8000-000000000901"

// trustSnapshot is a map with a kinda-k1 replica peer whose cluster's
// trust names roots, with DER held for those in held.
func trustSnapshot(t *testing.T, roots [][]byte, held ...[]byte) mapsession.Snapshot {
	t.Helper()
	snapshot := snapshotFixture(t, 7, replicaFixture(t, snapshotFixture(t, 7).Scope(), 3, 0))
	cluster := mapsession.KubernetesClusterTrust{
		ID: must(kubecluster.ParseID(testTrustClusterID)), Name: "kinda-k1",
		TLSName: "kinda-k1.kube." + kubernetesTestZone,
	}
	for _, root := range roots {
		cluster.Roots = append(cluster.Roots, sha256.Sum256(root))
	}
	if len(roots) == 0 {
		cluster.TLSName = ""
	}
	der := map[[32]byte][]byte{}
	for _, root := range held {
		der[sha256.Sum256(root)] = root
	}
	trust, ok := mapsession.NewKubernetesTrust([]mapsession.KubernetesClusterTrust{cluster}, der)
	if !ok {
		t.Fatal("trust")
	}
	return snapshot.WithKubernetes(mapsession.KubernetesView{}.WithTrust(trust))
}

func withTrust(snapshot mapsession.Snapshot, trust mapsession.KubernetesTrust) mapsession.Snapshot {
	return snapshot.WithKubernetes(mapsession.KubernetesView{}.WithTrust(trust))
}

// The node is sent each root's DER once while a listed cluster names it;
// the list again only when it changes (K1a4d design §2.4).
func TestEncodeKubernetesClustersSendsRootsOnce(t *testing.T) {
	t.Parallel()
	old, next := []byte("old root"), []byte("next root")
	state := kubeClusterState{}
	first := trustSnapshot(t, [][]byte{old}, old)
	message, state, _ := state.encodeKubernetesClusters(first, dnsname.Default(), true)
	clusters := message.GetClusters()
	if message.GetAvailability() != mtcpv1.KubernetesClusters_AVAILABLE || len(clusters) != 1 ||
		clusters[0].GetClusterId() != testTrustClusterID || clusters[0].GetDnsName() != "kinda-k1.kube."+kubernetesTestZone ||
		clusters[0].GetTlsServerName() != "kinda-k1.kube."+kubernetesTestZone || len(message.GetRoots()) != 1 ||
		!bytes.Equal(message.GetRoots()[0], old) {
		t.Fatalf("snapshot field = %v", message)
	}
	if message, _, _ := state.encodeKubernetesClusters(first, dnsname.Default(), false); message != nil {
		t.Fatalf("an unchanged delta carries %v", message)
	}
	// A next root: the list and only the new DER.
	second := trustSnapshot(t, [][]byte{old, next}, old, next)
	message, state, _ = state.encodeKubernetesClusters(second, dnsname.Default(), false)
	if len(message.GetClusters()[0].GetRootFingerprints()) != 2 || len(message.GetRoots()) != 1 ||
		!bytes.Equal(message.GetRoots()[0], next) {
		t.Fatalf("a next root's delta = %v", message)
	}
	// The cluster leaves, then returns: its DER is sent again.
	gone := withTrust(snapshotFixture(t, 7), mapsession.EmptyKubernetesTrust())
	message, state, _ = state.encodeKubernetesClusters(gone, dnsname.Default(), false)
	if message == nil || len(message.GetClusters()) != 0 || message.GetAvailability() != mtcpv1.KubernetesClusters_AVAILABLE {
		t.Fatalf("the cluster left: %v", message)
	}
	message, _, _ = state.encodeKubernetesClusters(second, dnsname.Default(), false)
	if len(message.GetRoots()) != 2 {
		t.Fatalf("the cluster returned without its DER: %v", message)
	}
}

// While not available the list and the sent set stay: UNREAD is said in a
// snapshot or before any list of the epoch, never after one; RESTORE once;
// the next available list is sent whole, without DER the node holds.
func TestEncodeKubernetesClustersWhileUnavailable(t *testing.T) {
	t.Parallel()
	root := []byte("root")
	available := trustSnapshot(t, [][]byte{root}, root)
	unread := withTrust(available, mapsession.UnavailableKubernetesTrust(mapsession.KubernetesTrustUnread))
	restore := withTrust(available, mapsession.UnavailableKubernetesTrust(mapsession.KubernetesTrustRestore))

	state := kubeClusterState{}
	message, state, _ := state.encodeKubernetesClusters(unread, dnsname.Default(), true)
	if message.GetAvailability() != mtcpv1.KubernetesClusters_UNREAD || len(message.GetClusters()) != 0 {
		t.Fatalf("a snapshot while unread = %v", message)
	}
	if message, _, _ := state.encodeKubernetesClusters(unread, dnsname.Default(), false); message != nil {
		t.Fatalf("UNREAD again = %v", message)
	}
	message, state, _ = state.encodeKubernetesClusters(available, dnsname.Default(), false)
	if message.GetAvailability() != mtcpv1.KubernetesClusters_AVAILABLE || len(message.GetRoots()) != 1 {
		t.Fatalf("available after unread = %v", message)
	}
	// A transient failure after a list of the epoch: nothing.
	if message, _, _ := state.encodeKubernetesClusters(unread, dnsname.Default(), false); message != nil {
		t.Fatalf("UNREAD after a list = %v", message)
	}
	message, state, _ = state.encodeKubernetesClusters(restore, dnsname.Default(), false)
	if message.GetAvailability() != mtcpv1.KubernetesClusters_RESTORE || len(message.GetClusters()) != 0 {
		t.Fatalf("RESTORE = %v", message)
	}
	if message, _, _ := state.encodeKubernetesClusters(restore, dnsname.Default(), false); message != nil {
		t.Fatalf("RESTORE again = %v", message)
	}
	// Back: the list again, its DER not (the node kept it).
	message, _, _ = state.encodeKubernetesClusters(available, dnsname.Default(), false)
	if message.GetAvailability() != mtcpv1.KubernetesClusters_AVAILABLE || len(message.GetClusters()) != 1 ||
		len(message.GetRoots()) != 0 {
		t.Fatalf("available after a restore = %v", message)
	}
}

// A cluster without a CA yet is listed without roots or TLS name; a root
// the inventory holds no DER of is named, not sent.
func TestEncodeKubernetesClustersWithoutRoots(t *testing.T) {
	t.Parallel()
	message, _, _ := kubeClusterState{}.encodeKubernetesClusters(trustSnapshot(t, nil), dnsname.Default(), true)
	if cluster := message.GetClusters(); len(cluster) != 1 || cluster[0].GetTlsServerName() != "" ||
		len(cluster[0].GetRootFingerprints()) != 0 {
		t.Fatalf("a cluster without a CA = %v", message)
	}
	message, _, _ = kubeClusterState{}.encodeKubernetesClusters(trustSnapshot(t, [][]byte{[]byte("root")}),
		dnsname.Default(), true)
	if len(message.GetClusters()[0].GetRootFingerprints()) != 1 || len(message.GetRoots()) != 0 {
		t.Fatalf("a root without DER = %v", message)
	}
}

// Only a session that negotiated kube.ca1 is sent its clusters.
func TestSinkSendsKubernetesClustersOnlyWithKubeCA(t *testing.T) {
	root := []byte("root")
	snapshot := trustSnapshot(t, [][]byte{root}, root)
	for _, negotiated := range []bool{false, true} {
		session, node, control := testSession(t)
		if negotiated {
			session.capabilities = append(session.capabilities, CapabilityKubeCA)
		}
		sink := newMapSink(session, false, []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}},
			time.Now)
		if err := sink.SendSnapshot(t.Context(), snapshot); err != nil {
			t.Fatal(err)
		}
		node.read() // KeyUpdate
		_, message, _ := node.read()
		sent, ok := message.(*mtcpv1.MapSnapshot)
		if !ok {
			t.Fatalf("sent %T", message)
		}
		if got := sent.GetKubernetesClusters(); (got != nil) != negotiated ||
			negotiated && len(got.GetRoots()) != 1 {
			t.Fatalf("negotiated %v: %v", negotiated, got)
		}
	}
}

// clusterReplica is a replica of cluster at 100.64.0.<marker>.
func clusterReplica(t *testing.T, marker byte, cluster string) mapsession.PeerCandidate {
	t.Helper()
	createdAt := time.Date(2026, time.September, 14, 3, 0, 0, 0, time.UTC)
	return must(mapsession.NewPeerCandidate(mapsession.PeerCandidateParams{
		NumericNodeID: 700 + int64(marker), NumericOwnerID: 11, Scope: snapshotFixture(t, 7).Scope(),
		NodeID:            must(node.ParseID(fmt.Sprintf("01890f00-0000-7000-8000-000000000%03d", 700+int(marker)))),
		OwnerID:           must(identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")),
		Hostname:          must(node.ParseHostname(fmt.Sprintf("%s-0", cluster))),
		DNSLabel:          must(node.ParseDNSLabel(fmt.Sprintf("%s-0", cluster))),
		KubernetesCluster: must(kubecluster.ParseName(cluster)),
		MachineKey:        must(node.NewMachineKey([32]byte{marker, 0xaa})),
		NodeKey:           must(node.NewKey([32]byte{marker, 0xbb})),
		SessionGeneration: 1, Addresses: []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("100.64.0.%d/32", marker))},
		CreatedAt: createdAt, KeyExpiry: createdAt.Add(24 * time.Hour),
	}))
}

// Roots past a message's 2 MiB of DER are counted and sent by the next
// message carrying the field, even with the list unchanged.
func TestEncodeKubernetesClustersDefersRootsPastTheBudget(t *testing.T) {
	t.Parallel()
	var peers []mapsession.PeerCandidate
	var clusters []mapsession.KubernetesClusterTrust
	roots := map[[32]byte][]byte{}
	for index := range 3 {
		name := fmt.Sprintf("c%d", index)
		peers = append(peers, clusterReplica(t, byte(10+index), name))
		der := bytes.Repeat([]byte{byte(index + 1)}, 1<<20)
		fingerprint := sha256.Sum256(der)
		roots[fingerprint] = der
		clusters = append(clusters, mapsession.KubernetesClusterTrust{
			ID:   must(kubecluster.ParseID(fmt.Sprintf("01890f00-0000-7000-8000-00000000090%d", index+1))),
			Name: must(kubecluster.ParseName(name)), TLSName: name + ".kube.example", Roots: [][32]byte{fingerprint},
		})
	}
	trust, ok := mapsession.NewKubernetesTrust(clusters, roots)
	if !ok {
		t.Fatal("trust")
	}
	snapshot := withTrust(snapshotFixture(t, 7, peers...), trust)
	message, state, counts := kubeClusterState{}.encodeKubernetesClusters(snapshot, dnsname.Default(), true)
	if len(message.GetClusters()) != 3 || len(message.GetRoots()) != 2 || counts.deferred != 1 {
		t.Fatalf("snapshot: %d clusters, %d roots, %+v", len(message.GetClusters()), len(message.GetRoots()), counts)
	}
	message, _, counts = state.encodeKubernetesClusters(snapshot, dnsname.Default(), false)
	if len(message.GetRoots()) != 1 || counts.deferred != 0 {
		t.Fatalf("the next delta: %d roots, %+v", len(message.GetRoots()), counts)
	}
}
