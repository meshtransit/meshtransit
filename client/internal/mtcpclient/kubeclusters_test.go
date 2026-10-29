package mtcpclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
)

const (
	testClusterID   = "01890f00-0000-7000-8000-000000000901"
	testClusterName = "kinda-k1.kube.000000000101.000000000201.mesh.internal"
)

// clusterRoot makes a root as Core does, permitting name.
func clusterRoot(t *testing.T, name string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{name},
		ExcludedIPRanges: []*net.IPNet{
			{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func fingerprintOf(der []byte) []byte {
	sum := sha256.Sum256(der)
	return sum[:]
}

// clustersField lists kinda-k1 naming roots, carrying sent's DER.
func clustersField(roots [][]byte, sent ...[]byte) *mtcpv1.KubernetesClusters {
	cluster := &mtcpv1.KubernetesCluster{
		ClusterId: testClusterID, Name: "kinda-k1", DnsName: testClusterName, TlsServerName: testClusterName,
	}
	for _, root := range roots {
		cluster.RootFingerprints = append(cluster.RootFingerprints, fingerprintOf(root))
	}
	return &mtcpv1.KubernetesClusters{
		Clusters: []*mtcpv1.KubernetesCluster{cluster}, Roots: sent,
		Availability: mtcpv1.KubernetesClusters_AVAILABLE,
	}
}

func unavailableField(availability mtcpv1.KubernetesClusters_Availability) *mtcpv1.KubernetesClusters {
	return &mtcpv1.KubernetesClusters{Availability: availability}
}

// A field whose structure is wrong drops the map (§7.11).
func TestCheckKubeClusters(t *testing.T) {
	t.Parallel()
	root := clusterRoot(t, testClusterName)
	if err := checkKubeClusters(clustersField([][]byte{root}, root)); err != nil {
		t.Fatalf("a valid field: %v", err)
	}
	for name, change := range map[string]func(*mtcpv1.KubernetesClusters){
		"unspecified": func(field *mtcpv1.KubernetesClusters) { field.Availability = 0 },
		"unknown":     func(field *mtcpv1.KubernetesClusters) { field.Availability = 9 },
		"clusters while unread": func(field *mtcpv1.KubernetesClusters) {
			field.Availability = mtcpv1.KubernetesClusters_UNREAD
		},
		"bad id":          func(field *mtcpv1.KubernetesClusters) { field.Clusters[0].ClusterId = "x" },
		"duplicate id":    func(field *mtcpv1.KubernetesClusters) { field.Clusters = append(field.Clusters, field.Clusters[0]) },
		"bad name":        func(field *mtcpv1.KubernetesClusters) { field.Clusters[0].Name = "Kinda" },
		"bad TLS name":    func(field *mtcpv1.KubernetesClusters) { field.Clusters[0].TlsServerName = "-x" },
		"bad fingerprint": func(field *mtcpv1.KubernetesClusters) { field.Clusters[0].RootFingerprints[0] = []byte{1} },
		"empty root":      func(field *mtcpv1.KubernetesClusters) { field.Roots = append(field.Roots, nil) },
	} {
		field := clustersField([][]byte{root}, root)
		change(field)
		if err := checkKubeClusters(field); !errors.Is(err, controlplane.ErrNetmapInvalid) {
			t.Errorf("%s: checkKubeClusters() = %v", name, err)
		}
	}
}

// A node trusts each root apart: a retiring root of another name (a
// rename) is left out, the cluster stays trusted; a missing DER leaves it
// incomplete; no root of its name, invalid; no CA yet, pending (§7.11).
func TestKubeClusterHoldTrust(t *testing.T) {
	t.Parallel()
	now := time.Now()
	current, renamed, missing := clusterRoot(t, testClusterName), clusterRoot(t, "old.kube.example"),
		clusterRoot(t, testClusterName)
	state := func(field *mtcpv1.KubernetesClusters) networkmap.KubernetesCluster {
		t.Helper()
		clusters := kubeClusterHold{}.apply(field, now).clusters(now)
		if len(clusters) != 1 {
			t.Fatalf("clusters = %+v", clusters)
		}
		return clusters[0]
	}
	if cluster := state(clustersField([][]byte{renamed, current}, renamed, current)); cluster.State !=
		networkmap.KubernetesClusterTrusted || cluster.Excluded != 1 || len(cluster.Roots) != 1 {
		t.Fatalf("after a rename: %+v", cluster)
	}
	if cluster := state(clustersField([][]byte{current, missing}, current)); cluster.State !=
		networkmap.KubernetesClusterIncomplete || len(cluster.Roots) != 1 {
		t.Fatalf("a root's DER missing: %+v", cluster)
	}
	if cluster := state(clustersField([][]byte{renamed}, renamed)); cluster.State !=
		networkmap.KubernetesClusterInvalid || len(cluster.Roots) != 0 {
		t.Fatalf("no root of its name: %+v", cluster)
	}
	pending := clustersField(nil)
	pending.Clusters[0].TlsServerName = ""
	if cluster := state(pending); cluster.State != networkmap.KubernetesClusterPending {
		t.Fatalf("no CA yet: %+v", cluster)
	}
	garbage := []byte("not a root")
	if cluster := state(clustersField([][]byte{garbage, current}, garbage, current)); cluster.State !=
		networkmap.KubernetesClusterTrusted || cluster.Excluded != 1 {
		t.Fatalf("a malformed root: %+v", cluster)
	}
}

// While not available the hold keeps its list and DER for 25 hours from the
// first such map; only an AVAILABLE list replaces it, and the pool keeps
// only DER the list names (§7.11).
func TestKubeClusterHoldWhileUnavailable(t *testing.T) {
	t.Parallel()
	start := time.Now()
	root, next := clusterRoot(t, testClusterName), clusterRoot(t, testClusterName)
	hold := kubeClusterHold{}.apply(clustersField([][]byte{root}, root), start)
	hold = hold.apply(unavailableField(mtcpv1.KubernetesClusters_UNREAD), start.Add(time.Hour))
	hold = hold.apply(unavailableField(mtcpv1.KubernetesClusters_RESTORE), start.Add(20*time.Hour))
	if clusters := hold.clusters(start.Add(25 * time.Hour)); clusters[0].State != networkmap.KubernetesClusterTrusted {
		t.Fatalf("within 25 hours of the first: %+v", clusters)
	}
	if clusters := hold.clusters(start.Add(26*time.Hour + time.Minute)); clusters[0].State !=
		networkmap.KubernetesClusterUnavailable || len(clusters[0].Roots) != 0 {
		t.Fatalf("past 25 hours of the first: %+v", clusters)
	}
	// AVAILABLE again: the clock clears; a delta adds only the new DER.
	hold = hold.apply(clustersField([][]byte{root, next}, next), start.Add(27*time.Hour))
	if !hold.unavailableSince.IsZero() || len(hold.pool) != 2 {
		t.Fatalf("hold = %+v", hold)
	}
	if clusters := hold.clusters(start.Add(60 * time.Hour)); clusters[0].State != networkmap.KubernetesClusterTrusted ||
		len(clusters[0].Roots) != 2 {
		t.Fatalf("both roots: %+v", clusters)
	}
	// The old root leaves the list: its DER goes.
	hold = hold.apply(clustersField([][]byte{next}), start.Add(61*time.Hour))
	if _, kept := hold.pool[[32]byte(fingerprintOf(root))]; kept || len(hold.pool) != 1 {
		t.Fatalf("pool keeps %d roots", len(hold.pool))
	}
	// DER no listed cluster names is not taken.
	stray := clusterRoot(t, testClusterName)
	if hold = hold.apply(clustersField([][]byte{next}, stray), start.Add(62*time.Hour)); len(hold.pool) != 1 {
		t.Fatalf("a stray root was taken: %d", len(hold.pool))
	}
}

// A session that negotiated kube.ca1 needs the field in every snapshot; a
// delta without it changes nothing; the hold outlives the session.
func TestMapStateKubeClusters(t *testing.T) {
	t.Parallel()
	root := clusterRoot(t, testClusterName)
	hold := &kubeClusterHold{}
	session := func() *mapState {
		state := newMapState(false)
		state.takesClusters, state.clustersNegotiated, state.kubeClusters = true, true, hold
		return state
	}
	snapshot := func(epoch uint64, field *mtcpv1.KubernetesClusters) *mtcpv1.MapSnapshot {
		return &mtcpv1.MapSnapshot{View: &mtcpv1.View{Epoch: epoch, Seq: 1}, Self: &mtcpv1.Device{DeviceId: "self"},
			KubernetesClusters: field}
	}
	state := session()
	if err := state.applySnapshot(snapshot(1, nil)); !errors.Is(err, controlplane.ErrNetmapInvalid) {
		t.Fatalf("a snapshot without the field: %v", err)
	}
	if err := state.applySnapshot(snapshot(1, clustersField([][]byte{root}, root))); err != nil {
		t.Fatal(err)
	}
	if err := state.applyDelta(&mtcpv1.MapDelta{View: &mtcpv1.View{Epoch: 1, Seq: 2}}); err != nil ||
		len(hold.list) != 1 {
		t.Fatalf("a delta without the field: %v, %d", err, len(hold.list))
	}
	// A new session that says UNREAD keeps what the last one held.
	next := session()
	if err := next.applySnapshot(snapshot(2, unavailableField(mtcpv1.KubernetesClusters_UNREAD))); err != nil ||
		len(hold.list) != 1 || hold.unavailableSince.IsZero() {
		t.Fatalf("UNREAD on a new session: %v, %+v", err, hold)
	}
	// A bad field changes nothing.
	bad := clustersField([][]byte{root})
	bad.Clusters[0].ClusterId = "bad"
	if err := next.applyDelta(&mtcpv1.MapDelta{View: &mtcpv1.View{Epoch: 2, Seq: 2}, KubernetesClusters: bad}); err == nil ||
		hold.unavailableSince.IsZero() {
		t.Fatalf("a bad delta: %v", err)
	}
}

// A snapshot that fails after a valid field leaves the hold as it was; a
// session that did not negotiate kube.ca1 ignores the field; only a node
// that is not a gateway declares it.
func TestKubeClustersOnlyWithAWholeMap(t *testing.T) {
	t.Parallel()
	root := clusterRoot(t, testClusterName)
	hold := &kubeClusterHold{}
	state := newMapState(false)
	state.takesClusters, state.clustersNegotiated, state.kubeClusters = true, true, hold
	duplicate := &mtcpv1.MapSnapshot{
		View: &mtcpv1.View{Epoch: 1, Seq: 1}, Self: &mtcpv1.Device{DeviceId: "self"},
		Peers:              []*mtcpv1.Device{{DeviceId: "peer"}, {DeviceId: "peer"}},
		KubernetesClusters: clustersField([][]byte{root}, root),
	}
	if err := state.applySnapshot(duplicate); err == nil || len(hold.list) != 0 {
		t.Fatalf("a failed snapshot: %v, %d clusters", err, len(hold.list))
	}
	ignoring := newMapState(false)
	ignoring.takesClusters, ignoring.kubeClusters = true, hold
	if err := ignoring.applySnapshot(&mtcpv1.MapSnapshot{View: &mtcpv1.View{Epoch: 1, Seq: 1},
		Self: &mtcpv1.Device{DeviceId: "self"}, KubernetesClusters: clustersField([][]byte{root}, root)}); err != nil ||
		len(hold.list) != 0 {
		t.Fatalf("not negotiated: %v, %d clusters", err, len(hold.list))
	}
	node := streamCapabilities(controlplane.NetmapOptions{}, false)
	gateway := streamCapabilities(controlplane.NetmapOptions{}, true)
	if !slices.Contains(node, kubeClusterCapability) || slices.Contains(gateway, kubeClusterCapability) {
		t.Fatalf("capabilities: node %v, gateway %v", node, gateway)
	}
}

// The 25-hour clock is wall time; a DNS name the node cannot use is cleared,
// not a reason to drop the map.
func TestKubeClusterHoldWallClockAndNames(t *testing.T) {
	t.Parallel()
	root := clusterRoot(t, testClusterName)
	start := time.Now()
	hold := kubeClusterHold{}.apply(clustersField([][]byte{root}, root), start)
	hold = hold.apply(unavailableField(mtcpv1.KubernetesClusters_UNREAD), start)
	if hold.unavailableSince != hold.unavailableSince.Round(0) {
		t.Fatal("the clock keeps a monotonic reading")
	}
	clusters := hold.clusters(start.Round(0).Add(kubeClustersHeldLong))
	if clusters[0].State != networkmap.KubernetesClusterTrusted ||
		!clusters[0].HeldUntil.Equal(start.Round(0).Add(kubeClustersHeldLong)) {
		t.Fatalf("at the limit: %+v", clusters[0])
	}
	field := clustersField([][]byte{root}, root)
	field.Clusters[0].DnsName = "Bad Name"
	if err := checkKubeClusters(field); err != nil {
		t.Fatalf("a bad DNS name dropped the map: %v", err)
	}
	if cleared := (kubeClusterHold{}).apply(field, start).clusters(start); cleared[0].DNSName != "" ||
		cleared[0].State != networkmap.KubernetesClusterTrusted {
		t.Fatalf("a bad DNS name: %+v", cleared[0])
	}
}
