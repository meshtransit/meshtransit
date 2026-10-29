package mtcpclient

import (
	"crypto/sha256"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/kubetrust"
)

// kubeClusterCapability is kube.ca1: the node takes the Kubernetes clusters
// it may reach and their roots in its map (mtcp-v1 §7.11, K1a4d).
const kubeClusterCapability = "kube.ca1"

// Bounds of the clusters field a node takes, well above Core's (1,000
// clusters, 2 MiB of DER a message) so Core may raise its own without a
// node dropping maps (K1a4d design §6, review v2 M3).
const (
	maxKubeClusters      = 10_000
	maxKubeRoots         = 30_000
	maxKubeRootBytes     = 8 << 20
	maxKubeClusterRoots  = 16
	maxKubeRootSize      = 16 << 10 // Core stores at most 8 KiB
	maxKubePoolBytes     = 32 << 20 // above Core's worst case, 1,000 clusters × 3 roots × 8 KiB
	kubeClustersHeldLong = 25 * time.Hour
)

// kubeClusterHold is what a node holds of its clusters across sessions
// (§7.11): the last authoritative list, the roots' DER by fingerprint, and
// when the first map that was not AVAILABLE came (zero: none since the last
// AVAILABLE one). It lives with the client, by Device, not the session or
// the stream: a reconnect neither clears it nor restarts the clock.
type kubeClusterHold struct {
	list []*mtcpv1.KubernetesCluster
	pool map[[32]byte][]byte
	// verdicts are each held root's check for the TLS name a cluster names
	// it with, made once when the list arrives (review d3 M3).
	verdicts map[kubeRootUse]bool
	// unavailableSince is wall time (no monotonic reading): a host asleep
	// still ages the clock (review d3 M1).
	unavailableSince time.Time
}

// kubeRootUse is a root as a cluster names it.
type kubeRootUse struct {
	fingerprint [32]byte
	name        string
}

// checkKubeClusters checks a field's structure: anything wrong drops the
// map, as for any other field; a root that is not one Core makes only
// leaves that root out later.
func checkKubeClusters(field *mtcpv1.KubernetesClusters) error {
	invalid := func(what string) error {
		return fmt.Errorf("%w: Kubernetes clusters: %s", controlplane.ErrNetmapInvalid, what)
	}
	switch field.GetAvailability() {
	case mtcpv1.KubernetesClusters_AVAILABLE:
	case mtcpv1.KubernetesClusters_RESTORE, mtcpv1.KubernetesClusters_UNREAD:
		if len(field.GetClusters()) != 0 || len(field.GetRoots()) != 0 {
			return invalid("clusters while not available")
		}
	default:
		return invalid("no availability")
	}
	if len(field.GetClusters()) > maxKubeClusters || len(field.GetRoots()) > maxKubeRoots {
		return invalid("over its bounds")
	}
	size := 0
	for _, der := range field.GetRoots() {
		if size += len(der); len(der) == 0 || len(der) > maxKubeRootSize || size > maxKubeRootBytes {
			return invalid("roots over their bounds")
		}
	}
	previous := ""
	for _, cluster := range field.GetClusters() {
		id := cluster.GetClusterId()
		if !validUUID(id) || id <= previous {
			return invalid("cluster IDs not unique and in order")
		}
		previous = id
		// A DNS name the node cannot use is cleared when applied, not a
		// reason to drop the map (review d3 L6).
		if !kubetrust.ValidName(cluster.GetName()) || len(cluster.GetName()) > 63 ||
			cluster.GetTlsServerName() != "" && !kubetrust.ValidName(cluster.GetTlsServerName()) {
			return invalid("a cluster name")
		}
		if len(cluster.GetRootFingerprints()) > maxKubeClusterRoots {
			return invalid("too many roots for a cluster")
		}
		for _, fingerprint := range cluster.GetRootFingerprints() {
			if len(fingerprint) != sha256.Size {
				return invalid("a root fingerprint")
			}
		}
	}
	return nil
}

// validUUID accepts a canonical lowercase UUID.
func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range []byte(value) {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
				return false
			}
		}
	}
	return true
}

// apply returns the hold after a checked field at now. An AVAILABLE list
// replaces the list; the pool takes the field's DER that the list names and
// drops what it no longer names. Otherwise nothing changes but the clock,
// which starts at the first such map (§7.11).
func (hold kubeClusterHold) apply(field *mtcpv1.KubernetesClusters, now time.Time) kubeClusterHold {
	if field.GetAvailability() != mtcpv1.KubernetesClusters_AVAILABLE {
		if hold.unavailableSince.IsZero() {
			hold.unavailableSince = now.Round(0)
		}
		return hold
	}
	named := map[[32]byte]struct{}{}
	for _, cluster := range field.GetClusters() {
		for _, fingerprint := range cluster.GetRootFingerprints() {
			named[[32]byte(fingerprint)] = struct{}{}
		}
	}
	pool := make(map[[32]byte][]byte, len(named))
	for fingerprint, der := range hold.pool {
		if _, ok := named[fingerprint]; ok {
			pool[fingerprint] = der
		}
	}
	size := 0
	for _, der := range pool {
		size += len(der)
	}
	for _, der := range field.GetRoots() {
		fingerprint := sha256.Sum256(der)
		if _, ok := named[fingerprint]; !ok {
			continue
		}
		if _, held := pool[fingerprint]; !held && size+len(der) <= maxKubePoolBytes {
			pool[fingerprint], size = der, size+len(der)
		}
	}
	list := make([]*mtcpv1.KubernetesCluster, 0, len(field.GetClusters()))
	verdicts := map[kubeRootUse]bool{}
	for _, cluster := range field.GetClusters() {
		if cluster.GetDnsName() != "" && !kubetrust.ValidName(cluster.GetDnsName()) {
			cleared, _ := proto.Clone(cluster).(*mtcpv1.KubernetesCluster)
			cleared.DnsName = ""
			cluster = cleared
		}
		list = append(list, cluster)
		for _, fingerprint := range cluster.GetRootFingerprints() {
			use := kubeRootUse{fingerprint: [32]byte(fingerprint), name: cluster.GetTlsServerName()}
			der, held := pool[use.fingerprint]
			if _, checked := verdicts[use]; checked || !held {
				continue
			}
			usable, known := hold.verdicts[use]
			if !known {
				_, err := kubetrust.CheckRoot(der, use.name)
				usable = err == nil
			}
			verdicts[use] = usable
		}
	}
	return kubeClusterHold{list: list, pool: pool, verdicts: verdicts}
}

// clusters converts the hold at now: each cluster's state and usable roots;
// past kubeClustersHeldLong without an AVAILABLE map, every cluster is
// unavailable.
func (hold kubeClusterHold) clusters(now time.Time) []networkmap.KubernetesCluster {
	var heldUntil time.Time
	if !hold.unavailableSince.IsZero() {
		heldUntil = hold.unavailableSince.Add(kubeClustersHeldLong)
	}
	expired := !heldUntil.IsZero() && now.Round(0).After(heldUntil)
	clusters := make([]networkmap.KubernetesCluster, 0, len(hold.list))
	for _, entry := range hold.list {
		cluster := networkmap.KubernetesCluster{
			ID: entry.GetClusterId(), Name: entry.GetName(), DNSName: entry.GetDnsName(),
			TLSServerName: entry.GetTlsServerName(), HeldUntil: heldUntil,
		}
		for _, fingerprint := range entry.GetRootFingerprints() {
			cluster.RootFingerprints = append(cluster.RootFingerprints, [32]byte(fingerprint))
		}
		cluster.State, cluster.Roots, cluster.Excluded = hold.trust(cluster, expired)
		clusters = append(clusters, cluster)
	}
	return clusters
}

// trust is one cluster's state and usable roots (K1a4d design §6): each
// root checked apart, one that is not a root Core makes or permits another
// name left out.
func (hold kubeClusterHold) trust(cluster networkmap.KubernetesCluster, expired bool) (
	networkmap.KubernetesClusterState, [][]byte, int,
) {
	if expired {
		return networkmap.KubernetesClusterUnavailable, nil, 0
	}
	if len(cluster.RootFingerprints) == 0 {
		return networkmap.KubernetesClusterPending, nil, 0
	}
	var usable [][]byte
	missing, excluded := 0, 0
	for _, fingerprint := range cluster.RootFingerprints {
		der, held := hold.pool[fingerprint]
		if !held {
			missing++
			continue
		}
		if !hold.verdicts[kubeRootUse{fingerprint: fingerprint, name: cluster.TLSServerName}] {
			excluded++
			continue
		}
		usable = append(usable, der)
	}
	switch {
	case missing > 0:
		return networkmap.KubernetesClusterIncomplete, usable, excluded
	case len(usable) > 0:
		return networkmap.KubernetesClusterTrusted, usable, excluded
	default:
		return networkmap.KubernetesClusterInvalid, nil, excluded
	}
}
