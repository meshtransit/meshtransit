package mapsession

import (
	"crypto/sha256"
	"maps"
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/kubecluster"
)

// KubernetesAvailability says whether a Network's clusters' roots were read
// (K1a4d design §2.2). The zero value is never authoritative.
type KubernetesAvailability uint8

const (
	// KubernetesTrustUnread: not read, or the answer could not be trusted.
	KubernetesTrustUnread KubernetesAvailability = iota
	// KubernetesTrustAvailable: the clusters are the Network's, complete.
	KubernetesTrustAvailable
	// KubernetesTrustRestore: withheld while a database restore is
	// suspected.
	KubernetesTrustRestore
)

// MaximumKubernetesTrustRoots bounds the roots one cluster may name: next,
// active and retiring.
const MaximumKubernetesTrustRoots = 3

// KubernetesClusterTrust is what a client trusts one cluster's gateways by:
// the name their certificates carry and the roots, by fingerprint, in id
// order. A cluster without a CA yet has neither; a client trusts none of a
// cluster's roots without a TLS name.
type KubernetesClusterTrust struct {
	ID      kubecluster.ID
	Name    kubecluster.Name
	TLSName string
	Roots   [][32]byte
}

// KubernetesTrust is a Network's clusters' trust as the inventory read it:
// whether it was read, each active cluster's by name, and the DER of the
// roots it holds, by fingerprint (DER never changes for a fingerprint). It
// is immutable once built.
type KubernetesTrust struct {
	availability KubernetesAvailability
	clusters     map[kubecluster.Name]KubernetesClusterTrust
	roots        map[[32]byte][]byte
	// digest identifies the clusters and which of their roots are held,
	// so maps compare trusts in O(1) (every Device of a Network holds the
	// same one).
	digest [32]byte
}

// NewKubernetesTrust validates an available trust: distinct IDs, at most
// MaximumKubernetesTrustRoots distinct roots each, no TLS name without a
// root, and DER only of named roots, each its fingerprint's.
// The slices are kept, never written; callers must not change them.
func NewKubernetesTrust(clusters []KubernetesClusterTrust, roots map[[32]byte][]byte) (KubernetesTrust, bool) {
	named := map[[32]byte]struct{}{}
	byName := make(map[kubecluster.Name]KubernetesClusterTrust, len(clusters))
	ids := make(map[kubecluster.ID]struct{}, len(clusters))
	for _, cluster := range clusters {
		_, duplicateName := byName[cluster.Name]
		_, duplicateID := ids[cluster.ID]
		if duplicateName || duplicateID || !cluster.ID.IsValid() || cluster.Name.String() == "" ||
			len(cluster.Roots) > MaximumKubernetesTrustRoots || cluster.TLSName != "" && len(cluster.Roots) == 0 {
			return KubernetesTrust{}, false
		}
		for index, root := range cluster.Roots {
			if slices.Contains(cluster.Roots[:index], root) {
				return KubernetesTrust{}, false
			}
			named[root] = struct{}{}
		}
		byName[cluster.Name], ids[cluster.ID] = cluster, struct{}{}
	}
	for fingerprint, der := range roots {
		if _, ok := named[fingerprint]; !ok || sha256.Sum256(der) != fingerprint {
			return KubernetesTrust{}, false
		}
	}
	trust := KubernetesTrust{availability: KubernetesTrustAvailable, clusters: byName, roots: maps.Clone(roots)}
	trust.digest = trust.computeDigest()
	return trust, true
}

// computeDigest hashes the clusters in name order: ID, name, TLS name and
// each root with whether its DER is held.
func (trust KubernetesTrust) computeDigest() [32]byte {
	hash := sha256.New()
	for _, name := range slices.Sorted(maps.Keys(trust.clusters)) {
		cluster := trust.clusters[name]
		id := cluster.ID.String()
		for _, field := range []string{id, string(name), cluster.TLSName} {
			hash.Write([]byte{byte(len(field))})
			hash.Write([]byte(field))
		}
		hash.Write([]byte{byte(len(cluster.Roots))})
		for _, root := range cluster.Roots {
			held := byte(0)
			if _, ok := trust.roots[root]; ok {
				held = 1
			}
			hash.Write(root[:])
			hash.Write([]byte{held})
		}
	}
	return [32]byte(hash.Sum(nil))
}

// Equal reports whether two trusts say the same: their availability and,
// when available, the same clusters, roots and held DER.
func (trust KubernetesTrust) Equal(other KubernetesTrust) bool {
	return trust.availability == other.availability && trust.digest == other.digest
}

// EmptyKubernetesTrust is the available trust of a Network without a
// cluster gateway: no client's map names a cluster.
func EmptyKubernetesTrust() KubernetesTrust {
	trust := KubernetesTrust{availability: KubernetesTrustAvailable}
	trust.digest = trust.computeDigest()
	return trust
}

// UnavailableKubernetesTrust is a trust that was not read, for reason
// (KubernetesTrustUnread or KubernetesTrustRestore).
func UnavailableKubernetesTrust(reason KubernetesAvailability) KubernetesTrust {
	if reason != KubernetesTrustRestore {
		reason = KubernetesTrustUnread
	}
	return KubernetesTrust{availability: reason}
}

// Availability says whether the trust was read.
func (trust KubernetesTrust) Availability() KubernetesAvailability { return trust.availability }

// Cluster returns one active cluster's trust by name.
func (trust KubernetesTrust) Cluster(name kubecluster.Name) (KubernetesClusterTrust, bool) {
	cluster, ok := trust.clusters[name]
	return cluster, ok
}

// Root returns a root's DER by fingerprint, when the inventory holds it.
func (trust KubernetesTrust) Root(fingerprint [32]byte) ([]byte, bool) {
	der, ok := trust.roots[fingerprint]
	return der, ok
}

// Len returns how many active clusters the trust names.
func (trust KubernetesTrust) Len() int { return len(trust.clusters) }

// MaximumKubernetesClientClusters bounds the clusters one map names
// (§7.11); the newest past it are left out (IDs are UUIDv7).
const MaximumKubernetesClientClusters = 1000

// KubernetesClientCluster is one cluster a node's map names: its trust and
// its name in the Network's zone (empty when the zone is unknown).
type KubernetesClientCluster struct {
	KubernetesClusterTrust
	DNSName string
}

// KubernetesClusters returns the clusters a node's map names (§7.11): each
// with a gateway replica among its authorized peers of its own Network, the
// same that DNS names, in ID order, at most MaximumKubernetesClientClusters;
// dropped counts those left out. Only an available trust names any.
func (snapshot Snapshot) KubernetesClusters(suffix dnsname.Suffix) (clusters []KubernetesClientCluster, dropped int) {
	trust := snapshot.kubernetes.trust
	if trust.availability != KubernetesTrustAvailable || len(trust.clusters) == 0 {
		return nil, 0 // the common case: no peer is walked
	}
	zone, named := snapshot.zone(suffix)
	seen := map[kubecluster.Name]struct{}{}
	for _, peer := range snapshot.authorized {
		name, replica := peer.KubernetesCluster()
		if !replica || peer.scope != snapshot.scope {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		cluster, ok := trust.clusters[name]
		if !ok {
			continue // not an active cluster as the trust was read
		}
		client := KubernetesClientCluster{KubernetesClusterTrust: cluster}
		if named {
			client.DNSName, _ = zone.KubernetesClusterName(name.String())
		}
		clusters = append(clusters, client)
	}
	slices.SortFunc(clusters, func(first, second KubernetesClientCluster) int {
		return strings.Compare(first.ID.String(), second.ID.String())
	})
	if len(clusters) > MaximumKubernetesClientClusters {
		dropped = len(clusters) - MaximumKubernetesClientClusters
		clusters = clusters[:MaximumKubernetesClientClusters]
	}
	return clusters, dropped
}
