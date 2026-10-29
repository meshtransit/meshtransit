package mapsession

import (
	"crypto/sha256"
	"maps"
	"slices"

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
	return KubernetesTrust{availability: KubernetesTrustAvailable, clusters: byName, roots: maps.Clone(roots)}, true
}

// EmptyKubernetesTrust is the available trust of a Network without a
// cluster gateway: no client's map names a cluster.
func EmptyKubernetesTrust() KubernetesTrust {
	return KubernetesTrust{availability: KubernetesTrustAvailable}
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
