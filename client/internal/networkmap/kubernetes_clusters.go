package networkmap

import (
	"errors"
	"slices"
	"time"
)

// KubernetesClusterState says whether a node may trust a cluster's
// gateways (mtcp-v1 §7.11, K1a4d design §6).
type KubernetesClusterState string

const (
	// KubernetesClusterPending: the cluster has no CA yet.
	KubernetesClusterPending KubernetesClusterState = "pending"
	// KubernetesClusterTrusted: every root's DER is held and at least one
	// usable root carries the cluster's TLS name.
	KubernetesClusterTrusted KubernetesClusterState = "trusted"
	// KubernetesClusterIncomplete: a root's DER is not held yet.
	KubernetesClusterIncomplete KubernetesClusterState = "incomplete"
	// KubernetesClusterInvalid: no usable root carries the TLS name.
	KubernetesClusterInvalid KubernetesClusterState = "invalid"
	// KubernetesClusterUnavailable: Core could not say for longer than the
	// node keeps what it held (25 hours), or since the node started.
	KubernetesClusterUnavailable KubernetesClusterState = "unavailable"
)

// KubernetesCluster is one cluster a node may reach and what it trusts the
// cluster's gateways by: Roots are the DER of the usable roots carrying
// TLSServerName, RootFingerprints every root the map names, Excluded how
// many of those were left out (not a root Core makes, or another name).
type KubernetesCluster struct {
	ID, Name, DNSName, TLSServerName string
	State                            KubernetesClusterState
	RootFingerprints                 [][32]byte
	Roots                            [][]byte
	Excluded                         int
	// HeldUntil, set while Core cannot say (§7.11), is when the node stops
	// trusting what it holds: past it a user of the cluster treats it as
	// unavailable, whenever the map was built (review d3 M2).
	HeldUntil time.Time
}

// CheckKubernetesClusters reports known states and usable roots only where
// a cluster is trusted or incomplete.
func CheckKubernetesClusters(clusters []KubernetesCluster) error {
	for _, cluster := range clusters {
		switch cluster.State {
		case KubernetesClusterTrusted, KubernetesClusterIncomplete:
		case KubernetesClusterPending, KubernetesClusterInvalid, KubernetesClusterUnavailable:
			if len(cluster.Roots) != 0 {
				return errors.New("networkmap: roots of a cluster that cannot be trusted")
			}
		default:
			return errors.New("networkmap: unknown Kubernetes cluster state")
		}
		if cluster.ID == "" || cluster.Name == "" {
			return errors.New("networkmap: Kubernetes cluster without an ID or name")
		}
	}
	return nil
}

func cloneKubernetesClusters(clusters []KubernetesCluster) []KubernetesCluster {
	if clusters == nil {
		return nil
	}
	cloned := make([]KubernetesCluster, len(clusters))
	for index, cluster := range clusters {
		cluster.RootFingerprints = slices.Clone(cluster.RootFingerprints)
		cluster.Roots = make([][]byte, len(clusters[index].Roots))
		for root, der := range clusters[index].Roots {
			cluster.Roots[root] = slices.Clone(der)
		}
		cloned[index] = cluster
	}
	return cloned
}
