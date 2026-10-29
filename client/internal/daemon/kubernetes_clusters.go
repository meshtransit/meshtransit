package daemon

import (
	"encoding/hex"
	"slices"
	"time"

	"meshtransit.net/client/internal/networkmap"
)

// KubernetesClusterView is one cluster a node may reach, for its status:
// names, how far the node trusts the cluster's gateways, and its roots by
// fingerprint (never their DER).
type KubernetesClusterView struct {
	ID, Name, DNSName, TLSServerName string
	State                            string
	RootFingerprints                 []string
	// RootsExcluded counts roots left out: not a root Core makes, or one
	// permitting another name (the retiring root after a rename).
	RootsExcluded int
	// HeldUntil is when what the node holds stops counting while Core
	// cannot say; zero otherwise.
	HeldUntil time.Time
	// CAFile, CAFileState and CAFileReason are the cluster's CA file (K1e
	// design §3.4); empty without one.
	CAFile, CAFileState, CAFileReason string
}

// kubernetesClustersAt returns views as of now: one held past HeldUntil
// is unavailable, though no map came since (review d3 M2).
func kubernetesClustersAt(views []KubernetesClusterView, now time.Time) []KubernetesClusterView {
	if views == nil {
		return nil
	}
	current := slices.Clone(views)
	for index := range current {
		if !current[index].HeldUntil.IsZero() && now.Round(0).After(current[index].HeldUntil) {
			current[index].State = string(networkmap.KubernetesClusterUnavailable)
		}
	}
	return current
}

// kubernetesClusterViews is the status of a map's clusters; nil when the
// node does not take them.
func kubernetesClusterViews(clusters []networkmap.KubernetesCluster) []KubernetesClusterView {
	if clusters == nil {
		return nil
	}
	views := make([]KubernetesClusterView, 0, len(clusters))
	for _, cluster := range clusters {
		view := KubernetesClusterView{
			ID: cluster.ID, Name: cluster.Name, DNSName: cluster.DNSName, TLSServerName: cluster.TLSServerName,
			State: string(cluster.State), RootsExcluded: cluster.Excluded, HeldUntil: cluster.HeldUntil,
		}
		for _, fingerprint := range cluster.RootFingerprints {
			view.RootFingerprints = append(view.RootFingerprints, hex.EncodeToString(fingerprint[:]))
		}
		views = append(views, view)
	}
	return views
}
