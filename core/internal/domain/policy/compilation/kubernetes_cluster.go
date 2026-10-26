package compilation

import (
	"context"
	"errors"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/policy"
)

// clusterGroups maps the scope's Kubernetes clusters to their own Device
// Groups and back, for one compilation.
type clusterGroups struct {
	byCluster map[kubecluster.ID]devicegroup.ID
	byGroup   map[devicegroup.ID]kubecluster.ID
}

// resolveKubernetesClusters reads the clusters' groups when a rule names a
// cluster or any Device Group, making the group of each named cluster first.
// Rules that name neither ask for nothing.
func (service *Service) resolveKubernetesClusters(ctx context.Context, session accountsession.Session,
	request Request) (clusterGroups, error) {
	var named []kubecluster.ID
	seen := make(map[kubecluster.ID]struct{})
	groups := false
	for _, intent := range request.rules {
		groups = groups || intent.sourceGroupID.IsValid() || intent.destinationDeviceGroupID.IsValid()
		if cluster := intent.destinationCluster; cluster.IsValid() {
			if _, duplicate := seen[cluster]; !duplicate {
				seen[cluster] = struct{}{}
				named = append(named, cluster)
			}
		}
	}
	if len(named) == 0 && (!groups || service.clusters == nil) {
		return clusterGroups{}, nil
	}
	if service.clusters == nil || len(named) > kubecluster.MaximumClustersPerNetwork {
		return clusterGroups{}, ErrInvalidRequest
	}
	resolved, err := service.clusters.ResolvePolicyKubernetesClusters(ctx, session, request.scope, named)
	if err != nil {
		return clusterGroups{}, classifyKubernetesClusterResolutionError(err)
	}
	result := clusterGroups{
		byCluster: make(map[kubecluster.ID]devicegroup.ID, len(resolved)),
		byGroup:   make(map[devicegroup.ID]kubecluster.ID, len(resolved)),
	}
	for _, group := range resolved {
		_, clusterSeen := result.byCluster[group.ClusterID]
		_, groupSeen := result.byGroup[group.GroupID]
		if !group.IsValid() || clusterSeen || groupSeen {
			return clusterGroups{}, ErrUnavailable
		}
		result.byCluster[group.ClusterID], result.byGroup[group.GroupID] = group.GroupID, group.ClusterID
	}
	for _, cluster := range named {
		if _, found := result.byCluster[cluster]; !found {
			return clusterGroups{}, ErrKubernetesClusterUnavailable
		}
	}
	return result, nil
}

// destination returns the group a rule reaches and the cluster it is the
// own group of, if any. A cluster's group is a destination only, on TCP 443.
func (groups clusterGroups) destination(intent RuleIntent) (devicegroup.ID, kubecluster.ID, error) {
	if _, cluster := groups.byGroup[intent.sourceGroupID]; cluster {
		return devicegroup.ID{}, kubecluster.ID{}, ErrInvalidRequest
	}
	group, cluster := intent.destinationDeviceGroupID, intent.destinationCluster
	if cluster.IsValid() {
		group = groups.byCluster[cluster]
	} else if owner, found := groups.byGroup[group]; found {
		cluster = owner
	}
	ports, _ := policy.CanonicalTraffic(intent.protocol, intent.destinationPortRanges)
	if cluster.IsValid() && (!group.IsValid() || !policy.IsKubernetesTraffic(intent.protocol, ports)) {
		return devicegroup.ID{}, kubecluster.ID{}, ErrInvalidRequest
	}
	return group, cluster, nil
}

func classifyKubernetesClusterResolutionError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return errors.Join(ErrUnavailable, err)
	case errors.Is(err, kubecluster.ErrForbidden):
		return errors.Join(ErrForbidden, err)
	case errors.Is(err, kubecluster.ErrNotFound):
		return errors.Join(ErrKubernetesClusterUnavailable, err)
	default:
		return errors.Join(ErrUnavailable, err)
	}
}
