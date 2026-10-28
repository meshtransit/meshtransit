package compilation

import (
	"context"
	"errors"
	"slices"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
)

// clusterGroups maps the scope's Kubernetes clusters to their own Device
// Groups and back, for one compilation.
type clusterGroups struct {
	byCluster map[kubecluster.ID]devicegroup.ID
	byGroup   map[devicegroup.ID]kubecluster.ID
}

// Prepare makes the own Device Group of each Kubernetes cluster the request
// names that has none yet. Making one advances the Network revision, so a
// caller that brackets Compile with authority reads (simulation) prepares
// first; Compile then ensures again, which finds each group and writes
// nothing (one ensure transaction per named cluster, then one read). A request
// naming no cluster asks for nothing.
func (service *Service) Prepare(ctx context.Context, session accountsession.Session, request Request) error {
	if ctx == nil || service == nil || !session.IsValid() || !request.IsValid() {
		return ErrInvalidRequest
	}
	named, _ := namedKubernetesClusters(request)
	if len(named) == 0 {
		return nil
	}
	_, err := service.lookupKubernetesClusters(ctx, session, request, named)
	return err
}

// namedKubernetesClusters returns the clusters the request's rules name,
// once each, and whether any rule names a Device Group.
func namedKubernetesClusters(request Request) ([]kubecluster.ID, bool) {
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
	return named, groups
}

// resolveKubernetesClusters reads the clusters' groups when a rule names a
// cluster or any Device Group, making the group of each named cluster first
// (nothing when Prepare made them). Rules that name neither ask for nothing.
func (service *Service) resolveKubernetesClusters(ctx context.Context, session accountsession.Session,
	request Request) (clusterGroups, error) {
	named, groups := namedKubernetesClusters(request)
	if len(named) == 0 && (!groups || service.clusters == nil) {
		return clusterGroups{}, nil
	}
	return service.lookupKubernetesClusters(ctx, session, request, named)
}

func (service *Service) lookupKubernetesClusters(ctx context.Context, session accountsession.Session,
	request Request, named []kubecluster.ID) (clusterGroups, error) {
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

// keptKubernetesGroups returns how a group rule gets its Kubernetes groups:
// those it names, else those the replaced release (read once, when first
// needed) holds for the same rule from the same source to the same cluster,
// else none for a rule that had none there. A new rule to a cluster, or one
// now from another source or to another cluster, without groups is refused:
// its groups grant access somewhere else. Without a reader, only those it
// names.
func (service *Service) keptKubernetesGroups(ctx context.Context, session accountsession.Session,
	request Request) func(RuleIntent, kubecluster.ID) ([]string, error) {
	var base map[policy.RuleID]ReleasedClusterRule
	read := false
	return func(intent RuleIntent, cluster kubecluster.ID) ([]string, error) {
		if intent.kubernetesGroups != nil || !cluster.IsValid() || service.ruleGroups == nil {
			return intent.KubernetesGroups(), nil
		}
		if !read {
			// The first release (revision 2) replaces none: every rule to a
			// cluster is new.
			if replaced := request.revision - 1; replaced > 1 {
				held, err := service.ruleGroups.ReadPolicyKubernetesGroups(ctx, session, request.scope, replaced)
				if err != nil {
					return nil, err
				}
				base = held
			}
			read = true
		}
		released, held := base[intent.id]
		if !held {
			return nil, ErrKubernetesGroupsRequired
		}
		if released.Groups == nil {
			return nil, nil // released before K1a3: it grants no group
		}
		kind, source := intent.sourceSide()
		if released.Cluster != cluster || released.SourceKind != kind || released.SourceID != source {
			return nil, ErrKubernetesGroupsRequired
		}
		return slices.Clone(released.Groups), nil
	}
}

// sourceSide names the intent's source as a release side.
func (intent RuleIntent) sourceSide() (publication.SideKind, publicid.ID) {
	switch {
	case intent.sourceGroupID.IsValid():
		return publication.SideDeviceGroup, publicid.ID(intent.sourceGroupID)
	case intent.sourceIdentityGroupID.IsValid():
		return publication.SideIdentityGroup, publicid.ID(intent.sourceIdentityGroupID)
	case intent.sourceTagID.IsValid():
		return publication.SideDeviceTag, publicid.ID(intent.sourceTagID)
	default:
		return publication.SideDevice, publicid.ID(intent.sourceNodeID)
	}
}
