package compilation

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/resource/catalog"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/internal/domain/site"
)

// DestinationResolver returns one snapshot-consistent active Resource and
// Resource Group set, including every exact group member Resource.
type DestinationResolver interface {
	ResolvePolicyDestinations(
		context.Context,
		accountsession.Session,
		network.Scope,
		[]resource.ID,
		[]resource.GroupID,
	) ([]catalog.Resource, []catalog.Group, error)
}

// ImportedDestinationResolver returns active, exact-consumer-scope bilateral authority.
type ImportedDestinationResolver interface {
	ResolveImportedPolicyDestinations(
		context.Context,
		accountsession.Session,
		network.Scope,
		[]sharing.ImportedResourceID,
	) ([]sharing.PolicyDestination, error)
}

// ExitPoolResolver returns the active Exit Pools of the scope with the given
// IDs, as the reader may see them. A missing pool is absent from the result.
type ExitPoolResolver interface {
	ResolvePolicyExitPools(context.Context, accountsession.Session, network.Scope, []exitpool.ID) ([]exitpool.Pool, error)
}

// KubernetesClusterResolver returns the policy groups of the scope's active
// Kubernetes clusters, as the reader may see them, after making the group of
// each given cluster that has none yet. A cluster that is not active in the
// scope is absent from the result.
type KubernetesClusterResolver interface {
	ResolvePolicyKubernetesClusters(context.Context, accountsession.Session, network.Scope,
		[]kubecluster.ID) ([]kubecluster.PolicyGroup, error)
}

// ReleasedClusterRule is a rule to a Kubernetes cluster as a release holds
// it: the cluster, the source, and the Kubernetes groups, nil for a rule
// released before K1a3 (its traffic is always TCP 443).
type ReleasedClusterRule struct {
	Cluster    kubecluster.ID
	SourceKind publication.SideKind
	SourceID   publicid.ID
	Groups     []string
}

// KubernetesRuleGroupReader returns the rules to Kubernetes clusters of the
// scope's release at a policy revision (K1a3).
type KubernetesRuleGroupReader interface {
	ReadPolicyKubernetesGroups(context.Context, accountsession.Session, network.Scope,
		int64) (map[policy.RuleID]ReleasedClusterRule, error)
}

// SiteResolver returns the active Sites of the scope with the given IDs, as
// the reader may see them. A missing Site is absent from the result.
type SiteResolver interface {
	ResolvePolicySites(context.Context, accountsession.Session, network.Scope, []site.ID) ([]site.Site, error)
}

var (
	// ErrSiteRoutesDisabled reports a Site destination on a deployment that
	// does not route subnets.
	ErrSiteRoutesDisabled = errors.New("policy compilation: subnet routes are disabled")
	// ErrRouteOverlap reports rules that grant overlapping prefixes of
	// different Sites.
	ErrRouteOverlap = publication.ErrRouteOverlap
	// ErrOutsideSite reports a rule prefix that is not inside its Site.
	ErrOutsideSite = errors.New("policy compilation: prefix outside the Site")
	// ErrRoutePrefixLimit reports rules to Sites that grant more than
	// publication.MaximumGrantedRoutePrefixes prefixes in all.
	ErrRoutePrefixLimit = publication.ErrRoutePrefixLimit
	// ErrExitPoolsDisabled reports an Exit Pool destination on a compiler
	// without Exit Pools.
	ErrExitPoolsDisabled = errors.New("policy compilation: Exit Pools are disabled")
	// ErrKubernetesClusterUnavailable reports a rule to a Kubernetes cluster
	// that is not an active cluster of the scope.
	ErrKubernetesClusterUnavailable = errors.New("policy compilation: Kubernetes cluster unavailable")
	// ErrKubernetesGroupsRequired reports a new rule to a Kubernetes cluster
	// that names no Kubernetes group.
	ErrKubernetesGroupsRequired = errors.New("policy compilation: a new rule to a Kubernetes cluster needs groups")
)

// Service compiles typed Device, Resource, and Resource Group destinations.
type Service struct {
	destinations DestinationResolver
	imported     ImportedDestinationResolver
	sites        SiteResolver
	exitPools    ExitPoolResolver
	clusters     KubernetesClusterResolver
	ruleGroups   KubernetesRuleGroupReader
}

// WithKubernetesRuleGroups returns a compiler that keeps, for a rule to a
// cluster sent without groups, the groups it has in the release the request
// replaces, and refuses a new one without groups. Without it a rule keeps
// only the groups it names, and the database refuses one that would lose
// some.
func (service *Service) WithKubernetesRuleGroups(reader KubernetesRuleGroupReader) (*Service, error) {
	if service == nil || reader == nil {
		return nil, ErrInvalidRequest
	}
	extended := *service
	extended.ruleGroups = reader
	return &extended, nil
}

// WithKubernetesClusters returns a compiler that also compiles rules to
// Kubernetes clusters and names a rule to a cluster's own group as a rule to
// the cluster. Without it, a rule to a cluster is refused (ErrInvalidRequest);
// the database still refuses a cluster's group used any other way.
func (service *Service) WithKubernetesClusters(clusters KubernetesClusterResolver) (*Service, error) {
	if service == nil || clusters == nil {
		return nil, ErrInvalidRequest
	}
	extended := *service
	extended.clusters = clusters
	return &extended, nil
}

// WithExitPools returns a compiler that also compiles Exit Pool
// destinations. Without it, a rule whose destination is an Exit Pool is
// refused (ErrExitPoolsDisabled).
func (service *Service) WithExitPools(pools ExitPoolResolver) (*Service, error) {
	if service == nil || pools == nil {
		return nil, ErrInvalidRequest
	}
	extended := *service
	extended.exitPools = pools
	return &extended, nil
}

// WithSites returns a compiler that also compiles Site destinations. Without
// it, a rule whose destination is a Site is refused (ErrSiteRoutesDisabled).
func (service *Service) WithSites(sites SiteResolver) (*Service, error) {
	if service == nil || sites == nil {
		return nil, ErrInvalidRequest
	}
	extended := *service
	extended.sites = sites
	return &extended, nil
}

// NewService validates and constructs a policy compiler.
func NewService(
	destinations DestinationResolver,
	imported ...ImportedDestinationResolver,
) (*Service, error) {
	if destinations == nil {
		return nil, ErrInvalidRequest
	}
	if len(imported) > 1 || len(imported) == 1 && imported[0] == nil {
		return nil, ErrInvalidRequest
	}
	service := &Service{destinations: destinations}
	if len(imported) == 1 {
		service.imported = imported[0]
	}
	return service, nil
}

// Compile resolves Resource destinations and deterministically expands Resource Groups.
func (service *Service) Compile(
	ctx context.Context,
	session accountsession.Session,
	request Request,
) (publication.Candidate, error) {
	if ctx == nil || service == nil || service.destinations == nil || !session.IsValid() ||
		!request.IsValid() {
		return publication.Candidate{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return publication.Candidate{}, errors.Join(ErrUnavailable, err)
	}

	resourceIDs := uniqueResourceIDs(request.rules)
	groupIDs := uniqueResourceGroupIDs(request.rules)
	importedIDs := uniqueImportedResourceIDs(request.rules)
	if len(resourceIDs) > catalog.MaximumPolicyResources ||
		len(groupIDs) > catalog.MaximumPolicyResourceGroups {
		return publication.Candidate{}, ErrInvalidRequest
	}
	resolved := make(map[resource.ID]catalog.Resource, len(resourceIDs))
	resolvedGroups := make(map[resource.GroupID]catalog.Group, len(groupIDs))
	resolvedImported := make(
		map[sharing.ImportedResourceID]sharing.PolicyDestination,
		len(importedIDs),
	)
	if len(resourceIDs) > 0 || len(groupIDs) > 0 {
		values, groups, err := service.destinations.ResolvePolicyDestinations(
			ctx, session, request.scope, resourceIDs, groupIDs,
		)
		if err != nil {
			return publication.Candidate{}, classifyResourceResolutionError(err)
		}
		if len(groups) != len(groupIDs) {
			return publication.Candidate{}, ErrUnavailable
		}
		expectedGroups := make(map[resource.GroupID]struct{}, len(groupIDs))
		expectedResources := make(map[resource.ID]struct{}, len(resourceIDs))
		for _, id := range resourceIDs {
			expectedResources[id] = struct{}{}
		}
		for _, id := range groupIDs {
			expectedGroups[id] = struct{}{}
		}
		for _, group := range groups {
			_, requested := expectedGroups[group.ID()]
			if !requested || !group.IsValid() || group.Scope() != request.scope ||
				group.State() != resource.StateActive {
				return publication.Candidate{}, ErrResourceConflict
			}
			if _, duplicate := resolvedGroups[group.ID()]; duplicate {
				return publication.Candidate{}, ErrUnavailable
			}
			resolvedGroups[group.ID()] = group
			for _, member := range group.Members() {
				expectedResources[member.ResourceID()] = struct{}{}
			}
		}
		if len(expectedResources) > catalog.MaximumPolicyResources {
			return publication.Candidate{}, ErrInvalidRequest
		}
		if len(values) != len(expectedResources) {
			return publication.Candidate{}, ErrUnavailable
		}
		for _, value := range values {
			_, requested := expectedResources[value.ID()]
			if !requested || !value.IsValid() || value.Scope() != request.scope ||
				value.State() != resource.StateActive {
				return publication.Candidate{}, ErrResourceConflict
			}
			if _, duplicate := resolved[value.ID()]; duplicate {
				return publication.Candidate{}, ErrUnavailable
			}
			resolved[value.ID()] = value
		}
		for _, group := range groups {
			for _, member := range group.Members() {
				value, found := resolved[member.ResourceID()]
				if !found || member.ResourceVersion() != value.Version() ||
					member.TargetGeneration() != value.TargetGeneration() {
					return publication.Candidate{}, ErrResourceConflict
				}
			}
		}
	}
	if len(importedIDs) > 0 {
		if service.imported == nil {
			return publication.Candidate{}, ErrUnavailable
		}
		values, err := service.imported.ResolveImportedPolicyDestinations(
			ctx, session, request.scope, importedIDs,
		)
		if err != nil {
			return publication.Candidate{}, classifyImportedResolutionError(err)
		}
		if len(values) != len(importedIDs) {
			return publication.Candidate{}, ErrUnavailable
		}
		expected := make(map[sharing.ImportedResourceID]struct{}, len(importedIDs))
		for _, id := range importedIDs {
			expected[id] = struct{}{}
		}
		for _, value := range values {
			if _, requested := expected[value.ImportedResourceID()]; !requested ||
				!value.IsValid() || value.ConsumerScope() != request.scope {
				return publication.Candidate{}, ErrResourceConflict
			}
			if _, duplicate := resolvedImported[value.ImportedResourceID()]; duplicate {
				return publication.Candidate{}, ErrUnavailable
			}
			resolvedImported[value.ImportedResourceID()] = value
		}
	}

	routeRules, err := service.compileRouteRules(ctx, session, request)
	if err != nil {
		return publication.Candidate{}, err
	}
	exitRules, err := service.compileExitRules(ctx, session, request)
	if err != nil {
		return publication.Candidate{}, err
	}
	clusterGroups, err := service.resolveKubernetesClusters(ctx, session, request)
	if err != nil {
		return publication.Candidate{}, err
	}
	rules := make([]policy.Rule, 0, len(request.rules))
	destinations := make([]publication.ResourceDestination, 0, len(resourceIDs))
	groupDestinations := make([]publication.ResourceGroupDestination, 0, len(groupIDs))
	importedDestinations := make(
		[]publication.ImportedResourceDestination,
		0,
		len(importedIDs),
	)
	var groupRules []publication.GroupRule
	keptGroups := service.keptKubernetesGroups(ctx, session, request)
	for _, intent := range request.rules {
		destinationNodeID := intent.destinationNodeID
		if intent.destinationSiteID.IsValid() || intent.destinationExitPoolID.IsValid() {
			continue
		}
		if intent.SelectsDeviceGroup() {
			destinationGroup, cluster, err := clusterGroups.destination(intent)
			if err != nil {
				return publication.Candidate{}, err
			}
			groups, err := keptGroups(intent, cluster)
			if err != nil {
				return publication.Candidate{}, err
			}
			rule, err := publication.NewGroupRule(publication.GroupRuleParams{
				RuleID: intent.id, SourceNodeID: intent.sourceNodeID, SourceGroupID: intent.sourceGroupID,
				SourceIdentityGroupID: intent.sourceIdentityGroupID, SourceTagID: intent.sourceTagID,
				DestinationNodeID: intent.destinationNodeID, DestinationGroupID: destinationGroup,
				DestinationTagID: intent.destinationTagID, DestinationKubernetesClusterID: cluster,
				KubernetesGroups: groups,
				Protocol:         intent.protocol, DestinationPortRanges: intent.destinationPortRanges,
			})
			if err != nil {
				return publication.Candidate{}, ErrInvalidRequest
			}
			groupRules = append(groupRules, rule)
			continue
		}
		if intent.destinationImportedResourceID.IsValid() {
			resolved, found := resolvedImported[intent.destinationImportedResourceID]
			if !found {
				return publication.Candidate{}, ErrUnavailable
			}
			ranges, err := intersectImportedTraffic(intent, resolved.Contract().MaximumTraffic())
			if err != nil {
				return publication.Candidate{}, err
			}
			destination, err := publication.NewImportedResourceDestination(
				publication.ImportedResourceDestinationParams{
					RuleID: intent.id, SourceNodeID: intent.sourceNodeID,
					Resolution: resolved, Protocol: intent.protocol,
					DestinationPortRanges: ranges,
				},
			)
			if err != nil {
				return publication.Candidate{}, errors.Join(ErrUnavailable, err)
			}
			importedDestinations = append(importedDestinations, destination)
			continue
		} else if intent.destinationResourceID.IsValid() {
			value, found := resolved[intent.destinationResourceID]
			if !found {
				return publication.Candidate{}, ErrUnavailable
			}
			destinationNodeID = value.DeviceID()
			destination, err := publication.NewResourceDestination(
				publication.ResourceDestinationParams{
					RuleID: intent.id, Scope: request.scope, ResourceID: value.ID(),
					ResourceVersion: value.Version(), TargetGeneration: value.TargetGeneration(),
					InventoryRevision: value.InventoryRevision(), DestinationNodeID: value.DeviceID(),
					ResourceSemanticHash: value.SemanticHash(),
				},
			)
			if err != nil {
				return publication.Candidate{}, errors.Join(ErrUnavailable, err)
			}
			destinations = append(destinations, destination)
		} else if intent.destinationGroupID.IsValid() {
			group, found := resolvedGroups[intent.destinationGroupID]
			if !found {
				return publication.Candidate{}, ErrUnavailable
			}
			members := make([]publication.ResourceGroupMemberDestination, 0, len(group.Members()))
			seenNodes := make(map[node.ID]struct{}, len(group.Members()))
			for _, reference := range group.Members() {
				value, memberFound := resolved[reference.ResourceID()]
				if !memberFound {
					return publication.Candidate{}, ErrUnavailable
				}
				if _, duplicate := seenNodes[value.DeviceID()]; duplicate {
					return publication.Candidate{}, ErrResourceConflict
				}
				seenNodes[value.DeviceID()] = struct{}{}
				member, memberErr := publication.NewResourceGroupMemberDestination(
					publication.ResourceGroupMemberDestinationParams{
						Scope: request.scope, ResourceID: value.ID(), ResourceVersion: value.Version(),
						TargetGeneration: value.TargetGeneration(), InventoryRevision: value.InventoryRevision(),
						DestinationNodeID: value.DeviceID(), ResourceSemanticHash: value.SemanticHash(),
					},
				)
				if memberErr != nil {
					return publication.Candidate{}, errors.Join(ErrUnavailable, memberErr)
				}
				members = append(members, member)
				if err := appendCompiledRule(&rules, request, intent, value.DeviceID()); err != nil {
					return publication.Candidate{}, err
				}
			}
			groupDestination, groupErr := publication.NewResourceGroupDestination(
				publication.ResourceGroupDestinationParams{
					RuleID: intent.id, Scope: request.scope, ResourceGroupID: group.ID(),
					GroupVersion: group.Version(), DefinitionVersion: group.DefinitionVersion(),
					GroupRevision: group.GroupRevision(), GroupSemanticHash: group.SemanticHash(),
					Members: members,
				},
			)
			if groupErr != nil {
				return publication.Candidate{}, errors.Join(ErrUnavailable, groupErr)
			}
			groupDestinations = append(groupDestinations, groupDestination)
			continue
		}
		if err := appendCompiledRule(&rules, request, intent, destinationNodeID); err != nil {
			return publication.Candidate{}, err
		}
	}
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: request.scope, Revision: request.revision, Rules: rules,
	})
	if err != nil {
		return publication.Candidate{}, ErrInvalidRequest
	}
	candidate, err := candidateWithDestinations(snapshot, destinations, groupDestinations, importedDestinations)
	if err != nil {
		return candidate, err
	}
	if len(groupRules) > 0 {
		if candidate, err = candidate.WithGroupRules(groupRules); err != nil {
			return publication.Candidate{}, ErrInvalidRequest
		}
	}
	if len(routeRules) > 0 {
		candidate, err = candidate.WithRouteRules(routeRules)
		if errors.Is(err, publication.ErrRouteOverlap) || errors.Is(err, publication.ErrRoutePrefixLimit) {
			return publication.Candidate{}, err
		}
		if err != nil {
			return publication.Candidate{}, ErrInvalidRequest
		}
	}
	if len(exitRules) > 0 {
		if candidate, err = candidate.WithExitRules(exitRules); err != nil {
			return publication.Candidate{}, ErrInvalidRequest
		}
	}
	return candidate, nil
}

// compileExitRules resolves every Exit Pool destination in one read and
// turns each such rule into an exit rule.
func (service *Service) compileExitRules(ctx context.Context, session accountsession.Session,
	request Request) ([]publication.ExitRule, error) {
	var ids []exitpool.ID
	seen := make(map[exitpool.ID]struct{})
	for _, intent := range request.rules {
		if id := intent.destinationExitPoolID; id.IsValid() {
			if _, duplicate := seen[id]; !duplicate {
				seen[id] = struct{}{}
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	if service.exitPools == nil {
		return nil, ErrExitPoolsDisabled
	}
	if len(ids) > exitpool.MaximumPoolsPerNetwork {
		return nil, ErrInvalidRequest
	}
	pools, err := service.exitPools.ResolvePolicyExitPools(ctx, session, request.scope, ids)
	if err != nil {
		return nil, classifyExitPoolResolutionError(err)
	}
	resolved := make(map[exitpool.ID]struct{}, len(pools))
	for _, pool := range pools {
		if _, requested := seen[pool.ID]; !requested {
			return nil, ErrUnavailable
		}
		resolved[pool.ID] = struct{}{}
	}
	exitRules := make([]publication.ExitRule, 0, len(ids))
	for _, intent := range request.rules {
		if !intent.destinationExitPoolID.IsValid() {
			continue
		}
		if _, found := resolved[intent.destinationExitPoolID]; !found {
			return nil, ErrResourceConflict
		}
		rule, err := publication.NewExitRule(publication.ExitRuleParams{
			RuleID: intent.id, SourceNodeID: intent.sourceNodeID, SourceGroupID: intent.sourceGroupID,
			SourceIdentityGroupID: intent.sourceIdentityGroupID, SourceTagID: intent.sourceTagID,
			PoolID: intent.destinationExitPoolID, Protocol: intent.protocol,
			DestinationPortRanges: intent.destinationPortRanges,
		})
		if err != nil {
			return nil, ErrInvalidRequest
		}
		exitRules = append(exitRules, rule)
	}
	return exitRules, nil
}

func classifyExitPoolResolutionError(err error) error {
	switch {
	case errors.Is(err, exitpool.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, exitpool.ErrInvalid), errors.Is(err, exitpool.ErrNotFound):
		return ErrResourceConflict
	default:
		return errors.Join(ErrUnavailable, err)
	}
}

// compileRouteRules resolves every Site destination in one read and turns
// each such rule into a route rule granting the asked prefixes, each inside
// the Site, or the whole Site.
func (service *Service) compileRouteRules(ctx context.Context, session accountsession.Session,
	request Request) ([]publication.RouteRule, error) {
	var ids []site.ID
	seen := make(map[site.ID]struct{})
	for _, intent := range request.rules {
		if id := intent.destinationSiteID; id.IsValid() {
			if _, duplicate := seen[id]; !duplicate {
				seen[id] = struct{}{}
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	if service.sites == nil {
		return nil, ErrSiteRoutesDisabled
	}
	if len(ids) > site.MaximumSitesPerNetwork {
		return nil, ErrInvalidRequest
	}
	sites, err := service.sites.ResolvePolicySites(ctx, session, request.scope, ids)
	if err != nil {
		return nil, classifySiteResolutionError(err)
	}
	resolved := make(map[site.ID]site.Site, len(sites))
	for _, value := range sites {
		if _, requested := seen[value.ID]; !requested {
			return nil, ErrUnavailable
		}
		resolved[value.ID] = value
	}
	routeRules := make([]publication.RouteRule, 0, len(ids))
	granted := 0
	for _, intent := range request.rules {
		if !intent.destinationSiteID.IsValid() {
			continue
		}
		value, found := resolved[intent.destinationSiteID]
		if !found {
			return nil, ErrResourceConflict
		}
		prefixes := intent.destinationPrefixes
		if len(prefixes) == 0 {
			prefixes = value.Prefixes
		}
		// Stop before building more than a release may hold: a rule without
		// prefixes grants its whole Site.
		if granted += len(prefixes); granted > publication.MaximumGrantedRoutePrefixes {
			return nil, ErrRoutePrefixLimit
		}
		for _, prefix := range prefixes {
			if !prefix.IsValid() || prefix != prefix.Masked() || !site.Covers(value.Prefixes, []netip.Prefix{prefix}) {
				return nil, ErrOutsideSite
			}
		}
		rule, err := publication.NewRouteRule(publication.RouteRuleParams{
			RuleID: intent.id, SourceNodeID: intent.sourceNodeID, SourceGroupID: intent.sourceGroupID,
			SourceIdentityGroupID: intent.sourceIdentityGroupID, SourceTagID: intent.sourceTagID,
			SiteID: value.ID, Prefixes: prefixes, Protocol: intent.protocol,
			DestinationPortRanges: intent.destinationPortRanges,
		})
		if err != nil {
			return nil, ErrInvalidRequest
		}
		routeRules = append(routeRules, rule)
	}
	return routeRules, nil
}

func classifySiteResolutionError(err error) error {
	switch {
	case errors.Is(err, site.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, site.ErrInvalid), errors.Is(err, site.ErrNotFound):
		return ErrResourceConflict
	default:
		return errors.Join(ErrUnavailable, err)
	}
}

func candidateWithDestinations(
	snapshot policy.Snapshot,
	destinations []publication.ResourceDestination,
	groupDestinations []publication.ResourceGroupDestination,
	importedDestinations []publication.ImportedResourceDestination,
) (publication.Candidate, error) {
	if len(importedDestinations) > 0 {
		return publication.NewCandidateWithImportedResourceDestinations(
			snapshot, destinations, groupDestinations, importedDestinations,
		)
	}
	if len(destinations) == 0 {
		if len(groupDestinations) > 0 {
			return publication.NewCandidateWithResourceGroupDestinations(
				snapshot, nil, groupDestinations,
			)
		}
		return publication.NewCandidate(snapshot, 1)
	}
	if len(groupDestinations) > 0 {
		return publication.NewCandidateWithResourceGroupDestinations(
			snapshot, destinations, groupDestinations,
		)
	}
	return publication.NewCandidateWithResourceDestinations(snapshot, destinations)
}

func intersectImportedTraffic(
	intent RuleIntent,
	maximum sharing.TrafficSet,
) ([]policy.PortRange, error) {
	requestedConstraint, err := sharing.NewTrafficConstraint(sharing.TrafficConstraintParams{
		Protocol: intent.protocol, DestinationPortRanges: intent.destinationPortRanges,
	})
	if err != nil {
		return nil, ErrInvalidRequest
	}
	requested, err := sharing.NewTrafficSet([]sharing.TrafficConstraint{requestedConstraint})
	if err != nil {
		return nil, ErrInvalidRequest
	}
	effective, found := sharing.IntersectTraffic(requested, maximum)
	if !found {
		return nil, ErrResourceConflict
	}
	constraints := effective.Constraints()
	if len(constraints) != 1 || constraints[0].Protocol() != intent.protocol {
		return nil, ErrResourceConflict
	}
	return constraints[0].DestinationPortRanges(), nil
}

func appendCompiledRule(
	rules *[]policy.Rule,
	request Request,
	intent RuleIntent,
	destinationNodeID node.ID,
) error {
	if len(*rules) >= policy.MaximumRules {
		return ErrInvalidRequest
	}
	rule, err := policy.NewRule(policy.RuleParams{
		ID: intent.id, Scope: request.scope, SourceNodeID: intent.sourceNodeID,
		DestinationNodeID: destinationNodeID, Protocol: intent.protocol,
		DestinationPortRanges: intent.destinationPortRanges,
	})
	if err != nil {
		return ErrInvalidRequest
	}
	*rules = append(*rules, rule)
	return nil
}

func uniqueResourceIDs(rules []RuleIntent) []resource.ID {
	seen := make(map[resource.ID]struct{}, len(rules))
	for _, rule := range rules {
		if rule.destinationResourceID.IsValid() {
			seen[rule.destinationResourceID] = struct{}{}
		}
	}
	ids := make([]resource.ID, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(first, second resource.ID) int {
		return strings.Compare(first.String(), second.String())
	})
	return ids
}

func uniqueResourceGroupIDs(rules []RuleIntent) []resource.GroupID {
	seen := make(map[resource.GroupID]struct{}, len(rules))
	for _, rule := range rules {
		if rule.destinationGroupID.IsValid() {
			seen[rule.destinationGroupID] = struct{}{}
		}
	}
	ids := make([]resource.GroupID, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(first, second resource.GroupID) int {
		return strings.Compare(first.String(), second.String())
	})
	return ids
}

func uniqueImportedResourceIDs(rules []RuleIntent) []sharing.ImportedResourceID {
	seen := make(map[sharing.ImportedResourceID]struct{}, len(rules))
	for _, rule := range rules {
		if rule.destinationImportedResourceID.IsValid() {
			seen[rule.destinationImportedResourceID] = struct{}{}
		}
	}
	ids := make([]sharing.ImportedResourceID, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(first, second sharing.ImportedResourceID) int {
		return strings.Compare(first.String(), second.String())
	})
	return ids
}

func classifyResourceResolutionError(err error) error {
	switch {
	case errors.Is(err, catalog.ErrForbidden):
		return errors.Join(ErrForbidden, err)
	case errors.Is(err, catalog.ErrNotFound), errors.Is(err, catalog.ErrConflict):
		return errors.Join(ErrResourceConflict, err)
	case errors.Is(err, catalog.ErrInvalidRequest):
		return errors.Join(ErrInvalidRequest, err)
	default:
		return errors.Join(ErrUnavailable, fmt.Errorf("resolve policy Resources: %w", err))
	}
}

func classifyImportedResolutionError(err error) error {
	switch {
	case errors.Is(err, sharing.ErrForbidden):
		return errors.Join(ErrForbidden, err)
	case errors.Is(err, sharing.ErrNotFound), errors.Is(err, sharing.ErrConflict):
		return errors.Join(ErrResourceConflict, err)
	case errors.Is(err, sharing.ErrInvalidManagementRequest):
		return errors.Join(ErrInvalidRequest, err)
	default:
		return errors.Join(ErrUnavailable, fmt.Errorf("resolve policy Imported Resources: %w", err))
	}
}
