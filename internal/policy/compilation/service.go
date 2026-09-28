package compilation

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/resource/catalog"
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

// Service compiles typed Device, Resource, and Resource Group destinations.
type Service struct{ destinations DestinationResolver }

// NewService validates and constructs a policy compiler.
func NewService(destinations DestinationResolver) (*Service, error) {
	if destinations == nil {
		return nil, ErrInvalidRequest
	}
	return &Service{destinations: destinations}, nil
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
	if len(resourceIDs) > catalog.MaximumPolicyResources ||
		len(groupIDs) > catalog.MaximumPolicyResourceGroups {
		return publication.Candidate{}, ErrInvalidRequest
	}
	resolved := make(map[resource.ID]catalog.Resource, len(resourceIDs))
	resolvedGroups := make(map[resource.GroupID]catalog.Group, len(groupIDs))
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

	rules := make([]policy.Rule, 0, len(request.rules))
	destinations := make([]publication.ResourceDestination, 0, len(resourceIDs))
	groupDestinations := make([]publication.ResourceGroupDestination, 0, len(groupIDs))
	for _, intent := range request.rules {
		destinationNodeID := intent.destinationNodeID
		if intent.destinationResourceID.IsValid() {
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
