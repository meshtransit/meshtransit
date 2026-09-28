package compilation

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/resource/catalog"
)

// ResourceResolver returns one snapshot-consistent, active Resource set.
type ResourceResolver interface {
	ResolvePolicyResources(
		context.Context,
		accountsession.Session,
		network.Scope,
		[]resource.ID,
	) ([]catalog.Resource, error)
}

// Service compiles typed Device and Resource destinations without retaining state.
type Service struct{ resources ResourceResolver }

// NewService validates and constructs a policy compiler.
func NewService(resources ResourceResolver) (*Service, error) {
	if resources == nil {
		return nil, ErrInvalidRequest
	}
	return &Service{resources: resources}, nil
}

// Compile resolves Resource destinations and emits one immutable publication candidate.
func (service *Service) Compile(
	ctx context.Context,
	session accountsession.Session,
	request Request,
) (publication.Candidate, error) {
	if ctx == nil || service == nil || service.resources == nil || !session.IsValid() ||
		!request.IsValid() {
		return publication.Candidate{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return publication.Candidate{}, errors.Join(ErrUnavailable, err)
	}

	resourceIDs := uniqueResourceIDs(request.rules)
	if len(resourceIDs) > catalog.MaximumPolicyResources {
		return publication.Candidate{}, ErrInvalidRequest
	}
	resolved := make(map[resource.ID]catalog.Resource, len(resourceIDs))
	if len(resourceIDs) > 0 {
		values, err := service.resources.ResolvePolicyResources(ctx, session, request.scope, resourceIDs)
		if err != nil {
			return publication.Candidate{}, classifyResourceResolutionError(err)
		}
		if len(values) != len(resourceIDs) {
			return publication.Candidate{}, ErrUnavailable
		}
		expected := make(map[resource.ID]struct{}, len(resourceIDs))
		for _, id := range resourceIDs {
			expected[id] = struct{}{}
		}
		for _, value := range values {
			_, requested := expected[value.ID()]
			if !requested || !value.IsValid() || value.Scope() != request.scope ||
				value.State() != resource.StateActive {
				return publication.Candidate{}, ErrResourceConflict
			}
			if _, duplicate := resolved[value.ID()]; duplicate {
				return publication.Candidate{}, ErrUnavailable
			}
			resolved[value.ID()] = value
		}
	}

	rules := make([]policy.Rule, len(request.rules))
	destinations := make([]publication.ResourceDestination, 0, len(resourceIDs))
	for index, intent := range request.rules {
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
		}
		rule, err := policy.NewRule(policy.RuleParams{
			ID: intent.id, Scope: request.scope, SourceNodeID: intent.sourceNodeID,
			DestinationNodeID: destinationNodeID, Protocol: intent.protocol,
			DestinationPortRanges: intent.destinationPortRanges,
		})
		if err != nil {
			return publication.Candidate{}, ErrInvalidRequest
		}
		rules[index] = rule
	}
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: request.scope, Revision: request.revision, Rules: rules,
	})
	if err != nil {
		return publication.Candidate{}, ErrInvalidRequest
	}
	if len(destinations) == 0 {
		return publication.NewCandidate(snapshot, 1)
	}
	return publication.NewCandidateWithResourceDestinations(snapshot, destinations)
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
