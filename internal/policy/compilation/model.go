// Package compilation resolves typed policy intent into immutable Node-level artifacts.
package compilation

import (
	"errors"
	"slices"

	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/resource"
)

var (
	// ErrInvalidRequest reports malformed, ambiguous, or over-limit policy intent.
	ErrInvalidRequest = errors.New("policy compilation: invalid request")
	// ErrResourceConflict reports inactive or changed Resource authority.
	ErrResourceConflict = errors.New("policy compilation: resource conflict")
	// ErrForbidden hides which Resource catalog authorization prerequisite failed.
	ErrForbidden = errors.New("policy compilation: forbidden")
	// ErrUnavailable reports an unavailable authoritative dependency.
	ErrUnavailable = errors.New("policy compilation: unavailable")
)

// RuleIntentParams contains one atomic Access Rule before destination resolution.
type RuleIntentParams struct {
	ID                    policy.RuleID
	Scope                 network.Scope
	SourceNodeID          node.ID
	DestinationNodeID     node.ID
	DestinationResourceID resource.ID
	DestinationGroupID    resource.GroupID
	Protocol              policy.Protocol
	DestinationPortRanges []policy.PortRange
}

// RuleIntent is one immutable Access Rule with exactly one typed destination.
type RuleIntent struct {
	id                    policy.RuleID
	scope                 network.Scope
	sourceNodeID          node.ID
	destinationNodeID     node.ID
	destinationResourceID resource.ID
	destinationGroupID    resource.GroupID
	protocol              policy.Protocol
	destinationPortRanges []policy.PortRange
}

// NewRuleIntent validates one Device or Resource destination without resolving it.
func NewRuleIntent(params RuleIntentParams) (RuleIntent, error) {
	intent := RuleIntent{
		id: params.ID, scope: params.Scope, sourceNodeID: params.SourceNodeID,
		destinationNodeID:     params.DestinationNodeID,
		destinationResourceID: params.DestinationResourceID,
		destinationGroupID:    params.DestinationGroupID,
		protocol:              params.Protocol, destinationPortRanges: slices.Clone(params.DestinationPortRanges),
	}
	if !intent.IsValid() {
		return RuleIntent{}, ErrInvalidRequest
	}
	return intent, nil
}

// ID returns the stable Access Rule identity.
func (intent RuleIntent) ID() policy.RuleID { return intent.id }

// Scope returns the exact Workspace-qualified Network scope.
func (intent RuleIntent) Scope() network.Scope { return intent.scope }

// SourceNodeID returns the initiating Device identity.
func (intent RuleIntent) SourceNodeID() node.ID { return intent.sourceNodeID }

// DestinationNodeID returns the direct Device destination, when selected.
func (intent RuleIntent) DestinationNodeID() node.ID { return intent.destinationNodeID }

// DestinationResourceID returns the Resource destination, when selected.
func (intent RuleIntent) DestinationResourceID() resource.ID {
	return intent.destinationResourceID
}

// DestinationGroupID returns the Resource Group destination, when selected.
func (intent RuleIntent) DestinationGroupID() resource.GroupID {
	return intent.destinationGroupID
}

// Protocol returns the explicit packet protocol.
func (intent RuleIntent) Protocol() policy.Protocol { return intent.protocol }

// DestinationPortRanges returns caller-owned transport intervals.
func (intent RuleIntent) DestinationPortRanges() []policy.PortRange {
	return slices.Clone(intent.destinationPortRanges)
}

// IsValid reports whether the intent has exactly one typed destination.
func (intent RuleIntent) IsValid() bool {
	hasDevice := intent.destinationNodeID.IsValid()
	hasResource := intent.destinationResourceID.IsValid()
	hasGroup := intent.destinationGroupID.IsValid()
	if !intent.id.IsValid() || !intent.scope.IsValid() || !intent.sourceNodeID.IsValid() ||
		boolCount(hasDevice, hasResource, hasGroup) != 1 || !intent.protocol.IsValid() ||
		intent.destinationPortRanges == nil {
		return false
	}
	if hasDevice {
		_, err := policy.NewRule(policy.RuleParams{
			ID: intent.id, Scope: intent.scope, SourceNodeID: intent.sourceNodeID,
			DestinationNodeID: intent.destinationNodeID, Protocol: intent.protocol,
			DestinationPortRanges: intent.destinationPortRanges,
		})
		return err == nil
	}
	if len(intent.destinationPortRanges) > policy.MaximumPortRangesPerRule {
		return false
	}
	if intent.protocol == policy.ProtocolICMP {
		return len(intent.destinationPortRanges) == 0
	}
	if len(intent.destinationPortRanges) == 0 {
		return false
	}
	for _, portRange := range intent.destinationPortRanges {
		if portRange.First() == 0 || portRange.Last() < portRange.First() {
			return false
		}
	}
	return true
}

func boolCount(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

// RequestParams contains one complete policy compilation request.
type RequestParams struct {
	Scope    network.Scope
	Revision int64
	Rules    []RuleIntent
}

// Request is immutable typed policy intent for one successor revision.
type Request struct {
	scope    network.Scope
	revision int64
	rules    []RuleIntent
}

// NewRequest validates a bounded rule set with unique stable Access Rule IDs.
func NewRequest(params RequestParams) (Request, error) {
	request := Request{
		scope: params.Scope, revision: params.Revision, rules: slices.Clone(params.Rules),
	}
	if !request.IsValid() {
		return Request{}, ErrInvalidRequest
	}
	return request, nil
}

// Scope returns the exact compilation scope.
func (request Request) Scope() network.Scope { return request.scope }

// Revision returns the successor policy revision.
func (request Request) Revision() int64 { return request.revision }

// Rules returns caller-owned immutable rule intents.
func (request Request) Rules() []RuleIntent { return slices.Clone(request.rules) }

// IsValid reports whether every rule is exact-scoped, bounded, and uniquely identified.
func (request Request) IsValid() bool {
	if !request.scope.IsValid() || request.revision <= 1 || request.rules == nil ||
		len(request.rules) > policy.MaximumRules {
		return false
	}
	seen := make(map[policy.RuleID]struct{}, len(request.rules))
	for _, rule := range request.rules {
		if !rule.IsValid() || rule.scope != request.scope {
			return false
		}
		if _, duplicate := seen[rule.id]; duplicate {
			return false
		}
		seen[rule.id] = struct{}{}
	}
	return true
}
