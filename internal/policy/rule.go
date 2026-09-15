package policy

import (
	"errors"
	"slices"
	"strings"

	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

var (
	// ErrInvalidRuleID reports an absent or malformed stable Access Rule identity.
	ErrInvalidRuleID = errors.New("policy: invalid rule id")
	// ErrInvalidRule reports incomplete, unscoped, or unsafe compiled rule input.
	ErrInvalidRule = errors.New("policy: invalid compiled rule")
)

// RuleID is a validated opaque UUIDv7 identifying one stable Access Rule.
type RuleID publicid.ID

// ParseRuleID validates a canonical stable Access Rule identity.
func ParseRuleID(value string) (RuleID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return RuleID{}, ErrInvalidRuleID
	}
	return RuleID(id), nil
}

// String returns the canonical lower-case UUID representation.
func (id RuleID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the ID satisfies the UUIDv7 contract.
func (id RuleID) IsValid() bool { return publicid.ID(id).IsValid() }

// RuleParams contains one active, selector-resolved, same-Network allow edge.
type RuleParams struct {
	ID                    RuleID
	Scope                 network.Scope
	SourceNodeID          node.ID
	DestinationNodeID     node.ID
	Protocol              Protocol
	DestinationPortRanges []PortRange
}

// Rule is one immutable directional allow edge from an active policy release.
// It contains only product-owned stable identities and normalized packet intent.
type Rule struct {
	id                    RuleID
	scope                 network.Scope
	sourceNodeID          node.ID
	destinationNodeID     node.ID
	protocol              Protocol
	destinationPortRanges []PortRange
}

// NewRule validates and canonicalizes one selector-resolved allow edge.
func NewRule(params RuleParams) (Rule, error) {
	if len(params.DestinationPortRanges) > MaximumPortRangesPerRule {
		return Rule{}, ErrInvalidRule
	}
	ports := canonicalPortRanges(params.DestinationPortRanges)
	if !validRuleParams(params, ports) {
		return Rule{}, ErrInvalidRule
	}
	return Rule{
		id:                    params.ID,
		scope:                 params.Scope,
		sourceNodeID:          params.SourceNodeID,
		destinationNodeID:     params.DestinationNodeID,
		protocol:              params.Protocol,
		destinationPortRanges: ports,
	}, nil
}

// ID returns the stable Access Rule identity.
func (rule Rule) ID() RuleID { return rule.id }

// Scope returns the exact Workspace-qualified Network scope.
func (rule Rule) Scope() network.Scope { return rule.scope }

// SourceNodeID returns the resolved initiating Node identity.
func (rule Rule) SourceNodeID() node.ID { return rule.sourceNodeID }

// DestinationNodeID returns the resolved destination Node identity.
func (rule Rule) DestinationNodeID() node.ID { return rule.destinationNodeID }

// Protocol returns the one explicitly authorized protocol.
func (rule Rule) Protocol() Protocol { return rule.protocol }

// DestinationPortRanges returns caller-owned normalized destination intervals.
func (rule Rule) DestinationPortRanges() []PortRange {
	return slices.Clone(rule.destinationPortRanges)
}

// IsValid reports whether the compiled allow edge is complete and canonical.
func (rule Rule) IsValid() bool {
	return validRuleParams(rule.params(), rule.destinationPortRanges)
}

func (rule Rule) params() RuleParams {
	return RuleParams{
		ID:                    rule.id,
		Scope:                 rule.scope,
		SourceNodeID:          rule.sourceNodeID,
		DestinationNodeID:     rule.destinationNodeID,
		Protocol:              rule.protocol,
		DestinationPortRanges: slices.Clone(rule.destinationPortRanges),
	}
}

func (rule Rule) clone() Rule {
	cloned := rule
	cloned.destinationPortRanges = slices.Clone(rule.destinationPortRanges)
	return cloned
}

func (rule Rule) matches(request PacketRequest) bool {
	if rule.sourceNodeID != request.sourceNodeID ||
		rule.destinationNodeID != request.destinationNodeID || rule.protocol != request.protocol {
		return false
	}
	if rule.protocol == ProtocolICMP {
		return true
	}
	for _, portRange := range rule.destinationPortRanges {
		if request.destinationPort >= portRange.first && request.destinationPort <= portRange.last {
			return true
		}
	}
	return false
}

func validRuleParams(params RuleParams, ports []PortRange) bool {
	if !params.ID.IsValid() || !params.Scope.IsValid() || !params.SourceNodeID.IsValid() ||
		!params.DestinationNodeID.IsValid() || params.SourceNodeID == params.DestinationNodeID ||
		!params.Protocol.IsValid() {
		return false
	}
	if params.Protocol == ProtocolICMP {
		return len(ports) == 0
	}
	return validCanonicalPortRanges(ports)
}

func compareRules(first, second Rule) int {
	return strings.Compare(first.id.String(), second.id.String())
}

func equalRules(first, second Rule) bool {
	return first.id == second.id && first.scope == second.scope &&
		first.sourceNodeID == second.sourceNodeID &&
		first.destinationNodeID == second.destinationNodeID &&
		first.protocol == second.protocol &&
		slices.Equal(first.destinationPortRanges, second.destinationPortRanges)
}
