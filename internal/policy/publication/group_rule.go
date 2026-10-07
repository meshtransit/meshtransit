package publication

import (
	"errors"
	"slices"
	"strings"

	"github.com/meshtransit/meshtransit/internal/devicegroup"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
)

// ErrInvalidGroupRule reports a group rule without exactly one source, one
// destination and at least one Device Group side.
var ErrInvalidGroupRule = errors.New("policy publication: invalid group rule")

// GroupRuleParams describes one Access Rule that selects a Device Group on
// either side. Exactly one source and one destination are set.
type GroupRuleParams struct {
	RuleID                policy.RuleID
	SourceNodeID          node.ID
	SourceGroupID         devicegroup.ID
	DestinationNodeID     node.ID
	DestinationGroupID    devicegroup.ID
	Protocol              policy.Protocol
	DestinationPortRanges []policy.PortRange
}

// GroupRule is a release fact that names groups, not their members: maps
// resolve it from the membership current at each Network revision.
type GroupRule struct {
	ruleID                policy.RuleID
	sourceNodeID          node.ID
	sourceGroupID         devicegroup.ID
	destinationNodeID     node.ID
	destinationGroupID    devicegroup.ID
	protocol              policy.Protocol
	destinationPortRanges []policy.PortRange
}

// NewGroupRule validates one group rule and canonicalizes its ports.
func NewGroupRule(params GroupRuleParams) (GroupRule, error) {
	ports, valid := policy.CanonicalTraffic(params.Protocol, params.DestinationPortRanges)
	rule := GroupRule{
		ruleID: params.RuleID, sourceNodeID: params.SourceNodeID, sourceGroupID: params.SourceGroupID,
		destinationNodeID: params.DestinationNodeID, destinationGroupID: params.DestinationGroupID,
		protocol: params.Protocol, destinationPortRanges: ports,
	}
	if !valid || !rule.IsValid() {
		return GroupRule{}, ErrInvalidGroupRule
	}
	return rule, nil
}

// RuleID returns the Access Rule identity.
func (rule GroupRule) RuleID() policy.RuleID { return rule.ruleID }

// SourceNodeID returns the source Device, when the source is a Device.
func (rule GroupRule) SourceNodeID() node.ID { return rule.sourceNodeID }

// SourceGroupID returns the source Device Group, when the source is a group.
func (rule GroupRule) SourceGroupID() devicegroup.ID { return rule.sourceGroupID }

// DestinationNodeID returns the destination Device, when it is a Device.
func (rule GroupRule) DestinationNodeID() node.ID { return rule.destinationNodeID }

// DestinationGroupID returns the destination Device Group, when it is a group.
func (rule GroupRule) DestinationGroupID() devicegroup.ID { return rule.destinationGroupID }

// Protocol returns the packet protocol.
func (rule GroupRule) Protocol() policy.Protocol { return rule.protocol }

// DestinationPortRanges returns caller-owned canonical port ranges.
func (rule GroupRule) DestinationPortRanges() []policy.PortRange {
	return slices.Clone(rule.destinationPortRanges)
}

// IsValid reports exactly one source, one destination, at least one group
// side, and canonical traffic.
func (rule GroupRule) IsValid() bool {
	hasSourceNode, hasSourceGroup := rule.sourceNodeID.IsValid(), rule.sourceGroupID.IsValid()
	hasDestinationNode, hasDestinationGroup := rule.destinationNodeID.IsValid(), rule.destinationGroupID.IsValid()
	if !rule.ruleID.IsValid() || hasSourceNode == hasSourceGroup || hasDestinationNode == hasDestinationGroup ||
		(!hasSourceGroup && !hasDestinationGroup) {
		return false
	}
	ports, valid := policy.CanonicalTraffic(rule.protocol, rule.destinationPortRanges)
	return valid && slices.Equal(ports, rule.destinationPortRanges)
}

func compareGroupRules(first, second GroupRule) int {
	return strings.Compare(first.ruleID.String(), second.ruleID.String())
}

func cloneGroupRules(rules []GroupRule) []GroupRule {
	cloned := make([]GroupRule, len(rules))
	for index, rule := range rules {
		cloned[index] = rule
		cloned[index].destinationPortRanges = slices.Clone(rule.destinationPortRanges)
	}
	return cloned
}
