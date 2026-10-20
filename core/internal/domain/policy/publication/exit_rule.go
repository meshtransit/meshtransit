package publication

import (
	"errors"
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/publicid"
)

// ErrInvalidExitRule reports an exit rule without one source, an Exit Pool
// and canonical traffic.
var ErrInvalidExitRule = errors.New("policy publication: invalid exit rule")

// ExitRuleParams describes one Access Rule whose destination is an Exit
// Pool: its source may reach the Internet through the pool's exit nodes.
// Exactly one source is set. The destination is always the Internet as
// shared/internet defines it; a rule never names addresses.
type ExitRuleParams struct {
	RuleID                policy.RuleID
	SourceNodeID          node.ID
	SourceGroupID         devicegroup.ID
	SourceIdentityGroupID identitygroup.ID
	SourceTagID           devicetag.ID
	PoolID                exitpool.ID
	Protocol              policy.Protocol
	DestinationPortRanges []policy.PortRange
}

// ExitRule is a release fact that names a source selector and an Exit Pool.
// Maps resolve the source from membership current at each Network revision,
// as for route rules.
type ExitRule struct {
	ruleID                policy.RuleID
	source                RuleSide
	poolID                exitpool.ID
	protocol              policy.Protocol
	destinationPortRanges []policy.PortRange
}

// NewExitRule validates one exit rule and canonicalizes its ports.
func NewExitRule(params ExitRuleParams) (ExitRule, error) {
	ports, valid := policy.CanonicalTraffic(params.Protocol, params.DestinationPortRanges)
	rule := ExitRule{
		ruleID: params.RuleID,
		source: oneSide(
			RuleSide{SideDevice, publicid.ID(params.SourceNodeID)},
			RuleSide{SideDeviceGroup, publicid.ID(params.SourceGroupID)},
			RuleSide{SideIdentityGroup, publicid.ID(params.SourceIdentityGroupID)},
			RuleSide{SideDeviceTag, publicid.ID(params.SourceTagID)},
		),
		poolID: params.PoolID, protocol: params.Protocol, destinationPortRanges: ports,
	}
	if !valid || !rule.IsValid() {
		return ExitRule{}, ErrInvalidExitRule
	}
	return rule, nil
}

// RuleID returns the Access Rule identity.
func (rule ExitRule) RuleID() policy.RuleID { return rule.ruleID }

// Source returns the source side.
func (rule ExitRule) Source() RuleSide { return rule.source }

// PoolID returns the destination Exit Pool.
func (rule ExitRule) PoolID() exitpool.ID { return rule.poolID }

// Protocol returns the packet protocol.
func (rule ExitRule) Protocol() policy.Protocol { return rule.protocol }

// DestinationPortRanges returns caller-owned canonical port ranges.
func (rule ExitRule) DestinationPortRanges() []policy.PortRange {
	return slices.Clone(rule.destinationPortRanges)
}

// IsValid reports one source, an Exit Pool and canonical traffic.
func (rule ExitRule) IsValid() bool {
	if !rule.ruleID.IsValid() || !rule.source.IsValid() || !rule.poolID.IsValid() {
		return false
	}
	ports, valid := policy.CanonicalTraffic(rule.protocol, rule.destinationPortRanges)
	return valid && slices.Equal(ports, rule.destinationPortRanges)
}

func compareExitRules(first, second ExitRule) int {
	return strings.Compare(first.ruleID.String(), second.ruleID.String())
}

func cloneExitRules(rules []ExitRule) []ExitRule {
	cloned := make([]ExitRule, len(rules))
	for index, rule := range rules {
		cloned[index] = rule
		cloned[index].destinationPortRanges = slices.Clone(rule.destinationPortRanges)
	}
	return cloned
}

// appendExitRules encodes each exit rule after a count: rule ID, source
// side, pool ID, protocol and ports.
func appendExitRules(encoded []byte, rules []ExitRule) []byte {
	encoded = appendUint64(encoded, uint64(len(rules)))
	for _, rule := range rules {
		ruleID := publicid.ID(rule.ruleID).Bytes()
		poolID := publicid.ID(rule.poolID).Bytes()
		encoded = append(encoded, ruleID[:]...)
		encoded = appendGroupRuleSide(encoded, rule.source)
		encoded = append(encoded, poolID[:]...)
		encoded = append(encoded, byte(rule.protocol))
		encoded = appendUint64(encoded, uint64(len(rule.destinationPortRanges)))
		for _, portRange := range rule.destinationPortRanges {
			encoded = appendUint16(encoded, portRange.First())
			encoded = appendUint16(encoded, portRange.Last())
		}
	}
	return encoded
}
