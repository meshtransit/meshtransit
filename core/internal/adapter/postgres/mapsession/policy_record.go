package mapsession

import (
	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
)

type policyRuleRecord struct {
	policyRevision    int64
	ruleID            *string
	sourceNodeID      *string
	destinationNodeID *string
	protocol          *string
	portRangeFirst    []int32
	portRangeLast     []int32
}

func (record policyRuleRecord) rule(scope network.Scope) (policy.Rule, error) {
	if record.ruleID == nil || record.sourceNodeID == nil || record.destinationNodeID == nil ||
		record.protocol == nil || len(record.portRangeFirst) != len(record.portRangeLast) ||
		len(record.portRangeFirst) > policy.MaximumPortRangesPerRule {
		return policy.Rule{}, ErrSnapshotEvidence
	}
	ruleID, err := policy.ParseRuleID(*record.ruleID)
	if err != nil {
		return policy.Rule{}, ErrSnapshotEvidence
	}
	sourceNodeID, err := node.ParseID(*record.sourceNodeID)
	if err != nil {
		return policy.Rule{}, ErrSnapshotEvidence
	}
	destinationNodeID, err := node.ParseID(*record.destinationNodeID)
	if err != nil {
		return policy.Rule{}, ErrSnapshotEvidence
	}
	protocol, err := protocolFromText(*record.protocol)
	if err != nil {
		return policy.Rule{}, err
	}
	ports, err := portRanges(record.portRangeFirst, record.portRangeLast)
	if err != nil {
		return policy.Rule{}, err
	}
	rule, err := policy.NewRule(policy.RuleParams{
		ID:                    ruleID,
		Scope:                 scope,
		SourceNodeID:          sourceNodeID,
		DestinationNodeID:     destinationNodeID,
		Protocol:              protocol,
		DestinationPortRanges: ports,
	})
	if err != nil {
		return policy.Rule{}, ErrSnapshotEvidence
	}
	return rule, nil
}

func (record policyRuleRecord) isEmptyRelease() bool {
	return record.ruleID == nil && record.sourceNodeID == nil &&
		record.destinationNodeID == nil && record.protocol == nil &&
		len(record.portRangeFirst) == 0 && len(record.portRangeLast) == 0
}

func protocolFromText(value string) (policy.Protocol, error) {
	switch value {
	case "tcp":
		return policy.ProtocolTCP, nil
	case "udp":
		return policy.ProtocolUDP, nil
	case "icmp":
		return policy.ProtocolICMP, nil
	default:
		return policy.ProtocolUnknown, ErrSnapshotEvidence
	}
}

// networkPolicyRuleRecord is one row of load_map_network_policy_rules_v1.
type networkPolicyRuleRecord struct {
	ruleKind        string
	ruleID          string
	sourceKind      string
	sourceRef       int64
	destinationKind string
	destinationRef  int64
	protocol        string
	portFirst       []int32
	portLast        []int32
}

func (record networkPolicyRuleRecord) rule() (appmapsession.NetworkPolicyRule, error) {
	if record.ruleKind != "device" && record.ruleKind != "group" ||
		len(record.portFirst) != len(record.portLast) || len(record.portFirst) > policy.MaximumPortRangesPerRule {
		return appmapsession.NetworkPolicyRule{}, ErrSnapshotEvidence
	}
	ruleID, err := policy.ParseRuleID(record.ruleID)
	if err != nil {
		return appmapsession.NetworkPolicyRule{}, ErrSnapshotEvidence
	}
	protocol, err := protocolFromText(record.protocol)
	if err != nil {
		return appmapsession.NetworkPolicyRule{}, err
	}
	ports, err := portRanges(record.portFirst, record.portLast)
	if err != nil {
		return appmapsession.NetworkPolicyRule{}, err
	}
	rule := appmapsession.NetworkPolicyRule{
		ID: ruleID, SourceKind: selectorKindFromText(record.sourceKind), SourceRef: record.sourceRef,
		DestinationKind: selectorKindFromText(record.destinationKind), DestinationRef: record.destinationRef,
		Protocol: protocol, Ports: ports,
	}
	if record.ruleKind == "device" && (rule.SourceKind != appmapsession.SelectorDevice ||
		rule.DestinationKind != appmapsession.SelectorDevice) {
		return appmapsession.NetworkPolicyRule{}, ErrSnapshotEvidence
	}
	return rule, nil
}

func selectorKindFromText(value string) appmapsession.SelectorKind {
	switch value {
	case "device":
		return appmapsession.SelectorDevice
	case "device_group":
		return appmapsession.SelectorDeviceGroup
	case "identity_group":
		return appmapsession.SelectorIdentityGroup
	case "device_tag":
		return appmapsession.SelectorDeviceTag
	default:
		return appmapsession.SelectorUnknown
	}
}

// portRanges decodes the first/last port arrays of one rule.
func portRanges(firsts, lasts []int32) ([]policy.PortRange, error) {
	if len(firsts) != len(lasts) {
		return nil, ErrSnapshotEvidence
	}
	ports := make([]policy.PortRange, len(firsts))
	for index, first := range firsts {
		last := lasts[index]
		if first < 1 || first > 65535 || last < 1 || last > 65535 || last < first {
			return nil, ErrSnapshotEvidence
		}
		portRange, err := policy.NewPortRange(uint16(first), uint16(last))
		if err != nil {
			return nil, ErrSnapshotEvidence
		}
		ports[index] = portRange
	}
	return ports, nil
}
