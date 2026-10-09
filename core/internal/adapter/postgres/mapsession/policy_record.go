package mapsession

import (
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
	ports := make([]policy.PortRange, len(record.portRangeFirst))
	for index, first := range record.portRangeFirst {
		last := record.portRangeLast[index]
		if first < 1 || first > 65535 || last < 1 || last > 65535 || last < first {
			return policy.Rule{}, ErrSnapshotEvidence
		}
		firstPort := uint16(first)
		lastPort := uint16(last)
		portRange, rangeErr := policy.NewPortRange(firstPort, lastPort)
		if rangeErr != nil {
			return policy.Rule{}, ErrSnapshotEvidence
		}
		ports[index] = portRange
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
