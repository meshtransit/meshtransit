package postgres

import (
	"encoding/json"
	"errors"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
)

const attachPolicyExitRulesSQL = `SELECT mesh_ops.attach_policy_exit_rules_v1(
    $1::UUID,
    $2::TIMESTAMPTZ,
    $3::JSONB
)`

// errInvalidExitRulePayload reports a stored or encoded exit rule that does
// not decode to a valid rule.
var errInvalidExitRulePayload = errors.New("postgres: invalid exit rule payload")

// policyExitRulePayload is one exit rule as attach_policy_exit_rules_v1
// takes it and the simulation baseline returns it.
type policyExitRulePayload struct {
	ProjectionPublicID          string `json:"projection_public_id"`
	AccessRulePublicID          string `json:"access_rule_public_id"`
	SourceNodePublicID          string `json:"source_node_public_id,omitempty"`
	SourceDeviceGroupPublicID   string `json:"source_device_group_public_id,omitempty"`
	SourceIdentityGroupPublicID string `json:"source_identity_group_public_id,omitempty"`
	SourceDeviceTagPublicID     string `json:"source_device_tag_public_id,omitempty"`
	ExitPoolPublicID            string `json:"exit_pool_public_id"`
	Protocol                    string `json:"protocol"`
	PortRangeFirst              []int  `json:"port_range_first"`
	PortRangeLast               []int  `json:"port_range_last"`
}

// encodePolicyExitRules encodes the candidate's exit rules for
// attach_policy_exit_rules_v1, using the projection identities that follow
// the Device pairs, Imported Resource selectors, group rules and route
// rules. Nil means none.
func encodePolicyExitRules(change publication.Change) ([]byte, error) {
	candidate := change.Command().Candidate()
	exitRules := candidate.ExitRules()
	if len(exitRules) == 0 {
		return nil, nil
	}
	projectionIDs := change.MutationIDs().ProjectionIDs()
	offset := len(candidate.Snapshot().Rules()) + len(candidate.ImportedResourceDestinations()) +
		len(candidate.GroupRules()) + len(candidate.RouteRules())
	// Every projection of the release has an identity; this kind's follow
	// the kinds before it.
	if len(projectionIDs) != candidate.ProjectionCount() {
		return nil, ErrPolicyPublicationEvidence
	}
	payload := make([]policyExitRulePayload, len(exitRules))
	for index, rule := range exitRules {
		ports := rule.DestinationPortRanges()
		first, last := make([]int, len(ports)), make([]int, len(ports))
		for portIndex, portRange := range ports {
			first[portIndex], last[portIndex] = int(portRange.First()), int(portRange.Last())
		}
		item := policyExitRulePayload{
			ProjectionPublicID: projectionIDs[offset+index].String(), AccessRulePublicID: rule.RuleID().String(),
			ExitPoolPublicID: rule.PoolID().String(), Protocol: rule.Protocol().String(),
			PortRangeFirst: first, PortRangeLast: last,
		}
		source := rule.Source()
		switch source.Kind() {
		case publication.SideDeviceGroup:
			item.SourceDeviceGroupPublicID = source.ID().String()
		case publication.SideIdentityGroup:
			item.SourceIdentityGroupPublicID = source.ID().String()
		case publication.SideDeviceTag:
			item.SourceDeviceTagPublicID = source.ID().String()
		default:
			item.SourceNodePublicID = source.ID().String()
		}
		payload[index] = item
	}
	return json.Marshal(payload)
}

// decodePolicyExitRules rebuilds exit rules from the attach payload shape.
func decodePolicyExitRules(payloads []policyExitRulePayload) ([]publication.ExitRule, error) {
	rules := make([]publication.ExitRule, 0, len(payloads))
	for _, payload := range payloads {
		ruleID, err := policy.ParseRuleID(payload.AccessRulePublicID)
		poolID, poolErr := exitpool.ParseID(payload.ExitPoolPublicID)
		if err != nil || poolErr != nil || len(payload.PortRangeFirst) != len(payload.PortRangeLast) {
			return nil, errInvalidExitRulePayload
		}
		params := publication.ExitRuleParams{RuleID: ruleID, PoolID: poolID,
			Protocol: parsePolicyRuleProtocol(payload.Protocol)}
		var parseErrs []error
		if payload.SourceNodePublicID != "" {
			params.SourceNodeID, err = node.ParseID(payload.SourceNodePublicID)
			parseErrs = append(parseErrs, err)
		}
		if payload.SourceDeviceGroupPublicID != "" {
			params.SourceGroupID, err = devicegroup.ParseID(payload.SourceDeviceGroupPublicID)
			parseErrs = append(parseErrs, err)
		}
		if payload.SourceIdentityGroupPublicID != "" {
			params.SourceIdentityGroupID, err = identitygroup.ParseID(payload.SourceIdentityGroupPublicID)
			parseErrs = append(parseErrs, err)
		}
		if payload.SourceDeviceTagPublicID != "" {
			params.SourceTagID, err = devicetag.ParseID(payload.SourceDeviceTagPublicID)
			parseErrs = append(parseErrs, err)
		}
		for index := range payload.PortRangeFirst {
			first, last := payload.PortRangeFirst[index], payload.PortRangeLast[index]
			if first < 0 || first > 65535 || last < 0 || last > 65535 {
				return nil, errInvalidExitRulePayload
			}
			portRange, rangeErr := policy.NewPortRange(uint16(first), uint16(last))
			parseErrs = append(parseErrs, rangeErr)
			params.DestinationPortRanges = append(params.DestinationPortRanges, portRange)
		}
		if params.DestinationPortRanges == nil {
			params.DestinationPortRanges = []policy.PortRange{}
		}
		if errors.Join(parseErrs...) != nil {
			return nil, errInvalidExitRulePayload
		}
		rule, err := publication.NewExitRule(params)
		if err != nil {
			return nil, errInvalidExitRulePayload
		}
		rules = append(rules, rule)
	}
	return rules, nil
}
