package postgres

import (
	"encoding/json"
	"errors"
	"net/netip"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/site"
)

const attachPolicyRouteRulesSQL = `SELECT mesh_ops.attach_policy_route_rules_v1(
    $1::UUID,
    $2::TIMESTAMPTZ,
    $3::JSONB
)`

// errInvalidRouteRulePayload reports a stored or encoded route rule that does
// not decode to a valid rule.
var errInvalidRouteRulePayload = errors.New("postgres: invalid route rule payload")

// policyRouteRulePayload is one route rule as attach_policy_route_rules_v1
// takes it and the simulation baseline returns it.
type policyRouteRulePayload struct {
	ProjectionPublicID          string   `json:"projection_public_id"`
	AccessRulePublicID          string   `json:"access_rule_public_id"`
	SourceNodePublicID          string   `json:"source_node_public_id,omitempty"`
	SourceDeviceGroupPublicID   string   `json:"source_device_group_public_id,omitempty"`
	SourceIdentityGroupPublicID string   `json:"source_identity_group_public_id,omitempty"`
	SourceDeviceTagPublicID     string   `json:"source_device_tag_public_id,omitempty"`
	SitePublicID                string   `json:"site_public_id"`
	Prefixes                    []string `json:"prefixes"`
	Protocol                    string   `json:"protocol"`
	PortRangeFirst              []int    `json:"port_range_first"`
	PortRangeLast               []int    `json:"port_range_last"`
}

// encodePolicyRouteRules encodes the candidate's route rules for
// attach_policy_route_rules_v1, using the projection identities that follow
// the Device pairs, Imported Resource selectors and group rules. Nil means
// none.
func encodePolicyRouteRules(change publication.Change) ([]byte, error) {
	candidate := change.Command().Candidate()
	routeRules := candidate.RouteRules()
	if len(routeRules) == 0 {
		return nil, nil
	}
	projectionIDs := change.MutationIDs().ProjectionIDs()
	offset := len(candidate.Snapshot().Rules()) + len(candidate.ImportedResourceDestinations()) +
		len(candidate.GroupRules())
	if len(projectionIDs) != offset+len(routeRules) {
		return nil, ErrPolicyPublicationEvidence
	}
	payload := make([]policyRouteRulePayload, len(routeRules))
	for index, rule := range routeRules {
		ports := rule.DestinationPortRanges()
		first, last := make([]int, len(ports)), make([]int, len(ports))
		for portIndex, portRange := range ports {
			first[portIndex], last[portIndex] = int(portRange.First()), int(portRange.Last())
		}
		prefixes := make([]string, 0, len(rule.Prefixes()))
		for _, prefix := range rule.Prefixes() {
			prefixes = append(prefixes, prefix.String())
		}
		item := policyRouteRulePayload{
			ProjectionPublicID: projectionIDs[offset+index].String(), AccessRulePublicID: rule.RuleID().String(),
			SitePublicID: rule.SiteID().String(), Prefixes: prefixes,
			Protocol: rule.Protocol().String(), PortRangeFirst: first, PortRangeLast: last,
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

// decodePolicyRouteRules rebuilds route rules from the attach payload shape.
func decodePolicyRouteRules(payloads []policyRouteRulePayload) ([]publication.RouteRule, error) {
	rules := make([]publication.RouteRule, 0, len(payloads))
	for _, payload := range payloads {
		ruleID, err := policy.ParseRuleID(payload.AccessRulePublicID)
		siteID, siteErr := site.ParseID(payload.SitePublicID)
		if err != nil || siteErr != nil || len(payload.PortRangeFirst) != len(payload.PortRangeLast) {
			return nil, errInvalidRouteRulePayload
		}
		params := publication.RouteRuleParams{RuleID: ruleID, SiteID: siteID,
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
		for _, text := range payload.Prefixes {
			prefix, prefixErr := netip.ParsePrefix(text)
			parseErrs = append(parseErrs, prefixErr)
			params.Prefixes = append(params.Prefixes, prefix)
		}
		for index := range payload.PortRangeFirst {
			first, last := payload.PortRangeFirst[index], payload.PortRangeLast[index]
			if first < 0 || first > 65535 || last < 0 || last > 65535 {
				return nil, errInvalidRouteRulePayload
			}
			portRange, rangeErr := policy.NewPortRange(uint16(first), uint16(last))
			parseErrs = append(parseErrs, rangeErr)
			params.DestinationPortRanges = append(params.DestinationPortRanges, portRange)
		}
		if params.DestinationPortRanges == nil {
			params.DestinationPortRanges = []policy.PortRange{}
		}
		if errors.Join(parseErrs...) != nil {
			return nil, errInvalidRouteRulePayload
		}
		rule, err := publication.NewRouteRule(params)
		if err != nil {
			return nil, errInvalidRouteRulePayload
		}
		rules = append(rules, rule)
	}
	return rules, nil
}
