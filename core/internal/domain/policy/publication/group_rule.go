package publication

import (
	"errors"
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/publicid"
)

// ErrInvalidGroupRule reports a group rule without exactly one source, one
// destination and at least one selector side.
var ErrInvalidGroupRule = errors.New("policy publication: invalid group rule")

// SideKind names what one side of a group rule selects. The values are
// part of the release semantic hash and never change.
type SideKind byte

// Rule side kinds.
const (
	SideUnknown SideKind = iota
	// SideDevice is one Device.
	SideDevice
	// SideDeviceGroup is a Network Device Group.
	SideDeviceGroup
	// SideIdentityGroup is a Workspace Identity Group: the untagged Devices
	// its members own in the Network. Sources only.
	SideIdentityGroup
	// SideDeviceTag is every Device of the Network that carries the tag.
	SideDeviceTag
)

// RuleSide is one side of a group rule.
type RuleSide struct {
	kind SideKind
	id   publicid.ID
}

// Kind returns what the side selects.
func (side RuleSide) Kind() SideKind { return side.kind }

// ID returns the selected identity.
func (side RuleSide) ID() publicid.ID { return side.id }

// NewRuleSide validates a side of a known kind.
func NewRuleSide(kind SideKind, id publicid.ID) (RuleSide, error) {
	side := RuleSide{kind: kind, id: id}
	if !side.IsValid() {
		return RuleSide{}, ErrInvalidGroupRule
	}
	return side, nil
}

// IsValid reports a known kind with a valid identity.
func (side RuleSide) IsValid() bool {
	return side.kind >= SideDevice && side.kind <= SideDeviceTag && side.id.IsValid()
}

// GroupRuleParams describes one Access Rule that selects a Device Group,
// an Identity Group or a tag on either side. Exactly one source and one
// destination are set; an Identity Group is a source only.
type GroupRuleParams struct {
	RuleID                policy.RuleID
	SourceNodeID          node.ID
	SourceGroupID         devicegroup.ID
	SourceIdentityGroupID identitygroup.ID
	SourceTagID           devicetag.ID
	DestinationNodeID     node.ID
	DestinationGroupID    devicegroup.ID
	DestinationTagID      devicetag.ID
	// DestinationKubernetesClusterID names the cluster whose own Device
	// Group DestinationGroupID is: the rule reaches every replica of the
	// cluster, on TCP 443 only.
	DestinationKubernetesClusterID kubecluster.ID
	// KubernetesGroups are the Kubernetes groups a rule to a cluster grants,
	// in any order (K1a3). None on other rules; none on a cluster rule
	// released before K1a3, which grants no group.
	KubernetesGroups      []string
	Protocol              policy.Protocol
	DestinationPortRanges []policy.PortRange
}

// GroupRule is a release fact that names selectors, not their members: maps
// resolve it from the membership, ownership and tags current at each Network
// revision.
type GroupRule struct {
	ruleID      policy.RuleID
	source      RuleSide
	destination RuleSide
	// cluster labels a destination group that is a Kubernetes cluster's
	// own; it is not part of what the release grants.
	cluster kubecluster.ID
	// kubernetesGroups are sorted, distinct and nil when there are none.
	kubernetesGroups      []string
	protocol              policy.Protocol
	destinationPortRanges []policy.PortRange
}

// oneSide returns the single set side, or an invalid side when none or
// several are set.
func oneSide(candidates ...RuleSide) RuleSide {
	var chosen RuleSide
	for _, candidate := range candidates {
		if !candidate.id.IsValid() {
			continue
		}
		if chosen.id.IsValid() {
			return RuleSide{}
		}
		chosen = candidate
	}
	return chosen
}

// NewGroupRule validates one group rule and canonicalizes its ports.
func NewGroupRule(params GroupRuleParams) (GroupRule, error) {
	ports, valid := policy.CanonicalTraffic(params.Protocol, params.DestinationPortRanges)
	rule := GroupRule{
		ruleID: params.RuleID,
		source: oneSide(
			RuleSide{SideDevice, publicid.ID(params.SourceNodeID)},
			RuleSide{SideDeviceGroup, publicid.ID(params.SourceGroupID)},
			RuleSide{SideIdentityGroup, publicid.ID(params.SourceIdentityGroupID)},
			RuleSide{SideDeviceTag, publicid.ID(params.SourceTagID)},
		),
		destination: oneSide(
			RuleSide{SideDevice, publicid.ID(params.DestinationNodeID)},
			RuleSide{SideDeviceGroup, publicid.ID(params.DestinationGroupID)},
			RuleSide{SideDeviceTag, publicid.ID(params.DestinationTagID)},
		),
		cluster:          params.DestinationKubernetesClusterID,
		kubernetesGroups: canonicalKubernetesGroups(params.KubernetesGroups),
		protocol:         params.Protocol, destinationPortRanges: ports,
	}
	if !valid || !rule.IsValid() {
		return GroupRule{}, ErrInvalidGroupRule
	}
	return rule, nil
}

// RuleID returns the Access Rule identity.
func (rule GroupRule) RuleID() policy.RuleID { return rule.ruleID }

// Source returns the source side.
func (rule GroupRule) Source() RuleSide { return rule.source }

// Destination returns the destination side.
func (rule GroupRule) Destination() RuleSide { return rule.destination }

func sideID(side RuleSide, kind SideKind) publicid.ID {
	if side.kind != kind {
		return publicid.ID{}
	}
	return side.id
}

// SourceNodeID returns the source Device, when the source is a Device.
func (rule GroupRule) SourceNodeID() node.ID { return node.ID(sideID(rule.source, SideDevice)) }

// SourceGroupID returns the source Device Group, when the source is one.
func (rule GroupRule) SourceGroupID() devicegroup.ID {
	return devicegroup.ID(sideID(rule.source, SideDeviceGroup))
}

// SourceIdentityGroupID returns the source Identity Group, when the source is one.
func (rule GroupRule) SourceIdentityGroupID() identitygroup.ID {
	return identitygroup.ID(sideID(rule.source, SideIdentityGroup))
}

// SourceTagID returns the source tag, when the source is a tag.
func (rule GroupRule) SourceTagID() devicetag.ID {
	return devicetag.ID(sideID(rule.source, SideDeviceTag))
}

// DestinationNodeID returns the destination Device, when it is a Device.
func (rule GroupRule) DestinationNodeID() node.ID {
	return node.ID(sideID(rule.destination, SideDevice))
}

// DestinationGroupID returns the destination Device Group, when it is one.
func (rule GroupRule) DestinationGroupID() devicegroup.ID {
	return devicegroup.ID(sideID(rule.destination, SideDeviceGroup))
}

// DestinationTagID returns the destination tag, when it is a tag.
func (rule GroupRule) DestinationTagID() devicetag.ID {
	return devicetag.ID(sideID(rule.destination, SideDeviceTag))
}

// DestinationKubernetesClusterID returns the cluster whose own group the
// destination is, when it is one.
func (rule GroupRule) DestinationKubernetesClusterID() kubecluster.ID { return rule.cluster }

// KubernetesGroups returns the sorted Kubernetes groups a rule to a cluster
// grants, nil when it grants none.
func (rule GroupRule) KubernetesGroups() []string { return slices.Clone(rule.kubernetesGroups) }

// canonicalKubernetesGroups sorts a copy of groups, nil when there are none.
// Validity is checked by IsValid, so duplicates stay to be refused, and so
// does a non-nil empty list: none is nil, never an empty list given.
func canonicalKubernetesGroups(groups []string) []string {
	if groups == nil {
		return nil
	}
	sorted := slices.Clone(groups)
	slices.Sort(sorted)
	return sorted
}

// validKubernetesGroups reports nil, or 1 to 16 distinct sorted valid names.
func validKubernetesGroups(groups []string) bool {
	if groups == nil {
		return true
	}
	if len(groups) == 0 || len(groups) > kubecluster.MaximumRuleKubernetesGroups {
		return false
	}
	for index, group := range groups {
		if !kubecluster.ValidKubernetesGroup(group) || index > 0 && groups[index-1] >= group {
			return false
		}
	}
	return true
}

// Protocol returns the packet protocol.
func (rule GroupRule) Protocol() policy.Protocol { return rule.protocol }

// DestinationPortRanges returns caller-owned canonical port ranges.
func (rule GroupRule) DestinationPortRanges() []policy.PortRange {
	return slices.Clone(rule.destinationPortRanges)
}

// IsValid reports exactly one source and one destination, at least one
// selector side, an Identity Group only as a source, canonical traffic, and
// for a Kubernetes cluster's group, TCP 443 only and at most 16 sorted
// distinct Kubernetes groups, which no other rule names.
func (rule GroupRule) IsValid() bool {
	if !rule.ruleID.IsValid() || !rule.source.IsValid() || !rule.destination.IsValid() ||
		rule.destination.kind == SideIdentityGroup ||
		(rule.source.kind == SideDevice && rule.destination.kind == SideDevice) {
		return false
	}
	if rule.cluster != (kubecluster.ID{}) && (!rule.cluster.IsValid() ||
		rule.destination.kind != SideDeviceGroup || !policy.IsKubernetesTraffic(rule.protocol, rule.destinationPortRanges)) {
		return false
	}
	if !validKubernetesGroups(rule.kubernetesGroups) ||
		rule.kubernetesGroups != nil && rule.cluster == (kubecluster.ID{}) {
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
		cloned[index].kubernetesGroups = slices.Clone(rule.kubernetesGroups)
	}
	return cloned
}
