package mapsession

import (
	"slices"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
)

// KubernetesOwnerKind names who owns a Device, for the gateway of a cluster
// (K1a3 §4.1).
type KubernetesOwnerKind uint8

// Owner kinds.
const (
	KubernetesOwnerUnknown KubernetesOwnerKind = iota
	// KubernetesOwnerMember is a member's Device: its access rests on the
	// member's Workspace and Network memberships.
	KubernetesOwnerMember
	// KubernetesOwnerTags is a Device its tags speak for.
	KubernetesOwnerTags
	// KubernetesOwnerWorkspace is a Device of the Workspace itself.
	KubernetesOwnerWorkspace
)

// KubernetesSource is what a Device's Kubernetes access rests on beyond the
// policy: its owner, whether that owner is still a member and until when,
// when it last changed owner, and whether it forwards traffic for others.
// It is read only for a Network that has a cluster.
type KubernetesSource struct {
	Device    int64
	OwnerKind KubernetesOwnerKind
	// OwnerRef is the member's public ID, or "tags:" and the sorted tag IDs;
	// empty for the Workspace.
	OwnerRef string
	// MemberOwned reports a Device a member owns, tagged or not: its access
	// rests on that member whatever its tags say (§4.4). OwnerActive then
	// reports the member's active Workspace and Network memberships, and
	// OwnerValidUntil the earlier of their ends, zero for none; both are
	// unset for a Device of the Workspace.
	MemberOwned     bool
	OwnerActive     bool
	OwnerValidUntil time.Time
	// OwnerChangedAt is when the Device last changed owner; zero: never.
	OwnerChangedAt time.Time
	// Forwards reports a router of a Site or an exit node, in any state:
	// the Devices behind it would inherit its access (K1-I5).
	Forwards bool
}

// KubernetesGrant is one Kubernetes group a peer holds, until ValidUntil.
type KubernetesGrant struct {
	Group      string
	ValidUntil time.Time
}

// KubernetesAccess is what a cluster's gateway knows of one peer: the groups
// it holds, sorted, and its owner.
type KubernetesAccess struct {
	Grants         []KubernetesGrant
	OwnerKind      KubernetesOwnerKind
	OwnerRef       string
	OwnerChangedAt time.Time
}

func (source KubernetesSource) valid() bool {
	if source.Device <= 0 || !source.MemberOwned && (source.OwnerActive || !source.OwnerValidUntil.IsZero()) {
		return false
	}
	switch source.OwnerKind {
	case KubernetesOwnerMember:
		return source.MemberOwned && source.OwnerRef != ""
	case KubernetesOwnerTags:
		return strings.HasPrefix(source.OwnerRef, "tags:")
	case KubernetesOwnerWorkspace:
		return !source.MemberOwned && source.OwnerRef == ""
	default:
		return false
	}
}

// validRuleKubernetesGroups reports nil, or 1 to 16 sorted distinct groups
// on a rule to a Device Group (a cluster's own).
func validRuleKubernetesGroups(rule NetworkPolicyRule) bool {
	if rule.KubernetesGroups == nil {
		return true
	}
	if rule.DestinationKind != SelectorDeviceGroup || len(rule.KubernetesGroups) == 0 ||
		len(rule.KubernetesGroups) > kubecluster.MaximumRuleKubernetesGroups {
		return false
	}
	for index, group := range rule.KubernetesGroups {
		if !kubecluster.ValidKubernetesGroup(group) || index > 0 && rule.KubernetesGroups[index-1] >= group {
			return false
		}
	}
	return true
}

// KubernetesAccessFor returns, for a cluster gateway, the Kubernetes access
// of each peer whose edges to it a rule naming groups emits at now: exactly
// the edges For emits, so the packet filter and the access agree (K1a3
// §4.3). A grant lasts until the earliest deadline on the path it came by
// (the selector membership, the peer's own expiry, its owner's membership);
// the latest such path wins per group. A peer without source evidence, one
// that forwards for others, or a member's Device, tagged or not, whose owner
// is no longer an active member gets nothing (§4.4, §12.2, §13.5). A rule
// counts only when every live member of its destination group is a replica
// of the gateway's own cluster (replica): a cluster's group holds nothing
// else (TD-CORE-100). Nil for a Device that no such rule reaches.
func (networkPolicy NetworkPolicy) KubernetesAccessFor(gateway node.ID, replica func(node.ID) bool,
	now time.Time) map[node.ID]KubernetesAccess {
	inner := networkPolicy.inner
	if inner == nil || !inner.releaseActive || len(inner.sources) == 0 || replica == nil {
		return nil
	}
	self, known := inner.byNode[gateway]
	if !known || !inner.live(self, now) {
		return nil
	}
	grants := make(map[int64]map[string]time.Time)
	for _, rule := range inner.rules {
		if rule.KubernetesGroups == nil || !inner.selects(rule.DestinationKind, rule.DestinationRef, self, now) ||
			!inner.onlyReplicas(rule.DestinationRef, replica, now) {
			continue
		}
		inner.eachSelectedUntil(rule.SourceKind, rule.SourceRef, now, func(peer int64, selectedUntil time.Time) {
			source, found := inner.sources[peer]
			if peer == self || !found || source.Forwards || !inner.live(peer, now) ||
				source.MemberOwned && !source.OwnerActive {
				return
			}
			deadline := inner.devices[peer].ExpiresAt
			for _, limit := range []time.Time{selectedUntil, source.OwnerValidUntil} {
				if !limit.IsZero() && limit.Before(deadline) {
					deadline = limit
				}
			}
			if !now.Before(deadline) {
				return
			}
			if grants[peer] == nil {
				grants[peer] = make(map[string]time.Time)
			}
			for _, group := range rule.KubernetesGroups {
				if held, granted := grants[peer][group]; !granted || deadline.After(held) {
					grants[peer][group] = deadline
				}
			}
		})
	}
	if len(grants) == 0 {
		return nil
	}
	access := make(map[node.ID]KubernetesAccess, len(grants))
	for peer, groups := range grants {
		source := inner.sources[peer]
		entry := KubernetesAccess{Grants: make([]KubernetesGrant, 0, len(groups)), OwnerKind: source.OwnerKind,
			OwnerRef: source.OwnerRef, OwnerChangedAt: source.OwnerChangedAt}
		for group, until := range groups {
			entry.Grants = append(entry.Grants, KubernetesGrant{Group: group, ValidUntil: until})
		}
		slices.SortFunc(entry.Grants, compareKubernetesGrants)
		access[inner.devices[peer].NodeID] = entry
	}
	return access
}

// onlyReplicas reports whether every live member of Device group group is
// a replica.
func (inner *networkPolicy) onlyReplicas(group int64, replica func(node.ID) bool, now time.Time) bool {
	for _, entry := range inner.members[selectorKey{kind: SelectorDeviceGroup, id: group}] {
		if (entry.validUntil.IsZero() || now.Before(entry.validUntil)) && inner.live(entry.device, now) &&
			!replica(inner.devices[entry.device].NodeID) {
			return false
		}
	}
	return true
}

// eachSelectedUntil visits every Device one rule side selects at now, with
// the end of its selection (zero: none).
func (inner *networkPolicy) eachSelectedUntil(kind SelectorKind, ref int64, now time.Time,
	visit func(int64, time.Time)) {
	if kind == SelectorDevice {
		visit(ref, time.Time{})
		return
	}
	for _, entry := range inner.members[selectorKey{kind: kind, id: ref}] {
		if entry.validUntil.IsZero() || now.Before(entry.validUntil) {
			visit(entry.device, entry.validUntil)
		}
	}
}

// equalKubernetesSources compares two reads of the same Network's sources.
func equalKubernetesSources(left, right []KubernetesSource) bool {
	return slices.EqualFunc(left, right, func(first, second KubernetesSource) bool {
		return first.Device == second.Device && first.OwnerKind == second.OwnerKind &&
			first.OwnerRef == second.OwnerRef && first.MemberOwned == second.MemberOwned &&
			first.OwnerActive == second.OwnerActive &&
			first.OwnerValidUntil.Equal(second.OwnerValidUntil) && first.OwnerChangedAt.Equal(second.OwnerChangedAt) &&
			first.Forwards == second.Forwards
	})
}
