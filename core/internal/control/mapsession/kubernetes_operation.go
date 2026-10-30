package mapsession

import (
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/node"
)

// KubernetesOperationCheck is what a gateway's map says of a peer's
// Kubernetes operation (K1b0 §3.3).
type KubernetesOperationCheck uint8

// Checks.
const (
	// KubernetesOperationAllowed: the peer holds every group, unexpired.
	KubernetesOperationAllowed KubernetesOperationCheck = iota
	// KubernetesOperationNoPeer: the map gives the peer no access.
	KubernetesOperationNoPeer
	// KubernetesOperationNotGranted: a group is not the peer's, or expired.
	KubernetesOperationNotGranted
)

// KubernetesOperation checks a peer's operation under groups against the
// map sent: the peer must hold access, and each group a grant unexpired on
// the database clock, whole or narrowed by a profile (K2: the gateway let
// it through by that profile). It returns the peer's access when allowed.
func (snapshot Snapshot) KubernetesOperation(peer node.ID, groups []string) (KubernetesAccess,
	KubernetesOperationCheck,
) {
	access, found := snapshot.kubernetes.access[peer]
	if !found || len(access.Grants)+len(access.ScopedGrants) == 0 {
		return KubernetesAccess{}, KubernetesOperationNoPeer
	}
	held := false
	for _, grant := range access.Grants {
		held = held || !snapshot.deadlinePassed(grant.ValidUntil)
	}
	for _, grant := range access.ScopedGrants {
		held = held || !snapshot.deadlinePassed(grant.ValidUntil)
	}
	if !held {
		return KubernetesAccess{}, KubernetesOperationNoPeer
	}
	for _, group := range groups {
		if !snapshot.holdsKubernetesGroup(access, group) {
			return KubernetesAccess{}, KubernetesOperationNotGranted
		}
	}
	access.Grants = slices.Clone(access.Grants)
	access.ScopedGrants = slices.Clone(access.ScopedGrants)
	return access, KubernetesOperationAllowed
}

// holdsKubernetesGroup reports a whole or scoped grant of group, unexpired.
func (snapshot Snapshot) holdsKubernetesGroup(access KubernetesAccess, group string) bool {
	index, granted := slices.BinarySearchFunc(access.Grants, group,
		func(grant KubernetesGrant, group string) int { return strings.Compare(grant.Group, group) })
	if granted && !snapshot.deadlinePassed(access.Grants[index].ValidUntil) {
		return true
	}
	return slices.ContainsFunc(access.ScopedGrants, func(grant KubernetesScopedGrant) bool {
		return grant.Group == group && !snapshot.deadlinePassed(grant.ValidUntil)
	})
}

// KubernetesScopeHeld reports whether the peer's access in the map sent
// holds a scoped grant of group in scope, unexpired, and reporting when
// report: what an audit intent's profile must name (mtcp-v1 §7.12).
func (snapshot Snapshot) KubernetesScopeHeld(peer node.ID, group string, scope [32]byte, report bool) bool {
	access, found := snapshot.kubernetes.access[peer]
	return found && slices.ContainsFunc(access.ScopedGrants, func(grant KubernetesScopedGrant) bool {
		return grant.Group == group && grant.Scope == scope && (!report || grant.Report) &&
			!snapshot.deadlinePassed(grant.ValidUntil)
	})
}

// KubernetesWholeHeld reports whether the peer's access in the map sent
// holds the whole of group, unexpired: what an audit intent without a
// profile must rest on, from a gateway that takes profiles (§7.12).
func (snapshot Snapshot) KubernetesWholeHeld(peer node.ID, group string) bool {
	access, found := snapshot.kubernetes.access[peer]
	if !found {
		return false
	}
	index, granted := slices.BinarySearchFunc(access.Grants, group,
		func(grant KubernetesGrant, group string) int { return strings.Compare(grant.Group, group) })
	return granted && !snapshot.deadlinePassed(access.Grants[index].ValidUntil)
}

// String names an owner kind as the schema stores it: member, tags or
// workspace; empty for unknown.
func (kind KubernetesOwnerKind) String() string {
	switch kind {
	case KubernetesOwnerMember:
		return "member"
	case KubernetesOwnerTags:
		return "tags"
	case KubernetesOwnerWorkspace:
		return "workspace"
	}
	return ""
}
