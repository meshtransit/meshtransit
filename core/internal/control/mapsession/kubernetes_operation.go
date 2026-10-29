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
// the database clock. It returns the peer's access when allowed.
func (snapshot Snapshot) KubernetesOperation(peer node.ID, groups []string) (KubernetesAccess,
	KubernetesOperationCheck,
) {
	access, found := snapshot.kubernetes.access[peer]
	if !found || len(access.Grants) == 0 {
		return KubernetesAccess{}, KubernetesOperationNoPeer
	}
	held := false
	for _, grant := range access.Grants {
		held = held || !snapshot.deadlinePassed(grant.ValidUntil)
	}
	if !held {
		return KubernetesAccess{}, KubernetesOperationNoPeer
	}
	for _, group := range groups {
		index, granted := slices.BinarySearchFunc(access.Grants, group,
			func(grant KubernetesGrant, group string) int { return strings.Compare(grant.Group, group) })
		if !granted || snapshot.deadlinePassed(access.Grants[index].ValidUntil) {
			return KubernetesAccess{}, KubernetesOperationNotGranted
		}
	}
	access.Grants = slices.Clone(access.Grants)
	return access, KubernetesOperationAllowed
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
