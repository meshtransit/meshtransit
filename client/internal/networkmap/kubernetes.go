package networkmap

import (
	"errors"
	"slices"
	"strings"
	"time"
)

// maxKubernetesGrants bounds a peer's groups: one cluster's rules grant at
// most 64 (K1a3 §3.1).
const maxKubernetesGrants = 64

// KubernetesAccess is what a Kubernetes gateway's map says a peer may do in
// the gateway's cluster (mtcp-v1 §7.8): the groups it holds, each until a
// deadline, its owner by reference and when it last changed owner (zero:
// never). Only a gateway that negotiated gateway.kube.v1 gets it, and only
// on peers of its own Network.
type KubernetesAccess struct {
	Grants         []KubernetesGrant
	OwnerRef       string
	OwnerChangedAt time.Time
}

// KubernetesGrant is one group a peer holds until ValidUntil.
type KubernetesGrant struct {
	Group      string
	ValidUntil time.Time
}

// GroupsAt returns the groups the peer holds at now, sorted: a grant past its
// deadline is honoured no more, whatever Core sends next.
func (access *KubernetesAccess) GroupsAt(now time.Time) []string {
	if access == nil {
		return nil
	}
	groups := make([]string, 0, len(access.Grants))
	for _, grant := range access.Grants {
		if now.Before(grant.ValidUntil) {
			groups = append(groups, grant.Group)
		}
	}
	return groups
}

// CheckKubernetesAccess reports what is wrong with a peer's access, if
// anything: one to 64 sorted, distinct groups, each a DNS label with a
// deadline, and an owner that is the Workspace (empty), a member's public ID
// or "tags:" and up to 256 sorted tag IDs (mtcp-v1 §7.8).
func CheckKubernetesAccess(access *KubernetesAccess) error {
	if access == nil {
		return nil
	}
	if len(access.Grants) == 0 || len(access.Grants) > maxKubernetesGrants {
		return errors.New("kubernetes grant count is invalid")
	}
	for index, grant := range access.Grants {
		if !validKubernetesGroup(grant.Group) || grant.ValidUntil.IsZero() ||
			index > 0 && access.Grants[index-1].Group >= grant.Group {
			return errors.New("kubernetes grant is invalid")
		}
	}
	if !validKubernetesOwner(access.OwnerRef) {
		return errors.New("kubernetes owner is invalid")
	}
	return nil
}

// maxKubernetesOwnerTags bounds the tags an owner reference lists.
const maxKubernetesOwnerTags = 256

func validKubernetesOwner(owner string) bool {
	tags, tagged := strings.CutPrefix(owner, "tags:")
	if !tagged {
		return owner == "" || validPublicID(owner)
	}
	ids := strings.Split(tags, ",")
	if len(ids) > maxKubernetesOwnerTags {
		return false
	}
	for index, id := range ids {
		if !validPublicID(id) || index > 0 && ids[index-1] >= id {
			return false
		}
	}
	return true
}

// validPublicID accepts a canonical lowercase UUID.
func validPublicID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for index := range len(id) {
		character := id[index]
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
				return false
			}
		}
	}
	return true
}

// validKubernetesGroup accepts one DNS label: lowercase letters, digits and
// inner hyphens, at most 63 bytes.
func validKubernetesGroup(group string) bool {
	if group == "" || len(group) > 63 || group[0] == '-' || group[len(group)-1] == '-' {
		return false
	}
	for index := range len(group) {
		character := group[index]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

// CloneKubernetesAccess returns a copy that shares nothing with access.
func CloneKubernetesAccess(access *KubernetesAccess) *KubernetesAccess {
	if access == nil {
		return nil
	}
	cloned := *access
	cloned.Grants = slices.Clone(access.Grants)
	return &cloned
}
