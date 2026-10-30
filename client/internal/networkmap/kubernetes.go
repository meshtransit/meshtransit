package networkmap

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"time"

	"meshtransit.net/shared/kubeprofile"
)

// maxKubernetesGrants bounds a peer's grants across both lists: one
// cluster's rules grant at most 64 (K1a3 §3.1, mtcp-v1 §7.12).
const maxKubernetesGrants = 64

// KubernetesAccess is what a Kubernetes gateway's map says a peer may do in
// the gateway's cluster (mtcp-v1 §7.8): the groups it holds, each until a
// deadline, its owner by reference and when it last changed owner (zero:
// never). Only a gateway that negotiated gateway.kube.v1 gets it, and only
// on peers of its own Network.
type KubernetesAccess struct {
	// Grants are the groups the peer holds whole.
	Grants []KubernetesGrant
	// Scoped are the groups an access profile narrows (mtcp-v1 §7.12), only
	// for a gateway that takes profiles. Never the whole group.
	Scoped         []KubernetesScopedGrant
	OwnerRef       string
	OwnerChangedAt time.Time
}

// KubernetesGrant is one group a peer holds until ValidUntil.
type KubernetesGrant struct {
	Group      string
	ValidUntil time.Time
}

// KubernetesScopedGrant is a group as one rule narrows it, until
// ValidUntil: by the map's scope named Scope; Report lets the whole group
// through until ReportUntil, counting what the profile would deny.
type KubernetesScopedGrant struct {
	Group       string
	Scope       [32]byte
	Report      bool
	ReportUntil time.Time
	ValidUntil  time.Time
}

// KubernetesScope is a scope of a gateway's map (mtcp-v1 §7.12): the
// profile it applies, by hash and name, as one rule applies it.
type KubernetesScope struct {
	ProfileHash [32]byte
	ProfileName string
	Scope       kubeprofile.Scope
}

// GroupsAt returns the groups the peer holds whole at now, sorted: a grant
// past its deadline is honoured no more, whatever Core sends next. Scoped
// grants are never among them.
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

// WholeAt reports whether the peer holds group whole at now.
func (access *KubernetesAccess) WholeAt(now time.Time, group string) bool {
	if access == nil {
		return false
	}
	return slices.ContainsFunc(access.Grants, func(grant KubernetesGrant) bool {
		return grant.Group == group && now.Before(grant.ValidUntil)
	})
}

// ScopedAt returns group's scoped grants in force at now, in key order.
func (access *KubernetesAccess) ScopedAt(now time.Time, group string) []KubernetesScopedGrant {
	if access == nil {
		return nil
	}
	var grants []KubernetesScopedGrant
	for _, grant := range access.Scoped {
		if grant.Group == group && now.Before(grant.ValidUntil) {
			grants = append(grants, grant)
		}
	}
	return grants
}

// HeldAt returns the groups the peer holds at now, whole or through a
// scoped grant, sorted and distinct.
func (access *KubernetesAccess) HeldAt(now time.Time) []string {
	groups := access.GroupsAt(now)
	if access == nil {
		return groups
	}
	for _, grant := range access.Scoped {
		if now.Before(grant.ValidUntil) {
			groups = append(groups, grant.Group)
		}
	}
	slices.Sort(groups)
	return slices.Compact(groups)
}

// CheckKubernetesAccess reports what is wrong with a peer's access, if
// anything: one to 64 grants across both lists; whole grants sorted,
// distinct groups; scoped grants strictly sorted by key (mtcp-v1 §7.12);
// each group a DNS label with a deadline; and an owner that is the Workspace
// (empty), a member's public ID or "tags:" and up to 256 sorted tag IDs
// (mtcp-v1 §7.8).
func CheckKubernetesAccess(access *KubernetesAccess) error {
	if access == nil {
		return nil
	}
	if count := len(access.Grants) + len(access.Scoped); count == 0 || count > maxKubernetesGrants {
		return errors.New("kubernetes grant count is invalid")
	}
	for index, grant := range access.Scoped {
		if !ValidKubernetesGroup(grant.Group) || grant.ValidUntil.IsZero() ||
			index > 0 && compareScopedGrants(access.Scoped[index-1], grant) >= 0 {
			return errors.New("kubernetes scoped grant is invalid")
		}
	}
	for index, grant := range access.Grants {
		if !ValidKubernetesGroup(grant.Group) || grant.ValidUntil.IsZero() ||
			index > 0 && access.Grants[index-1].Group >= grant.Group {
			return errors.New("kubernetes grant is invalid")
		}
	}
	if !validKubernetesOwner(access.OwnerRef) {
		return errors.New("kubernetes owner is invalid")
	}
	return nil
}

// compareScopedGrants orders scoped grants by their key (mtcp-v1 §7.12):
// group, scope bytewise, enforcing before reporting, report deadline.
func compareScopedGrants(left, right KubernetesScopedGrant) int {
	if order := strings.Compare(left.Group, right.Group); order != 0 {
		return order
	}
	if order := bytes.Compare(left.Scope[:], right.Scope[:]); order != 0 {
		return order
	}
	if left.Report != right.Report {
		if left.Report {
			return 1
		}
		return -1
	}
	return left.ReportUntil.Compare(right.ReportUntil)
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

// ValidKubernetesGroup accepts one DNS label: lowercase letters, digits and
// inner hyphens, at most 63 bytes.
func ValidKubernetesGroup(group string) bool {
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
	cloned.Scoped = slices.Clone(access.Scoped)
	return &cloned
}

// KubernetesCA is what a gateway's map names of its cluster's CAs (mtcp-v1
// §7.10): the SHA-256 of the root's DER and of the intermediate that signs
// now, each empty when there is none, and the map's revision of the
// gateway's Network, which says how recent the map is.
type KubernetesCA struct {
	Root, Signing []byte
	MapRevision   uint64
}

// CheckKubernetesCA reports fingerprints of 32 bytes or none, and no
// intermediate without a root.
func CheckKubernetesCA(ca *KubernetesCA) error {
	if ca == nil {
		return nil
	}
	if len(ca.Root) != 0 && len(ca.Root) != 32 || len(ca.Signing) != 0 && len(ca.Signing) != 32 ||
		len(ca.Signing) != 0 && len(ca.Root) == 0 {
		return errors.New("networkmap: invalid Kubernetes CA fingerprints")
	}
	return nil
}
