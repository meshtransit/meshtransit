package mapsession

import (
	"bytes"
	"cmp"
	"slices"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/kubeprofile"
)

// MaximumKubernetesPeerGrants bounds one peer's grants across both lists,
// after merging (mtcp-v1 §7.12): a peer past it has no Kubernetes access.
const MaximumKubernetesPeerGrants = 64

// KubernetesRuleAccess is how a rule to a cluster narrows its groups (K2):
// a profile of the release, by content hash, applied in Namespaces with or
// without its cluster part, enforcing or reporting until ReportUntil.
// ScopeHash is what gateways name the scope by; NewNetworkPolicy checks it.
type KubernetesRuleAccess struct {
	ProfileHash [32]byte
	ScopeHash   [32]byte
	Namespaces  []string
	ClusterPart bool
	Report      bool
	ReportUntil time.Time
}

// KubernetesProfile is a profile a gateway's table may hold: its content
// hash, its ID (shown only) and its rules.
type KubernetesProfile struct {
	Hash    [32]byte
	ID      string
	Profile kubeprofile.Profile
}

// KubernetesScope is a profile as a rule applies it, by hash.
type KubernetesScope struct {
	Hash        [32]byte
	Profile     [32]byte
	Namespaces  []string
	ClusterPart bool
}

// KubernetesScopeTable is every profile and scope of the release of a
// gateway's cluster (mtcp-v1 §7.12), each list sorted by hash.
type KubernetesScopeTable struct {
	Profiles []KubernetesProfile
	Scopes   []KubernetesScope
}

// KubernetesScopedGrant is one group as a rule narrows it, until
// ValidUntil; a reporting grant lets the whole group through until
// ReportUntil, never later than ValidUntil.
type KubernetesScopedGrant struct {
	Group       string
	Scope       [32]byte
	Report      bool
	ReportUntil time.Time
	ValidUntil  time.Time
}

func (access *KubernetesRuleAccess) clone() *KubernetesRuleAccess {
	if access == nil {
		return nil
	}
	cloned := *access
	cloned.Namespaces = slices.Clone(access.Namespaces)
	return &cloned
}

func (access *KubernetesRuleAccess) equal(other *KubernetesRuleAccess) bool {
	if access == nil || other == nil {
		return access == other
	}
	return access.ProfileHash == other.ProfileHash && access.ScopeHash == other.ScopeHash &&
		slices.Equal(access.Namespaces, other.Namespaces) && access.ClusterPart == other.ClusterPart &&
		access.Report == other.Report && access.ReportUntil.Equal(other.ReportUntil)
}

// validKubernetesRuleAccess reports a profile of profiles applied with
// valid namespaces whose scope hash is ScopeHash, and a report deadline
// exactly when the rule reports.
func validKubernetesRuleAccess(access *KubernetesRuleAccess, profiles map[[32]byte]KubernetesProfile) bool {
	if access == nil {
		return true
	}
	if _, found := profiles[access.ProfileHash]; !found || access.Report == access.ReportUntil.IsZero() {
		return false
	}
	scope, err := kubeprofile.ScopeHash(access.ProfileHash, access.Namespaces, access.ClusterPart)
	return err == nil && scope == access.ScopeHash && slices.IsSorted(access.Namespaces) &&
		len(slices.Compact(slices.Clone(access.Namespaces))) == len(access.Namespaces)
}

// indexKubernetesProfiles checks each profile against its hash, once.
func indexKubernetesProfiles(profiles []KubernetesProfile) (map[[32]byte]KubernetesProfile, bool) {
	index := make(map[[32]byte]KubernetesProfile, len(profiles))
	for _, profile := range profiles {
		hash, err := kubeprofile.ContentHash(profile.Profile)
		if _, duplicate := index[profile.Hash]; err != nil || hash != profile.Hash || duplicate {
			return nil, false
		}
		index[profile.Hash] = KubernetesProfile{Hash: profile.Hash, ID: profile.ID,
			Profile: kubeprofile.Normalize(profile.Profile)}
	}
	return index, true
}

// KubernetesScopeTableFor returns the table of gateway's map: every scope of
// a rule whose destination selects the gateway and holds only replicas of
// its cluster, and the profiles they apply. Every replica of a cluster gets
// the same table; a membership change never changes it. Empty for a Device
// no such rule reaches.
func (networkPolicy NetworkPolicy) KubernetesScopeTableFor(gateway node.ID, replica func(node.ID) bool,
	now time.Time) KubernetesScopeTable {
	inner := networkPolicy.inner
	if inner == nil || !inner.releaseActive || replica == nil {
		return KubernetesScopeTable{}
	}
	self, known := inner.byNode[gateway]
	if !known || !inner.live(self, now) {
		return KubernetesScopeTable{}
	}
	scopes := make(map[[32]byte]KubernetesScope)
	used := make(map[[32]byte]struct{})
	for _, rule := range inner.rules {
		access := rule.KubernetesAccess
		if access == nil || !inner.selects(rule.DestinationKind, rule.DestinationRef, self, now) ||
			!inner.onlyReplicas(rule.DestinationRef, replica, now) {
			continue
		}
		scopes[access.ScopeHash] = KubernetesScope{Hash: access.ScopeHash, Profile: access.ProfileHash,
			Namespaces: slices.Clone(access.Namespaces), ClusterPart: access.ClusterPart}
		used[access.ProfileHash] = struct{}{}
	}
	table := KubernetesScopeTable{}
	for _, scope := range scopes {
		table.Scopes = append(table.Scopes, scope)
	}
	for hash := range used {
		table.Profiles = append(table.Profiles, inner.profiles[hash])
	}
	slices.SortFunc(table.Scopes, func(left, right KubernetesScope) int {
		return bytes.Compare(left.Hash[:], right.Hash[:])
	})
	slices.SortFunc(table.Profiles, func(left, right KubernetesProfile) int {
		return bytes.Compare(left.Hash[:], right.Hash[:])
	})
	return table
}

// IsEmpty reports a table without profiles or scopes.
func (table KubernetesScopeTable) IsEmpty() bool {
	return len(table.Profiles) == 0 && len(table.Scopes) == 0
}

// Equal compares two tables by their hashes: a hash names one content.
func (table KubernetesScopeTable) Equal(other KubernetesScopeTable) bool {
	return slices.EqualFunc(table.Profiles, other.Profiles, func(left, right KubernetesProfile) bool {
		return left.Hash == right.Hash && left.ID == right.ID
	}) && slices.EqualFunc(table.Scopes, other.Scopes, func(left, right KubernetesScope) bool {
		return left.Hash == right.Hash
	})
}

// compareKubernetesScopedGrants orders grants by their key (mtcp-v1 §7.12):
// group, scope bytewise, enforcing first, report deadline.
func compareKubernetesScopedGrants(left, right KubernetesScopedGrant) int {
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
	return cmp.Compare(left.ReportUntil.UnixMilli(), right.ReportUntil.UnixMilli())
}

// scopedGrantKey is what scoped grants merge by.
type scopedGrantKey struct {
	group       string
	scope       [32]byte
	report      bool
	reportUntil int64
}

// scopedGrants are one peer's scoped grants as rules add them, merged by
// key on the way in: as many as distinct keys, whatever the rules.
type scopedGrants map[scopedGrantKey]KubernetesScopedGrant

// add merges grant in: a reporting grant whose deadline passed at now
// enforces; a deadline past the grant's own end is cut to it; grants of one
// key keep the latest end.
func (grants scopedGrants) add(grant KubernetesScopedGrant, now time.Time) {
	if grant.Report && !now.Before(grant.ReportUntil) {
		grant.Report, grant.ReportUntil = false, time.Time{}
	}
	if grant.Report && grant.ReportUntil.After(grant.ValidUntil) {
		grant.ReportUntil = grant.ValidUntil
	}
	key := scopedGrantKey{group: grant.Group, scope: grant.Scope, report: grant.Report}
	if grant.Report {
		key.reportUntil = grant.ReportUntil.UnixMilli()
	}
	if held, found := grants[key]; !found || grant.ValidUntil.After(held.ValidUntil) {
		grants[key] = grant
	}
}

// sorted returns the grants by key, without those that end no later than a
// whole grant of their group.
func (grants scopedGrants) sorted(whole map[string]time.Time) []KubernetesScopedGrant {
	kept := make([]KubernetesScopedGrant, 0, len(grants))
	for _, grant := range grants {
		if until, found := whole[grant.Group]; found && !until.Before(grant.ValidUntil) {
			continue
		}
		kept = append(kept, grant)
	}
	if len(kept) == 0 {
		return nil
	}
	slices.SortFunc(kept, compareKubernetesScopedGrants)
	return kept
}

// mergeScopedGrants merges raw grants as KubernetesAccessFor does.
func mergeScopedGrants(raw []KubernetesScopedGrant, whole map[string]time.Time,
	now time.Time) []KubernetesScopedGrant {
	grants := make(scopedGrants, len(raw))
	for _, grant := range raw {
		grants.add(grant, now)
	}
	return grants.sorted(whole)
}

func equalKubernetesScopedGrants(left, right []KubernetesScopedGrant) bool {
	return slices.EqualFunc(left, right, func(first, second KubernetesScopedGrant) bool {
		return first.Group == second.Group && first.Scope == second.Scope && first.Report == second.Report &&
			first.ReportUntil.Equal(second.ReportUntil) && first.ValidUntil.Equal(second.ValidUntil)
	})
}
