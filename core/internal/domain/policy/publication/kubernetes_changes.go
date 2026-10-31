package publication

import (
	"cmp"
	"slices"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/policy"
)

// MaximumKubernetesChanges bounds each list of KubernetesChanges; the
// counts stay whole (K2h f5, design §34.1).
const MaximumKubernetesChanges = 256

// What a rule or a permission set change did.
const (
	KubernetesChangeAdded   = "added"
	KubernetesChangeRemoved = "removed"
	KubernetesChangeChanged = "changed"
)

// KubernetesSetChange is a permission set added, removed or changed
// (content, description or cluster) between two releases.
type KubernetesSetChange struct {
	Change string
	// Before and After: the set in each release; zero when absent there.
	Before, After KubernetesProfile
}

// KubernetesRuleChange is a rule to a Kubernetes cluster whose groups or
// access differ between two releases, or that one of them lacks.
type KubernetesRuleChange struct {
	RuleID policy.RuleID
	Change string
	// Cluster is the rule's cluster in the proposed release, else in the
	// baseline; ClusterBefore differs when the rule moved between clusters.
	Cluster, ClusterBefore kubecluster.ID
	// SourceBefore and SourceAfter: who the rule lets in, in each release
	// (zero when absent there); a wider source widens who holds the groups
	// (review f5 H2).
	SourceBefore, SourceAfter RuleSide
	GroupsBefore              []string
	GroupsAfter               []string
	// AccessBefore and AccessAfter are zero for full group rights (or when
	// the rule is absent from that release, see Change).
	AccessBefore, AccessAfter KubernetesAccess
	// SetContentChanged: the rule applies the same set in both, but its
	// content changed.
	SetContentChanged bool
}

// KubernetesChanges are what a proposal changes of Kubernetes access, for a
// reviewer (TD-CORE-110). The lists are bounded by MaximumKubernetesChanges
// and sorted by ID; the counts are whole.
type KubernetesChanges struct {
	Sets      []KubernetesSetChange
	SetCount  int
	Rules     []KubernetesRuleChange
	RuleCount int
}

// Truncated reports lists cut to MaximumKubernetesChanges.
func (changes KubernetesChanges) Truncated() bool {
	return changes.SetCount > len(changes.Sets) || changes.RuleCount > len(changes.Rules)
}

// KubernetesAccessDiff is what proposed changes of baseline's Kubernetes
// access: every permission set added, removed or changed, and every rule
// to a cluster added, removed, moved, or whose groups or access differ. It
// shows at least everything KubernetesAccessChanged weighs, and more: a
// rule's source and groups, and rules to clusters without a set.
func KubernetesAccessDiff(baseline, proposed Candidate) KubernetesChanges {
	var changes KubernetesChanges
	before := make(map[KubernetesProfileID]KubernetesProfile, len(baseline.kubernetesProfiles))
	for _, profile := range baseline.kubernetesProfiles {
		before[profile.id] = profile
	}
	var sets []KubernetesSetChange
	for _, profile := range proposed.kubernetesProfiles {
		held, kept := before[profile.id]
		delete(before, profile.id)
		switch {
		case !kept:
			sets = append(sets, KubernetesSetChange{Change: KubernetesChangeAdded, After: profile})
		case held.contentHash != profile.contentHash || held.description != profile.description ||
			held.cluster != profile.cluster || held.profile.Name != profile.profile.Name:
			sets = append(sets, KubernetesSetChange{Change: KubernetesChangeChanged, Before: held, After: profile})
		}
	}
	for _, profile := range before {
		sets = append(sets, KubernetesSetChange{Change: KubernetesChangeRemoved, Before: profile})
	}
	slices.SortFunc(sets, func(left, right KubernetesSetChange) int {
		return cmp.Compare(setChangeID(left).String(), setChangeID(right).String())
	})
	changes.SetCount, changes.Sets = len(sets), sets[:min(len(sets), MaximumKubernetesChanges)]

	held := make(map[policy.RuleID]GroupRule, len(baseline.groupRules))
	for _, rule := range baseline.groupRules {
		if rule.cluster.IsValid() {
			held[rule.ruleID] = rule
		}
	}
	var rules []KubernetesRuleChange
	for _, rule := range proposed.groupRules {
		earlier, kept := held[rule.ruleID]
		delete(held, rule.ruleID)
		if !rule.cluster.IsValid() {
			if kept {
				// A rule that pointed to a cluster no longer does.
				rules = append(rules, removedRule(earlier))
			}
			continue
		}
		if !kept {
			rules = append(rules, KubernetesRuleChange{
				RuleID: rule.ruleID, Change: KubernetesChangeAdded, Cluster: rule.cluster, SourceAfter: rule.source,
				GroupsAfter: slices.Clone(rule.kubernetesGroups), AccessAfter: rule.kubernetesAccess.clone(),
			})
			continue
		}
		if earlier.cluster == rule.cluster && earlier.source == rule.source &&
			slices.Equal(earlier.kubernetesGroups, rule.kubernetesGroups) &&
			earlier.kubernetesAccess.equal(rule.kubernetesAccess) &&
			earlier.kubernetesAccess.profileHash == rule.kubernetesAccess.profileHash {
			continue
		}
		rules = append(rules, KubernetesRuleChange{
			RuleID: rule.ruleID, Change: KubernetesChangeChanged, Cluster: rule.cluster,
			ClusterBefore: earlier.cluster, SourceBefore: earlier.source, SourceAfter: rule.source,
			GroupsBefore: slices.Clone(earlier.kubernetesGroups),
			GroupsAfter:  slices.Clone(rule.kubernetesGroups), AccessBefore: earlier.kubernetesAccess.clone(),
			AccessAfter: rule.kubernetesAccess.clone(),
			SetContentChanged: !rule.kubernetesAccess.IsZero() &&
				earlier.kubernetesAccess.profileID == rule.kubernetesAccess.profileID &&
				earlier.kubernetesAccess.profileHash != rule.kubernetesAccess.profileHash,
		})
	}
	for _, rule := range held {
		rules = append(rules, removedRule(rule))
	}
	slices.SortFunc(rules, func(left, right KubernetesRuleChange) int {
		return cmp.Compare(left.RuleID.String(), right.RuleID.String())
	})
	changes.RuleCount, changes.Rules = len(rules), rules[:min(len(rules), MaximumKubernetesChanges)]
	return changes
}

func removedRule(rule GroupRule) KubernetesRuleChange {
	return KubernetesRuleChange{
		RuleID: rule.ruleID, Change: KubernetesChangeRemoved, Cluster: rule.cluster, ClusterBefore: rule.cluster,
		SourceBefore: rule.source, GroupsBefore: slices.Clone(rule.kubernetesGroups),
		AccessBefore: rule.kubernetesAccess.clone(),
	}
}

func setChangeID(change KubernetesSetChange) KubernetesProfileID {
	if change.After.id.IsValid() {
		return change.After.id
	}
	return change.Before.id
}
