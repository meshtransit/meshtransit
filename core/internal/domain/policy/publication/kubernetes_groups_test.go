package publication_test

import (
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/policy"
	publication "meshtransit.net/core/internal/domain/policy/publication"
)

// A cluster rule without Kubernetes groups, as every rule released before
// K1a3: its hash and fingerprint must never change.
const (
	pinnedClusterRuleHash        = "eebb80b5f21c94969fd4bcbd9e67e5f9f559501afcb7b780910d0277cd13f2ab"
	pinnedClusterRuleFingerprint = "010000000101890f000000700080000000000009010901890f00000070008000000000000b012da48c9f9e8cb5d8ead1457491329836"
)

func clusterRuleWithGroups(t *testing.T, groups ...string) publication.GroupRule {
	t.Helper()
	params := clusterRuleParams(t, policy.ProtocolTCP, 443, 443)
	params.KubernetesGroups = groups
	rule, err := publication.NewGroupRule(params)
	if err != nil {
		t.Fatalf("NewGroupRule(%v) error = %v", groups, err)
	}
	return rule
}

func clusterCandidate(t *testing.T, rule publication.GroupRule) publication.Candidate {
	t.Helper()
	candidate, err := publicationCandidateFixture(t, 2, nil).WithGroupRules([]publication.GroupRule{rule})
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

// A rule to a cluster names the Kubernetes groups it grants: DNS labels, one
// to sixteen, kept sorted. No other rule names any (K1a3 §3.1).
func TestClusterRuleNamesKubernetesGroups(t *testing.T) {
	t.Parallel()
	rule := clusterRuleWithGroups(t, "view", "edit", "debug-pods")
	if got := rule.KubernetesGroups(); !slices.Equal(got, []string{"debug-pods", "edit", "view"}) {
		t.Fatalf("KubernetesGroups() = %v", got)
	}
	// The caller cannot change the rule through the returned slice.
	rule.KubernetesGroups()[0] = "admin"
	if rule.KubernetesGroups()[0] != "debug-pods" {
		t.Fatal("KubernetesGroups() shares the rule's slice")
	}
	if legacy := clusterRuleWithGroups(t); legacy.KubernetesGroups() != nil {
		t.Fatalf("a rule without groups names %v", legacy.KubernetesGroups())
	}
	seventeen := make([]string, 17)
	for index := range seventeen {
		seventeen[index] = "group-" + string(rune('a'+index))
	}
	for name, groups := range map[string][]string{
		"upper case":       {"View"},
		"underscore":       {"read_only"},
		"leading hyphen":   {"-view"},
		"trailing hyphen":  {"view-"},
		"empty":            {""},
		"64 characters":    {strings.Repeat("a", 64)},
		"a dot":            {"view.all"},
		"twice":            {"view", "view"},
		"seventeen groups": seventeen,
		"system prefix":    {"system:masters"},
		"none, but given":  {},
	} {
		params := clusterRuleParams(t, policy.ProtocolTCP, 443, 443)
		params.KubernetesGroups = groups
		if _, err := publication.NewGroupRule(params); !errors.Is(err, publication.ErrInvalidGroupRule) {
			t.Errorf("%s: error = %v, want ErrInvalidGroupRule", name, err)
		}
	}
	// Only a rule to a cluster names groups.
	params := clusterRuleParams(t, policy.ProtocolTCP, 443, 443)
	params.DestinationKubernetesClusterID = kubecluster.ID{}
	params.KubernetesGroups = []string{"view"}
	if _, err := publication.NewGroupRule(params); !errors.Is(err, publication.ErrInvalidGroupRule) {
		t.Errorf("groups on a plain group rule: error = %v", err)
	}
	if longest := clusterRuleWithGroups(t, strings.Repeat("a", 63)); len(longest.KubernetesGroups()) != 1 {
		t.Fatal("a 63-character group was refused")
	}
	if sixteen := clusterRuleWithGroups(t, seventeen[:16]...); len(sixteen.KubernetesGroups()) != 16 {
		t.Fatal("sixteen groups were refused")
	}
}

// The groups are part of what a release grants (K1a3-I3): they change the
// semantic hash, so an approval for [view] never publishes [edit]. A release
// whose rules name none keeps its hash, and every release keeps a legacy
// hash without groups for Cores before K1a3 (§13.4).
func TestKubernetesGroupsAreInTheReleaseHash(t *testing.T) {
	t.Parallel()
	none := clusterCandidate(t, clusterRuleWithGroups(t))
	view := clusterCandidate(t, clusterRuleWithGroups(t, "view"))
	edit := clusterCandidate(t, clusterRuleWithGroups(t, "edit"))
	both := clusterCandidate(t, clusterRuleWithGroups(t, "view", "edit"))
	noneHash := none.SemanticHash().Bytes()
	if got := hex.EncodeToString(noneHash[:]); got != pinnedClusterRuleHash {
		t.Fatalf("a cluster rule without groups hashes to %s, want %s", got, pinnedClusterRuleHash)
	}
	hashes := map[publication.SemanticHash]string{}
	for name, candidate := range map[string]publication.Candidate{"none": none, "view": view, "edit": edit,
		"both": both} {
		if previous, seen := hashes[candidate.SemanticHash()]; seen {
			t.Errorf("%s and %s hash alike", name, previous)
		}
		hashes[candidate.SemanticHash()] = name
		if candidate.LegacySemanticHash() != none.SemanticHash() {
			t.Errorf("%s: legacy hash differs from the hash without groups", name)
		}
	}
	if !view.CoversKubernetesGroups() || none.CoversKubernetesGroups() {
		t.Fatal("CoversKubernetesGroups() does not say whether the hash covers groups")
	}
	// Each rule's groups are its own: swapping them between two rules is
	// another release.
	second := clusterRuleParams(t, policy.ProtocolTCP, 443, 443)
	secondID, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000902")
	if err != nil {
		t.Fatal(err)
	}
	second.RuleID = secondID
	pair := func(first, other string) publication.SemanticHash {
		params := second
		params.KubernetesGroups = []string{other}
		rule, err := publication.NewGroupRule(params)
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := publicationCandidateFixture(t, 2, nil).WithGroupRules(
			[]publication.GroupRule{clusterRuleWithGroups(t, first), rule})
		if err != nil {
			t.Fatal(err)
		}
		return candidate.SemanticHash()
	}
	if pair("view", "edit") == pair("edit", "view") {
		t.Fatal("groups swapped between rules hash alike")
	}
	// The same groups given in another order are the same release.
	if clusterCandidate(t, clusterRuleWithGroups(t, "edit", "view")).SemanticHash() != both.SemanticHash() {
		t.Fatal("the order of the groups changed the hash")
	}
}

// A rule that names groups fingerprints apart from one that names others or
// none, so review shows a group change as a changed rule; a rule without
// groups keeps its fingerprint and format.
func TestKubernetesGroupsAreInTheRuleFingerprint(t *testing.T) {
	t.Parallel()
	none := ruleFingerprintsFixture(t, clusterCandidate(t, clusterRuleWithGroups(t)))
	if got := hex.EncodeToString(none.MarshalBinary()); got != pinnedClusterRuleFingerprint {
		t.Fatalf("a cluster rule without groups fingerprints to %s, want %s", got, pinnedClusterRuleFingerprint)
	}
	view := ruleFingerprintsFixture(t, clusterCandidate(t, clusterRuleWithGroups(t, "view")))
	edit := ruleFingerprintsFixture(t, clusterCandidate(t, clusterRuleWithGroups(t, "edit")))
	if view.MarshalBinary()[0] != none.MarshalBinary()[0] {
		t.Fatal("groups changed the fingerprint format")
	}
	for name, test := range map[string]struct {
		before, after publication.RuleFingerprintSet
	}{
		"none to view": {none, view},
		"view to edit": {view, edit},
		"view to none": {view, none},
	} {
		summary := publication.SummarizeRuleChanges(test.before, publication.RuleBaselinePreviousRelease, test.after)
		if summary.Changed() != 1 || summary.Unchanged() != 0 {
			t.Errorf("%s: changed %d, unchanged %d", name, summary.Changed(), summary.Unchanged())
		}
	}
}
