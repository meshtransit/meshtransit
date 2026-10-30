package publication_test

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/policy"
	publication "meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/shared/kubeprofile"
)

// The v9 hash of clusterProfileCandidate: pinned so that no change to the
// encoding goes unnoticed (releases are approved by it).
const pinnedProfileReleaseHash = "cc3974c0b8c97d764b124cb60c8807aba242b5e9659535d1af68267f59296924"

func publicationProfile(t *testing.T, id, name string, verbs ...string) publication.KubernetesProfile {
	t.Helper()
	profileID, err := publication.ParseKubernetesProfileID(id)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := publication.NewKubernetesProfile(publication.KubernetesProfileParams{ID: profileID,
		Description: "pods of a team", Profile: kubeprofile.Profile{Name: name,
			Namespaced: []kubeprofile.Rule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: verbs}}}})
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func profileAccess(t *testing.T, profile publication.KubernetesProfile, report time.Time,
	namespaces ...string) publication.KubernetesAccess {
	t.Helper()
	access, err := publication.NewKubernetesAccess(publication.KubernetesAccessParams{ProfileID: profile.ID(),
		ProfileHash: profile.ContentHash(), Namespaces: namespaces, Report: !report.IsZero(), ReportUntil: report})
	if err != nil {
		t.Fatal(err)
	}
	return access
}

func clusterRuleWithAccess(t *testing.T, access publication.KubernetesAccess, groups ...string) publication.GroupRule {
	t.Helper()
	params := clusterRuleParams(t, policy.ProtocolTCP, 443, 443)
	params.KubernetesGroups, params.KubernetesAccess = groups, access
	rule, err := publication.NewGroupRule(params)
	if err != nil {
		t.Fatal(err)
	}
	return rule
}

func clusterProfileCandidate(t *testing.T, profiles []publication.KubernetesProfile,
	rules ...publication.GroupRule) (publication.Candidate, error) {
	t.Helper()
	candidate, err := publicationCandidateFixture(t, 2, nil).WithKubernetesProfiles(profiles)
	if err != nil {
		t.Fatal(err)
	}
	return candidate.WithGroupRules(rules)
}

// A profile is normalized, hashed by content and described apart from it.
func TestKubernetesProfileContent(t *testing.T) {
	t.Parallel()
	first := publicationProfile(t, "01890f00-0000-7000-8000-000000000c01", "developer", "list", "get", "get")
	second := publicationProfile(t, "01890f00-0000-7000-8000-000000000c02", "developer", "get", "list")
	if first.ContentHash() != second.ContentHash() || first.Name() != "developer" {
		t.Fatalf("same rights hash apart: %x %x", first.ContentHash(), second.ContentHash())
	}
	for name, params := range map[string]publication.KubernetesProfileParams{
		"no ID": {Profile: kubeprofile.Profile{Name: "a", Namespaced: []kubeprofile.Rule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}}},
		"no rule": {ID: first.ID(), Profile: kubeprofile.Profile{Name: "a"}},
		"long description": {ID: first.ID(), Description: strings.Repeat("é", 513),
			Profile: first.Profile()},
		"control character": {ID: first.ID(), Description: "line\nbreak", Profile: first.Profile()},
	} {
		if _, err := publication.NewKubernetesProfile(params); !errors.Is(err,
			publication.ErrInvalidKubernetesProfile) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A rule applies a profile of its release, with that content and its
// groups; the release hash (v9) covers both, and the description does not
// count.
func TestCandidatePinsTheProfilesItsRulesApply(t *testing.T) {
	t.Parallel()
	developer := publicationProfile(t, "01890f00-0000-7000-8000-000000000c01", "developer", "get")
	auditor := publicationProfile(t, "01890f00-0000-7000-8000-000000000c02", "auditor", "list")
	rule := clusterRuleWithAccess(t, profileAccess(t, developer, time.Time{}, "team-a"), "view")
	candidate, err := clusterProfileCandidate(t, []publication.KubernetesProfile{developer, auditor}, rule)
	if err != nil {
		t.Fatal(err)
	}
	hash := candidate.SemanticHash().Bytes()
	if got := hex.EncodeToString(hash[:]); got != pinnedProfileReleaseHash {
		t.Fatalf("v9 hash = %s", got)
	}
	if !candidate.CoversKubernetesProfiles() || candidate.KubernetesProfiles()[0].ID() != developer.ID() {
		t.Fatal("profiles not held by ID")
	}
	described, err := publication.NewKubernetesProfile(publication.KubernetesProfileParams{ID: developer.ID(),
		Description: "another description", Profile: developer.Profile()})
	if err != nil {
		t.Fatal(err)
	}
	same, err := clusterProfileCandidate(t, []publication.KubernetesProfile{described, auditor}, rule)
	if err != nil || same.SemanticHash() != candidate.SemanticHash() {
		t.Fatalf("description changed the hash: %v", err)
	}
	without, err := clusterProfileCandidate(t, []publication.KubernetesProfile{developer}, rule)
	if err != nil || without.SemanticHash() == candidate.SemanticHash() {
		t.Fatalf("the profile set is not hashed: %v", err)
	}
	for name, rules := range map[string][]publication.GroupRule{
		"another namespace": {clusterRuleWithAccess(t, profileAccess(t, developer, time.Time{}, "team-b"), "view")},
		"reporting": {clusterRuleWithAccess(t,
			profileAccess(t, developer, time.UnixMilli(1_800_000_000_000), "team-a"), "view")},
		"another group": {clusterRuleWithAccess(t, profileAccess(t, developer, time.Time{}, "team-a"), "edit")},
		"full":          {clusterRuleWithGroups(t, "view")},
	} {
		other, err := clusterProfileCandidate(t, []publication.KubernetesProfile{developer, auditor}, rules...)
		if err != nil || other.SemanticHash() == candidate.SemanticHash() {
			t.Errorf("%s: same hash, %v", name, err)
		}
	}
	// Another content under the ID, or a profile the release lacks.
	edited := publicationProfile(t, "01890f00-0000-7000-8000-000000000c01", "developer", "get", "watch")
	if _, err := clusterProfileCandidate(t, []publication.KubernetesProfile{edited}, rule); err == nil {
		t.Fatal("a rule pins content the release does not hold")
	}
	if _, err := clusterProfileCandidate(t, []publication.KubernetesProfile{auditor}, rule); err == nil {
		t.Fatal("a rule applies a profile the release does not hold")
	}
	twin := publicationProfile(t, "01890f00-0000-7000-8000-000000000c03", "developer", "watch")
	if _, err := publicationCandidateFixture(t, 2, nil).WithKubernetesProfiles(
		[]publication.KubernetesProfile{developer, twin}); err == nil {
		t.Fatal("two profiles share a name")
	}
	params := clusterRuleParams(t, policy.ProtocolTCP, 443, 443)
	params.KubernetesAccess = profileAccess(t, developer, time.Time{}, "team-a")
	if _, err := publication.NewGroupRule(params); !errors.Is(err, publication.ErrInvalidGroupRule) {
		t.Fatalf("a profile without groups: %v", err)
	}
}

// A release keeps the hash each era of Core computed for it: v9 with
// profiles, v8 when a Core before K2 carried them, and before v8 without
// groups (K2 §24.1).
func TestCandidateHashesAsEachEra(t *testing.T) {
	t.Parallel()
	developer := publicationProfile(t, "01890f00-0000-7000-8000-000000000c01", "developer", "get")
	profiled, err := clusterProfileCandidate(t, []publication.KubernetesProfile{developer},
		clusterRuleWithAccess(t, profileAccess(t, developer, time.Time{}, "team-a"), "view"))
	if err != nil {
		t.Fatal(err)
	}
	grouped := clusterCandidate(t, clusterRuleWithGroups(t, "view"))
	if profiled.SemanticHashAs(true, true) != profiled.SemanticHash() ||
		profiled.SemanticHashAs(true, false) != grouped.SemanticHash() ||
		profiled.SemanticHashAs(false, false) != grouped.LegacySemanticHash() ||
		profiled.SemanticHashAs(false, true) != grouped.LegacySemanticHash() {
		t.Fatal("an era's hash differs from the release it would have computed")
	}
	for name, hash := range map[string]publication.SemanticHash{
		"v9": profiled.SemanticHash(), "v8": grouped.SemanticHash(), "before v8": grouped.LegacySemanticHash(),
	} {
		if !profiled.HashesAs(hash) {
			t.Errorf("%s not accepted", name)
		}
	}
	if grouped.HashesAs(profiled.SemanticHash()) {
		t.Fatal("a release without profiles accepts a v9 hash")
	}
	// Profiles nobody applies keep the release at v8.
	unused, err := clusterProfileCandidate(t, []publication.KubernetesProfile{developer},
		clusterRuleWithGroups(t, "view"))
	if err != nil || unused.SemanticHash() != grouped.SemanticHash() {
		t.Fatalf("unused profiles moved the hash: %v", err)
	}
}

// The rules to one cluster make at most 64 grant keys: a peer never holds
// more than a gateway takes (K2 §24.1 M5).
func TestCandidateBoundsTheGrantKeysOfACluster(t *testing.T) {
	t.Parallel()
	developer := publicationProfile(t, "01890f00-0000-7000-8000-000000000c01", "developer", "get")
	rules := make([]publication.GroupRule, 0, 5)
	for index := range 5 {
		params := clusterRuleParams(t, policy.ProtocolTCP, 443, 443)
		ruleID, err := policy.ParseRuleID(fmt.Sprintf("01890f00-0000-7000-8000-0000000009%02d", index+10))
		if err != nil {
			t.Fatal(err)
		}
		groups := make([]string, 13)
		for group := range groups {
			groups[group] = fmt.Sprintf("g%d", group)
		}
		params.RuleID, params.KubernetesGroups = ruleID, groups
		params.KubernetesAccess = profileAccess(t, developer, time.Time{}, fmt.Sprintf("team-%d", index))
		rule, err := publication.NewGroupRule(params)
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, rule)
	}
	if _, err := clusterProfileCandidate(t, []publication.KubernetesProfile{developer}, rules[:4]...); err != nil {
		t.Fatalf("52 keys: %v", err)
	}
	if _, err := clusterProfileCandidate(t, []publication.KubernetesProfile{developer}, rules...); !errors.Is(err,
		publication.ErrKubernetesAccessLimit) {
		t.Fatalf("65 keys: %v", err)
	}
}

// A report deadline is kept to the millisecond and only with report.
func TestKubernetesAccessShape(t *testing.T) {
	t.Parallel()
	developer := publicationProfile(t, "01890f00-0000-7000-8000-000000000c01", "developer", "get")
	until := time.Date(2026, 11, 1, 0, 0, 0, 123_456_789, time.FixedZone("ICT", 7*3600))
	access := profileAccess(t, developer, until, "b", "a", "a")
	if !access.ReportUntil().Equal(until.Truncate(time.Millisecond)) || access.ReportUntil().Location() != time.UTC ||
		strings.Join(access.Namespaces(), ",") != "a,b" {
		t.Fatalf("access = %v %v", access.ReportUntil(), access.Namespaces())
	}
	for name, params := range map[string]publication.KubernetesAccessParams{
		"no profile":   {ProfileHash: developer.ContentHash(), Namespaces: []string{"a"}},
		"no content":   {ProfileID: developer.ID(), Namespaces: []string{"a"}},
		"no namespace": {ProfileID: developer.ID(), ProfileHash: developer.ContentHash()},
		"deadline without report": {ProfileID: developer.ID(), ProfileHash: developer.ContentHash(),
			Namespaces: []string{"a"}, ReportUntil: until},
		"report without deadline": {ProfileID: developer.ID(), ProfileHash: developer.ContentHash(),
			Namespaces: []string{"a"}, Report: true},
	} {
		if _, err := publication.NewKubernetesAccess(params); !errors.Is(err,
			publication.ErrInvalidKubernetesProfile) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !(publication.KubernetesAccess{}).IsZero() || access.IsZero() {
		t.Fatal("IsZero")
	}
}

// A rule's fingerprint names its profile, so the rule history shows a
// change of profile, namespaces or mode.
func TestRuleFingerprintNamesTheProfile(t *testing.T) {
	t.Parallel()
	developer := publicationProfile(t, "01890f00-0000-7000-8000-000000000c01", "developer", "get")
	fingerprint := func(rule publication.GroupRule) string {
		t.Helper()
		candidate, err := clusterProfileCandidate(t, []publication.KubernetesProfile{developer}, rule)
		if err != nil {
			t.Fatal(err)
		}
		set, err := publication.FingerprintRules(candidate)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(set.MarshalBinary())
	}
	full := fingerprint(clusterRuleWithGroups(t, "view"))
	teamA := fingerprint(clusterRuleWithAccess(t, profileAccess(t, developer, time.Time{}, "team-a"), "view"))
	teamB := fingerprint(clusterRuleWithAccess(t, profileAccess(t, developer, time.Time{}, "team-b"), "view"))
	if full == teamA || teamA == teamB {
		t.Fatal("the fingerprint does not follow the profile")
	}
}

// An approver must see a change of profile or of how a rule applies one;
// other changes of group rules are not that (review d2 M2).
func TestKubernetesAccessChanged(t *testing.T) {
	t.Parallel()
	developer := publicationProfile(t, "01890f00-0000-7000-8000-000000000c01", "developer", "get")
	edited := publicationProfile(t, "01890f00-0000-7000-8000-000000000c01", "developer", "get", "list")
	teamA := clusterRuleWithAccess(t, profileAccess(t, developer, time.Time{}, "team-a"), "view")
	candidate := func(profiles []publication.KubernetesProfile, rules ...publication.GroupRule) publication.Candidate {
		t.Helper()
		value, err := clusterProfileCandidate(t, profiles, rules...)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	base := candidate([]publication.KubernetesProfile{developer}, teamA)
	for name, test := range map[string]struct {
		proposed publication.Candidate
		changed  bool
	}{
		"same":                {candidate([]publication.KubernetesProfile{developer}, teamA), false},
		"other groups only":   {candidate([]publication.KubernetesProfile{developer}, clusterRuleWithAccess(t, profileAccess(t, developer, time.Time{}, "team-a"), "edit")), false},
		"rule removed":        {candidate([]publication.KubernetesProfile{developer}), false},
		"to full groups":      {candidate([]publication.KubernetesProfile{developer}, clusterRuleWithGroups(t, "view")), true},
		"another namespace":   {candidate([]publication.KubernetesProfile{developer}, clusterRuleWithAccess(t, profileAccess(t, developer, time.Time{}, "team-b"), "view")), true},
		"profile edited":      {candidate([]publication.KubernetesProfile{edited}, clusterRuleWithAccess(t, profileAccess(t, edited, time.Time{}, "team-a"), "view")), true},
		"profile set changed": {candidate(nil, clusterRuleWithGroups(t, "view")), true},
	} {
		if got := publication.KubernetesAccessChanged(base, test.proposed); got != test.changed {
			t.Errorf("%s: changed = %t", name, got)
		}
	}
	plain := candidate(nil, clusterRuleWithGroups(t, "view"))
	if publication.KubernetesAccessChanged(plain, candidate(nil, clusterRuleWithGroups(t, "edit"))) {
		t.Fatal("full groups changing is not a profile change")
	}
	if publication.KubernetesAccessChanged(plain, candidate([]publication.KubernetesProfile{developer}, teamA)) == false {
		t.Fatal("a rule newly applying a profile is a change")
	}
}
