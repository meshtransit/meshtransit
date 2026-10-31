package publication_test

import (
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
)

// What a reviewer sees of a proposal's Kubernetes access (K2h f5): sets
// added, removed and changed; rules added, removed and changed, with their
// groups and access before and after.
func TestKubernetesAccessDiff(t *testing.T) {
	t.Parallel()
	developer := publicationProfile(t, "01890f00-0000-7000-8000-000000000c01", "developer", "get")
	edited := publicationProfile(t, "01890f00-0000-7000-8000-000000000c01", "developer", "get", "list")
	reader := publicationProfile(t, "01890f00-0000-7000-8000-000000000c02", "reader", "get")
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

	if diff := publication.KubernetesAccessDiff(base, base); diff.SetCount != 0 || diff.RuleCount != 0 ||
		diff.Truncated() {
		t.Fatalf("no change: %+v", diff)
	}
	// Other groups only: a change a reviewer must see, though no set moved.
	diff := publication.KubernetesAccessDiff(base, candidate([]publication.KubernetesProfile{developer},
		clusterRuleWithAccess(t, profileAccess(t, developer, time.Time{}, "team-a"), "edit")))
	if diff.RuleCount != 1 || diff.Rules[0].Change != publication.KubernetesChangeChanged ||
		diff.Rules[0].GroupsBefore[0] != "view" || diff.Rules[0].GroupsAfter[0] != "edit" ||
		diff.Rules[0].SetContentChanged || diff.SetCount != 0 {
		t.Fatalf("groups: %+v", diff)
	}
	// The set's content changed: the set, and the rule applying it.
	diff = publication.KubernetesAccessDiff(base, candidate([]publication.KubernetesProfile{edited},
		clusterRuleWithAccess(t, profileAccess(t, edited, time.Time{}, "team-a"), "view")))
	if diff.SetCount != 1 || diff.Sets[0].Change != publication.KubernetesChangeChanged ||
		diff.Sets[0].Before.ContentHash() == diff.Sets[0].After.ContentHash() || diff.RuleCount != 1 ||
		!diff.Rules[0].SetContentChanged {
		t.Fatalf("content: %+v", diff)
	}
	// To full group rights, the set removed: both seen.
	diff = publication.KubernetesAccessDiff(base, candidate(nil, clusterRuleWithGroups(t, "view")))
	if diff.SetCount != 1 || diff.Sets[0].Change != publication.KubernetesChangeRemoved ||
		diff.RuleCount != 1 || diff.Rules[0].AccessBefore.IsZero() || !diff.Rules[0].AccessAfter.IsZero() {
		t.Fatalf("to full: %+v", diff)
	}
	// A set added, unused, and the rule removed.
	diff = publication.KubernetesAccessDiff(base, candidate([]publication.KubernetesProfile{developer, reader}))
	if diff.SetCount != 1 || diff.Sets[0].Change != publication.KubernetesChangeAdded ||
		diff.Sets[0].After.Name() != "reader" || diff.RuleCount != 1 ||
		diff.Rules[0].Change != publication.KubernetesChangeRemoved || diff.Rules[0].GroupsBefore[0] != "view" {
		t.Fatalf("added set, removed rule: %+v", diff)
	}
	// A rule to a cluster from nothing: added, with full rights seen as such.
	diff = publication.KubernetesAccessDiff(candidate(nil), candidate(nil, clusterRuleWithGroups(t, "admin")))
	if diff.RuleCount != 1 || diff.Rules[0].Change != publication.KubernetesChangeAdded ||
		!diff.Rules[0].AccessAfter.IsZero() || diff.Rules[0].GroupsAfter[0] != "admin" {
		t.Fatalf("added rule: %+v", diff)
	}
	// Another namespace: changed.
	diff = publication.KubernetesAccessDiff(base, candidate([]publication.KubernetesProfile{developer},
		clusterRuleWithAccess(t, profileAccess(t, developer, time.Time{}, "team-b"), "view")))
	if diff.RuleCount != 1 || diff.Rules[0].AccessAfter.Namespaces()[0] != "team-b" {
		t.Fatalf("namespace: %+v", diff)
	}
	// Whatever KubernetesAccessChanged weighs, the diff shows.
	for _, proposed := range []publication.Candidate{
		candidate([]publication.KubernetesProfile{edited},
			clusterRuleWithAccess(t, profileAccess(t, edited, time.Time{}, "team-a"), "view")),
		candidate(nil, clusterRuleWithGroups(t, "view")),
		candidate([]publication.KubernetesProfile{developer, reader}, teamA),
	} {
		if publication.KubernetesAccessChanged(base, proposed) {
			if diff := publication.KubernetesAccessDiff(base, proposed); diff.SetCount+diff.RuleCount == 0 {
				t.Fatalf("a change KubernetesAccessChanged sees is missing: %+v", diff)
			}
		}
	}
}

// An independent check (review f5 M2): over every pair of a rule's forms
// (absent; each source, cluster and groups; full rights or a set in each
// namespace, content and way of applying), the diff is empty exactly when
// the rule's (source, cluster, groups, access, set content) and the sets
// are the same on both sides, and names the rule as added, removed or
// changed, with each side's cluster, as the forms say.
func TestKubernetesAccessDiffAgreesWithTuples(t *testing.T) {
	t.Parallel()
	developer := publicationProfile(t, "01890f00-0000-7000-8000-000000000c01", "developer", "get")
	edited := publicationProfile(t, "01890f00-0000-7000-8000-000000000c01", "developer", "get", "list")
	report := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	clusters := map[string]string{
		"01890f00-0000-7000-8000-000000000b01": "000000000a02",
		"01890f00-0000-7000-8000-000000000b02": "000000000a04",
	}
	type form struct {
		present bool
		source  string
		cluster string
		groups  string
		set     *publication.KubernetesProfile
		ns      string
		// way: "enforce", "cluster" (cluster part) or "report".
		way string
	}
	forms := []form{{}}
	for _, source := range []string{"000000000a01", "000000000a03"} {
		for cluster := range clusters {
			for _, groups := range []string{"view", "edit"} {
				base := form{present: true, source: source, cluster: cluster, groups: groups}
				forms = append(forms, base)
				for _, set := range []*publication.KubernetesProfile{&developer, &edited} {
					for _, ns := range []string{"team-a", "team-b"} {
						for _, way := range []string{"enforce", "cluster", "report"} {
							withSet := base
							withSet.set, withSet.ns, withSet.way = set, ns, way
							forms = append(forms, withSet)
						}
					}
				}
			}
		}
	}
	build := func(f form) publication.Candidate {
		t.Helper()
		var profiles []publication.KubernetesProfile
		var rules []publication.GroupRule
		if f.set != nil {
			profiles = []publication.KubernetesProfile{*f.set}
		}
		if f.present {
			params := clusterRuleParams(t, policy.ProtocolTCP, 443, 443)
			cluster, err := kubecluster.ParseID(f.cluster)
			if err != nil {
				t.Fatal(err)
			}
			params.SourceGroupID = mustGroupID(t, f.source)
			params.DestinationKubernetesClusterID = cluster
			params.DestinationGroupID = mustGroupID(t, clusters[f.cluster])
			params.KubernetesGroups = []string{f.groups}
			if f.set != nil {
				until := time.Time{}
				if f.way == "report" {
					until = report
				}
				access, err := publication.NewKubernetesAccess(publication.KubernetesAccessParams{
					ProfileID: f.set.ID(), ProfileHash: f.set.ContentHash(), Namespaces: []string{f.ns},
					ClusterPart: f.way == "cluster", Report: f.way == "report", ReportUntil: until,
				})
				if err != nil {
					t.Fatal(err)
				}
				params.KubernetesAccess = access
			}
			rule, err := publication.NewGroupRule(params)
			if err != nil {
				t.Fatal(err)
			}
			rules = append(rules, rule)
		}
		candidate, err := clusterProfileCandidate(t, profiles, rules...)
		if err != nil {
			t.Fatal(err)
		}
		return candidate
	}
	built := make([]publication.Candidate, len(forms))
	for index, f := range forms {
		built[index] = build(f)
	}
	tuple := func(f form) string {
		hash := ""
		if f.set != nil {
			content := f.set.ContentHash()
			hash = string(content[:])
		}
		if !f.present {
			return "absent|" + hash
		}
		return f.source + "|" + f.cluster + "|" + f.groups + "|" + f.ns + "|" + f.way + "|" + hash
	}
	for first, before := range forms {
		for second, after := range forms {
			diff := publication.KubernetesAccessDiff(built[first], built[second])
			same := tuple(before) == tuple(after)
			if same != (diff.SetCount+diff.RuleCount == 0) {
				t.Fatalf("%+v → %+v: same %t, diff %+v", before, after, same, diff)
			}
			ruleSame := before.present == after.present && (!before.present || tuple(before) == tuple(after))
			if ruleSame {
				if diff.RuleCount != 0 {
					t.Fatalf("%+v → %+v: a rule change %+v", before, after, diff.Rules)
				}
				continue
			}
			want := publication.KubernetesChangeChanged
			switch {
			case !before.present:
				want = publication.KubernetesChangeAdded
			case !after.present:
				want = publication.KubernetesChangeRemoved
			}
			if diff.RuleCount != 1 || diff.Rules[0].Change != want {
				t.Fatalf("%+v → %+v: want %s, diff %+v", before, after, want, diff.Rules)
			}
			rule := diff.Rules[0]
			moved := want == publication.KubernetesChangeChanged && before.cluster != after.cluster
			if (want != publication.KubernetesChangeRemoved && rule.Cluster.String() != after.cluster) ||
				(want == publication.KubernetesChangeRemoved && rule.Cluster.String() != before.cluster) ||
				(moved && rule.ClusterBefore.String() != before.cluster) ||
				(want != publication.KubernetesChangeAdded && rule.GroupsBefore[0] != before.groups) ||
				(want != publication.KubernetesChangeRemoved && rule.GroupsAfter[0] != after.groups) ||
				rule.SetContentChanged != (want == publication.KubernetesChangeChanged && before.set != nil &&
					after.set != nil && before.set.ContentHash() != after.set.ContentHash()) {
				t.Fatalf("%+v → %+v: sides %+v", before, after, rule)
			}
		}
	}
}
