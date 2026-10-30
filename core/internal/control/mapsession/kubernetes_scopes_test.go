package mapsession

import (
	"fmt"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/shared/kubeprofile"
)

func scopeProfileFixture(t *testing.T, name string) KubernetesProfile {
	t.Helper()
	profile := kubeprofile.Profile{Name: name, Namespaced: []kubeprofile.Rule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}}
	hash, err := kubeprofile.ContentHash(profile)
	if err != nil {
		t.Fatal(err)
	}
	return KubernetesProfile{Hash: hash, ID: "01890f00-0000-7000-8000-00000000cc01", Profile: profile}
}

func ruleAccessFixture(t *testing.T, profile KubernetesProfile, report time.Time,
	namespaces ...string) *KubernetesRuleAccess {
	t.Helper()
	scope, err := kubeprofile.ScopeHash(profile.Hash, namespaces, false)
	if err != nil {
		t.Fatal(err)
	}
	return &KubernetesRuleAccess{ProfileHash: profile.Hash, ScopeHash: scope, Namespaces: namespaces,
		Report: !report.IsZero(), ReportUntil: report}
}

// scopedPolicyFixture: gateway 9 is cluster group 90's only member; Devices
// 1 and 2 are in group 10. rules are to the cluster, from group 10.
func scopedPolicyFixture(t *testing.T, profiles []KubernetesProfile,
	rules ...NetworkPolicyRule) (NetworkPolicy, map[int64]node.ID, error) {
	t.Helper()
	ids := map[int64]node.ID{}
	devices := make([]PolicyDevice, 0, 3)
	for _, device := range []int64{1, 2, 9} {
		ids[device] = policyNodeID(t, device)
		devices = append(devices, PolicyDevice{Device: device, NodeID: ids[device], ExpiresAt: policyNow.Add(24 * time.Hour)})
	}
	https, _ := policy.NewPortRange(443, 443)
	for index := range rules {
		rules[index].ID, rules[index].SourceKind, rules[index].SourceRef = policyRuleID(t, index+1),
			SelectorDeviceGroup, 10
		rules[index].DestinationKind, rules[index].DestinationRef = SelectorDeviceGroup, 90
		rules[index].Protocol, rules[index].Ports = policy.ProtocolTCP, []policy.PortRange{https}
	}
	networkPolicy, err := NewNetworkPolicy(NetworkPolicyParams{
		Scope: snapshotFixture(t).Scope(), Revision: 4, ReleaseActive: true, Rules: rules,
		Members: []SelectorMember{
			{Kind: SelectorDeviceGroup, Selector: 90, Device: 9},
			{Kind: SelectorDeviceGroup, Selector: 10, Device: 1}, {Kind: SelectorDeviceGroup, Selector: 10, Device: 2},
		},
		Devices: devices,
		KubernetesSources: []KubernetesSource{
			{Device: 1, OwnerKind: KubernetesOwnerWorkspace}, {Device: 2, OwnerKind: KubernetesOwnerWorkspace},
			{Device: 9, OwnerKind: KubernetesOwnerWorkspace},
		},
		KubernetesProfiles: profiles,
	})
	return networkPolicy, ids, err
}

// A rule with a profile grants its groups narrowed by the profile's scope;
// the gateway's table holds that scope and profile; a whole grant of the
// group that lasts as long makes the scoped one needless (K2 §27).
func TestKubernetesAccessCarriesScopedGrants(t *testing.T) {
	t.Parallel()
	developer := scopeProfileFixture(t, "developer")
	teamA := ruleAccessFixture(t, developer, time.Time{}, "team-a")
	networkPolicy, ids, err := scopedPolicyFixture(t, []KubernetesProfile{developer},
		NetworkPolicyRule{KubernetesGroups: []string{"edit", "view"}, KubernetesAccess: teamA},
		NetworkPolicyRule{KubernetesGroups: []string{"view"}})
	if err != nil {
		t.Fatal(err)
	}
	access, crowded := networkPolicy.KubernetesAccessFor(ids[9], replicaOf(ids), policyNow)
	entry := access[ids[1]]
	if crowded != 0 || len(entry.Grants) != 1 || entry.Grants[0].Group != "view" ||
		len(entry.ScopedGrants) != 1 || entry.ScopedGrants[0].Group != "edit" ||
		entry.ScopedGrants[0].Scope != teamA.ScopeHash || entry.ScopedGrants[0].Report {
		t.Fatalf("access = %+v", entry)
	}
	table := networkPolicy.KubernetesScopeTableFor(ids[9], replicaOf(ids), policyNow)
	if len(table.Scopes) != 1 || table.Scopes[0].Hash != teamA.ScopeHash || len(table.Profiles) != 1 ||
		table.Profiles[0].Hash != developer.Hash {
		t.Fatalf("table = %+v", table)
	}
	if other := networkPolicy.KubernetesScopeTableFor(ids[1], replicaOf(ids), policyNow); !other.IsEmpty() {
		t.Fatalf("a Device that is not the gateway got a table: %+v", other)
	}
	view, err := NewKubernetesView(access, table)
	if err != nil {
		t.Fatal(err)
	}
	// A session without gateway.kube.v2 keeps only whole grants.
	stripped := view.WithoutProfiles()
	if got, _ := stripped.For(ids[1]); len(got.ScopedGrants) != 0 || len(got.Grants) != 1 || !stripped.Scopes().IsEmpty() {
		t.Fatalf("stripped = %+v", got)
	}
	if _, err := NewKubernetesView(access, KubernetesScopeTable{}); err == nil {
		t.Fatal("a scoped grant outside the table was taken")
	}
}

// A reporting grant enforces once its deadline passes and never reports
// past its own end; the view refreshes at the deadline.
func TestReportingGrantsEnforceAtTheirDeadline(t *testing.T) {
	t.Parallel()
	developer := scopeProfileFixture(t, "developer")
	deadline := policyNow.Add(time.Hour)
	reporting := ruleAccessFixture(t, developer, deadline, "team-a")
	networkPolicy, ids, err := scopedPolicyFixture(t, []KubernetesProfile{developer},
		NetworkPolicyRule{KubernetesGroups: []string{"view"}, KubernetesAccess: reporting})
	if err != nil {
		t.Fatal(err)
	}
	access, _ := networkPolicy.KubernetesAccessFor(ids[9], replicaOf(ids), policyNow)
	if grant := access[ids[1]].ScopedGrants[0]; !grant.Report || !grant.ReportUntil.Equal(deadline) {
		t.Fatalf("before = %+v", grant)
	}
	view, err := NewKubernetesView(access, networkPolicy.KubernetesScopeTableFor(ids[9], replicaOf(ids), policyNow))
	if err != nil || !view.RefreshAt().Equal(deadline) {
		t.Fatalf("refresh = %v, %v", view.RefreshAt(), err)
	}
	later, _ := networkPolicy.KubernetesAccessFor(ids[9], replicaOf(ids), deadline)
	if grant := later[ids[1]].ScopedGrants[0]; grant.Report || !grant.ReportUntil.IsZero() {
		t.Fatalf("after = %+v", grant)
	}
	cut := mergeScopedGrants([]KubernetesScopedGrant{{Group: "view", Scope: reporting.ScopeHash, Report: true,
		ReportUntil: policyNow.Add(48 * time.Hour), ValidUntil: policyNow.Add(time.Hour)}}, nil, policyNow)
	if !cut[0].ReportUntil.Equal(policyNow.Add(time.Hour)) {
		t.Fatalf("a deadline past the grant's end = %+v", cut[0])
	}
}

// A peer with more than 64 grants after merging gets no access, counted.
func TestKubernetesAccessBoundsAPeersGrants(t *testing.T) {
	t.Parallel()
	developer := scopeProfileFixture(t, "developer")
	rules := make([]NetworkPolicyRule, 0, 5)
	for index := range 5 {
		groups := make([]string, 13)
		for group := range groups {
			groups[group] = fmt.Sprintf("g%02d", group)
		}
		rules = append(rules, NetworkPolicyRule{KubernetesGroups: groups,
			KubernetesAccess: ruleAccessFixture(t, developer, time.Time{}, fmt.Sprintf("team-%d", index))})
	}
	networkPolicy, ids, err := scopedPolicyFixture(t, []KubernetesProfile{developer}, rules...)
	if err != nil {
		t.Fatal(err)
	}
	access, crowded := networkPolicy.KubernetesAccessFor(ids[9], replicaOf(ids), policyNow)
	if crowded != 2 || len(access) != 0 {
		t.Fatalf("access = %d peers, %d crowded", len(access), crowded)
	}
}

// Evidence that does not hold together is refused: a profile under another
// hash, a rule naming a profile the release lacks, a scope hash that is not
// its content's, a profile without groups.
func TestNetworkPolicyChecksProfileEvidence(t *testing.T) {
	t.Parallel()
	developer := scopeProfileFixture(t, "developer")
	auditor := scopeProfileFixture(t, "auditor")
	wrongHash := developer
	wrongHash.Hash = auditor.Hash
	badScope := ruleAccessFixture(t, developer, time.Time{}, "team-a")
	badScope.ScopeHash[0] ^= 1
	for name, test := range map[string]struct {
		profiles []KubernetesProfile
		rule     NetworkPolicyRule
	}{
		"profile under another hash": {[]KubernetesProfile{wrongHash},
			NetworkPolicyRule{KubernetesGroups: []string{"view"}}},
		"profile the release lacks": {nil, NetworkPolicyRule{KubernetesGroups: []string{"view"},
			KubernetesAccess: ruleAccessFixture(t, developer, time.Time{}, "team-a")}},
		"scope hash not its content's": {[]KubernetesProfile{developer},
			NetworkPolicyRule{KubernetesGroups: []string{"view"}, KubernetesAccess: badScope}},
		"profile without groups": {[]KubernetesProfile{developer},
			NetworkPolicyRule{KubernetesAccess: ruleAccessFixture(t, developer, time.Time{}, "team-a")}},
	} {
		if _, _, err := scopedPolicyFixture(t, test.profiles, test.rule); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Merging keeps one grant per key with the latest end; reporting grants of
// other deadlines stay apart, after the enforcing one; a whole grant that
// ends sooner leaves the scoped grant (review d3 M3).
func TestMergeScopedGrants(t *testing.T) {
	t.Parallel()
	scope := [32]byte{1}
	hour, day := policyNow.Add(time.Hour), policyNow.Add(24*time.Hour)
	merged := mergeScopedGrants([]KubernetesScopedGrant{
		{Group: "edit", Scope: scope, ValidUntil: hour},
		{Group: "edit", Scope: scope, ValidUntil: day},
		{Group: "edit", Scope: scope, Report: true, ReportUntil: policyNow.Add(3 * time.Hour), ValidUntil: day},
		{Group: "edit", Scope: scope, Report: true, ReportUntil: policyNow.Add(2 * time.Hour), ValidUntil: day},
		{Group: "view", Scope: scope, ValidUntil: day},
	}, map[string]time.Time{"view": hour}, policyNow)
	if len(merged) != 4 || merged[0].Report || !merged[0].ValidUntil.Equal(day) ||
		!merged[1].Report || !merged[1].ReportUntil.Equal(policyNow.Add(2*time.Hour)) ||
		!merged[2].ReportUntil.Equal(policyNow.Add(3*time.Hour)) || merged[3].Group != "view" {
		t.Fatalf("merged = %+v", merged)
	}
	covered := mergeScopedGrants([]KubernetesScopedGrant{{Group: "view", Scope: scope, ValidUntil: hour}},
		map[string]time.Time{"view": day}, policyNow)
	if covered != nil {
		t.Fatalf("a scoped grant a longer whole grant covers = %+v", covered)
	}
}

// Exactly 64 grants after merging stay; the 65th withholds the peer.
func TestKubernetesAccessGrantBoundary(t *testing.T) {
	t.Parallel()
	developer := scopeProfileFixture(t, "developer")
	rules := func(count int) []NetworkPolicyRule {
		out := make([]NetworkPolicyRule, 0, count)
		for index := range count {
			groups := make([]string, 16)
			for group := range groups {
				groups[group] = fmt.Sprintf("g%02d", group)
			}
			out = append(out, NetworkPolicyRule{KubernetesGroups: groups,
				KubernetesAccess: ruleAccessFixture(t, developer, time.Time{}, fmt.Sprintf("team-%d", index))})
		}
		return out
	}
	full, ids, err := scopedPolicyFixture(t, []KubernetesProfile{developer}, rules(4)...)
	if err != nil {
		t.Fatal(err)
	}
	if access, crowded := full.KubernetesAccessFor(ids[9], replicaOf(ids), policyNow); crowded != 0 ||
		len(access[ids[1]].ScopedGrants) != 64 {
		t.Fatalf("64 grants = %d, crowded %d", len(access[ids[1]].ScopedGrants), crowded)
	}
	over := append(rules(4), NetworkPolicyRule{KubernetesGroups: []string{"extra"}})
	past, ids, err := scopedPolicyFixture(t, []KubernetesProfile{developer}, over...)
	if err != nil {
		t.Fatal(err)
	}
	if access, crowded := past.KubernetesAccessFor(ids[9], replicaOf(ids), policyNow); crowded != 2 || len(access) != 0 {
		t.Fatalf("65 grants = %d peers, crowded %d", len(access), crowded)
	}
}

// A view changes when only its table does; a session without
// gateway.kube.v2 takes neither table nor scoped grants and refreshes only
// when a whole grant lapses (review d3 H1).
func TestKubernetesViewTableAndSessions(t *testing.T) {
	t.Parallel()
	developer := scopeProfileFixture(t, "developer")
	teamA := ruleAccessFixture(t, developer, policyNow.Add(time.Hour), "team-a")
	networkPolicy, ids, err := scopedPolicyFixture(t, []KubernetesProfile{developer},
		NetworkPolicyRule{KubernetesGroups: []string{"edit"}, KubernetesAccess: teamA},
		NetworkPolicyRule{KubernetesGroups: []string{"view"}})
	if err != nil {
		t.Fatal(err)
	}
	access, _ := networkPolicy.KubernetesAccessFor(ids[9], replicaOf(ids), policyNow)
	table := networkPolicy.KubernetesScopeTableFor(ids[9], replicaOf(ids), policyNow)
	view := must(NewKubernetesView(access, table))
	extra := table
	extra.Scopes = append(append([]KubernetesScope(nil), table.Scopes...),
		KubernetesScope{Hash: [32]byte{0xff}, Profile: developer.Hash, Namespaces: []string{"*"}})
	if view.Equal(must(NewKubernetesView(access, extra))) {
		t.Fatal("a view with another table is equal")
	}
	if !view.RefreshAt().Equal(policyNow.Add(time.Hour)) {
		t.Fatalf("refresh at the report deadline = %v", view.RefreshAt())
	}
	stripped := view.WithoutProfiles()
	if stripped.ProfilesTaken() || !stripped.Scopes().IsEmpty() || !stripped.RefreshAt().Equal(policyNow.Add(24*time.Hour)) {
		t.Fatalf("stripped refresh = %v", stripped.RefreshAt())
	}
	snapshot := snapshotFixture(t).WithKubernetes(view)
	v1 := snapshot.withKubernetesCapability(Request{}.WithKubernetes())
	v2 := snapshot.withKubernetesCapability(Request{}.WithKubernetes().WithKubernetesProfiles())
	if v1.Kubernetes().ProfilesTaken() || !v1.Kubernetes().Scopes().IsEmpty() || !v2.Kubernetes().ProfilesTaken() ||
		v2.Kubernetes().Scopes().IsEmpty() {
		t.Fatal("sessions take the wrong profiles")
	}
}
