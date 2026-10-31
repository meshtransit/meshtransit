package compilation_test

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
)

// otherClusterID is a cluster the fixture's rule does not go to.
const otherClusterID = "01890f00-0000-7000-8000-000000000f02"

func setCluster(cluster kubecluster.ID) compilation.ProfileCluster {
	return compilation.ProfileCluster{Cluster: cluster}
}

// A set sent without its cluster keeps the one it has; a new one is a set
// of every cluster until sets belong to clusters, then must name one; null
// makes a set of every cluster only of one that was; a set never moves but
// from every cluster to one (K2h Q261, Q264).
func TestServiceBindsPermissionSetsToClusters(t *testing.T) {
	t.Parallel()
	fixture := newClusterRuleFixture(t)
	other := mustCluster(t, otherClusterID)
	developer := mustProfile(t, developerProfileID, "developer", "get")
	bound := developer.WithCluster(fixture.cluster)
	id := developer.ID()
	full := fixture.toCluster([]string{"view"}, &compilation.KubernetesAccessIntent{Full: true})
	read := func(profiles ...publication.KubernetesProfile) *ruleGroupReaderFixture {
		return &ruleGroupReaderFixture{base: map[policy.RuleID]compilation.ReleasedClusterRule{},
			profiles: profiles}
	}
	sets := func(t *testing.T, test accessCase) []publication.KubernetesProfile {
		t.Helper()
		candidate, err := fixture.compileAccess(t, test)
		if err != nil {
			t.Fatal(err)
		}
		return candidate.KubernetesProfiles()
	}
	// Kept: the cluster of the replaced release.
	if got := sets(t, accessCase{reader: read(bound), profiles: []publication.KubernetesProfile{developer},
		params: full}); got[0].Cluster() != fixture.cluster {
		t.Fatalf("kept cluster = %v", got[0].Cluster())
	}
	// New, unnamed: every cluster with the flag off.
	if got := sets(t, accessCase{reader: read(), profiles: []publication.KubernetesProfile{developer},
		params: full}); got[0].Cluster().IsValid() {
		t.Fatalf("new set = %v", got[0].Cluster())
	}
	// Every cluster to one, with the same ID.
	if got := sets(t, accessCase{reader: read(developer), profiles: []publication.KubernetesProfile{developer},
		clusters: map[publication.KubernetesProfileID]compilation.ProfileCluster{id: setCluster(fixture.cluster)},
		params:   full}); got[0].Cluster() != fixture.cluster {
		t.Fatalf("bound in place = %v", got[0].Cluster())
	}
	for name, test := range map[string]struct {
		test accessCase
		want error
	}{
		"new set with the flag on": {accessCase{reader: read(), clustered: true,
			profiles: []publication.KubernetesProfile{developer}, params: full},
			compilation.ErrKubernetesProfileClusterRequired},
		"null for a new set with the flag on": {accessCase{reader: read(), clustered: true,
			profiles: []publication.KubernetesProfile{developer},
			clusters: map[publication.KubernetesProfileID]compilation.ProfileCluster{id: {Legacy: true}},
			params:   full}, compilation.ErrKubernetesProfileClusterRequired},
		"null for a bound set": {accessCase{reader: read(bound),
			profiles: []publication.KubernetesProfile{developer},
			clusters: map[publication.KubernetesProfileID]compilation.ProfileCluster{id: {Legacy: true}},
			params:   full}, compilation.ErrKubernetesProfileClusterChange},
		"to another cluster": {accessCase{reader: read(bound),
			profiles: []publication.KubernetesProfile{developer},
			clusters: map[publication.KubernetesProfileID]compilation.ProfileCluster{id: setCluster(other)},
			params:   full}, compilation.ErrKubernetesProfileClusterChange},
	} {
		if _, err := fixture.compileAccess(t, test.test); !errors.Is(err, test.want) {
			t.Errorf("%s: error = %v, want %v", name, err, test.want)
		}
	}
}

// A rule applies a set of its own cluster, or of every cluster; once sets
// belong to clusters, a set of every cluster only on a rule that applies it
// already (K2h-I1, Q268).
func TestServiceAppliesOnlySetsOfTheRulesCluster(t *testing.T) {
	t.Parallel()
	fixture := newClusterRuleFixture(t)
	developer := mustProfile(t, developerProfileID, "developer", "get")
	applied := fixture.toCluster([]string{"view"}, profileIntent(t, developerProfileID, "team-a"))
	empty := &ruleGroupReaderFixture{base: map[policy.RuleID]compilation.ReleasedClusterRule{}}
	named := func(cluster kubecluster.ID) map[publication.KubernetesProfileID]compilation.ProfileCluster {
		return map[publication.KubernetesProfileID]compilation.ProfileCluster{developer.ID(): setCluster(cluster)}
	}
	if _, err := fixture.compileAccess(t, accessCase{reader: empty,
		profiles: []publication.KubernetesProfile{developer}, clusters: named(mustCluster(t, otherClusterID)),
		params: applied}); !errors.Is(err, compilation.ErrKubernetesProfileWrongCluster) {
		t.Fatalf("a set of another cluster: %v", err)
	}
	if _, err := fixture.compileAccess(t, accessCase{reader: empty,
		profiles: []publication.KubernetesProfile{developer}, clusters: named(fixture.cluster),
		params: applied}); err != nil {
		t.Fatalf("a set of the rule's cluster: %v", err)
	}
	if _, err := fixture.compileAccess(t, accessCase{reader: empty,
		profiles: []publication.KubernetesProfile{developer}, params: applied}); err != nil {
		t.Fatalf("a set of every cluster with the flag off: %v", err)
	}
	if _, err := fixture.compileAccess(t, accessCase{reader: empty, clustered: true,
		profiles: []publication.KubernetesProfile{developer},
		clusters: map[publication.KubernetesProfileID]compilation.ProfileCluster{developer.ID(): {Legacy: true}},
		params:   applied}); !errors.Is(err, compilation.ErrKubernetesProfileClusterRequired) {
		t.Fatalf("a new set of every cluster with the flag on: %v", err)
	}
	// A rule that applies a set of every cluster keeps it with the flag on.
	held, err := publication.NewKubernetesAccess(publication.KubernetesAccessParams{ProfileID: developer.ID(),
		ProfileHash: developer.ContentHash(), Namespaces: []string{"team-a"}})
	if err != nil {
		t.Fatal(err)
	}
	keeping := &ruleGroupReaderFixture{base: map[policy.RuleID]compilation.ReleasedClusterRule{
		fixture.rule: {Cluster: fixture.cluster, SourceKind: publication.SideDeviceGroup,
			SourceID: publicid.ID(fixture.userGroup), Groups: []string{"view"}, Access: held},
	}, profiles: []publication.KubernetesProfile{developer}}
	if _, err := fixture.compileAccess(t, accessCase{reader: keeping, clustered: true,
		params: applied}); err != nil {
		t.Fatalf("a rule keeping its set of every cluster: %v", err)
	}
	// Moved to another cluster, it applies the set of every cluster anew
	// (review h1 M3).
	moved := &ruleGroupReaderFixture{base: map[policy.RuleID]compilation.ReleasedClusterRule{
		fixture.rule: {Cluster: mustCluster(t, otherClusterID), SourceKind: publication.SideDeviceGroup,
			SourceID: publicid.ID(fixture.userGroup), Groups: []string{"view"}, Access: held},
	}, profiles: []publication.KubernetesProfile{developer}}
	if _, err := fixture.compileAccess(t, accessCase{reader: moved, clustered: true,
		params: applied}); !errors.Is(err, compilation.ErrKubernetesProfileLegacy) {
		t.Fatalf("a rule moved with its set of every cluster: %v", err)
	}
	newRule := &ruleGroupReaderFixture{base: map[policy.RuleID]compilation.ReleasedClusterRule{},
		profiles: []publication.KubernetesProfile{developer}}
	if _, err := fixture.compileAccess(t, accessCase{reader: newRule, clustered: true,
		params: applied}); !errors.Is(err, compilation.ErrKubernetesProfileLegacy) {
		t.Fatalf("a new rule on a set of every cluster: %v", err)
	}
}

// Names: one per cluster; a set of every cluster named like no other set;
// until sets belong to clusters, a name shared across clusters only as the
// replaced release had it; and the count (K2h §32.12 M-2, M-6).
func TestServiceChecksPermissionSetNames(t *testing.T) {
	t.Parallel()
	fixture := newClusterRuleFixture(t)
	other := mustCluster(t, otherClusterID)
	full := fixture.toCluster([]string{"view"}, &compilation.KubernetesAccessIntent{Full: true})
	first := mustProfile(t, developerProfileID, "developer", "get")
	second := mustProfile(t, auditorProfileID, "developer", "list")
	clusters := map[publication.KubernetesProfileID]compilation.ProfileCluster{
		first.ID(): setCluster(fixture.cluster), second.ID(): setCluster(other),
	}
	empty := &ruleGroupReaderFixture{base: map[policy.RuleID]compilation.ReleasedClusterRule{}}
	sent := []publication.KubernetesProfile{first, second}
	if _, err := fixture.compileAccess(t, accessCase{reader: empty, profiles: sent, clusters: clusters,
		params: full}); !errors.Is(err, compilation.ErrKubernetesProfileName) {
		t.Fatalf("a new shared name with the flag off: %v", err)
	}
	if _, err := fixture.compileAccess(t, accessCase{reader: empty, clustered: true, profiles: sent,
		clusters: clusters, params: full}); err != nil {
		t.Fatalf("a shared name with the flag on: %v", err)
	}
	carried := &ruleGroupReaderFixture{base: map[policy.RuleID]compilation.ReleasedClusterRule{},
		profiles: []publication.KubernetesProfile{first.WithCluster(fixture.cluster), second.WithCluster(other)}}
	if _, err := fixture.compileAccess(t, accessCase{reader: carried, profiles: sent, params: full}); err != nil {
		t.Fatalf("a shared name carried with the flag off: %v", err)
	}
	sameCluster := map[publication.KubernetesProfileID]compilation.ProfileCluster{
		first.ID(): setCluster(fixture.cluster), second.ID(): setCluster(fixture.cluster),
	}
	if _, err := fixture.compileAccess(t, accessCase{reader: empty, clustered: true, profiles: sent,
		clusters: sameCluster, params: full}); !errors.Is(err, compilation.ErrKubernetesProfileName) {
		t.Fatalf("one name twice in a cluster: %v", err)
	}
	legacy := map[publication.KubernetesProfileID]compilation.ProfileCluster{
		first.ID(): setCluster(fixture.cluster), second.ID(): {Legacy: true},
	}
	if _, err := fixture.compileAccess(t, accessCase{reader: empty, profiles: sent, clusters: legacy,
		params: full}); !errors.Is(err, compilation.ErrKubernetesProfileName) {
		t.Fatalf("a set of every cluster named like another: %v", err)
	}
	many := make([]publication.KubernetesProfile, 0, publication.MaximumSharedKubernetesProfiles+1)
	bindings := make(map[publication.KubernetesProfileID]compilation.ProfileCluster, cap(many))
	for index := range cap(many) {
		id := publicid.ID(first.ID())
		bytes := id.Bytes()
		bytes[14], bytes[15] = byte(index>>8), byte(index)
		next, err := publicid.FromBytes(bytes)
		if err != nil {
			t.Fatal(err)
		}
		profile := mustProfile(t, next.String(), "set-"+next.String()[30:], "get")
		many = append(many, profile)
		bindings[profile.ID()] = setCluster(fixture.cluster)
	}
	if _, err := fixture.compileAccess(t, accessCase{reader: empty, profiles: many, clusters: bindings,
		params: full}); !errors.Is(err, compilation.ErrKubernetesProfileLimit) {
		t.Fatalf("257 sets with the flag off: %v", err)
	}
}
