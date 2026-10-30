package compilation_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/kubeprofile"
)

func mustProfile(t *testing.T, id, name string, verbs ...string) publication.KubernetesProfile {
	t.Helper()
	profileID, err := publication.ParseKubernetesProfileID(id)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := publication.NewKubernetesProfile(publication.KubernetesProfileParams{ID: profileID,
		Description: "team pods", Profile: kubeprofile.Profile{Name: name, Namespaced: []kubeprofile.Rule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: verbs}}}})
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

const (
	developerProfileID = "01890f00-0000-7000-8000-000000000c01"
	auditorProfileID   = "01890f00-0000-7000-8000-000000000c02"
)

// accessCase compiles one rule to the fixture's cluster at revision 3 over
// reader's release.
type accessCase struct {
	reader   *ruleGroupReaderFixture
	required bool
	profiles []publication.KubernetesProfile
	params   compilation.RuleIntentParams
}

func (fixture clusterRuleFixture) compileAccess(t *testing.T, test accessCase) (publication.Candidate, error) {
	t.Helper()
	resolver := &clusterResolverFixture{groups: []kubecluster.PolicyGroup{
		{ClusterID: fixture.cluster, Name: "kinda-k1", GroupID: fixture.clusterGroup},
	}}
	_, service := fixture.compile(t, resolver, compilation.RuleIntentParams{SourceGroupID: fixture.userGroup,
		DestinationKubernetesClusterID: fixture.cluster, Protocol: policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{fixture.https}, KubernetesGroups: []string{"view"}})
	params := test.params
	params.ID, params.Scope = fixture.rule, compilationScopeFixture(t)
	intent, err := compilation.NewRuleIntent(params)
	if err != nil {
		t.Fatal(err)
	}
	request, err := compilation.NewRequest(compilation.RequestParams{Scope: compilationScopeFixture(t),
		Revision: 3, Rules: []compilation.RuleIntent{intent}, KubernetesProfiles: test.profiles})
	if err != nil {
		t.Fatal(err)
	}
	if test.reader != nil {
		if service, err = service.WithKubernetesAccess(test.reader, fixedNow); err != nil {
			t.Fatal(err)
		}
	}
	if test.required {
		if service, err = service.WithKubernetesAccessRequired(); err != nil {
			t.Fatal(err)
		}
	}
	return service.Compile(t.Context(), compilationSessionFixture(t), request)
}

func (fixture clusterRuleFixture) toCluster(groups []string, access *compilation.KubernetesAccessIntent) compilation.RuleIntentParams {
	return compilation.RuleIntentParams{SourceGroupID: fixture.userGroup,
		DestinationKubernetesClusterID: fixture.cluster, Protocol: policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{fixture.https}, KubernetesGroups: groups,
		KubernetesAccess: access}
}

func profileIntent(t *testing.T, id string, namespaces ...string) *compilation.KubernetesAccessIntent {
	t.Helper()
	profileID, err := publication.ParseKubernetesProfileID(id)
	if err != nil {
		t.Fatal(err)
	}
	return &compilation.KubernetesAccessIntent{ProfileID: profileID, Namespaces: namespaces}
}

// An access intent is full and nothing else, or a profile with namespaces
// and a deadline exactly when it reports; only to a cluster.
func TestRuleIntentKubernetesAccessShape(t *testing.T) {
	t.Parallel()
	fixture := newClusterRuleFixture(t)
	profile := profileIntent(t, developerProfileID, "team-a")
	for name, test := range map[string]struct {
		access *compilation.KubernetesAccessIntent
		valid  bool
	}{
		"full":                {&compilation.KubernetesAccessIntent{Full: true}, true},
		"profile":             {profile, true},
		"every namespace":     {profileIntent(t, developerProfileID, "*"), true},
		"full with namespace": {&compilation.KubernetesAccessIntent{Full: true, Namespaces: []string{"a"}}, false},
		"full with profile":   {&compilation.KubernetesAccessIntent{Full: true, ProfileID: profile.ProfileID}, false},
		"no namespace":        {profileIntent(t, developerProfileID), false},
		"star and a name":     {profileIntent(t, developerProfileID, "*", "a"), false},
		"bad namespace":       {profileIntent(t, developerProfileID, "Team"), false},
		"report, no deadline": {&compilation.KubernetesAccessIntent{ProfileID: profile.ProfileID,
			Namespaces: []string{"a"}, Report: true}, false},
		"deadline, no report": {&compilation.KubernetesAccessIntent{ProfileID: profile.ProfileID,
			Namespaces: []string{"a"}, ReportUntil: fixedNow()}, false},
		"neither": {&compilation.KubernetesAccessIntent{}, false},
	} {
		params := fixture.toCluster([]string{"view"}, test.access)
		params.ID, params.Scope = fixture.rule, compilationScopeFixture(t)
		if _, err := compilation.NewRuleIntent(params); (err == nil) != test.valid {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	params := fixture.toCluster(nil, profile)
	params.ID, params.Scope = fixture.rule, compilationScopeFixture(t)
	params.DestinationKubernetesClusterID, params.DestinationDeviceGroupID = kubecluster.ID{}, fixture.clusterGroup
	if _, err := compilation.NewRuleIntent(params); !errors.Is(err, compilation.ErrInvalidRequest) {
		t.Fatalf("access to a Device Group: %v", err)
	}
}

// A rule names a profile of the release: its content is pinned and the
// release hash covers it.
func TestServiceAppliesANamedProfile(t *testing.T) {
	t.Parallel()
	fixture := newClusterRuleFixture(t)
	developer := mustProfile(t, developerProfileID, "developer", "get", "list")
	reader := &ruleGroupReaderFixture{base: map[policy.RuleID]compilation.ReleasedClusterRule{}}
	candidate, err := fixture.compileAccess(t, accessCase{reader: reader,
		profiles: []publication.KubernetesProfile{developer},
		params:   fixture.toCluster([]string{"view"}, profileIntent(t, developerProfileID, "team-b", "team-a"))})
	if err != nil {
		t.Fatal(err)
	}
	access := candidate.GroupRules()[0].KubernetesAccess()
	if access.ProfileID() != developer.ID() || access.ProfileHash() != developer.ContentHash() ||
		!slices.Equal(access.Namespaces(), []string{"team-a", "team-b"}) || access.Report() ||
		!candidate.CoversKubernetesProfiles() || len(candidate.KubernetesProfiles()) != 1 {
		t.Fatalf("access = %+v", access)
	}
	full, err := fixture.compileAccess(t, accessCase{reader: reader,
		profiles: []publication.KubernetesProfile{developer},
		params:   fixture.toCluster([]string{"view"}, &compilation.KubernetesAccessIntent{Full: true})})
	if err != nil || full.CoversKubernetesProfiles() || full.SemanticHash() == candidate.SemanticHash() {
		t.Fatalf("full = %v", err)
	}
	if _, err := fixture.compileAccess(t, accessCase{reader: reader,
		profiles: []publication.KubernetesProfile{developer},
		params:   fixture.toCluster([]string{"view"}, profileIntent(t, auditorProfileID, "team-a"))}); !errors.Is(err,
		compilation.ErrKubernetesProfileUnknown) {
		t.Fatalf("unknown profile: %v", err)
	}
	if _, err := fixture.compileAccess(t, accessCase{reader: reader,
		params:   fixture.toCluster(nil, profileIntent(t, developerProfileID, "team-a")),
		profiles: []publication.KubernetesProfile{developer}}); !errors.Is(err,
		compilation.ErrKubernetesGroupsRequired) {
		t.Fatalf("profile without groups on a new rule: %v", err)
	}
	if _, err := fixture.compileAccess(t, accessCase{profiles: []publication.KubernetesProfile{developer},
		params: fixture.toCluster([]string{"view"}, nil)}); !errors.Is(err, compilation.ErrInvalidRequest) {
		t.Fatalf("profiles to a compiler without access: %v", err)
	}
}

// Sent without access, a rule keeps the profile it has, with the content
// the new release gives it, whatever groups it sends; it may not move with
// it, nor keep a profile the release drops (K2 §24.1 H1).
func TestServiceKeepsTheAccessOfTheReplacedRelease(t *testing.T) {
	t.Parallel()
	fixture := newClusterRuleFixture(t)
	developer := mustProfile(t, developerProfileID, "developer", "get")
	edited := mustProfile(t, developerProfileID, "developer", "get", "list", "watch")
	held, err := publication.NewKubernetesAccess(publication.KubernetesAccessParams{ProfileID: developer.ID(),
		ProfileHash: developer.ContentHash(), Namespaces: []string{"team-a"}, ClusterPart: true})
	if err != nil {
		t.Fatal(err)
	}
	released := compilation.ReleasedClusterRule{Cluster: fixture.cluster, SourceKind: publication.SideDeviceGroup,
		SourceID: publicid.ID(fixture.userGroup), Groups: []string{"view"}, Access: held}
	reader := func(rule compilation.ReleasedClusterRule) *ruleGroupReaderFixture {
		return &ruleGroupReaderFixture{base: map[policy.RuleID]compilation.ReleasedClusterRule{fixture.rule: rule},
			profiles: []publication.KubernetesProfile{developer}}
	}
	// The current Console sends the groups again and no access.
	kept, err := fixture.compileAccess(t, accessCase{reader: reader(released),
		params: fixture.toCluster([]string{"edit", "view"}, nil)})
	if err != nil {
		t.Fatal(err)
	}
	rule := kept.GroupRules()[0]
	if access := rule.KubernetesAccess(); access.ProfileHash() != developer.ContentHash() || !access.ClusterPart() ||
		!slices.Equal(rule.KubernetesGroups(), []string{"edit", "view"}) || len(kept.KubernetesProfiles()) != 1 {
		t.Fatalf("kept = %+v", access)
	}
	followed, err := fixture.compileAccess(t, accessCase{reader: reader(released),
		profiles: []publication.KubernetesProfile{edited}, params: fixture.toCluster(nil, nil)})
	if err != nil || followed.GroupRules()[0].KubernetesAccess().ProfileHash() != edited.ContentHash() {
		t.Fatalf("edited profile: %v", err)
	}
	moved := fixture.toCluster([]string{"view"}, nil)
	otherGroup, err := devicegroup.ParseID("01890f00-0000-7000-8000-000000000a02")
	if err != nil {
		t.Fatal(err)
	}
	moved.SourceGroupID = otherGroup
	if _, err := fixture.compileAccess(t, accessCase{reader: reader(released), params: moved}); !errors.Is(err,
		compilation.ErrKubernetesAccessRequired) {
		t.Fatalf("moved with a profile: %v", err)
	}
	otherCluster := released
	otherCluster.Cluster = mustCluster(t, "01890f00-0000-7000-8000-000000000f02")
	if _, err := fixture.compileAccess(t, accessCase{reader: reader(otherCluster),
		params: fixture.toCluster([]string{"view"}, nil)}); !errors.Is(err, compilation.ErrKubernetesAccessRequired) {
		t.Fatalf("to another cluster with a profile: %v", err)
	}
	if _, err := fixture.compileAccess(t, accessCase{reader: reader(released),
		profiles: []publication.KubernetesProfile{},
		params:   fixture.toCluster([]string{"view"}, nil)}); !errors.Is(err, compilation.ErrKubernetesProfileInUse) {
		t.Fatalf("dropped profile: %v", err)
	}
	full, err := fixture.compileAccess(t, accessCase{reader: reader(released),
		params: fixture.toCluster([]string{"view"}, &compilation.KubernetesAccessIntent{Full: true})})
	if err != nil || !full.GroupRules()[0].KubernetesAccess().IsZero() || len(full.KubernetesProfiles()) != 1 {
		t.Fatalf("to full: %v", err)
	}
}

// A new rule to a cluster sent without access gets its groups in full until
// access is required (Q195, Q229); a rule that had full groups keeps them.
func TestServiceRequiresAccessOnlyWhenTurnedOn(t *testing.T) {
	t.Parallel()
	fixture := newClusterRuleFixture(t)
	fresh := &ruleGroupReaderFixture{base: map[policy.RuleID]compilation.ReleasedClusterRule{}}
	params := fixture.toCluster([]string{"view"}, nil)
	candidate, err := fixture.compileAccess(t, accessCase{reader: fresh, params: params})
	if err != nil || !candidate.GroupRules()[0].KubernetesAccess().IsZero() {
		t.Fatalf("not required: %v", err)
	}
	if _, err := fixture.compileAccess(t, accessCase{reader: fresh, required: true, params: params}); !errors.Is(err,
		compilation.ErrKubernetesAccessRequired) {
		t.Fatalf("required: %v", err)
	}
	if _, err := fixture.compileAccess(t, accessCase{reader: fresh, required: true,
		params: fixture.toCluster([]string{"view"}, &compilation.KubernetesAccessIntent{Full: true})}); err != nil {
		t.Fatalf("explicit full: %v", err)
	}
	fullHeld := &ruleGroupReaderFixture{base: map[policy.RuleID]compilation.ReleasedClusterRule{fixture.rule: {
		Cluster: fixture.cluster, SourceKind: publication.SideDeviceGroup,
		SourceID: publicid.ID(fixture.userGroup), Groups: []string{"view"}}}}
	if _, err := fixture.compileAccess(t, accessCase{reader: fullHeld, required: true, params: params}); err != nil {
		t.Fatalf("kept full: %v", err)
	}
}

// A reporting rule's deadline is in the next 14 days.
func TestServiceBoundsTheReportDeadline(t *testing.T) {
	t.Parallel()
	fixture := newClusterRuleFixture(t)
	developer := mustProfile(t, developerProfileID, "developer", "get")
	reader := &ruleGroupReaderFixture{base: map[policy.RuleID]compilation.ReleasedClusterRule{}}
	for name, test := range map[string]struct {
		until time.Time
		valid bool
	}{
		"in a day":                         {fixedNow().Add(24 * time.Hour), true},
		"in 14 days less the clock margin": {fixedNow().Add(publication.MaximumKubernetesReport - 5*time.Minute), true},
		"in 14 days":                       {fixedNow().Add(publication.MaximumKubernetesReport), false},
		"now":                              {fixedNow(), false},
		"in the past":                      {fixedNow().Add(-time.Hour), false},
	} {
		access := profileIntent(t, developerProfileID, "team-a")
		access.Report, access.ReportUntil = true, test.until
		candidate, err := fixture.compileAccess(t, accessCase{reader: reader,
			profiles: []publication.KubernetesProfile{developer},
			params:   fixture.toCluster([]string{"view"}, access)})
		if !test.valid {
			if !errors.Is(err, compilation.ErrKubernetesReportWindow) {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err != nil || !candidate.GroupRules()[0].KubernetesAccess().ReportUntil().Equal(test.until) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Only a compiler that read the replaced release's access marks its
// candidates as knowing profiles: no other may be written by the writer that
// no longer carries them (review d2 M1).
func TestServiceMarksCandidatesThatKnowProfiles(t *testing.T) {
	t.Parallel()
	fixture := newClusterRuleFixture(t)
	reader := &ruleGroupReaderFixture{base: map[policy.RuleID]compilation.ReleasedClusterRule{}}
	known, err := fixture.compileAccess(t, accessCase{reader: reader, params: fixture.toCluster([]string{"view"}, nil)})
	if err != nil || !known.KnowsKubernetesProfiles() {
		t.Fatalf("with a reader = %v", err)
	}
	unknown, err := fixture.compileAccess(t, accessCase{params: fixture.toCluster([]string{"view"}, nil)})
	if err != nil || unknown.KnowsKubernetesProfiles() {
		t.Fatalf("without a reader = %v", err)
	}
}
