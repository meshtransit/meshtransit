package compilation_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
)

func mustCluster(t *testing.T, text string) kubecluster.ID {
	t.Helper()
	id, err := kubecluster.ParseID(text)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type ruleGroupReaderFixture struct {
	base      map[policy.RuleID]compilation.ReleasedClusterRule
	err       error
	revisions []int64
}

func (fixture *ruleGroupReaderFixture) ReadPolicyKubernetesGroups(_ context.Context, _ accountsession.Session,
	_ network.Scope, revision int64) (map[policy.RuleID]compilation.ReleasedClusterRule, error) {
	fixture.revisions = append(fixture.revisions, revision)
	return fixture.base, fixture.err
}

// An intent to a cluster names Kubernetes groups; no other intent does.
func TestRuleIntentNamesKubernetesGroupsOnlyToACluster(t *testing.T) {
	t.Parallel()
	fixture := newClusterRuleFixture(t)
	base := compilation.RuleIntentParams{ID: fixture.rule, Scope: compilationScopeFixture(t),
		SourceGroupID: fixture.userGroup, DestinationKubernetesClusterID: fixture.cluster,
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{fixture.https}}
	named := base
	named.KubernetesGroups = []string{"view", "edit"}
	intent, err := compilation.NewRuleIntent(named)
	if err != nil || !slices.Equal(intent.KubernetesGroups(), []string{"edit", "view"}) {
		t.Fatalf("NewRuleIntent() = %v, %v", intent.KubernetesGroups(), err)
	}
	for name, groups := range map[string][]string{
		"none, but given": {}, "invalid": {"View"}, "twice": {"view", "view"},
	} {
		params := base
		params.KubernetesGroups = groups
		if _, err := compilation.NewRuleIntent(params); !errors.Is(err, compilation.ErrInvalidRequest) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	plain := named
	plain.DestinationKubernetesClusterID, plain.DestinationDeviceGroupID = kubecluster.ID{}, fixture.clusterGroup
	if _, err := compilation.NewRuleIntent(plain); !errors.Is(err, compilation.ErrInvalidRequest) {
		t.Fatalf("groups to a Device Group: %v", err)
	}
}

// A rule to a cluster sent without groups keeps the groups it has in the
// release the request replaces; one that has none there keeps none; a new
// one must name some (K1a3 §13.4).
func TestServiceKeepsTheKubernetesGroupsOfTheReplacedRelease(t *testing.T) {
	t.Parallel()
	fixture := newClusterRuleFixture(t)
	resolver := &clusterResolverFixture{groups: []kubecluster.PolicyGroup{
		{ClusterID: fixture.cluster, Name: "kinda-k1", GroupID: fixture.clusterGroup},
	}}
	toCluster := compilation.RuleIntentParams{SourceGroupID: fixture.userGroup,
		DestinationKubernetesClusterID: fixture.cluster, Protocol: policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{fixture.https}}
	compile := func(reader *ruleGroupReaderFixture, params compilation.RuleIntentParams) ([]string, error) {
		t.Helper()
		_, service := fixture.compile(t, resolver, params)
		// Revision 3 replaces the release at revision 2.
		params.ID, params.Scope = fixture.rule, compilationScopeFixture(t)
		intent, err := compilation.NewRuleIntent(params)
		if err != nil {
			t.Fatal(err)
		}
		request, err := compilation.NewRequest(compilation.RequestParams{
			Scope: compilationScopeFixture(t), Revision: 3, Rules: []compilation.RuleIntent{intent},
		})
		if err != nil {
			t.Fatal(err)
		}
		service, err = service.WithKubernetesRuleGroups(reader)
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := service.Compile(t.Context(), compilationSessionFixture(t), request)
		if err != nil {
			return nil, err
		}
		return candidate.GroupRules()[0].KubernetesGroups(), nil
	}
	released := compilation.ReleasedClusterRule{Cluster: fixture.cluster, SourceKind: publication.SideDeviceGroup,
		SourceID: publicid.ID(fixture.userGroup), Groups: []string{"view"}}
	held := &ruleGroupReaderFixture{base: map[policy.RuleID]compilation.ReleasedClusterRule{fixture.rule: released}}
	if groups, err := compile(held, toCluster); err != nil || !slices.Equal(groups, []string{"view"}) ||
		!slices.Equal(held.revisions, []int64{2}) {
		t.Fatalf("kept = %v, %v, read %v", groups, err, held.revisions)
	}
	// A rule that now names another source or cluster is another grant: it
	// names its groups again.
	otherSource := toCluster
	otherGroup, err := devicegroup.ParseID("01890f00-0000-7000-8000-000000000a02")
	if err != nil {
		t.Fatal(err)
	}
	otherSource.SourceGroupID = otherGroup
	otherCluster := released
	otherCluster.Cluster = mustCluster(t, "01890f00-0000-7000-8000-000000000f02")
	for name, test := range map[string]struct {
		base   compilation.ReleasedClusterRule
		params compilation.RuleIntentParams
	}{
		"another source":  {released, otherSource},
		"another cluster": {otherCluster, toCluster},
	} {
		reader := &ruleGroupReaderFixture{base: map[policy.RuleID]compilation.ReleasedClusterRule{
			fixture.rule: test.base}}
		if _, err := compile(reader, test.params); !errors.Is(err, compilation.ErrKubernetesGroupsRequired) {
			t.Errorf("%s: %v", name, err)
		}
	}
	given := toCluster
	given.KubernetesGroups = []string{"edit"}
	if groups, err := compile(held, given); err != nil || !slices.Equal(groups, []string{"edit"}) {
		t.Fatalf("replaced = %v, %v", groups, err)
	}
	unnamed := released
	unnamed.Groups = nil
	legacy := &ruleGroupReaderFixture{base: map[policy.RuleID]compilation.ReleasedClusterRule{fixture.rule: unnamed}}
	if groups, err := compile(legacy, toCluster); err != nil || groups != nil {
		t.Fatalf("legacy = %v, %v", groups, err)
	}
	fresh := &ruleGroupReaderFixture{base: map[policy.RuleID]compilation.ReleasedClusterRule{}}
	if _, err := compile(fresh, toCluster); !errors.Is(err, compilation.ErrKubernetesGroupsRequired) {
		t.Fatalf("new rule without groups: %v", err)
	}
	if groups, err := compile(fresh, given); err != nil || !slices.Equal(groups, []string{"edit"}) {
		t.Fatalf("new rule = %v, %v", groups, err)
	}
	broken := &ruleGroupReaderFixture{err: compilation.ErrUnavailable}
	if _, err := compile(broken, toCluster); !errors.Is(err, compilation.ErrUnavailable) {
		t.Fatalf("unreadable base: %v", err)
	}
}

// The first release replaces none: a rule to a cluster names groups, and
// nothing is read.
func TestServiceReadsNoGroupsForTheFirstRelease(t *testing.T) {
	t.Parallel()
	fixture := newClusterRuleFixture(t)
	resolver := &clusterResolverFixture{groups: []kubecluster.PolicyGroup{
		{ClusterID: fixture.cluster, Name: "kinda-k1", GroupID: fixture.clusterGroup},
	}}
	request, service := fixture.compile(t, resolver, compilation.RuleIntentParams{SourceGroupID: fixture.userGroup,
		DestinationKubernetesClusterID: fixture.cluster, Protocol: policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{fixture.https}})
	reader := &ruleGroupReaderFixture{}
	service, err := service.WithKubernetesRuleGroups(reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Compile(t.Context(), compilationSessionFixture(t), request); !errors.Is(err,
		compilation.ErrKubernetesGroupsRequired) || len(reader.revisions) != 0 {
		t.Fatalf("first release: %v, read %v", err, reader.revisions)
	}
}
