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
)

type clusterResolverFixture struct {
	groups  []kubecluster.PolicyGroup
	err     error
	ensured [][]kubecluster.ID
}

func (fixture *clusterResolverFixture) ResolvePolicyKubernetesClusters(_ context.Context,
	_ accountsession.Session, _ network.Scope, clusters []kubecluster.ID) ([]kubecluster.PolicyGroup, error) {
	fixture.ensured = append(fixture.ensured, slices.Clone(clusters))
	return slices.Clone(fixture.groups), fixture.err
}

type clusterRuleFixture struct {
	cluster          kubecluster.ID
	clusterGroup     devicegroup.ID
	userGroup        devicegroup.ID
	rule             policy.RuleID
	https, kubeletss policy.PortRange
}

func newClusterRuleFixture(t *testing.T) clusterRuleFixture {
	t.Helper()
	cluster, _ := kubecluster.ParseID("01890f00-0000-7000-8000-000000000f01")
	clusterGroup, _ := devicegroup.ParseID("01890f00-0000-7000-8000-000000000a09")
	userGroup, _ := devicegroup.ParseID("01890f00-0000-7000-8000-000000000a01")
	rule, _ := policy.ParseRuleID("01890f00-0000-7000-8000-000000000801")
	https, _ := policy.NewPortRange(443, 443)
	other, _ := policy.NewPortRange(10250, 10250)
	return clusterRuleFixture{cluster: cluster, clusterGroup: clusterGroup, userGroup: userGroup, rule: rule,
		https: https, kubeletss: other}
}

func (fixture clusterRuleFixture) compile(t *testing.T, resolver compilation.KubernetesClusterResolver,
	params compilation.RuleIntentParams) (compilation.Request, *compilation.Service) {
	t.Helper()
	params.ID, params.Scope = fixture.rule, compilationScopeFixture(t)
	intent, err := compilation.NewRuleIntent(params)
	if err != nil {
		t.Fatal(err)
	}
	request, err := compilation.NewRequest(compilation.RequestParams{
		Scope: compilationScopeFixture(t), Revision: 2, Rules: []compilation.RuleIntent{intent},
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := compilation.NewService(&compilationResourceResolverFixture{})
	if err != nil {
		t.Fatal(err)
	}
	if resolver != nil {
		if service, err = service.WithKubernetesClusters(resolver); err != nil {
			t.Fatal(err)
		}
	}
	return request, service
}

func TestRuleIntentToAClusterIsTCP443Only(t *testing.T) {
	t.Parallel()
	fixture := newClusterRuleFixture(t)
	base := compilation.RuleIntentParams{
		ID: fixture.rule, Scope: compilationScopeFixture(t), SourceGroupID: fixture.userGroup,
		DestinationKubernetesClusterID: fixture.cluster, Protocol: policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{fixture.https},
	}
	intent, err := compilation.NewRuleIntent(base)
	if err != nil || !intent.SelectsDeviceGroup() || intent.DestinationKubernetesClusterID() != fixture.cluster {
		t.Fatalf("NewRuleIntent() = %+v, %v", intent, err)
	}
	for name, change := range map[string]func(*compilation.RuleIntentParams){
		"udp":          func(p *compilation.RuleIntentParams) { p.Protocol = policy.ProtocolUDP },
		"another port": func(p *compilation.RuleIntentParams) { p.DestinationPortRanges = []policy.PortRange{fixture.kubeletss} },
		"two ports": func(p *compilation.RuleIntentParams) {
			p.DestinationPortRanges = []policy.PortRange{fixture.https, fixture.kubeletss}
		},
		"and a group": func(p *compilation.RuleIntentParams) { p.DestinationDeviceGroupID = fixture.clusterGroup },
	} {
		params := base
		change(&params)
		if _, err := compilation.NewRuleIntent(params); !errors.Is(err, compilation.ErrInvalidRequest) {
			t.Errorf("%s: error = %v, want ErrInvalidRequest", name, err)
		}
	}
	// A reader that knows a group is a cluster's names the cluster instead.
	groupParams := base
	groupParams.DestinationKubernetesClusterID, groupParams.DestinationDeviceGroupID = kubecluster.ID{}, fixture.clusterGroup
	byGroup, err := compilation.NewRuleIntent(groupParams)
	if err != nil {
		t.Fatal(err)
	}
	named, err := byGroup.WithKubernetesCluster(fixture.cluster)
	if err != nil || named.DestinationKubernetesClusterID() != fixture.cluster || named.DestinationDeviceGroupID().IsValid() {
		t.Fatalf("WithKubernetesCluster() = %+v, %v", named, err)
	}
}

func TestServiceCompilesAClusterRuleToTheClustersGroup(t *testing.T) {
	t.Parallel()
	fixture := newClusterRuleFixture(t)
	resolver := &clusterResolverFixture{groups: []kubecluster.PolicyGroup{
		{ClusterID: fixture.cluster, Name: "kinda-k1", GroupID: fixture.clusterGroup},
	}}
	tcp443 := compilation.RuleIntentParams{Protocol: policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{fixture.https}}

	// By cluster: the group is made if needed and the rule reaches it.
	byCluster := tcp443
	byCluster.SourceGroupID, byCluster.DestinationKubernetesClusterID = fixture.userGroup, fixture.cluster
	request, service := fixture.compile(t, resolver, byCluster)
	candidate, err := service.Compile(t.Context(), compilationSessionFixture(t), request)
	if err != nil || len(candidate.GroupRules()) != 1 ||
		candidate.GroupRules()[0].DestinationGroupID() != fixture.clusterGroup ||
		candidate.GroupRules()[0].DestinationKubernetesClusterID() != fixture.cluster ||
		len(resolver.ensured) != 1 || !slices.Equal(resolver.ensured[0], []kubecluster.ID{fixture.cluster}) {
		t.Fatalf("Compile() = %+v, %v, ensured %v", candidate.GroupRules(), err, resolver.ensured)
	}

	// By the cluster's group, as an older Console sends it back: labelled.
	byGroup := tcp443
	byGroup.SourceGroupID, byGroup.DestinationDeviceGroupID = fixture.userGroup, fixture.clusterGroup
	request, service = fixture.compile(t, resolver, byGroup)
	candidate, err = service.Compile(t.Context(), compilationSessionFixture(t), request)
	if err != nil || candidate.GroupRules()[0].DestinationKubernetesClusterID() != fixture.cluster {
		t.Fatalf("Compile() by group = %+v, %v", candidate.GroupRules(), err)
	}

	refused := map[string]compilation.RuleIntentParams{
		"the cluster's group on another port": {SourceGroupID: fixture.userGroup,
			DestinationDeviceGroupID: fixture.clusterGroup, Protocol: policy.ProtocolTCP,
			DestinationPortRanges: []policy.PortRange{fixture.kubeletss}},
		"the cluster's group as a source": {SourceGroupID: fixture.clusterGroup,
			DestinationDeviceGroupID: fixture.userGroup, Protocol: policy.ProtocolTCP,
			DestinationPortRanges: []policy.PortRange{fixture.https}},
	}
	for name, params := range refused {
		request, service := fixture.compile(t, resolver, params)
		if _, err := service.Compile(t.Context(), compilationSessionFixture(t), request); !errors.Is(err,
			compilation.ErrInvalidRequest) {
			t.Errorf("%s: error = %v, want ErrInvalidRequest", name, err)
		}
	}

	// A cluster the Network does not have, and a compiler without clusters.
	missing := &clusterResolverFixture{}
	request, service = fixture.compile(t, missing, byCluster)
	if _, err := service.Compile(t.Context(), compilationSessionFixture(t), request); !errors.Is(err,
		compilation.ErrKubernetesClusterUnavailable) {
		t.Fatalf("unknown cluster: %v", err)
	}
	request, service = fixture.compile(t, nil, byCluster)
	if _, err := service.Compile(t.Context(), compilationSessionFixture(t), request); !errors.Is(err,
		compilation.ErrInvalidRequest) {
		t.Fatalf("compiler without clusters: %v", err)
	}
	forbidden := &clusterResolverFixture{err: kubecluster.ErrForbidden}
	request, service = fixture.compile(t, forbidden, byCluster)
	if _, err := service.Compile(t.Context(), compilationSessionFixture(t), request); !errors.Is(err,
		compilation.ErrForbidden) {
		t.Fatalf("forbidden: %v", err)
	}

	// Rules that name no group never ask for clusters.
	quiet := &clusterResolverFixture{}
	plain := tcp443
	plain.SourceNodeID, plain.DestinationNodeID = compilationNodeID(t, "000000000701"), compilationNodeID(t, "000000000702")
	request, service = fixture.compile(t, quiet, plain)
	if _, err := service.Compile(t.Context(), compilationSessionFixture(t), request); err != nil || len(quiet.ensured) != 0 {
		t.Fatalf("Device rule: %v, ensured %v", err, quiet.ensured)
	}
}
