package accessgraph_test

import (
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/workspace"
)

// A path to a cluster carries its rule's groups; other paths and the
// snapshot it came from stay as they were (K1d d4c).
func TestSnapshotWithKubernetesGroups(t *testing.T) {
	t.Parallel()
	snapshot, clusterRule, otherRule, clusterID := kubernetesGroupsSnapshot(t)
	clusters := map[policy.RuleID]kubecluster.ID{clusterRule: clusterID, otherRule: clusterID}

	grouped, err := snapshot.WithKubernetesGroups(map[policy.RuleID][]string{
		clusterRule: {"view", "edit"}, otherRule: {"view"},
	}, clusters)
	if err != nil {
		t.Fatal(err)
	}
	paths := grouped.Paths()
	if !slices.Equal(paths[0].KubernetesGroups(), []string{"view", "edit"}) || paths[1].KubernetesGroups() != nil {
		t.Fatalf("groups = %v, %v", paths[0].KubernetesGroups(), paths[1].KubernetesGroups())
	}
	if snapshot.Paths()[0].KubernetesGroups() != nil {
		t.Fatal("WithKubernetesGroups changed the snapshot it came from")
	}
	held := paths[0].KubernetesGroups()
	held[0] = "cluster-admin"
	if grouped.Paths()[0].KubernetesGroups()[0] != "view" {
		t.Fatal("KubernetesGroups shares its slice")
	}

	for name, groups := range map[string][]string{
		"invalid group": {"view", "Bad Group!"},
		"too many":      slices.Repeat([]string{"view"}, kubecluster.MaximumRuleKubernetesGroups+1),
		"empty name":    {""},
	} {
		if _, err := snapshot.WithKubernetesGroups(map[policy.RuleID][]string{clusterRule: groups},
			clusters); !errors.Is(err, accessgraph.ErrInvalidSnapshot) {
			t.Fatalf("%s: err = %v, want ErrInvalidSnapshot", name, err)
		}
	}
	// The release's rule names another cluster than the path reached.
	other, err := kubecluster.ParseID("01890f00-0000-7000-8000-000000000b02")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.WithKubernetesGroups(map[policy.RuleID][]string{clusterRule: {"view"}},
		map[policy.RuleID]kubecluster.ID{clusterRule: other}); !errors.Is(err, accessgraph.ErrInvalidSnapshot) {
		t.Fatalf("another cluster's rule: err = %v, want ErrInvalidSnapshot", err)
	}
}

// kubernetesGroupsSnapshot is a snapshot with a path through a cluster's own
// Device Group, named the cluster, and a path to a plain Device.
func kubernetesGroupsSnapshot(t *testing.T) (accessgraph.Snapshot, policy.RuleID, policy.RuleID,
	kubecluster.ID) {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	must(err)
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000201")
	must(err)
	scope, err := network.NewScope(workspaceID, networkID)
	must(err)
	source, err := node.ParseID("01890f00-0000-7000-8000-000000000301")
	must(err)
	replica, err := node.ParseID("01890f00-0000-7000-8000-000000000302")
	must(err)
	clusterRule, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000501")
	must(err)
	otherRule, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000502")
	must(err)
	clusterGroup, err := devicegroup.ParseID("01890f00-0000-7000-8000-000000000a01")
	must(err)
	clusterID, err := kubecluster.ParseID("01890f00-0000-7000-8000-000000000b01")
	must(err)
	clusterName, err := kubecluster.ParseName("prod")
	must(err)
	ports, err := policy.NewPortRange(443, 443)
	must(err)
	path := func(projection string, rule policy.RuleID, group devicegroup.ID) accessgraph.Path {
		projectionID, err := publication.ParseProjectionID(projection)
		must(err)
		built, err := accessgraph.NewPath(accessgraph.PathParams{
			ProjectionID: projectionID, RuleID: rule, SourceNodeID: source, DestinationNodeID: replica,
			Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{ports},
			SelectorKind: accessgraph.SelectorKindDevice, DestinationDeviceGroupID: group,
		})
		must(err)
		return built
	}
	releaseID, err := publication.ParseReleaseID("01890f00-0000-7000-8000-000000000901")
	must(err)
	hash, err := publication.NewSemanticHash(sha256.Sum256([]byte("kubernetes groups fixture")))
	must(err)
	participant, err := accessgraph.NewParticipant(accessgraph.ParticipantStateActive, "gateway")
	must(err)
	snapshot, err := accessgraph.NewSnapshot(accessgraph.SnapshotParams{
		Scope: scope, NetworkRevision: 5, InventoryRevision: 1, GroupRevision: 1, PolicyRevision: 3,
		DNSRevision: 1, RouteRevision: 1, SharingRevision: 1, IsolationGeneration: 1, HasActiveRelease: true,
		ReleaseID: releaseID, CompilerFormatVersion: 3, SemanticHash: hash, TargetNodeID: replica,
		Paths: []accessgraph.Path{
			path("01890f00-0000-7000-8000-000000000701", clusterRule, clusterGroup),
			path("01890f00-0000-7000-8000-000000000702", otherRule, devicegroup.ID{}),
		},
		Source: participant, TargetKind: accessgraph.TargetKindDevice, Target: participant,
	})
	must(err)
	named, err := snapshot.WithKubernetesClusters([]kubecluster.PolicyGroup{{
		ClusterID: clusterID, Name: clusterName, GroupID: clusterGroup,
	}})
	must(err)
	return named, clusterRule, otherRule, clusterID
}
