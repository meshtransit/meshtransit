package catalog_test

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/catalog"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/workspace"
)

// A rule to a cluster's own group reads as a rule to the cluster; other
// group rules stay group rules, and the snapshot stays Device rules only.
func TestSnapshotNamesKubernetesClusters(t *testing.T) {
	t.Parallel()
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000201")
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	users, _ := devicegroup.ParseID("01890f00-0000-7000-8000-000000000a01")
	replicas, _ := devicegroup.ParseID("01890f00-0000-7000-8000-000000000a09")
	cluster, _ := kubecluster.ParseID("01890f00-0000-7000-8000-000000000f01")
	https, _ := policy.NewPortRange(443, 443)
	intent := func(suffix string, destination devicegroup.ID) compilation.RuleIntent {
		id, _ := policy.ParseRuleID("01890f00-0000-7000-8000-" + suffix)
		value, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
			ID: id, Scope: scope, SourceGroupID: users, DestinationDeviceGroupID: destination,
			Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{https},
		})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	hash, _ := publication.NewSemanticHash([32]byte{1})
	snapshot, err := catalog.NewSnapshot(catalog.SnapshotParams{
		Scope: scope, Revision: 3, SemanticHash: hash, RuleCount: 2, DeviceRulesOnly: true,
		Rows: []catalog.Row{{Intent: intent("000000000801", replicas)}, {Intent: intent("000000000802", users)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	named, err := snapshot.WithKubernetesClusters([]kubecluster.PolicyGroup{
		{ClusterID: cluster, Name: "kinda-k1", GroupID: replicas},
	})
	rows := named.Rows()
	if err != nil || !named.DeviceRulesOnly() || rows[0].Intent.DestinationKubernetesClusterID() != cluster ||
		rows[0].Intent.DestinationDeviceGroupID().IsValid() || rows[1].Intent.DestinationDeviceGroupID() != users {
		t.Fatalf("WithKubernetesClusters() = %+v, %v", rows, err)
	}
	if snapshot.Rows()[0].Intent.DestinationDeviceGroupID() != replicas {
		t.Fatal("the original snapshot changed")
	}
	if _, err := snapshot.WithKubernetesClusters([]kubecluster.PolicyGroup{{GroupID: replicas}}); !errors.Is(err,
		catalog.ErrInvalidSnapshot) {
		t.Fatalf("an invalid group: %v", err)
	}
}
