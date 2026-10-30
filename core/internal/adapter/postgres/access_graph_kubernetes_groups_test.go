package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/workspace"
)

type kubernetesGroupsRow struct {
	encoded *string
	err     error
}

func (row kubernetesGroupsRow) Scan(destination ...any) error {
	if row.err != nil {
		return row.err
	}
	*destination[0].(**string) = row.encoded
	return nil
}

// Paths to a cluster carry their rule's groups from the explained release;
// a reader who may not read the rules, a bad read or a rule naming another
// cluster never shows groups (K1d d4c).
func TestGroupKubernetesClusterPaths(t *testing.T) {
	t.Parallel()
	snapshot, scope := groupsSnapshotFixture(t, true)
	session := accountSessionManagementScopeSession(t, time.Date(2026, time.October, 30, 0, 0, 0, 0, time.UTC))
	read := func(encoded *string, err error) (accessgraph.Snapshot, int, error) {
		calls := 0
		grouped, groupErr := groupKubernetesClusterPaths(context.Background(),
			func(context.Context, string, ...any) resourceAuthorityRow {
				calls++
				return kubernetesGroupsRow{encoded: encoded, err: err}
			}, session, scope, time.Now(), snapshot)
		return grouped, calls, groupErr
	}
	text := func(value string) *string { return &value }
	const rules = `{"policy_revision":6,"hashed":true,"rules":[{"id":"01890f00-0000-7000-8000-000000000501",` +
		`"cluster_id":"CLUSTER","source_kind":"device","source_id":"01890f00-0000-7000-8000-000000000301",` +
		`"groups":["edit","view"]}]}`
	cluster := "01890f00-0000-7000-8000-000000000b01"

	grouped, calls, err := read(text(strings.ReplaceAll(rules, "CLUSTER", cluster)), nil)
	if err != nil || calls != 1 || !slices.Equal(grouped.Paths()[0].KubernetesGroups(), []string{"edit", "view"}) {
		t.Fatalf("groups = %v, calls %d, %v", grouped.Paths()[0].KubernetesGroups(), calls, err)
	}
	// Not a reader of the rules, or no release at the revision: no groups.
	if grouped, _, err := read(nil, nil); err != nil || grouped.Paths()[0].KubernetesGroups() != nil {
		t.Fatalf("unread groups = %v, %v", grouped.Paths()[0].KubernetesGroups(), err)
	}
	for name, test := range map[string]struct {
		encoded *string
		err     error
		want    error
	}{
		"another revision": {text(`{"policy_revision":5,"hashed":false,"rules":[]}`), nil,
			accessgraph.ErrInvalidSnapshot},
		"another cluster": {text(strings.ReplaceAll(rules, "CLUSTER", "01890f00-0000-7000-8000-000000000b02")), nil,
			accessgraph.ErrInvalidSnapshot},
		"unsorted groups": {text(`{"policy_revision":6,"hashed":true,"rules":[{"id":"01890f00-0000-7000-8000-` +
			`000000000501","cluster_id":"` + cluster + `","source_kind":"device","source_id":"01890f00-0000-7000-` +
			`8000-000000000301","groups":["view","edit"]}]}`), nil, accessgraph.ErrInvalidSnapshot},
		"database": {nil, errors.New("connection reset"), accessgraph.ErrUnavailable},
	} {
		if _, _, err := read(test.encoded, test.err); !errors.Is(err, test.want) {
			t.Errorf("%s: err = %v, want %v", name, err, test.want)
		}
	}
	// No path to a cluster: nothing is read.
	plain, _ := groupsSnapshotFixture(t, false)
	calls = 0
	if _, err := groupKubernetesClusterPaths(context.Background(),
		func(context.Context, string, ...any) resourceAuthorityRow {
			calls++
			return kubernetesGroupsRow{}
		}, session, scope, time.Now(), plain); err != nil || calls != 0 {
		t.Fatalf("a snapshot with no cluster path read %d times, %v", calls, err)
	}
}

// groupsSnapshotFixture is a snapshot at policy revision 6 with one path
// through a Device Group, named cluster b01 when toCluster.
func groupsSnapshotFixture(t *testing.T, toCluster bool) (accessgraph.Snapshot, network.Scope) {
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
	rule, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000501")
	must(err)
	group, err := devicegroup.ParseID("01890f00-0000-7000-8000-000000000a01")
	must(err)
	projection, err := publication.ParseProjectionID("01890f00-0000-7000-8000-000000000701")
	must(err)
	ports, err := policy.NewPortRange(443, 443)
	must(err)
	path, err := accessgraph.NewPath(accessgraph.PathParams{
		ProjectionID: projection, RuleID: rule, SourceNodeID: source, DestinationNodeID: replica,
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{ports},
		SelectorKind: accessgraph.SelectorKindDevice, DestinationDeviceGroupID: group,
	})
	must(err)
	release, err := publication.ParseReleaseID("01890f00-0000-7000-8000-000000000901")
	must(err)
	hash, err := publication.NewSemanticHash(sha256.Sum256([]byte("groups fixture")))
	must(err)
	participant, err := accessgraph.NewParticipant(accessgraph.ParticipantStateActive, "prod-0")
	must(err)
	snapshot, err := accessgraph.NewSnapshot(accessgraph.SnapshotParams{
		Scope: scope, NetworkRevision: 12, InventoryRevision: 8, GroupRevision: 9, PolicyRevision: 6,
		DNSRevision: 2, RouteRevision: 2, SharingRevision: 2, IsolationGeneration: 1, HasActiveRelease: true,
		ReleaseID: release, CompilerFormatVersion: 3, SemanticHash: hash, TargetNodeID: replica,
		Paths: []accessgraph.Path{path}, Source: participant, TargetKind: accessgraph.TargetKindDevice,
		Target: participant,
	})
	must(err)
	if !toCluster {
		return snapshot, scope
	}
	cluster, err := kubecluster.ParseID("01890f00-0000-7000-8000-000000000b01")
	must(err)
	name, err := kubecluster.ParseName("prod")
	must(err)
	snapshot, err = snapshot.WithKubernetesClusters([]kubecluster.PolicyGroup{{ClusterID: cluster, Name: name,
		GroupID: group}})
	must(err)
	return snapshot, scope
}
