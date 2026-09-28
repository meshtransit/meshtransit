package postgres

import (
	"encoding/json"
	"testing"

	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func TestAccessGraphSnapshotRecordDecodesResourceGroupProvenance(t *testing.T) {
	t.Parallel()

	query := postgresAccessGraphQueryFixture(t)
	releaseID := "01890f00-0000-7000-8000-000000000901"
	compilerFormat := 3
	targetNodeID := "01890f00-0000-7000-8000-000000000302"
	record := accessGraphSnapshotRecord{
		NetworkRevision: 12, InventoryRevision: 8, GroupRevision: 9,
		PolicyRevision: 6, DNSRevision: 2, RouteRevision: 2,
		SharingRevision: 2, IsolationGeneration: 1, HasActiveRelease: true,
		ReleaseID: &releaseID, CompilerFormatVersion: &compilerFormat,
		SemanticHash: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		TargetNodeID: &targetNodeID,
		Paths: []accessGraphPathRecord{{
			ProjectionID:      "01890f00-0000-7000-8000-000000000701",
			RuleID:            "01890f00-0000-7000-8000-000000000501",
			SourceNodeID:      "01890f00-0000-7000-8000-000000000301",
			DestinationNodeID: targetNodeID, Protocol: "tcp",
			DestinationPortRangeFirst: []int{443}, DestinationPortRangeLast: []int{443},
			SelectorKind:          "resource_group",
			DestinationResourceID: "01890f00-0000-7000-8000-000000000601",
			DestinationGroupID:    "01890f00-0000-7000-8000-000000000651",
		}},
	}

	snapshot, err := record.snapshot(query)
	if err != nil {
		t.Fatalf("snapshot() error = %v", err)
	}
	paths := snapshot.Paths()
	if !snapshot.IsValid() || snapshot.PolicyRevision() != 6 ||
		snapshot.TargetNodeID().String() != targetNodeID || len(paths) != 1 ||
		paths[0].SelectorKind() != accessgraph.SelectorKindResourceGroup ||
		paths[0].DestinationResourceID() != query.DestinationResourceID() ||
		!paths[0].DestinationGroupID().IsValid() {
		t.Fatalf("snapshot = %+v, paths = %+v", snapshot, paths)
	}
}

func TestAccessGraphPathRecordRejectsMismatchedPortArrays(t *testing.T) {
	t.Parallel()

	record := accessGraphPathRecord{
		ProjectionID:      "01890f00-0000-7000-8000-000000000701",
		RuleID:            "01890f00-0000-7000-8000-000000000501",
		SourceNodeID:      "01890f00-0000-7000-8000-000000000301",
		DestinationNodeID: "01890f00-0000-7000-8000-000000000302",
		Protocol:          "tcp", DestinationPortRangeFirst: []int{443},
		DestinationPortRangeLast: nil, SelectorKind: "device",
	}
	if _, err := record.path(); err == nil {
		t.Fatal("path() accepted mismatched port arrays")
	}
}

func TestAccessGraphPathRecordJSONNullOptionalIDsRemainAbsent(t *testing.T) {
	t.Parallel()

	var record accessGraphPathRecord
	err := json.Unmarshal([]byte(`{
		"projection_id":"01890f00-0000-7000-8000-000000000701",
		"access_rule_id":"01890f00-0000-7000-8000-000000000501",
		"source_device_id":"01890f00-0000-7000-8000-000000000301",
		"destination_device_id":"01890f00-0000-7000-8000-000000000302",
		"protocol":"icmp","destination_port_range_first":[],
		"destination_port_range_last":[],"selector_kind":"device",
		"destination_resource_id":null,"destination_resource_group_id":null
	}`), &record)
	if err != nil {
		t.Fatal(err)
	}
	path, err := record.path()
	if err != nil {
		t.Fatalf("path() error = %v", err)
	}
	if path.DestinationResourceID().IsValid() || path.DestinationGroupID().IsValid() {
		t.Fatalf("optional provenance = %+v", path)
	}
}

func postgresAccessGraphQueryFixture(t *testing.T) accessgraph.Query {
	t.Helper()
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000201")
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	sourceID, _ := node.ParseID("01890f00-0000-7000-8000-000000000301")
	resourceID, _ := resource.ParseID("01890f00-0000-7000-8000-000000000601")
	query, err := accessgraph.NewQuery(accessgraph.QueryParams{
		Scope: scope, SourceNodeID: sourceID, DestinationResourceID: resourceID,
		Protocol: policy.ProtocolTCP, DestinationPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	return query
}
