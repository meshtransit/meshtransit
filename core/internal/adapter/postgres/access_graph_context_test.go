package postgres

import (
	"errors"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing"
)

const postgresSharedContext = `{"source":{"state":"active","name":"poc-02"},
"target":{"kind":"imported_resource","state":"active","name":"poc01"},
"share":{"trust_contract_id":"01890f00-0000-7000-8000-000000000851","state":"active",
"expires_at":null,"provider_workspace_code":"280133080243","provider_network_code":"467111232749",
"access_name":"poc01.280133080243.467111232749.shared.mesh"}}`

func TestAccessGraphSnapshotRecordDecodesSharedDevicePath(t *testing.T) {
	t.Parallel()

	query := postgresSharedAccessGraphQueryFixture(t)
	record := postgresSharedSnapshotRecord(t, postgresSharedContext)
	snapshot, err := record.snapshot(query)
	if err != nil {
		t.Fatalf("snapshot() error = %v", err)
	}
	share, hasShare := snapshot.Share()
	paths := snapshot.Paths()
	if _, expires := share.ExpiresAt(); !hasShare || expires || share.State() != sharing.ContractStateActive ||
		share.AccessName() != "poc01.280133080243.467111232749.shared.mesh" ||
		snapshot.TargetKind() != accessgraph.TargetKindImportedResource || len(paths) != 1 ||
		paths[0].SelectorKind() != accessgraph.SelectorKindImportedResource ||
		paths[0].TrustContractID() != share.ContractID() || paths[0].DestinationNodeID().IsValid() {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestAccessGraphSnapshotRecordDecodesShareExpiry(t *testing.T) {
	t.Parallel()

	encoded := strings.Replace(postgresSharedContext, `"expires_at":null`, `"expires_at":"2026-10-13T07:58:34.123456+00:00"`, 1)
	encoded = strings.Replace(encoded, `"state":"active",`+"\n"+`"expires_at"`, `"state":"expired",`+"\n"+`"expires_at"`, 1)
	record := postgresSharedSnapshotRecord(t, encoded)
	record.Paths = nil
	snapshot, err := record.snapshot(postgresSharedAccessGraphQueryFixture(t))
	if err != nil {
		t.Fatalf("snapshot() error = %v", err)
	}
	share, _ := snapshot.Share()
	expiresAt, expires := share.ExpiresAt()
	if !expires || expiresAt.Year() != 2026 || share.State() != sharing.ContractStateExpired {
		t.Fatalf("share = %+v", share)
	}
}

func TestDecodeAccessGraphContextRejectsUnexpectedInput(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		encoded string
	}{
		{name: "unknown field", encoded: `{"source":{"state":"active","name":"a"},"target":{"kind":"device","state":"active","name":"b"},"share":null,"extra":1}`},
		{name: "trailing document", encoded: `{"source":{"state":"active","name":"a"},"target":{"kind":"device","state":"active","name":"b"},"share":null}{}`},
		{name: "oversized", encoded: `{"source":{"state":"active","name":"` + strings.Repeat("a", maximumAccessGraphContextBytes) + `"}}`},
		{name: "not JSON", encoded: `source=active`},
	} {
		if _, err := decodeAccessGraphContext(test.encoded); !errors.Is(err, accessgraph.ErrInvalidSnapshot) {
			t.Errorf("%s: error = %v", test.name, err)
		}
	}
}

func TestAccessGraphSnapshotRecordRejectsIncompleteShare(t *testing.T) {
	t.Parallel()

	for name, encoded := range map[string]string{
		"missing workspace code": strings.Replace(postgresSharedContext, `"provider_workspace_code":"280133080243"`, `"provider_workspace_code":null`, 1),
		"malformed contract":     strings.Replace(postgresSharedContext, `01890f00-0000-7000-8000-000000000851`, `not-a-contract`, 1),
		"unknown contract state": strings.Replace(postgresSharedContext, `"state":"active",`+"\n"+`"expires_at"`, `"state":"paused",`+"\n"+`"expires_at"`, 1),
		"unknown target kind":    strings.Replace(postgresSharedContext, `"kind":"imported_resource"`, `"kind":"peer"`, 1),
		"zero expiry":            strings.Replace(postgresSharedContext, `"expires_at":null`, `"expires_at":"0001-01-01T00:00:00Z"`, 1),
	} {
		record := postgresSharedSnapshotRecord(t, postgresSharedContext)
		record.Context = postgresAccessGraphContextFixture(t, encoded)
		record.Paths = nil
		if _, err := record.snapshot(postgresSharedAccessGraphQueryFixture(t)); !errors.Is(err, accessgraph.ErrInvalidSnapshot) {
			t.Errorf("%s: snapshot() error = %v", name, err)
		}
	}
}

func postgresAccessGraphContextFixture(t *testing.T, encoded string) accessGraphContextRecord {
	t.Helper()
	record, err := decodeAccessGraphContext(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func postgresSharedSnapshotRecord(t *testing.T, encoded string) accessGraphSnapshotRecord {
	t.Helper()
	releaseID := "01890f00-0000-7000-8000-000000000901"
	compilerFormat := 4
	return accessGraphSnapshotRecord{
		NetworkRevision: 12, InventoryRevision: 8, GroupRevision: 9,
		PolicyRevision: 6, DNSRevision: 2, RouteRevision: 2,
		SharingRevision: 2, IsolationGeneration: 1, HasActiveRelease: true,
		ReleaseID: &releaseID, CompilerFormatVersion: &compilerFormat,
		SemanticHash: append(make([]byte, 31), 1),
		Paths: []accessGraphPathRecord{{
			ProjectionID: "01890f00-0000-7000-8000-000000000702",
			RuleID:       "01890f00-0000-7000-8000-000000000502",
			SourceNodeID: "01890f00-0000-7000-8000-000000000301",
			Protocol:     "icmp", DestinationPortRangeFirst: []int{}, DestinationPortRangeLast: []int{},
			SelectorKind:                  "imported_resource",
			DestinationImportedResourceID: "01890f00-0000-7000-8000-000000000801",
			TrustContractID:               "01890f00-0000-7000-8000-000000000851",
		}},
		Context: postgresAccessGraphContextFixture(t, encoded),
	}
}

func postgresSharedAccessGraphQueryFixture(t *testing.T) accessgraph.Query {
	t.Helper()
	importedID, err := sharing.ParseImportedResourceID("01890f00-0000-7000-8000-000000000801")
	if err != nil {
		t.Fatal(err)
	}
	base := postgresAccessGraphQueryFixture(t)
	query, err := accessgraph.NewQuery(accessgraph.QueryParams{
		Scope: base.Scope(), SourceNodeID: base.SourceNodeID(),
		DestinationImportedResourceID: importedID, Protocol: policy.ProtocolICMP,
	})
	if err != nil {
		t.Fatal(err)
	}
	return query
}
