package postgres

import (
	"errors"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/accessgraph"
)

func TestAccessGraphNodeRecordDecodesEachKind(t *testing.T) {
	t.Parallel()

	share := `{"trust_contract_id":"01890f00-0000-7000-8000-000000000851","state":"active",` +
		`"expires_at":null,"provider_workspace_code":"280133080243","provider_network_code":"467111232749",` +
		`"access_name":"poc01b.280133080243.467111232749.shared.mesh"}`
	tests := []struct {
		name     string
		document string
		want     accessgraph.GraphNodeKind
		wantErr  bool
	}{
		{name: "device", document: `[{"kind":"device","id":"01890f00-0000-7000-8000-000000000301","name":"poc-02","state":"active","share":null}]`, want: accessgraph.GraphNodeKindDevice},
		{name: "resource", document: `[{"kind":"resource","id":"01890f00-0000-7000-8000-000000000601","name":"db","state":"inactive","share":null}]`, want: accessgraph.GraphNodeKindResource},
		{name: "shared Device", document: `[{"kind":"imported_resource","id":"01890f00-0000-7000-8000-000000000981","name":"poc01b","state":"active","share":` + share + `}]`, want: accessgraph.GraphNodeKindImportedResource},
		{name: "shared Device without contract", document: `[{"kind":"imported_resource","id":"01890f00-0000-7000-8000-000000000981","name":"poc01b","state":"active","share":null}]`, wantErr: true},
		{name: "contract on a Device", document: `[{"kind":"device","id":"01890f00-0000-7000-8000-000000000301","name":"poc-02","state":"active","share":` + share + `}]`, wantErr: true},
		{name: "missing participant", document: `[{"kind":"device","id":"01890f00-0000-7000-8000-000000000301","name":null,"state":"missing","share":null}]`, wantErr: true},
		{name: "unknown kind", document: `[{"kind":"group","id":"01890f00-0000-7000-8000-000000000301","name":"x","state":"active","share":null}]`, wantErr: true},
		{name: "unknown field", document: `[{"kind":"device","id":"01890f00-0000-7000-8000-000000000301","name":"x","state":"active","share":null,"address":"10.0.0.1"}]`, wantErr: true},
		{name: "trailing data", document: `[] []`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var records []accessGraphNodeRecord
			err := decodeAccessGraphListingJSON(test.document, &records)
			if err == nil && len(records) == 1 {
				var graphNode accessgraph.GraphNode
				graphNode, err = records[0].node()
				if err == nil && graphNode.Kind() != test.want {
					t.Fatalf("kind = %v, want %v", graphNode.Kind(), test.want)
				}
			}
			if (err != nil) != test.wantErr {
				t.Fatalf("decode error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestAccessGraphListingRejectsOversizedDocuments(t *testing.T) {
	t.Parallel()

	var records []accessGraphNodeRecord
	oversized := "[" + strings.Repeat(" ", maximumAccessGraphListingBytes) + "]"
	if err := decodeAccessGraphListingJSON(oversized, &records); !errors.Is(err, accessgraph.ErrInvalidSnapshot) {
		t.Fatalf("decode oversized error = %v", err)
	}
}
