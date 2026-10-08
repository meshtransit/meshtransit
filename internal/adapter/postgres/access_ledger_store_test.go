package postgres

import (
	"errors"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/internal/accessgraph/ledger"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

func mustAccessLedgerID(t *testing.T, value string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestAccessLedgerStoresRejectWrongPools(t *testing.T) {
	t.Parallel()
	for _, pool := range []*Pool{nil, {role: PoolRoleRuntime}, {role: PoolRoleWorker}} {
		if store, err := NewAccessLedgerStore(pool); store != nil || !errors.Is(err, ErrInvalidAccessLedger) {
			t.Fatalf("NewAccessLedgerStore(%+v) accepted", pool)
		}
	}
	if store, err := NewAccessGraphHistoryStore(&Pool{role: PoolRoleWorker}, AccountSessionOptions{}); store != nil ||
		!errors.Is(err, ledger.ErrUnavailable) {
		t.Fatal("history store accepted a worker pool")
	}
}

func TestDecodeAccessLedgerProofAndHash(t *testing.T) {
	t.Parallel()
	snapshot := mustAccessLedgerID(t, "01890f00-0000-7000-8000-000000013401")
	change := mustAccessLedgerID(t, "01890f00-0000-7000-8000-000000013402")
	event := mustAccessLedgerID(t, "01890f00-0000-7000-8000-000000013403")
	hash := strings.Repeat("ab", 32)
	recorded := `{"recorded":true,"busy":false,"snapshot_id":"` + snapshot.String() + `","network_revision":7,` +
		`"digest":"` + hash + `","stream_id":3,"sequence":12,"previous_hash":"` + hash + `",` +
		`"payload":"{\"format\": \"access-edges/v1\"}"}`
	proof, err := decodeAccessLedgerProof(recorded, snapshot)
	if err != nil || !proof.Recorded || proof.Sequence != 12 || proof.NetworkRevision != 7 {
		t.Fatalf("decode = %+v %v", proof, err)
	}
	first, err := hashAccessLedgerEvent(proof, change, event)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := hashAccessLedgerEvent(proof, change, event)
	other, _ := hashAccessLedgerEvent(proof, change, snapshot)
	if first != second || first == other {
		t.Fatal("event hash is not bound to its identity")
	}
	if proof, err := decodeAccessLedgerProof(`{"recorded":false,"busy":true}`, snapshot); err != nil || !proof.Busy {
		t.Fatalf("busy = %+v %v", proof, err)
	}
	for name, encoded := range map[string]string{
		"other snapshot":   strings.Replace(recorded, snapshot.String(), change.String(), 1),
		"short digest":     strings.Replace(recorded, `"digest":"`+hash, `"digest":"abcd`, 1),
		"zero sequence":    strings.Replace(recorded, `"sequence":12`, `"sequence":0`, 1),
		"unknown field":    strings.Replace(recorded, `"busy":false`, `"busy":false,"extra":1`, 1),
		"unchanged detail": `{"recorded":false,"busy":false,"network_revision":3}`,
		"trailing value":   recorded + "{}",
	} {
		if _, err := decodeAccessLedgerProof(encoded, snapshot); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDecodeAccessGraphHistory(t *testing.T) {
	t.Parallel()
	key := strings.Repeat("0a", 32)
	encoded := `{"workspace_id":"01890f00-0000-7000-8000-000000000101",` +
		`"network_id":"01890f00-0000-7000-8000-000000000201","at":"2026-10-08T12:00:00Z",` +
		`"recorded_since":"2026-10-08T10:00:00Z","network_revision":9,` +
		`"snapshot":{"id":"01890f00-0000-7000-8000-000000013401","network_revision":9,` +
		`"effective_at":"2026-10-08T11:00:00Z","recorded_at":"2026-10-08T11:00:02Z","edge_count":1,"digest":"` + key + `"},` +
		`"edges":[{"edge_id":"` + key + `","access_rule_id":"01890f00-0000-7000-8000-000000000501",` +
		`"selector_kind":"device","source_device_id":"01890f00-0000-7000-8000-000000000301","source_hostname":"a",` +
		`"destination_device_id":"01890f00-0000-7000-8000-000000000302","destination_hostname":null,` +
		`"destination_imported_resource_id":null,"trust_contract_id":null,"destination_resource_id":null,` +
		`"destination_resource_group_id":null,"source_selector_kind":"device_group",` +
		`"source_selector_id":"01890f00-0000-7000-8000-000000000901","destination_selector_kind":null,` +
		`"destination_selector_id":null,"protocol":"tcp","destination_port_range_first":[22,443],` +
		`"destination_port_range_last":[22,443],"valid_from_revision":4,"valid_from_at":"2026-10-08T10:00:00Z",` +
		`"valid_to_revision":null,"valid_to_at":null,"expires_at":null}]}`
	result, err := decodeAccessGraphHistory(encoded, 2)
	if err != nil {
		t.Fatal(err)
	}
	edge := result.Edges[0]
	if result.NetworkRevision != 9 || result.Snapshot == nil || result.Snapshot.EdgeCount != 1 ||
		edge.Key.String() != key || edge.Protocol != policy.ProtocolTCP || len(edge.Ports) != 2 ||
		edge.Ports[1].First() != 443 || edge.SourceHostname != "a" || edge.DestinationHostname != "" ||
		!edge.SourceSelectorID.IsValid() || edge.ValidToRevision != 0 || !edge.ExpiresAt.IsZero() {
		t.Fatalf("result = %+v", result)
	}
	for name, mutated := range map[string]string{
		"bad protocol":     strings.Replace(encoded, `"protocol":"tcp"`, `"protocol":"any"`, 1),
		"uneven ports":     strings.Replace(encoded, `"destination_port_range_last":[22,443]`, `"destination_port_range_last":[22]`, 1),
		"half closed":      strings.Replace(encoded, `"valid_to_revision":null`, `"valid_to_revision":5`, 1),
		"bad key":          strings.Replace(encoded, `"edge_id":"`+key, `"edge_id":"zz`+key[2:], 1),
		"descending range": strings.Replace(encoded, `"destination_port_range_first":[22,443]`, `"destination_port_range_first":[23,443]`, 1),
		"missing edges":    strings.Replace(encoded, `"edges":[`, `"other":[`, 1),
	} {
		if _, err := decodeAccessGraphHistory(mutated, 2); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := decodeAccessGraphHistory(encoded, 0); err == nil {
		t.Error("page larger than requested accepted")
	}
}
