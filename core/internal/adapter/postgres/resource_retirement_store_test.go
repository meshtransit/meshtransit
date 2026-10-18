package postgres

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/resource/retirement"
)

const (
	retirementTestResource = "01890f00-0000-7000-8000-000000000310"
	retirementTestOther    = "01890f00-0000-7000-8000-000000000311"
	retirementTestChange   = "01890f00-0000-7000-8000-000000000320"
)

func retirementFixture(t *testing.T) (resource.ID, publicid.ID) {
	t.Helper()
	id, err := resource.ParseID(retirementTestResource)
	if err != nil {
		t.Fatal(err)
	}
	change, err := publicid.Parse(retirementTestChange)
	if err != nil {
		t.Fatal(err)
	}
	return id, change
}

func TestDecodeResourceRetirementPage(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, encoded string
		limit         int
		wantErr       bool
		wantItems     int
		wantDone      bool
	}{
		{name: "empty", encoded: `{"items":[],"done":true}`, limit: 2, wantDone: true},
		{name: "two in order", limit: 2, wantItems: 2, encoded: `{"items":[
{"resource_id":"` + retirementTestResource + `","requested_at":"2026-10-18T01:00:00Z"},
{"resource_id":"` + retirementTestOther + `","requested_at":"2026-10-18T01:00:00Z"}],"done":false}`},
		{name: "unordered", limit: 2, wantErr: true, encoded: `{"items":[
{"resource_id":"` + retirementTestOther + `","requested_at":"2026-10-18T01:00:00Z"},
{"resource_id":"` + retirementTestResource + `","requested_at":"2026-10-18T01:00:00Z"}],"done":true}`},
		{name: "extra key", limit: 2, wantErr: true, encoded: `{"items":[
{"resource_id":"` + retirementTestResource + `","requested_at":"2026-10-18T01:00:00Z","device":"x"}],"done":true}`},
		{name: "missing done", limit: 2, wantErr: true, encoded: `{"items":[]}`},
		{name: "trailing value", limit: 2, wantErr: true, encoded: `{"items":[],"done":true}{}`},
	} {
		page, err := decodeResourceRetirementPage([]byte(test.encoded), retirement.Cursor{}, test.limit)
		if (err != nil) != test.wantErr || test.wantErr && !errors.Is(err, ErrResourceRetirement) {
			t.Errorf("%s: error = %v, wantErr %v", test.name, err, test.wantErr)
			continue
		}
		if !test.wantErr && (len(page.Items) != test.wantItems || page.Done != test.wantDone) {
			t.Errorf("%s: page = %+v", test.name, page)
		}
	}
}

func retirementProofJSON(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	proof := map[string]any{
		"changed": true, "transaction_id": "123", "change_id": retirementTestChange,
		"resource_id": retirementTestResource, "aggregate_version": 4,
		"event": map[string]any{
			"workspace_id": "01890f00-0000-7000-8000-000000000101", "network_id": "01890f00-0000-7000-8000-000000000201",
			"stream_id": 1, "sequence": 9, "previous_hash": strings.Repeat("ab", 32), "network_revision": 12,
			"audit_payload": `{"reason":"device_removed"}`, "outbox_payload": `{"subsystem":"inventory"}`,
		},
	}
	mutate(proof)
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestDecodeResourceRetirementProof(t *testing.T) {
	t.Parallel()
	id, change := retirementFixture(t)
	if proof, err := decodeResourceRetirementProof([]byte(`{"changed":false,"events":[]}`), id, change); err != nil || proof.Changed {
		t.Fatalf("unchanged proof = %+v, %v", proof, err)
	}
	if proof, err := decodeResourceRetirementProof([]byte(`{"changed":false,"blocked":true,"events":[]}`), id, change); err != nil ||
		proof.Changed || !proof.Blocked {
		t.Fatalf("blocked proof = %+v, %v", proof, err)
	}
	for _, test := range []struct {
		name    string
		mutate  func(map[string]any)
		wantErr bool
	}{
		{name: "valid", mutate: func(map[string]any) {}},
		{name: "another Resource", mutate: func(p map[string]any) { p["resource_id"] = retirementTestOther }, wantErr: true},
		{name: "another change", mutate: func(p map[string]any) { p["change_id"] = retirementTestOther }, wantErr: true},
		{name: "first version", mutate: func(p map[string]any) { p["aggregate_version"] = 1 }, wantErr: true},
		{name: "no event", mutate: func(p map[string]any) { delete(p, "event") }, wantErr: true},
		{name: "events list too", mutate: func(p map[string]any) { p["events"] = []any{} }, wantErr: true},
		{name: "pre-hashed event", mutate: func(p map[string]any) {
			p["event"].(map[string]any)["event_hash"] = strings.Repeat("00", 32)
		}, wantErr: true},
		{name: "short previous hash", mutate: func(p map[string]any) {
			p["event"].(map[string]any)["previous_hash"] = "ab"
		}, wantErr: true},
		{name: "unknown key", mutate: func(p map[string]any) { p["device"] = "x" }, wantErr: true},
		{name: "changed and blocked", mutate: func(p map[string]any) { p["blocked"] = true }, wantErr: true},
	} {
		proof, err := decodeResourceRetirementProof(retirementProofJSON(t, test.mutate), id, change)
		if (err != nil) != test.wantErr {
			t.Errorf("%s: error = %v, wantErr %v", test.name, err, test.wantErr)
			continue
		}
		if test.wantErr {
			continue
		}
		eventID, outboxID := publicid.ID(id), change
		encoded, err := hashResourceRetirementEvent(proof, change, eventID, outboxID)
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		var event resourceRetirementEvidence
		if err := json.Unmarshal(encoded, &event); err != nil || len(event.EventHash) != 64 ||
			event.EventID != eventID.String() || event.OutboxID != outboxID.String() || event.Sequence != 9 {
			t.Fatalf("hashed event = %+v, %v", event, err)
		}
	}
}
