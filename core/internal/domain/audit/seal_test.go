package audit_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/audit"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

// sealVectorHex pins the v2 encoding. Changing it breaks every exported
// record ever verified, so it changes only with a new hash version.
const sealVectorHex = "016575104ed2b058570bcfcea2bbdb826a1b7ea4f0ba0aba6f177ebbffa9429a"

func sealVectorRecord(t *testing.T) audit.Record {
	t.Helper()
	payload := `{"reason": "maintenance window", "revision": 7}`
	var parsed map[string]any
	if err := json.Unmarshal([]byte(payload), &parsed); err != nil {
		t.Fatal(err)
	}
	return audit.Record{
		RecordVersion: audit.RecordVersion,
		EventID:       "01928f6e-7a10-7000-8000-000000000001",
		EventTime:     "2026-10-07T04:05:06.123456Z",
		StreamID:      "01928f6e-7a10-7000-8000-000000000002",
		Sequence:      42,
		WorkspaceID:   "01928f6e-7a10-7000-8000-000000000003",
		NetworkID:     "01928f6e-7a10-7000-8000-000000000004",
		ChangeID:      "01928f6e-7a10-7000-8000-000000000005",
		ActorKind:     audit.ActorPrincipal, ActorPrincipalID: "01928f6e-7a10-7000-8000-000000000006",
		Action: "policy.published", Permission: "policy.publish", Result: audit.ResultSucceeded,
		TargetKind: "policy", TargetID: "01928f6e-7a10-7000-8000-000000000007",
		AfterSemanticHash: hex.EncodeToString(make([]byte, 31)) + "01",
		PayloadVersion:    1, Payload: parsed, PayloadCanonical: payload,
		Integrity: audit.RecordIntegrity{
			Status: audit.IntegritySealed, HashVersion: audit.SealHashVersion,
			PreviousSeal: hex.EncodeToString(make([]byte, 32)),
		},
	}
}

func TestSealMatchesPinnedVector(t *testing.T) {
	t.Parallel()
	record := sealVectorRecord(t)
	material, err := record.SealMaterial()
	if err != nil {
		t.Fatalf("SealMaterial() error = %v", err)
	}
	seal, err := audit.Seal(material)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if got := hex.EncodeToString(seal[:]); got != sealVectorHex {
		t.Fatalf("Seal() = %s, want %s", got, sealVectorHex)
	}
	record.Integrity.Seal = sealVectorHex
	if err := record.VerifySeal(); err != nil {
		t.Fatalf("VerifySeal() error = %v", err)
	}
}

func TestSealBindsEveryCoveredField(t *testing.T) {
	t.Parallel()
	base := sealVectorRecord(t)
	base.Integrity.Seal = sealVectorHex
	mutations := map[string]func(*audit.Record){
		"time":      func(r *audit.Record) { r.EventTime = "2026-10-07T04:05:06.123457Z" },
		"sequence":  func(r *audit.Record) { r.Sequence++ },
		"stream":    func(r *audit.Record) { r.StreamID = "01928f6e-7a10-7000-8000-000000000009" },
		"workspace": func(r *audit.Record) { r.WorkspaceID = "01928f6e-7a10-7000-8000-000000000009" },
		"network":   func(r *audit.Record) { r.NetworkID = "" },
		"actor":     func(r *audit.Record) { r.ActorKind, r.ActorPrincipalID = audit.ActorSystem, "" },
		"result":    func(r *audit.Record) { r.Result = audit.ResultDenied },
		"target":    func(r *audit.Record) { r.TargetKind = "share" },
		"payload":   func(r *audit.Record) { r.PayloadCanonical = `{"reason": "maintenance window", "revision": 8}` },
		"zero hash": func(r *audit.Record) { r.BeforeSemanticHash = hex.EncodeToString(make([]byte, 32)) },
		"spacing":   func(r *audit.Record) { r.PayloadCanonical = `{"reason":"maintenance window","revision":7}` },
		"previous":  func(r *audit.Record) { r.Integrity.PreviousSeal = hex.EncodeToString(make([]byte, 31)) + "ff" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			record := base
			mutate(&record)
			if err := record.VerifySeal(); !errors.Is(err, audit.ErrInvalidRecord) {
				t.Fatalf("VerifySeal() after changing %s = %v, want ErrInvalidRecord", name, err)
			}
		})
	}
}

func TestSealRejectsIncompleteMaterial(t *testing.T) {
	t.Parallel()
	material, err := sealVectorRecord(t).SealMaterial()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*audit.SealMaterial){
		"sequence":         func(m *audit.SealMaterial) { m.Sequence = 0 },
		"time":             func(m *audit.SealMaterial) { m.OccurredAt = time.Time{} },
		"network only":     func(m *audit.SealMaterial) { m.WorkspaceID = publicid.ID{} },
		"result":           func(m *audit.SealMaterial) { m.Result = "ok" },
		"label":            func(m *audit.SealMaterial) { m.Action = "Policy Published" },
		"payload":          func(m *audit.SealMaterial) { m.PayloadCanonical = "" },
		"payload encoding": func(m *audit.SealMaterial) { m.PayloadCanonical = "{\"a\": \"\xff\"}" },
	}
	for name, mutate := range cases {
		changed := material
		mutate(&changed)
		if _, err := audit.Seal(changed); !errors.Is(err, audit.ErrInvalidEventHash) {
			t.Errorf("Seal(%s) error = %v, want ErrInvalidEventHash", name, err)
		}
	}
	if _, err := audit.Seal(material); err != nil {
		t.Fatalf("Seal(valid) error = %v", err)
	}
}

func TestLegacyRecordHasNoSealMaterial(t *testing.T) {
	t.Parallel()
	record := sealVectorRecord(t)
	record.Integrity = audit.RecordIntegrity{Status: audit.IntegrityLegacyUnsealed}
	if _, err := record.SealMaterial(); !errors.Is(err, audit.ErrInvalidRecord) {
		t.Fatalf("SealMaterial(legacy) error = %v", err)
	}
}
