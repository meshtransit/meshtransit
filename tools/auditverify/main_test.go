package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/audit/exportformat"
	"github.com/meshtransit/meshtransit/internal/audit/history"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

// The tool's seal is written from the specification; MeshCore's seal is the
// reference. Both must agree on the pinned vector and on generated chains.
const pinnedSeal = "016575104ed2b058570bcfcea2bbdb826a1b7ea4f0ba0aba6f177ebbffa9429a"

func TestSealMatchesPinnedVector(t *testing.T) {
	t.Parallel()
	item := record{
		EventID: "01928f6e-7a10-7000-8000-000000000001", EventTime: "2026-10-07T04:05:06.123456Z",
		StreamID: "01928f6e-7a10-7000-8000-000000000002", Sequence: 42,
		WorkspaceID: "01928f6e-7a10-7000-8000-000000000003", NetworkID: "01928f6e-7a10-7000-8000-000000000004",
		ChangeID: "01928f6e-7a10-7000-8000-000000000005", ActorPrincipalID: "01928f6e-7a10-7000-8000-000000000006",
		Action: "policy.published", Permission: "policy.publish", Result: "succeeded", TargetKind: "policy",
		TargetID: "01928f6e-7a10-7000-8000-000000000007", AfterSemanticHash: strings.Repeat("00", 31) + "01",
		PayloadVersion: 1, PayloadCanonical: `{"reason": "maintenance window", "revision": 7}`,
	}
	item.Integrity.PreviousSeal = strings.Repeat("00", 32)
	computed, err := seal(item)
	if err != nil || hex.EncodeToString(computed) != pinnedSeal {
		t.Fatalf("seal() = %x, %v; want %s", computed, err, pinnedSeal)
	}
}

const (
	testWorkspace = "01928f6e-7a10-7000-8000-000000000003"
	testStream    = "01928f6e-7a10-7000-8000-0000000000aa"
)

// chain builds sealed records with MeshCore's implementation.
func chain(t *testing.T, count int) []audit.Record {
	t.Helper()
	records := make([]audit.Record, 0, count)
	previous := strings.Repeat("00", 32)
	for index := range count {
		record := audit.Record{
			RecordVersion: audit.RecordVersion,
			EventID:       "01928f6e-7a10-7000-8000-0000000001" + twoDigits(index),
			EventTime:     time.Date(2026, 10, 7, 4, 0, index, 1000, time.UTC).Format(audit.RecordTimeLayout),
			StreamID:      testStream, Sequence: int64(10 + index), WorkspaceID: testWorkspace,
			ChangeID:  "01928f6e-7a10-7000-8000-0000000002" + twoDigits(index),
			ActorKind: audit.ActorSystem, Action: "workspace.renamed", Permission: "workspace.update",
			Result: audit.ResultSucceeded, TargetKind: "workspace", TargetID: testWorkspace,
			BeforeSemanticHash: strings.Repeat("00", 32), PayloadVersion: 1,
			Payload: map[string]any{"name": "Café ✓"}, PayloadCanonical: `{"name": "Café ✓"}`,
			Integrity: audit.RecordIntegrity{Status: audit.IntegritySealed, HashVersion: audit.SealHashVersion,
				PreviousSeal: previous},
		}
		material, err := record.SealMaterial()
		if err != nil {
			t.Fatal(err)
		}
		value, err := audit.Seal(material)
		if err != nil {
			t.Fatal(err)
		}
		record.Integrity.Seal = hex.EncodeToString(value[:])
		previous = record.Integrity.Seal
		records = append(records, record)
	}
	return records
}

func twoDigits(value int) string {
	return fmt.Sprintf("%02d", value)
}

func writeExport(t *testing.T, records []audit.Record, format string) string {
	t.Helper()
	workspaceID, err := workspace.ParseID(testWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	export := history.Export{
		Query:   history.ExportQuery{WorkspaceID: workspaceID, Since: now.Add(-48 * time.Hour), Until: now},
		Records: records, Actors: map[string]string{}, GeneratedAt: now,
	}
	var body bytes.Buffer
	if format == "csv" {
		err = exportformat.WriteCSV(&body, export)
	} else {
		err = exportformat.WriteJSON(&body, export)
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "export."+format)
	if err := os.WriteFile(path, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func verifyFile(t *testing.T, path string) (int, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run([]string{path}, &stdout, &stderr)
	return code, stdout.String() + stderr.String()
}

func TestVerifiesMeshCoreExports(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"json", "csv"} {
		code, output := verifyFile(t, writeExport(t, chain(t, 5), format))
		if code != 0 || !strings.Contains(output, "result: VERIFIED") || !strings.Contains(output, "sealing starts at #10") {
			t.Fatalf("%s export: exit %d\n%s", format, code, output)
		}
	}
}

func TestDetectsTamperingAndGaps(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		mutate func([]audit.Record) []audit.Record
		want   string
	}{
		"changed action": {func(records []audit.Record) []audit.Record {
			records[2].Action = "workspace.created"
			return records
		}, "#12 seal does not match"},
		"deleted event": {func(records []audit.Record) []audit.Record {
			return append(records[:2], records[3:]...)
		}, "events #12 to #12 are missing"},
		"reordered link": {func(records []audit.Record) []audit.Record {
			records[3].Integrity.PreviousSeal = records[1].Integrity.Seal
			return records
		}, "#13 seal does not match"},
		"unknown status": {func(records []audit.Record) []audit.Record {
			records[4].Integrity.Status = "trusted"
			return records
		}, "unknown integrity status"},
	}
	for name, test := range cases {
		for _, format := range []string{"json", "csv"} {
			code, output := verifyFile(t, writeExport(t, test.mutate(chain(t, 5)), format))
			if code != 1 || !strings.Contains(output, test.want) {
				t.Errorf("%s (%s): exit %d, want failure %q\n%s", name, format, code, test.want, output)
			}
		}
	}
}

func TestRejectsUsageAndUnreadableFiles(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("no arguments exit = %d, want 2", code)
	}
	path := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(path, []byte(`{"export_version": 2, "Records": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, output := verifyFile(t, path); code != 2 || !strings.Contains(output, "unsupported export_version") {
		t.Fatalf("version 2 export exit = %d\n%s", code, output)
	}
}
