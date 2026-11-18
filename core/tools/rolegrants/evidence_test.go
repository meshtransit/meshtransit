package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestEvidenceFindsWhatTheManifestMisses(t *testing.T) {
	t.Parallel()
	snapshot := filepath.Join(t.TempDir(), "pgss.csv")
	rows := "mesh_runtime,t,1,4,\"SELECT * FROM mesh_ops.known_v1($1)\"\n" +
		"mesh_runtime,t,2,1,\"UPDATE mesh.device SET state = $1 WHERE id = $2\"\n" +
		"mesh_runtime,f,3,9,\"INSERT INTO mesh.inner_table (a) VALUES ($1)\"\n" +
		"mesh_control,t,4,2,\"SELECT mesh_ops.control_only_v1()\"\n" +
		"mesh_observer,t,5,1,\"SELECT mesh_ops.other_v1()\"\n"
	if err := os.WriteFile(snapshot, []byte(rows), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Evidence([]string{snapshot}, map[string]Usage{
		"api":     {Functions: []string{"mesh_ops.known_v1", "mesh_ops.unused_v1"}},
		"control": {Functions: []string{"mesh_ops.control_only_v1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Snapshots != 1 || report.Statements != 3 {
		t.Fatalf("report = %+v", report)
	}
	// The direct UPDATE the manifest lacks is unexplained; the statement
	// inside a function and the unknown login are not counted.
	if got := report.Unexplained["api"]["updates"]; !slices.Equal(got, []string{"mesh.device"}) {
		t.Errorf("unexplained api updates = %v", got)
	}
	if _, found := report.Unexplained["control"]; found || len(report.Unexplained) != 1 {
		t.Errorf("unexplained = %v", report.Unexplained)
	}
	if report.Covered["api"]["functions"] != 1 || report.Total["api"]["functions"] != 2 ||
		!slices.Equal(report.Unseen["api"]["functions"], []string{"mesh_ops.unused_v1"}) {
		t.Errorf("coverage = %v of %v, unseen %v", report.Covered, report.Total, report.Unseen)
	}
}
