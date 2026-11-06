package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Samples as pg-backend-sampler.sh writes them: pid, private anonymous
// resident kB, then the process title.
const backendSamples = `101 9000 postgres: mesh_runtime meshtransit 172.17.0.1(51000) idle
101 41000 postgres: mesh_runtime meshtransit 172.17.0.1(51000) idle in transaction
102 23000 postgres: mesh_worker meshtransit 172.17.0.1(51002) idle
103 2600 postgres: checkpointer
104 3100 postgres: autovacuum launcher
105 52000 postgres: mesh_migrator meshtransit [local] SELECT
not a sample line
106 notanumber postgres: mesh_runtime meshtransit 172.17.0.1(51010) idle
101 30000 postgres: mesh_runtime meshtransit 172.17.0.1(51000) idle
`

func TestScanBackendsKeepsEachClientBackendsPeak(t *testing.T) {
	t.Parallel()
	peaks, err := scanBackends(strings.NewReader(backendSamples))
	if err != nil {
		t.Fatal(err)
	}
	// Background processes (checkpointer, autovacuum…) are not client backends.
	want := []backendPeak{
		{pid: "105", role: "mesh_migrator", kb: 52000},
		{pid: "101", role: "mesh_runtime", kb: 41000},
		{pid: "102", role: "mesh_worker", kb: 23000},
	}
	if len(peaks) != len(want) {
		t.Fatalf("peaks = %+v", peaks)
	}
	for index, peak := range want {
		if peaks[index] != peak {
			t.Fatalf("peak %d = %+v, want %+v", index, peaks[index], peak)
		}
	}
}

func TestBackendGateChecksOnlyTheGatedRoles(t *testing.T) {
	t.Parallel()
	peaks, err := scanBackends(strings.NewReader(backendSamples))
	if err != nil {
		t.Fatal(err)
	}
	// Runtime roles over 40 MiB fail; the migrator's DDL is not request work.
	over := overBudget(peaks, 40, []string{"mesh_runtime", "mesh_worker"})
	if len(over) != 1 || over[0].pid != "101" {
		t.Fatalf("over = %+v", over)
	}
	if got := overBudget(peaks, 41, []string{"mesh_runtime", "mesh_worker"}); len(got) != 0 {
		t.Fatalf("41 MiB budget: over = %+v", got)
	}
}

func TestScanBackendsFindsNothingInGarbage(t *testing.T) {
	t.Parallel()
	peaks, err := scanBackends(strings.NewReader("garbage\n"))
	if err != nil || len(peaks) != 0 {
		t.Fatalf("peaks = %+v, err = %v", peaks, err)
	}
}

func TestRunBackendModeExitCodes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, contents string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	samples := write("samples.txt", backendSamples)
	roles := splitRoles(" mesh_runtime , mesh_worker ,")
	for name, test := range map[string]struct {
		path  string
		maxMB int
		roles []string
		want  int
	}{
		"within budget":     {samples, 41, roles, 0},
		"over budget":       {samples, 40, roles, 1},
		"no client backend": {write("empty.txt", "garbage\n"), 41, roles, 2},
		"missing file":      {filepath.Join(dir, "absent.txt"), 41, roles, 2},
		"no roles":          {samples, 41, splitRoles(" , "), 2},
	} {
		var out, errs bytes.Buffer
		if got := runBackendMode(&out, &errs, test.path, test.maxMB, test.roles); got != test.want {
			t.Errorf("%s: exit %d, want %d (%s)", name, got, test.want, errs.String())
		}
	}
}
