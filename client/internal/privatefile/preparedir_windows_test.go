//go:build windows

package privatefile

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A junction planted where a state directory belongs is refused, and the
// directory it points to keeps its access list.
func TestPrepareDirRefusesAJunction(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(base, "logs")
	if output, err := exec.CommandContext(t.Context(), "cmd", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil { //nolint:gosec // Test paths under t.TempDir.
		t.Fatalf("mklink: %v: %s", err, output)
	}
	if err := PrepareDir(junction, 0o700); err == nil {
		t.Fatal("PrepareDir accepted a junction")
	}
	if err := CheckFile(target, nil); err == nil {
		t.Fatal("the junction's target was restricted")
	}
}

func TestPrepareDirCreatesARestrictedDirectory(t *testing.T) {
	base := t.TempDir()
	if err := PrepareDir(filepath.Join(base, "missing", "state"), 0o700); err == nil {
		t.Fatal("PrepareDir created a directory under a missing parent")
	}
	dir := filepath.Join(base, "state")
	if err := PrepareDir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Restricted at creation, before any RestrictDir call.
	if err := CheckFile(dir, nil); err != nil {
		t.Fatalf("new directory: %v", err)
	}
	if err := PrepareDir(dir, 0o700); err != nil {
		t.Fatalf("PrepareDir on its own directory: %v", err)
	}
}
