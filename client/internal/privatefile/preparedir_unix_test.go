//go:build !windows

package privatefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareDirCreatesOnlyTheLastDirectory(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	if err := PrepareDir(filepath.Join(base, "missing", "state"), 0o700); err == nil {
		t.Fatal("PrepareDir created a directory under a missing parent")
	}
	if _, err := os.Lstat(filepath.Join(base, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("PrepareDir created the missing parent: %v", err)
	}

	dir := filepath.Join(base, "state")
	if err := PrepareDir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("created %v, %v; want a 0700 directory", info, err)
	}
	if err := PrepareDir(dir, 0o700); err != nil {
		t.Fatalf("PrepareDir on its own directory: %v", err)
	}
}

func TestPrepareDirRefusesWhatIsNotARealDirectory(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	target := filepath.Join(base, "elsewhere")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, file} {
		if err := PrepareDir(path, 0o700); err == nil {
			t.Errorf("PrepareDir(%s) accepted it", filepath.Base(path))
		}
	}
}
