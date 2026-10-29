//go:build !windows

package privatefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPublicDir(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	kube := filepath.Join(base, "kube")
	if err := PreparePublicDir(kube, 1); err != nil {
		t.Fatalf("PreparePublicDir() = %v", err)
	}
	if info, err := os.Stat(kube); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v, %v", info.Mode(), err)
	}
	profile := filepath.Join(kube, "profile-1")
	if err := PreparePublicDir(profile, 2); err != nil {
		t.Fatalf("a profile directory: %v", err)
	}
	refused := func(name string, setup func() string, strict int) {
		t.Helper()
		if err := CheckPublicDir(setup(), strict); !errors.Is(err, ErrNotPublicDir) {
			t.Errorf("%s: %v", name, err)
		}
	}
	refused("writable by others", func() string {
		dir := filepath.Join(base, "open")
		mustMkdir(t, dir, 0o777)
		return dir
	}, 1)
	refused("a link", func() string {
		link := filepath.Join(base, "link")
		if err := os.Symlink(kube, link); err != nil {
			t.Fatal(err)
		}
		return link
	}, 1)
	refused("a strict parent writable by others", func() string {
		parent := filepath.Join(base, "open-parent")
		mustMkdir(t, parent, 0o777)
		child := filepath.Join(parent, "child")
		mustMkdir(t, child, 0o755)
		return child
	}, 2)
	refused("an ancestor writable by others without the sticky bit", func() string {
		parent := filepath.Join(base, "shared")
		mustMkdir(t, parent, 0o777)
		child := filepath.Join(parent, "kube")
		mustMkdir(t, child, 0o755)
		return child
	}, 1)
	sticky := filepath.Join(base, "sticky")
	mustMkdir(t, sticky, 0o777|os.ModeSticky)
	child := filepath.Join(sticky, "kube")
	mustMkdir(t, child, 0o755)
	if err := CheckPublicDir(child, 1); err != nil {
		t.Fatalf("a sticky ancestor: %v", err)
	}
	// A link above the strict levels that a user owns decides where the
	// files are: refused (review e1b M1).
	target := filepath.Join(base, "real")
	mustMkdir(t, target, 0o755)
	mustMkdir(t, filepath.Join(target, "kube"), 0o755)
	userLink := filepath.Join(base, "user-link")
	if err := os.Symlink(target, userLink); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if err := CheckPublicDir(filepath.Join(userLink, "kube"), 1); !errors.Is(err, ErrNotPublicDir) {
			t.Fatalf("a user's link above the strict levels: %v", err)
		}
	}
	if err := CheckPublicDir("relative/kube", 1); !errors.Is(err, ErrNotPublicDir) {
		t.Fatalf("a relative path: %v", err)
	}
}

func mustMkdir(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
}
