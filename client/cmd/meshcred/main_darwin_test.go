package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProvisionCreatesOnceAndChecksTheKey(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "meshd.identity-key")
	uid, gid := os.Getuid(), os.Getgid()
	if err := provision(path, uid, gid, bytes.NewReader(bytes.Repeat([]byte{7}, 32))); err != nil {
		t.Fatalf("provision() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o400 || info.Size() != 32 {
		t.Fatalf("key file = %v, %v", info, err)
	}
	// A second provision keeps the existing key.
	if err := provision(path, uid, gid, bytes.NewReader(bytes.Repeat([]byte{9}, 32))); err != nil {
		t.Fatalf("second provision() error = %v", err)
	}
	content, _ := os.ReadFile(path) //nolint:gosec // test temp file
	if !bytes.Equal(content, bytes.Repeat([]byte{7}, 32)) {
		t.Fatal("second provision replaced the key")
	}
	if err := provision(path, uid+1, gid, bytes.NewReader(nil)); err == nil {
		t.Fatal("provision accepted a key owned by another user")
	}
	broad := filepath.Join(t.TempDir(), "broad")
	if err := os.WriteFile(broad, bytes.Repeat([]byte{1}, 32), 0o644); err != nil { //nolint:gosec // deliberately too broad
		t.Fatal(err)
	}
	if err := provision(broad, uid, gid, bytes.NewReader(nil)); err == nil {
		t.Fatal("provision accepted a world-readable key")
	}
}

func TestRunRefusesUnsupportedOperations(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"rotate", "recover"} {
		stderr := &bytes.Buffer{}
		if code := run([]string{operation}, stderr); code != 1 || !strings.Contains(stderr.String(), "not supported on macOS") {
			t.Fatalf("run(%s) = %d, %q", operation, code, stderr.String())
		}
	}
	stderr := &bytes.Buffer{}
	if code := run([]string{"unknown"}, stderr); code != 2 {
		t.Fatalf("run(unknown) = %d", code)
	}
}
