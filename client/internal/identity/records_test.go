package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHasRecords(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	if has, err := HasRecords(stateDir); err != nil || has {
		t.Fatalf("HasRecords(empty) = %t, %v", has, err)
	}
	dir := filepath.Join(stateDir, identityDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".identity-abc.tmp"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if has, err := HasRecords(stateDir); err != nil || has {
		t.Fatalf("HasRecords(temporary only) = %t, %v", has, err)
	}
	if err := os.WriteFile(filepath.Join(dir, testProfileID+".json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if has, err := HasRecords(stateDir); err != nil || !has {
		t.Fatalf("HasRecords(with a record) = %t, %v", has, err)
	}
}
