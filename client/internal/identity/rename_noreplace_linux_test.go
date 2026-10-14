package identity

import (
	"errors"
	"os"
	"testing"
)

func TestRenameNoReplaceInstallsANewRecordOnly(t *testing.T) {
	t.Parallel()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	write := func(name, content string) {
		t.Helper()
		if err := root.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".first.tmp", "first")
	if err := renameNoReplace(root, ".first.tmp", "record"); err != nil {
		t.Fatalf("renameNoReplace() error = %v", err)
	}
	if _, err := root.Stat(".first.tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the temporary file stayed: %v", err)
	}
	write(".second.tmp", "second")
	if err := renameNoReplace(root, ".second.tmp", "record"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("renameNoReplace() over a record error = %v, want os.ErrExist", err)
	}
	if content, err := root.ReadFile("record"); err != nil || string(content) != "first" {
		t.Fatalf("the record = %q, %v; it must not be replaced", content, err)
	}
}
