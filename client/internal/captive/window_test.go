package captive

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenWindowWritesWhatTheHelperReads(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "captive.json")
	now := time.Date(2026, time.October, 21, 23, 0, 0, 0, time.UTC)
	window, err := OpenWindow(path, 90*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(path) //nolint:gosec // the test's own file
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeWindow(encoded)
	if err != nil || decoded != window || decoded.Duration() != 90*time.Second {
		t.Fatalf("decodeWindow() = %+v, %v; wrote %+v", decoded, err, window)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("window file mode = %v, %v", info.Mode(), err)
	}
	again, err := OpenWindow(path, DefaultWindow, now)
	if err != nil || again.ID == window.ID {
		t.Fatalf("opening again kept the window id: %v", err)
	}
	for _, bad := range []time.Duration{0, -time.Second, MaximumWindow + time.Second} {
		if _, err := OpenWindow(path, bad, now); err == nil {
			t.Errorf("OpenWindow(%s) was accepted", bad)
		}
	}
	if err := CloseWindow(path); err != nil {
		t.Fatal(err)
	}
	if err := CloseWindow(path); err != nil {
		t.Fatalf("closing no window: %v", err)
	}
	if _, err := ReadWindow(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadWindow() of a closed window = %v", err)
	}
}

func TestDecodeWindowRefusesWhatOpenWindowNeverWrites(t *testing.T) {
	t.Parallel()
	id := strings.Repeat("ab", 16)
	for _, bad := range []string{
		`{"id":"` + id + `","seconds":301,"opened":"2026-10-21T23:00:00Z"}`,
		`{"id":"` + id + `","seconds":0,"opened":"2026-10-21T23:00:00Z"}`,
		`{"id":"short","seconds":60,"opened":"2026-10-21T23:00:00Z"}`,
		`{"id":"` + id + `","seconds":60,"opened":"2026-10-21T23:00:00Z","until":"2099-01-01T00:00:00Z"}`,
		`{"id":"` + id + `","seconds":60,"opened":"2026-10-21T23:00:00Z"} {}`,
		strings.Repeat(" ", maximumWindowFileBytes+1),
	} {
		if _, err := decodeWindow([]byte(bad)); !errors.Is(err, ErrWindowInvalid) {
			t.Errorf("decodeWindow(%.60q) = %v", bad, err)
		}
	}
}

// A window file another user could write is never honoured.
func TestReadWindowRefusesAFileRootDoesNotOwnAlone(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root owns the test's files")
	}
	path := filepath.Join(t.TempDir(), "captive.json")
	if _, err := OpenWindow(path, time.Minute, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWindow(path); !errors.Is(err, ErrWindowInvalid) {
		t.Fatalf("ReadWindow() of a user's file = %v", err)
	}
}
