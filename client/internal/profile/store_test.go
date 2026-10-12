package profile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	firstID  = "00000000000000000000000000000001"
	secondID = "00000000000000000000000000000002"
)

func TestOpen(t *testing.T) {
	t.Parallel()

	t.Run("rejects relative directory", func(t *testing.T) {
		t.Parallel()

		_, err := Open("relative")
		if err == nil {
			t.Fatal("Open() error = nil, want an absolute-path error")
		}
	})

	t.Run("creates private directory", func(t *testing.T) {
		t.Parallel()

		dir := filepath.Join(t.TempDir(), "state")
		store, err := Open(dir)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		t.Cleanup(func() { _ = store.Close() })

		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("Stat() error = %v", err)
		}
		if got, expected := info.Mode().Perm(), os.FileMode(0o700); got != expected {
			t.Fatalf("directory mode = %04o, want %04o", got, expected)
		}
	})
}

func TestStore_Snapshot(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	if _, err := store.Create(t.Context(), CreateInput{
		Name:       "production",
		ControlURL: "https://transit.example.com",
	}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	first := store.Snapshot()
	first.Profiles[0].Name = "mutated"
	second := store.Snapshot()
	if got, expected := second.Profiles[0].Name, "production"; got != expected {
		t.Fatalf("Snapshot() name = %q, want %q", got, expected)
	}
}

func TestStore_Create(t *testing.T) {
	t.Parallel()

	t.Run("keeps exactly one active profile", func(t *testing.T) {
		t.Parallel()

		store := newTestStore(t)
		first, err := store.Create(t.Context(), CreateInput{
			Name:       "production",
			ControlURL: "https://TRANSIT.example.com/",
		})
		if err != nil {
			t.Fatalf("first Create() error = %v", err)
		}
		second, err := store.Create(t.Context(), CreateInput{
			Name:       "staging",
			ControlURL: "https://staging.example.com/control/",
		})
		if err != nil {
			t.Fatalf("second Create() error = %v", err)
		}

		snapshot := store.Snapshot()
		if got, expected := snapshot.ActiveProfileID, first.ID; got != expected {
			t.Fatalf("active profile = %q, want %q", got, expected)
		}
		if second.ID == snapshot.ActiveProfileID {
			t.Fatal("second profile became active implicitly")
		}
		if got, expected := first.ControlURL, "https://transit.example.com/"; got != expected {
			t.Fatalf("normalized control url = %q, want %q", got, expected)
		}
		if got, expected := second.ControlURL, "https://staging.example.com/control"; got != expected {
			t.Fatalf("normalized path = %q, want %q", got, expected)
		}

		info, err := os.Stat(filepath.Join(store.dir, stateFileName))
		if err != nil {
			t.Fatalf("Stat() error = %v", err)
		}
		if got, expected := info.Mode().Perm(), os.FileMode(0o600); got != expected {
			t.Fatalf("state mode = %04o, want %04o", got, expected)
		}
	})

	t.Run("rejects duplicate name case-insensitively", func(t *testing.T) {
		t.Parallel()

		store := newTestStore(t)
		_, err := store.Create(t.Context(), CreateInput{
			Name:       "Production",
			ControlURL: "https://one.example.com",
		})
		if err != nil {
			t.Fatalf("first Create() error = %v", err)
		}
		_, err = store.Create(t.Context(), CreateInput{
			Name:       "production",
			ControlURL: "https://two.example.com",
		})
		if !errors.Is(err, ErrDuplicate) {
			t.Fatalf("second Create() error = %v, want ErrDuplicate", err)
		}
	})

	t.Run("rejects cancelled context", func(t *testing.T) {
		t.Parallel()

		store := newTestStore(t)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		_, err := store.Create(ctx, CreateInput{
			Name:       "production",
			ControlURL: "https://transit.example.com",
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Create() error = %v, want context.Canceled", err)
		}
	})
}

func TestStore_CreateValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input CreateInput
	}{
		{
			name:  "empty name",
			input: CreateInput{ControlURL: "https://transit.example.com"},
		},
		{
			name: "name with control character",
			input: CreateInput{
				Name:       "bad\nname",
				ControlURL: "https://transit.example.com",
			},
		},
		{
			name: "overlong name",
			input: CreateInput{
				Name:       strings.Repeat("a", maxNameRunes+1),
				ControlURL: "https://transit.example.com",
			},
		},
		{
			name: "plain http",
			input: CreateInput{
				Name:       "bad",
				ControlURL: "http://transit.example.com",
			},
		},
		{
			name: "url credentials",
			//nolint:gosec // This invalid fixture verifies that URL credentials are rejected.
			input: CreateInput{
				Name:       "bad",
				ControlURL: "https://user:password@transit.example.com",
			},
		},
		{
			name: "url query",
			input: CreateInput{
				Name:       "bad",
				ControlURL: "https://transit.example.com?network=forged",
			},
		},
		{
			name: "nonstandard tls port",
			input: CreateInput{
				Name:       "bad",
				ControlURL: "https://transit.example.com:8443",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			store := newTestStore(t)
			_, err := store.Create(t.Context(), test.input)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Create() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestStore_Active(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	if _, err := store.Active(t.Context()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty Active() error = %v, want ErrNotFound", err)
	}
	created, err := store.Create(t.Context(), CreateInput{
		Name:       "production",
		ControlURL: "https://transit.example.com",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	active, err := store.Active(t.Context())
	if err != nil {
		t.Fatalf("Active() error = %v", err)
	}
	if got, expected := active.ID, created.ID; got != expected {
		t.Fatalf("Active().ID = %q, want %q", got, expected)
	}
}

func TestStore_Activate(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	_, err := store.Create(t.Context(), CreateInput{
		Name:       "production",
		ControlURL: "https://one.example.com",
	})
	if err != nil {
		t.Fatalf("first Create() error = %v", err)
	}
	second, err := store.Create(t.Context(), CreateInput{
		Name:       "staging",
		ControlURL: "https://two.example.com",
	})
	if err != nil {
		t.Fatalf("second Create() error = %v", err)
	}

	selected, err := store.Activate(t.Context(), second.ID)
	if err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if selected.ID != second.ID {
		t.Fatalf("Activate() id = %q, want %q", selected.ID, second.ID)
	}
	if got, expected := store.Snapshot().ActiveProfileID, second.ID; got != expected {
		t.Fatalf("active profile = %q, want %q", got, expected)
	}

	reopened, err := Open(store.dir)
	if err != nil {
		t.Fatalf("reopening store: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if got, expected := reopened.Snapshot().ActiveProfileID, second.ID; got != expected {
		t.Fatalf("reopened active profile = %q, want %q", got, expected)
	}

	_, err = store.Activate(t.Context(), "ffffffffffffffffffffffffffffffff")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Activate() missing error = %v, want ErrNotFound", err)
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()

	ids := []string{firstID, secondID}
	index := 0
	idSource := func() (string, error) {
		if index >= len(ids) {
			return "", errors.New("test id source exhausted")
		}
		id := ids[index]
		index++

		return id, nil
	}
	clock := func() time.Time {
		return time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)
	}

	store, err := openWith(t.TempDir(), clock, idSource)
	if err != nil {
		t.Fatalf("openWith() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	return store
}

func TestStore_SetDisconnectedPersists(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if store.Snapshot().Disconnected {
		t.Fatal("a new store starts disconnected")
	}
	if changed, err := store.SetDisconnected(t.Context(), true); err != nil || !changed {
		t.Fatalf("SetDisconnected(true) = %t, %v", changed, err)
	}
	if changed, err := store.SetDisconnected(t.Context(), true); err != nil || changed {
		t.Fatalf("repeat SetDisconnected(true) = %t, %v, want unchanged", changed, err)
	}
	_ = store.Close()

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if !reopened.Snapshot().Disconnected {
		t.Fatal("the disconnected preference did not survive a restart")
	}
	if changed, err := reopened.SetDisconnected(t.Context(), false); err != nil || !changed {
		t.Fatalf("SetDisconnected(false) = %t, %v", changed, err)
	}
}
