package profile

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Every profile write goes through the hook first, with the state file's
// name and exactly the bytes then installed.
func TestStore_PersistHookSeesEveryWrite(t *testing.T) {
	t.Parallel()

	var names []string
	var data [][]byte
	store := newTestStore(t, WithPersistHook(func(_ context.Context, name string, encoded []byte) error {
		names = append(names, name)
		data = append(data, bytes.Clone(encoded))
		return nil
	}))
	ctx := t.Context()
	steps := []struct {
		name string
		run  func() error
	}{
		{"Create", func() error {
			_, err := store.Create(ctx, CreateInput{Name: "production", ControlURL: "https://transit.example.com"})
			return err
		}},
		{"Create second", func() error {
			_, err := store.Create(ctx, CreateInput{Name: "staging", ControlURL: "https://staging.example.com"})
			return err
		}},
		{"Activate", func() error {
			_, err := store.Activate(ctx, secondID)
			return err
		}},
		{"SetDisconnected", func() error {
			_, err := store.SetDisconnected(ctx, true)
			return err
		}},
	}
	for i, step := range steps {
		if err := step.run(); err != nil {
			t.Fatalf("%s error = %v", step.name, err)
		}
		if len(names) != i+1 {
			t.Fatalf("after %s the hook ran %d times, want %d", step.name, len(names), i+1)
		}
		if names[i] != stateFileName {
			t.Fatalf("%s hook name = %q, want %q", step.name, names[i], stateFileName)
		}
		onDisk, err := os.ReadFile(filepath.Join(store.dir, stateFileName))
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		if !bytes.Equal(data[i], onDisk) {
			t.Fatalf("%s hook data differs from the installed state", step.name)
		}
	}

	// Changes that change nothing write nothing.
	if _, err := store.Activate(ctx, secondID); err != nil {
		t.Fatalf("Activate(unchanged) error = %v", err)
	}
	if _, err := store.SetDisconnected(ctx, true); err != nil {
		t.Fatalf("SetDisconnected(unchanged) error = %v", err)
	}
	if len(names) != len(steps) {
		t.Fatalf("unchanged state ran the hook: %d calls, want %d", len(names), len(steps))
	}
}

// A hook that fails aborts the write: the caller sees its error, and neither
// the file nor the store's state moves.
func TestStore_PersistHookFailureLeavesTheState(t *testing.T) {
	t.Parallel()

	mirrorDown := errors.New("mirror unavailable")
	var failWith error
	store := newTestStore(t, WithPersistHook(func(context.Context, string, []byte) error { return failWith }))
	ctx := t.Context()

	failWith = mirrorDown
	if _, err := store.Create(ctx, CreateInput{Name: "production", ControlURL: "https://transit.example.com"}); !errors.Is(err, mirrorDown) {
		t.Fatalf("Create() error = %v, want the hook's error", err)
	}
	if _, err := os.Lstat(filepath.Join(store.dir, stateFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Lstat() after a failed Create error = %v, want no state file", err)
	}
	if got := len(store.Snapshot().Profiles); got != 0 {
		t.Fatalf("a failed Create left %d profiles in memory", got)
	}

	failWith = nil
	if _, err := store.Create(ctx, CreateInput{Name: "production", ControlURL: "https://transit.example.com"}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	before, err := os.ReadFile(filepath.Join(store.dir, stateFileName))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	failWith = mirrorDown
	if _, err := store.SetDisconnected(ctx, true); !errors.Is(err, mirrorDown) {
		t.Fatalf("SetDisconnected() error = %v, want the hook's error", err)
	}
	after, err := os.ReadFile(filepath.Join(store.dir, stateFileName))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("a failed hook changed the state file")
	}
	if store.Snapshot().Disconnected {
		t.Fatal("a failed hook still changed the state in memory")
	}
}

// The hook gets the caller's context, so a mirror call ends when the caller
// gives up.
func TestStore_PersistHookGetsTheCallersContext(t *testing.T) {
	t.Parallel()

	type key struct{}
	var seen any
	store := newTestStore(t, WithPersistHook(func(ctx context.Context, _ string, _ []byte) error {
		seen = ctx.Value(key{})
		return nil
	}))
	ctx := context.WithValue(t.Context(), key{}, "caller")
	if _, err := store.Create(ctx, CreateInput{Name: "production", ControlURL: "https://transit.example.com"}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if seen != "caller" {
		t.Fatalf("hook context value = %v, want the caller's", seen)
	}
}
