package identity

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/secretstore"
)

// recordingHook keeps what each persist hook call saw and fails while
// failWith is set.
type recordingHook struct {
	mu       sync.Mutex
	names    []string
	data     [][]byte
	failWith error
}

func (h *recordingHook) persist(_ context.Context, name string, data []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failWith != nil {
		return h.failWith
	}
	h.names = append(h.names, name)
	h.data = append(h.data, bytes.Clone(data))
	return nil
}

func (h *recordingHook) calls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.names)
}

// last returns the most recent call, or ok false when the hook never ran.
func (h *recordingHook) last() (name string, data []byte, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.names) == 0 {
		return "", nil, false
	}
	return h.names[len(h.names)-1], h.data[len(h.data)-1], true
}

func (h *recordingHook) fail(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.failWith = err
}

// Every write the store makes goes through the hook first, with the record's
// file name and exactly the bytes then installed, so a mirror of the hook's
// input is a copy of the directory.
func TestStore_PersistHookSeesEveryWrite(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 25, 1, 2, 3, 0, time.UTC)
	hook := &recordingHook{}
	store, err := openWith(t.TempDir(), func() time.Time { return now }, testProtector(t, 0x41), WithPersistHook(hook.persist))
	if err != nil {
		t.Fatalf("openWith() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := t.Context()
	nextControlKey := []byte("next-control-public")
	steps := []struct {
		name string
		run  func() error
	}{
		{"Create", func() error { return store.Create(ctx, testRecord(t, now)) }},
		{"ReplaceCredentials", func() error {
			_, err := store.ReplaceCredentials(ctx, testProfileID, []byte("machine-2"), []byte("node-2"))
			return err
		}},
		{"SetRegistration", func() error {
			_, err := store.SetRegistration(ctx, testProfileID, "", true)
			return err
		}},
		{"BeginNodeKeyRotation", func() error {
			_, err := store.BeginNodeKeyRotation(ctx, testProfileID, []byte("node-3"))
			return err
		}},
		{"CompleteNodeKeyRotation", func() error {
			_, err := store.CompleteNodeKeyRotation(ctx, testProfileID, []byte("node-3"))
			return err
		}},
		{"BeginNodeKeyRotation again", func() error {
			_, err := store.BeginNodeKeyRotation(ctx, testProfileID, []byte("node-4"))
			return err
		}},
		{"AbandonNodeKeyRotation", func() error {
			_, err := store.AbandonNodeKeyRotation(ctx, testProfileID, []byte("node-4"))
			return err
		}},
		{"StageNextControlKey", func() error {
			_, err := store.StageNextControlKey(ctx, testProfileID, nextControlKey, "sha256:"+strings.Repeat("b", 64))
			return err
		}},
		{"PromoteNextControlKey", func() error {
			_, err := store.PromoteNextControlKey(ctx, testProfileID, nextControlKey)
			return err
		}},
	}
	for i, step := range steps {
		if err := step.run(); err != nil {
			t.Fatalf("%s error = %v", step.name, err)
		}
		if got := hook.calls(); got != i+1 {
			t.Fatalf("after %s the hook ran %d times, want %d", step.name, got, i+1)
		}
		name, data, _ := hook.last()
		if name != recordFileName(testProfileID) {
			t.Fatalf("%s hook name = %q, want %q", step.name, name, recordFileName(testProfileID))
		}
		if onDisk := readIdentityFile(t, store.dir, testProfileID); !bytes.Equal(data, onDisk) {
			t.Fatalf("%s hook data differs from the installed record", step.name)
		}
	}

	// A change that changes nothing writes nothing.
	if _, err := store.StageNextControlKey(ctx, testProfileID, nil, ""); err != nil {
		t.Fatalf("StageNextControlKey(unchanged) error = %v", err)
	}
	if got := hook.calls(); got != len(steps) {
		t.Fatalf("an unchanged record ran the hook: %d calls, want %d", got, len(steps))
	}
}

// Rewrapping a fallback-key record, whether on Get or in MigrateAll, is a
// write too and goes through the hook.
func TestStore_PersistHookSeesRewraps(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	oldKey := bytes.Repeat([]byte{0x42}, secretstore.KeySize)
	newKey := bytes.Repeat([]byte{0x43}, secretstore.KeySize)
	oldProtector, err := secretstore.New(oldKey)
	if err != nil {
		t.Fatalf("secretstore.New(old) error = %v", err)
	}
	oldStore, err := Open(stateDir, oldProtector)
	if err != nil {
		t.Fatalf("Open(old) error = %v", err)
	}
	for _, profileID := range []string{testProfileID, secondTestProfileID} {
		if err := oldStore.Create(t.Context(), testRecordForProfile(t, profileID, time.Now())); err != nil {
			t.Fatalf("Create(%s) error = %v", profileID, err)
		}
	}
	if err := oldStore.Close(); err != nil {
		t.Fatalf("Close(old) error = %v", err)
	}

	rotatingProtector, err := secretstore.NewWithFallback(newKey, oldKey)
	if err != nil {
		t.Fatalf("secretstore.NewWithFallback() error = %v", err)
	}
	hook := &recordingHook{}
	store, err := Open(stateDir, rotatingProtector, WithPersistHook(hook.persist))
	if err != nil {
		t.Fatalf("Open(rotating) error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, err := store.Get(t.Context(), testProfileID); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if name, data, ok := hook.last(); !ok || hook.calls() != 1 || name != recordFileName(testProfileID) ||
		!bytes.Equal(data, readIdentityFile(t, store.dir, testProfileID)) {
		t.Fatalf("Get rewrap: hook calls = %d, last name = %q", hook.calls(), name)
	}
	if err := store.MigrateAll(t.Context()); err != nil {
		t.Fatalf("MigrateAll() error = %v", err)
	}
	if name, data, ok := hook.last(); !ok || hook.calls() != 2 || name != recordFileName(secondTestProfileID) ||
		!bytes.Equal(data, readIdentityFile(t, store.dir, secondTestProfileID)) {
		t.Fatalf("MigrateAll rewrap: hook calls = %d, last name = %q", hook.calls(), name)
	}
}

// A hook that fails aborts the write: the caller sees its error and the
// record on disk stays as it was, or absent for a new one.
func TestStore_PersistHookFailureLeavesTheRecord(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 25, 4, 5, 6, 0, time.UTC)
	hook := &recordingHook{}
	store, err := openWith(t.TempDir(), func() time.Time { return now }, testProtector(t, 0x44), WithPersistHook(hook.persist))
	if err != nil {
		t.Fatalf("openWith() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	mirrorDown := errors.New("mirror unavailable")
	hook.fail(mirrorDown)
	if err := store.Create(t.Context(), testRecord(t, now)); !errors.Is(err, mirrorDown) {
		t.Fatalf("Create() error = %v, want the hook's error", err)
	}
	if _, err := store.Get(t.Context(), testProfileID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() after a failed Create error = %v, want ErrNotFound", err)
	}

	hook.fail(nil)
	if err := store.Create(t.Context(), testRecord(t, now)); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	before := readIdentityFile(t, store.dir, testProfileID)
	hook.fail(mirrorDown)
	if _, err := store.SetRegistration(t.Context(), testProfileID, "", true); !errors.Is(err, mirrorDown) {
		t.Fatalf("SetRegistration() error = %v, want the hook's error", err)
	}
	if after := readIdentityFile(t, store.dir, testProfileID); !bytes.Equal(after, before) {
		t.Fatal("a failed hook changed the record on disk")
	}
	hook.fail(nil)
	loaded, err := store.Get(t.Context(), testProfileID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if loaded.IsRegistered() {
		t.Fatal("a failed hook still registered the identity")
	}
}

// Creating a record the store already holds fails before the hook runs, so
// within the store a mirror never holds a record the directory refused.
func TestStore_PersistHookSkipsARefusedCreate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 25, 7, 8, 9, 0, time.UTC)
	hook := &recordingHook{}
	store, err := openWith(t.TempDir(), func() time.Time { return now }, testProtector(t, 0x45), WithPersistHook(hook.persist))
	if err != nil {
		t.Fatalf("openWith() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if err := store.Create(t.Context(), testRecord(t, now)); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Create(t.Context(), testRecord(t, now)); !errors.Is(err, ErrExists) {
		t.Fatalf("second Create() error = %v, want ErrExists", err)
	}
	if got := hook.calls(); got != 1 {
		t.Fatalf("hook ran %d times, want 1", got)
	}
}

// A rewrap on Get whose hook fails fails the Get and keeps the fallback-key
// record, so the next Get tries again.
func TestStore_PersistHookFailureOnRewrapKeepsTheRecord(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	oldKey := bytes.Repeat([]byte{0x46}, secretstore.KeySize)
	newKey := bytes.Repeat([]byte{0x47}, secretstore.KeySize)
	oldProtector, err := secretstore.New(oldKey)
	if err != nil {
		t.Fatalf("secretstore.New(old) error = %v", err)
	}
	oldStore, err := Open(stateDir, oldProtector)
	if err != nil {
		t.Fatalf("Open(old) error = %v", err)
	}
	if err := oldStore.Create(t.Context(), testRecord(t, time.Now())); err != nil {
		t.Fatalf("Create(old) error = %v", err)
	}
	before := readIdentityFile(t, oldStore.dir, testProfileID)
	if err := oldStore.Close(); err != nil {
		t.Fatalf("Close(old) error = %v", err)
	}

	rotatingProtector, err := secretstore.NewWithFallback(newKey, oldKey)
	if err != nil {
		t.Fatalf("secretstore.NewWithFallback() error = %v", err)
	}
	hook := &recordingHook{}
	store, err := Open(stateDir, rotatingProtector, WithPersistHook(hook.persist))
	if err != nil {
		t.Fatalf("Open(rotating) error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	mirrorDown := errors.New("mirror unavailable")
	hook.fail(mirrorDown)
	if _, err := store.Get(t.Context(), testProfileID); !errors.Is(err, mirrorDown) {
		t.Fatalf("Get() error = %v, want the hook's error", err)
	}
	if after := readIdentityFile(t, store.dir, testProfileID); !bytes.Equal(after, before) {
		t.Fatal("a failed hook replaced the fallback-key record")
	}
	hook.fail(nil)
	if _, err := store.Get(t.Context(), testProfileID); err != nil {
		t.Fatalf("Get() after the mirror recovered error = %v", err)
	}
	if hook.calls() != 1 {
		t.Fatalf("hook calls = %d, want 1", hook.calls())
	}
}

// The hook gets the caller's context, so a mirror call ends when the caller
// gives up.
func TestStore_PersistHookGetsTheCallersContext(t *testing.T) {
	t.Parallel()

	type key struct{}
	var seen any
	now := time.Date(2026, time.October, 25, 10, 11, 12, 0, time.UTC)
	store, err := openWith(t.TempDir(), func() time.Time { return now }, testProtector(t, 0x48),
		WithPersistHook(func(ctx context.Context, _ string, _ []byte) error {
			seen = ctx.Value(key{})
			return nil
		}))
	if err != nil {
		t.Fatalf("openWith() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.WithValue(t.Context(), key{}, "caller")
	if err := store.Create(ctx, testRecord(t, now)); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if seen != "caller" {
		t.Fatalf("hook context value = %v, want the caller's", seen)
	}
}
