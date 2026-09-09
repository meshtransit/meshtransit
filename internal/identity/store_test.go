package identity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testProfileID = "00000000000000000000000000000001"

func TestStore_CreateGetAndUpdate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 9, 1, 2, 3, 0, time.UTC)
	store, err := openWith(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatalf("openWith() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	record := testRecord(t, now)
	if err := store.Create(t.Context(), record); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Create(t.Context(), record); !errors.Is(err, ErrExists) {
		t.Fatalf("second Create() error = %v, want ErrExists", err)
	}

	loaded, err := store.Get(t.Context(), testProfileID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got, expected := loaded.ControlKeyFingerprint(), record.ControlKeyFingerprint(); got != expected {
		t.Fatalf("fingerprint = %q, want %q", got, expected)
	}
	if loaded.IsRegistered() || loaded.HasPendingAuth() {
		t.Fatalf("initial registration state = %s, want unregistered", loaded)
	}

	pendingURL := "https://control.example.com/register/opaque-handle"
	pending, err := store.SetRegistration(t.Context(), testProfileID, pendingURL, false)
	if err != nil {
		t.Fatalf("SetRegistration(pending) error = %v", err)
	}
	if !pending.HasPendingAuth() || pending.PendingAuthURL() != pendingURL {
		t.Fatalf("pending state = %s, want pending authorization", pending)
	}

	registered, err := store.SetRegistration(t.Context(), testProfileID, "", true)
	if err != nil {
		t.Fatalf("SetRegistration(registered) error = %v", err)
	}
	if !registered.IsRegistered() || registered.HasPendingAuth() {
		t.Fatalf("registered state = %s, want registered without pending url", registered)
	}

	info, err := os.Stat(filepath.Join(store.dir, recordFileName(testProfileID)))
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got, expected := info.Mode().Perm(), os.FileMode(0o600); got != expected {
		t.Fatalf("record mode = %04o, want %04o", got, expected)
	}
}

func TestStore_RejectsUnsafeRecords(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*testing.T, string)
	}{
		{
			name: "symbolic link",
			prepare: func(t *testing.T, path string) {
				t.Helper()
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "broad permissions",
			prepare: func(t *testing.T, path string) {
				t.Helper()
				//nolint:gosec // The test intentionally creates an over-permissive file.
				if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unknown field",
			prepare: func(t *testing.T, path string) {
				t.Helper()
				body := fmt.Sprintf(`{"version":1,"profile_id":%q,"unknown":true}`, testProfileID)
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			stateDir := t.TempDir()
			store, err := Open(stateDir)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			t.Cleanup(func() { _ = store.Close() })
			test.prepare(t, filepath.Join(store.dir, recordFileName(testProfileID)))

			if _, err := store.Get(t.Context(), testProfileID); err == nil {
				t.Fatal("Get() error = nil, want unsafe-record error")
			}
		})
	}
}

func TestRecord_RedactsSecrets(t *testing.T) {
	t.Parallel()

	record := testRecord(t, time.Now())
	for _, rendered := range []string{
		fmt.Sprintf("%v", record),
		fmt.Sprintf("%#v", record),
		fmt.Sprintf("%v", record.Material()),
		fmt.Sprintf("%#v", record.Material()),
	} {
		for _, secret := range []string{"machine-secret", "node-secret", "control-public"} {
			if strings.Contains(rendered, secret) {
				t.Fatalf("formatted identity %q contains secret %q", rendered, secret)
			}
		}
	}
}

func TestStore_ContextCancellation(t *testing.T) {
	t.Parallel()

	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := store.Get(ctx, testProfileID); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get() error = %v, want context.Canceled", err)
	}
}

func testRecord(t *testing.T, now time.Time) Record {
	t.Helper()

	record, err := NewRecord(
		testProfileID,
		Material{
			MachinePrivateKey: []byte("machine-secret"),
			NodePrivateKey:    []byte("node-secret"),
			ControlPublicKey:  []byte("control-public"),
		},
		"sha256:"+strings.Repeat("a", 64),
		now,
	)
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}

	return record
}
