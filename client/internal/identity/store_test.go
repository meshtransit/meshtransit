package identity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/secretstore"
)

const (
	testProfileID       = "00000000000000000000000000000001"
	secondTestProfileID = "00000000000000000000000000000002"
)

func TestStore_CreateGetAndUpdate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 9, 1, 2, 3, 0, time.UTC)
	store, err := openWith(
		t.TempDir(),
		func() time.Time { return now },
		testProtector(t, 0x10),
	)
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
	encoded := readIdentityFile(t, store.dir, testProfileID)
	for _, secret := range []string{
		"machine-secret",
		"node-secret",
		"control-public",
		pendingURL,
	} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("protected identity contains plaintext %q", secret)
		}
	}
}

func TestStore_NodeKeyRotationStagesBeforeAtomicPromotion(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 16, 7, 8, 9, 0, time.UTC)
	store, err := openWith(
		t.TempDir(),
		func() time.Time { return now },
		testProtector(t, 0x18),
	)
	if err != nil {
		t.Fatalf("openWith() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	record := testRecord(t, now)
	record.isRegistered = true
	if err := store.Create(t.Context(), record); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	pendingKey := []byte("pending-node-secret")
	staged, err := store.BeginNodeKeyRotation(t.Context(), testProfileID, pendingKey)
	if err != nil {
		t.Fatalf("BeginNodeKeyRotation() error = %v", err)
	}
	if !staged.HasPendingNodeKeyRotation() ||
		string(staged.PendingNodePrivateKey()) != string(pendingKey) ||
		string(staged.Material().NodePrivateKey) != "node-secret" {
		t.Fatal("staged rotation replaced active key before remote commit")
	}
	if _, err := store.BeginNodeKeyRotation(
		t.Context(),
		testProfileID,
		pendingKey,
	); err != nil {
		t.Fatalf("idempotent BeginNodeKeyRotation() error = %v", err)
	}
	if _, err := store.BeginNodeKeyRotation(
		t.Context(),
		testProfileID,
		[]byte("different-node-secret"),
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("conflicting BeginNodeKeyRotation() error = %v, want ErrInvalid", err)
	}

	completed, err := store.CompleteNodeKeyRotation(t.Context(), testProfileID, pendingKey)
	if err != nil {
		t.Fatalf("CompleteNodeKeyRotation() error = %v", err)
	}
	if completed.HasPendingNodeKeyRotation() ||
		string(completed.Material().NodePrivateKey) != string(pendingKey) {
		t.Fatal("completed rotation did not atomically promote staged key")
	}
}

func TestStore_UpgradesProtectedVersionOneRecord(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 16, 8, 9, 10, 0, time.UTC)
	store, err := openWith(
		t.TempDir(),
		func() time.Time { return now },
		testProtector(t, 0x19),
	)
	if err != nil {
		t.Fatalf("openWith() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	record := testRecord(t, now)
	legacy := toPersisted(record)
	legacy.Version = legacyRecordVersion
	plaintext, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("json.Marshal(legacy) error = %v", err)
	}
	protected, err := store.protector.Seal(
		t.Context(),
		plaintext,
		recordAdditionalData(testProfileID),
	)
	clear(plaintext)
	if err != nil {
		t.Fatalf("Seal(legacy) error = %v", err)
	}
	envelope := persistedEnvelope{
		Format:    envelopeFormat,
		Version:   envelopeVersion,
		ProfileID: testProfileID,
		Algorithm: envelopeAlgorithm,
		Payload:   base64.RawStdEncoding.EncodeToString(protected),
	}
	clear(protected)
	path := filepath.Join(store.dir, recordFileName(testProfileID))
	writeEnvelope(t, path, envelope)
	before := readIdentityFilePath(t, path)

	loaded, err := store.Get(t.Context(), testProfileID)
	if err != nil {
		t.Fatalf("Get(version one) error = %v", err)
	}
	if !sameRecord(loaded, record) {
		t.Fatal("upgraded version-one identity changed record")
	}
	after := readIdentityFilePath(t, path)
	if bytes.Equal(after, before) {
		t.Fatal("version-one protected identity was not rewritten")
	}
	if err := store.VerifyAllCurrent(t.Context()); err != nil {
		t.Fatalf("VerifyAllCurrent() error = %v", err)
	}
}

func TestStore_MigratesLegacyPlaintextAtomically(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 12, 1, 2, 3, 0, time.UTC)
	stateDir := t.TempDir()
	store, err := openWith(stateDir, func() time.Time { return now }, testProtector(t, 0x31))
	if err != nil {
		t.Fatalf("openWith() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	record := testRecord(t, now)
	legacy, err := json.Marshal(toPersisted(record))
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	legacy = append(legacy, '\n')
	path := filepath.Join(store.dir, recordFileName(testProfileID))
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	loaded, err := store.Get(t.Context(), testProfileID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !sameRecord(loaded, record) {
		t.Fatal("migrated record does not match legacy identity")
	}
	protected := readIdentityFile(t, store.dir, testProfileID)
	if bytes.Equal(protected, legacy) || bytes.Contains(protected, []byte("machine-secret")) {
		t.Fatal("legacy identity was not replaced with protected bytes")
	}
	envelope := persistedEnvelope{}
	if err := decodeStrict(protected, &envelope); err != nil {
		t.Fatalf("decodeStrict(envelope) error = %v", err)
	}
	if envelope.Format != envelopeFormat || envelope.ProfileID != testProfileID || envelope.Payload == "" {
		t.Fatalf("migrated envelope metadata = %#v", envelope)
	}
}

func TestStore_MigrationFailurePreservesLegacyRecord(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 12, 2, 3, 4, 0, time.UTC)
	stateDir := t.TempDir()
	store, err := openWith(stateDir, func() time.Time { return now }, failingProtector{})
	if err != nil {
		t.Fatalf("openWith() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	legacy, err := json.Marshal(toPersisted(testRecord(t, now)))
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	legacy = append(legacy, '\n')
	path := filepath.Join(store.dir, recordFileName(testProfileID))
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if _, err := store.Get(t.Context(), testProfileID); err == nil {
		t.Fatal("Get() error = nil, want migration failure")
	}
	if after := readIdentityFile(t, store.dir, testProfileID); !bytes.Equal(after, legacy) {
		t.Fatal("failed migration changed the last readable legacy record")
	}
}

func TestStore_RewrapsFallbackKeyRecordAtomically(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	oldKey := bytes.Repeat([]byte{0x35}, secretstore.KeySize)
	newKey := bytes.Repeat([]byte{0x36}, secretstore.KeySize)
	oldProtector, err := secretstore.New(oldKey)
	if err != nil {
		t.Fatalf("secretstore.New(old) error = %v", err)
	}
	oldStore, err := Open(stateDir, oldProtector)
	if err != nil {
		t.Fatalf("Open(old) error = %v", err)
	}
	record := testRecord(t, time.Now())
	if err := oldStore.Create(t.Context(), record); err != nil {
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
	rotatingStore, err := Open(stateDir, rotatingProtector)
	if err != nil {
		t.Fatalf("Open(rotating) error = %v", err)
	}
	loaded, err := rotatingStore.Get(t.Context(), testProfileID)
	if err != nil {
		t.Fatalf("Get(rotating) error = %v", err)
	}
	if !sameRecord(loaded, record) {
		t.Fatal("rotated record does not match original identity")
	}
	after := readIdentityFile(t, rotatingStore.dir, testProfileID)
	if bytes.Equal(after, before) {
		t.Fatal("fallback-key record was not replaced")
	}
	if err := rotatingStore.Close(); err != nil {
		t.Fatalf("Close(rotating) error = %v", err)
	}

	newProtector, err := secretstore.New(newKey)
	if err != nil {
		t.Fatalf("secretstore.New(new) error = %v", err)
	}
	newStore, err := Open(stateDir, newProtector)
	if err != nil {
		t.Fatalf("Open(new) error = %v", err)
	}
	t.Cleanup(func() { _ = newStore.Close() })
	if _, err := newStore.Get(t.Context(), testProfileID); err != nil {
		t.Fatalf("Get(new) error = %v", err)
	}

	oldOnlyProtector, err := secretstore.New(oldKey)
	if err != nil {
		t.Fatalf("secretstore.New(old-only) error = %v", err)
	}
	oldOnlyStore, err := Open(stateDir, oldOnlyProtector)
	if err != nil {
		t.Fatalf("Open(old-only) error = %v", err)
	}
	t.Cleanup(func() { _ = oldOnlyStore.Close() })
	if _, err := oldOnlyStore.Get(t.Context(), testProfileID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Get(old-only) error = %v, want ErrCorrupt", err)
	}
}

func TestStore_RewrapFailurePreservesFallbackKeyRecord(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	oldKey := bytes.Repeat([]byte{0x37}, secretstore.KeySize)
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

	fallbackProtector, err := secretstore.New(oldKey)
	if err != nil {
		t.Fatalf("secretstore.New(fallback) error = %v", err)
	}
	store, err := openWith(
		stateDir,
		time.Now,
		&failingRewrapProtector{fallback: fallbackProtector},
	)
	if err != nil {
		t.Fatalf("openWith() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.Get(t.Context(), testProfileID); err == nil {
		t.Fatal("Get() error = nil, want rewrap failure")
	}
	after := readIdentityFile(t, store.dir, testProfileID)
	if !bytes.Equal(after, before) {
		t.Fatal("failed rewrap changed the last readable record")
	}
}

func TestStore_MigrateAllRewrapsEveryFallbackRecord(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	oldKey := bytes.Repeat([]byte{0x38}, secretstore.KeySize)
	newKey := bytes.Repeat([]byte{0x39}, secretstore.KeySize)
	oldProtector, err := secretstore.New(oldKey)
	if err != nil {
		t.Fatalf("secretstore.New(old) error = %v", err)
	}
	oldStore, err := Open(stateDir, oldProtector)
	if err != nil {
		t.Fatalf("Open(old) error = %v", err)
	}
	for _, profileID := range []string{testProfileID, secondTestProfileID} {
		if err := oldStore.Create(
			t.Context(),
			testRecordForProfile(t, profileID, time.Now()),
		); err != nil {
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
	rotatingStore, err := Open(stateDir, rotatingProtector)
	if err != nil {
		t.Fatalf("Open(rotating) error = %v", err)
	}
	if err := rotatingStore.MigrateAll(t.Context()); err != nil {
		t.Fatalf("MigrateAll() error = %v", err)
	}
	if err := rotatingStore.Close(); err != nil {
		t.Fatalf("Close(rotating) error = %v", err)
	}

	newProtector, err := secretstore.New(newKey)
	if err != nil {
		t.Fatalf("secretstore.New(new) error = %v", err)
	}
	newStore, err := Open(stateDir, newProtector)
	if err != nil {
		t.Fatalf("Open(new) error = %v", err)
	}
	t.Cleanup(func() { _ = newStore.Close() })
	for _, profileID := range []string{testProfileID, secondTestProfileID} {
		if _, err := newStore.Get(t.Context(), profileID); err != nil {
			t.Fatalf("Get(%s) error = %v", profileID, err)
		}
	}
}

func TestStore_MigrateAllRejectsNonCanonicalRecordName(t *testing.T) {
	t.Parallel()

	store, err := Open(t.TempDir(), testProtector(t, 0x3a))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := os.WriteFile(filepath.Join(store.dir, "INVALID.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := store.MigrateAll(t.Context()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("MigrateAll() error = %v, want ErrCorrupt", err)
	}
}

func TestStore_VerifyAllCurrentDoesNotMigrateLegacyRecord(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	store, err := Open(stateDir, testProtector(t, 0x3b))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	record := testRecord(t, time.Now())
	legacy, err := json.Marshal(toPersisted(record))
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	legacy = append(legacy, '\n')
	path := filepath.Join(store.dir, recordFileName(testProfileID))
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if err := store.VerifyAllCurrent(t.Context()); !errors.Is(err, ErrMigrationRequired) {
		t.Fatalf("VerifyAllCurrent() error = %v, want ErrMigrationRequired", err)
	}
	if after := readIdentityFilePath(t, path); !bytes.Equal(after, legacy) {
		t.Fatal("VerifyAllCurrent() changed legacy state")
	}
	if err := store.MigrateAll(t.Context()); err != nil {
		t.Fatalf("MigrateAll() error = %v", err)
	}
	if err := store.VerifyAllCurrent(t.Context()); err != nil {
		t.Fatalf("VerifyAllCurrent(migrated) error = %v", err)
	}
}

func TestStore_RejectsTamperingWrongKeyAndProfileSwap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*testing.T, string)
		openKey byte
	}{
		{
			name: "tampered ciphertext",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				envelope := persistedEnvelope{}
				if err := decodeStrict(readIdentityFilePath(t, path), &envelope); err != nil {
					t.Fatal(err)
				}
				if envelope.Payload[0] == 'A' {
					envelope.Payload = "B" + envelope.Payload[1:]
				} else {
					envelope.Payload = "A" + envelope.Payload[1:]
				}
				writeEnvelope(t, path, envelope)
			},
			openKey: 0x41,
		},
		{
			name:    "wrong key",
			mutate:  func(*testing.T, string) {},
			openKey: 0x42,
		},
		{
			name: "unsupported version",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				envelope := persistedEnvelope{}
				if err := decodeStrict(readIdentityFilePath(t, path), &envelope); err != nil {
					t.Fatal(err)
				}
				envelope.Version++
				writeEnvelope(t, path, envelope)
			},
			openKey: 0x41,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			stateDir := t.TempDir()
			store, err := Open(stateDir, testProtector(t, 0x41))
			if err != nil {
				t.Fatalf("Open(create) error = %v", err)
			}
			if err := store.Create(t.Context(), testRecord(t, time.Now())); err != nil {
				t.Fatalf("Create() error = %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			path := filepath.Join(stateDir, identityDirName, recordFileName(testProfileID))
			test.mutate(t, path)

			reopened, err := Open(stateDir, testProtector(t, test.openKey))
			if err != nil {
				t.Fatalf("Open(read) error = %v", err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			_, err = reopened.Get(t.Context(), testProfileID)
			if test.name == "unsupported version" {
				if !errors.Is(err, ErrUnsupported) {
					t.Fatalf("Get() error = %v, want ErrUnsupported", err)
				}

				return
			}
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Get() error = %v, want ErrCorrupt", err)
			}
		})
	}
}

func TestStore_RejectsCrossProfileCiphertext(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	store, err := Open(stateDir, testProtector(t, 0x50))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	first := testRecordForProfile(t, testProfileID, time.Now())
	second := testRecordForProfile(t, secondTestProfileID, time.Now())
	if err := store.Create(t.Context(), first); err != nil {
		t.Fatalf("Create(first) error = %v", err)
	}
	if err := store.Create(t.Context(), second); err != nil {
		t.Fatalf("Create(second) error = %v", err)
	}
	firstBytes := readIdentityFile(t, store.dir, testProfileID)
	secondPath := filepath.Join(store.dir, recordFileName(secondTestProfileID))
	if err := os.WriteFile(secondPath, firstBytes, 0o600); err != nil {
		t.Fatalf("WriteFile(swapped) error = %v", err)
	}

	if _, err := store.Get(t.Context(), secondTestProfileID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Get(swapped) error = %v, want ErrCorrupt", err)
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
			store, err := Open(stateDir, testProtector(t, 0x20))
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

	store, err := Open(t.TempDir(), testProtector(t, 0x30))
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

func FuzzStoreDecodeRecord(f *testing.F) {
	protector, err := secretstore.New(bytes.Repeat([]byte{0x62}, secretstore.KeySize))
	if err != nil {
		f.Fatalf("secretstore.New() error = %v", err)
	}
	f.Cleanup(func() { _ = protector.Close() })
	store := &Store{protector: protector}
	f.Add([]byte("{}"))
	f.Add([]byte(`{"format":"meshtransit.identity","version":1}`))
	f.Add([]byte(`{"version":1,"profile_id":"00000000000000000000000000000001"}`))

	f.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) == 0 || len(encoded) > maxRecordBytes {
			t.Skip()
		}
		_, _, _ = store.decodeRecord(t.Context(), testProfileID, encoded)
	})
}

func testRecord(t *testing.T, now time.Time) Record {
	t.Helper()

	return testRecordForProfile(t, testProfileID, now)
}

func testRecordForProfile(t *testing.T, profileID string, now time.Time) Record {
	t.Helper()

	record, err := NewRecord(
		profileID,
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

func testProtector(t *testing.T, fill byte) *secretstore.Protector {
	t.Helper()

	protector, err := secretstore.New(bytes.Repeat([]byte{fill}, secretstore.KeySize))
	if err != nil {
		t.Fatalf("secretstore.New() error = %v", err)
	}

	return protector
}

func readIdentityFile(t *testing.T, dir, profileID string) []byte {
	t.Helper()

	return readIdentityFilePath(t, filepath.Join(dir, recordFileName(profileID)))
}

func readIdentityFilePath(t *testing.T, path string) []byte {
	t.Helper()

	//nolint:gosec // Tests read only files under their own temporary directory.
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	return encoded
}

func writeEnvelope(t *testing.T, path string, envelope persistedEnvelope) {
	t.Helper()

	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal(envelope) error = %v", err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile(envelope) error = %v", err)
	}
}

type failingProtector struct{}

func (failingProtector) Seal(context.Context, []byte, []byte) ([]byte, error) {
	return nil, errors.New("injected protection failure")
}

func (failingProtector) OpenWithRotation(
	context.Context,
	[]byte,
	[]byte,
) ([]byte, bool, error) {
	return nil, false, errors.New("injected open failure")
}

func (failingProtector) Close() error { return nil }

type failingRewrapProtector struct {
	fallback *secretstore.Protector
}

func (*failingRewrapProtector) Seal(context.Context, []byte, []byte) ([]byte, error) {
	return nil, errors.New("injected rewrap failure")
}

func (p *failingRewrapProtector) OpenWithRotation(
	ctx context.Context,
	protected []byte,
	additionalData []byte,
) ([]byte, bool, error) {
	plaintext, err := p.fallback.Open(ctx, protected, additionalData)

	return plaintext, err == nil, err
}

func (p *failingRewrapProtector) Close() error { return p.fallback.Close() }

func TestStore_ReplaceCredentialsKeepsTheControlPin(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 12, 1, 2, 3, 0, time.UTC)
	store, err := openWith(t.TempDir(), func() time.Time { return now }, testProtector(t, 0x10))
	if err != nil {
		t.Fatalf("openWith() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	record := testRecord(t, now)
	if err := store.Create(t.Context(), record); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := store.SetRegistration(t.Context(), testProfileID, "", true); err != nil {
		t.Fatalf("SetRegistration() error = %v", err)
	}

	replaced, err := store.ReplaceCredentials(t.Context(), testProfileID, []byte("machine-new"), []byte("node-new"))
	if err != nil {
		t.Fatalf("ReplaceCredentials() error = %v", err)
	}
	loaded, err := store.Get(t.Context(), testProfileID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	for _, got := range []Record{replaced, loaded} {
		material := got.Material()
		if string(material.MachinePrivateKey) != "machine-new" || string(material.NodePrivateKey) != "node-new" ||
			string(material.ControlPublicKey) != "control-public" ||
			got.ControlKeyFingerprint() != record.ControlKeyFingerprint() ||
			got.IsRegistered() || got.HasPendingAuth() {
			t.Fatalf("replaced record = %s, want new keys, same pin, unregistered", got)
		}
	}
	if _, err := store.ReplaceCredentials(t.Context(), testProfileID, []byte("machine-new"), []byte("node-other")); err == nil {
		t.Fatal("ReplaceCredentials() accepted the current machine key")
	}
	if _, err := store.ReplaceCredentials(t.Context(), secondTestProfileID, []byte("a"), []byte("b")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReplaceCredentials(missing) error = %v, want ErrNotFound", err)
	}
}
