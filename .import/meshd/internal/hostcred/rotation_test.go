package hostcred

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/meshtransit/meshd/internal/secretstore"
)

func TestRotationLifecycle(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	recoveryPath := path + ".recovery"
	oldKey := bytes.Repeat([]byte{0x81}, secretstore.KeySize)
	newKey := bytes.Repeat([]byte{0x82}, secretstore.KeySize)
	writeFakeEncryptedCredential(t, path, oldKey)
	runner := &fakeRunner{}
	cfg := Config{
		Path:         path,
		RecoveryPath: recoveryPath,
		Random:       bytes.NewReader(newKey),
		run:          runner.Run,
	}

	if err := Rotate(t.Context(), cfg); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	rotating := readFakeEncryptedCredential(t, path)
	defer clear(rotating)
	hasFallback, err := secretstore.CredentialHasFallback(rotating)
	if err != nil || !hasFallback {
		t.Fatalf("CredentialHasFallback() = %t, %v", hasFallback, err)
	}
	matches, err := secretstore.CredentialFallbackMatches(rotating, oldKey)
	if err != nil || !matches {
		t.Fatalf("CredentialFallbackMatches() = %t, %v", matches, err)
	}
	active, err := secretstore.CopyActiveKey(rotating)
	if err != nil {
		t.Fatalf("CopyActiveKey() error = %v", err)
	}
	if !bytes.Equal(active, newKey) {
		t.Fatal("rotating credential does not contain expected active key")
	}
	clear(active)
	if recovery := readFakeEncryptedCredential(t, recoveryPath); !bytes.Equal(recovery, rotating) {
		clear(recovery)
		t.Fatal("recovery copy does not match rotating credential")
	} else {
		clear(recovery)
	}
	if err := Rotate(t.Context(), cfg); err != nil {
		t.Fatalf("second Rotate() error = %v, want idempotent success", err)
	}

	verified := 0
	verifyNewKey := func(_ context.Context, key []byte) error {
		verified++
		if !bytes.Equal(key, newKey) {
			return errors.New("unexpected active key")
		}

		return nil
	}
	if err := Finalize(t.Context(), cfg, verifyNewKey); err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	finalized := readFakeEncryptedCredential(t, path)
	if !bytes.Equal(finalized, newKey) {
		clear(finalized)
		t.Fatal("finalized credential is not the active key")
	}
	clear(finalized)
	if _, err := os.Lstat(recoveryPath); err != nil {
		t.Fatalf("recovery copy after Finalize() error = %v", err)
	}
	if err := Commit(t.Context(), cfg, verifyNewKey); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if verified != 2 {
		t.Fatalf("active verifier calls = %d, want 2", verified)
	}
	if _, err := os.Lstat(recoveryPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery copy after Commit() error = %v, want not exist", err)
	}
}

func TestRotationOperationsAreCrashRetrySafe(t *testing.T) {
	t.Parallel()

	oldKey := bytes.Repeat([]byte{0x91}, secretstore.KeySize)
	newKey := bytes.Repeat([]byte{0x92}, secretstore.KeySize)
	keySet, err := secretstore.EncodeKeySet(newKey, oldKey)
	if err != nil {
		t.Fatalf("EncodeKeySet() error = %v", err)
	}
	defer clear(keySet)

	tests := []struct {
		name          string
		prepare       func(*testing.T, string, string)
		operation     func(context.Context, Config, ActiveVerifier) error
		wantPrimary   []byte
		wantRecovery  []byte
		wantVerifyRun bool
		wantSyncRuns  int
	}{
		{
			name: "rotate after primary rename",
			prepare: func(t *testing.T, path, recoveryPath string) {
				t.Helper()
				writeFakeEncryptedCredential(t, path, keySet)
				writeFakeEncryptedCredential(t, recoveryPath, keySet)
			},
			operation: func(ctx context.Context, cfg Config, _ ActiveVerifier) error {
				return Rotate(ctx, cfg)
			},
			wantPrimary:  keySet,
			wantRecovery: keySet,
			wantSyncRuns: 1,
		},
		{
			name: "finalize after primary rename",
			prepare: func(t *testing.T, path, recoveryPath string) {
				t.Helper()
				writeFakeEncryptedCredential(t, path, newKey)
				writeFakeEncryptedCredential(t, recoveryPath, keySet)
			},
			operation:     Finalize,
			wantPrimary:   newKey,
			wantRecovery:  keySet,
			wantVerifyRun: true,
			wantSyncRuns:  1,
		},
		{
			name: "commit after recovery removal",
			prepare: func(t *testing.T, path, _ string) {
				t.Helper()
				writeFakeEncryptedCredential(t, path, newKey)
			},
			operation:     Commit,
			wantPrimary:   newKey,
			wantVerifyRun: true,
			wantSyncRuns:  1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, fileName)
			recoveryPath := path + ".recovery"
			test.prepare(t, path, recoveryPath)
			verifyRuns := 0
			verify := func(_ context.Context, active []byte) error {
				verifyRuns++
				if !bytes.Equal(active, newKey) {
					return errors.New("unexpected active key")
				}

				return nil
			}
			syncRuns := 0
			cfg := Config{
				Path:         path,
				RecoveryPath: recoveryPath,
				run:          (&fakeRunner{}).Run,
				files: fileOperations{
					syncDir: func(string) error {
						syncRuns++

						return nil
					},
				},
			}
			if err := test.operation(t.Context(), cfg, verify); err != nil {
				t.Fatalf("retry operation error = %v", err)
			}
			if got := readFakeEncryptedCredential(t, path); !bytes.Equal(got, test.wantPrimary) {
				clear(got)
				t.Fatal("retry changed the primary credential unexpectedly")
			} else {
				clear(got)
			}
			if test.wantRecovery == nil {
				if _, err := os.Lstat(recoveryPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("recovery after retry error = %v, want not exist", err)
				}
			} else if got := readFakeEncryptedCredential(t, recoveryPath); !bytes.Equal(got, test.wantRecovery) {
				clear(got)
				t.Fatal("retry changed the recovery credential unexpectedly")
			} else {
				clear(got)
			}
			if got := verifyRuns > 0; got != test.wantVerifyRun {
				t.Fatalf("active verifier called = %t, want %t", got, test.wantVerifyRun)
			}
			if syncRuns != test.wantSyncRuns {
				t.Fatalf("directory sync calls = %d, want %d", syncRuns, test.wantSyncRuns)
			}
		})
	}
}

func TestRotationRetriesAfterDirectorySyncFailure(t *testing.T) {
	t.Parallel()

	errInjectedSync := errors.New("injected directory sync failure")
	tests := []struct {
		name       string
		operation  string
		failOnSync int
	}{
		{name: "rotate after durable recovery", operation: "rotate", failOnSync: 1},
		{name: "rotate after primary activation", operation: "rotate", failOnSync: 2},
		{name: "finalize after primary replacement", operation: "finalize", failOnSync: 1},
		{name: "commit after recovery removal", operation: "commit", failOnSync: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, fileName)
			recoveryPath := path + ".recovery"
			oldKey := bytes.Repeat([]byte{0xa1}, secretstore.KeySize)
			newKey := bytes.Repeat([]byte{0xa2}, secretstore.KeySize)
			writeFakeEncryptedCredential(t, path, oldKey)
			base := Config{
				Path:         path,
				RecoveryPath: recoveryPath,
				Random:       bytes.NewReader(newKey),
				run:          (&fakeRunner{}).Run,
			}
			verify := func(_ context.Context, active []byte) error {
				if !bytes.Equal(active, newKey) {
					return errors.New("unexpected active key")
				}

				return nil
			}

			if test.operation != "rotate" {
				if err := Rotate(t.Context(), base); err != nil {
					t.Fatalf("Rotate(setup) error = %v", err)
				}
			}
			if test.operation == "commit" {
				if err := Finalize(t.Context(), base, verify); err != nil {
					t.Fatalf("Finalize(setup) error = %v", err)
				}
			}

			syncCalls := 0
			faulted := base
			faulted.files.syncDir = func(string) error {
				syncCalls++
				if syncCalls == test.failOnSync {
					return errInjectedSync
				}

				return nil
			}
			var err error
			switch test.operation {
			case "rotate":
				err = Rotate(t.Context(), faulted)
			case "finalize":
				err = Finalize(t.Context(), faulted, verify)
			case "commit":
				err = Commit(t.Context(), faulted, verify)
			default:
				t.Fatalf("unsupported test operation %q", test.operation)
			}
			if !errors.Is(err, errInjectedSync) {
				t.Fatalf("faulted %s error = %v, want injected sync error", test.operation, err)
			}

			switch test.operation {
			case "rotate":
				if err := Rotate(t.Context(), base); err != nil {
					t.Fatalf("Rotate(retry) error = %v", err)
				}
				if err := Finalize(t.Context(), base, verify); err != nil {
					t.Fatalf("Finalize() error = %v", err)
				}
				if err := Commit(t.Context(), base, verify); err != nil {
					t.Fatalf("Commit() error = %v", err)
				}
			case "finalize":
				if err := Finalize(t.Context(), base, verify); err != nil {
					t.Fatalf("Finalize(retry) error = %v", err)
				}
				if err := Commit(t.Context(), base, verify); err != nil {
					t.Fatalf("Commit() error = %v", err)
				}
			case "commit":
				if err := Commit(t.Context(), base, verify); err != nil {
					t.Fatalf("Commit(retry) error = %v", err)
				}
			}
			if got := readFakeEncryptedCredential(t, path); !bytes.Equal(got, newKey) {
				clear(got)
				t.Fatal("completed retry did not retain the new active key")
			} else {
				clear(got)
			}
			if _, err := os.Lstat(recoveryPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("recovery after completed retry error = %v, want not exist", err)
			}
		})
	}
}

func TestRotationRetriesAfterFilesystemOperationFailure(t *testing.T) {
	t.Parallel()

	errInjected := errors.New("injected filesystem failure")
	tests := []struct {
		name      string
		operation string
		files     fileOperations
	}{
		{
			name:      "rotate encrypted file sync",
			operation: "rotate",
			files: fileOperations{
				syncFile: func(string) error { return errInjected },
			},
		},
		{
			name:      "rotate recovery link",
			operation: "rotate",
			files: fileOperations{
				link: func(string, string) error { return errInjected },
			},
		},
		{
			name:      "rotate primary rename",
			operation: "rotate",
			files: fileOperations{
				rename: func(string, string) error { return errInjected },
			},
		},
		{
			name:      "finalize primary rename",
			operation: "finalize",
			files: fileOperations{
				rename: func(string, string) error { return errInjected },
			},
		},
		{
			name:      "commit recovery removal",
			operation: "commit",
			files: fileOperations{
				remove: func(string) error { return errInjected },
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, fileName)
			recoveryPath := path + ".recovery"
			oldKey := bytes.Repeat([]byte{0xc1}, secretstore.KeySize)
			newKey := bytes.Repeat([]byte{0xc2}, secretstore.KeySize)
			writeFakeEncryptedCredential(t, path, oldKey)
			base := Config{
				Path:         path,
				RecoveryPath: recoveryPath,
				Random:       bytes.NewReader(newKey),
				run:          (&fakeRunner{}).Run,
			}
			verify := func(_ context.Context, active []byte) error {
				if !bytes.Equal(active, newKey) {
					return errors.New("unexpected active key")
				}

				return nil
			}
			if test.operation != "rotate" {
				if err := Rotate(t.Context(), base); err != nil {
					t.Fatalf("Rotate(setup) error = %v", err)
				}
			}
			if test.operation == "commit" {
				if err := Finalize(t.Context(), base, verify); err != nil {
					t.Fatalf("Finalize(setup) error = %v", err)
				}
			}

			faulted := base
			faulted.files = test.files
			var err error
			switch test.operation {
			case "rotate":
				err = Rotate(t.Context(), faulted)
			case "finalize":
				err = Finalize(t.Context(), faulted, verify)
			case "commit":
				err = Commit(t.Context(), faulted, verify)
			default:
				t.Fatalf("unsupported test operation %q", test.operation)
			}
			if !errors.Is(err, errInjected) {
				t.Fatalf("faulted %s error = %v, want injected failure", test.operation, err)
			}

			base.Random = bytes.NewReader(newKey)
			switch test.operation {
			case "rotate":
				if err := Rotate(t.Context(), base); err != nil {
					t.Fatalf("Rotate(retry) error = %v", err)
				}
				if err := Finalize(t.Context(), base, verify); err != nil {
					t.Fatalf("Finalize() error = %v", err)
				}
				if err := Commit(t.Context(), base, verify); err != nil {
					t.Fatalf("Commit() error = %v", err)
				}
			case "finalize":
				if err := Finalize(t.Context(), base, verify); err != nil {
					t.Fatalf("Finalize(retry) error = %v", err)
				}
				if err := Commit(t.Context(), base, verify); err != nil {
					t.Fatalf("Commit() error = %v", err)
				}
			case "commit":
				if err := Commit(t.Context(), base, verify); err != nil {
					t.Fatalf("Commit(retry) error = %v", err)
				}
			}

			if got := readFakeEncryptedCredential(t, path); !bytes.Equal(got, newKey) {
				clear(got)
				t.Fatal("completed retry did not retain the new active key")
			} else {
				clear(got)
			}
			if _, err := os.Lstat(recoveryPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("recovery after completed retry error = %v, want not exist", err)
			}
		})
	}
}

func TestRotationRetriesRejectUnverifiedRecoveryState(t *testing.T) {
	t.Parallel()

	errUnreadableIdentities := errors.New("injected unreadable identities")
	oldKey := bytes.Repeat([]byte{0xb1}, secretstore.KeySize)
	newKey := bytes.Repeat([]byte{0xb2}, secretstore.KeySize)
	keySet, err := secretstore.EncodeKeySet(newKey, oldKey)
	if err != nil {
		t.Fatalf("EncodeKeySet() error = %v", err)
	}
	defer clear(keySet)
	mismatched, err := secretstore.EncodeKeySet(
		bytes.Repeat([]byte{0xb3}, secretstore.KeySize),
		oldKey,
	)
	if err != nil {
		t.Fatalf("EncodeKeySet(mismatched) error = %v", err)
	}
	defer clear(mismatched)

	tests := []struct {
		name            string
		primary         []byte
		recovery        []byte
		operation       func(context.Context, Config, ActiveVerifier) error
		expected        error
		wantVerifyCalls int
	}{
		{
			name:      "rotate missing recovery",
			primary:   keySet,
			operation: func(ctx context.Context, cfg Config, _ ActiveVerifier) error { return Rotate(ctx, cfg) },
			expected:  ErrRecoveryMissing,
		},
		{
			name:      "rotate mismatched recovery",
			primary:   keySet,
			recovery:  mismatched,
			operation: func(ctx context.Context, cfg Config, _ ActiveVerifier) error { return Rotate(ctx, cfg) },
			expected:  ErrRecoveryInvalid,
		},
		{
			name:      "finalize missing recovery",
			primary:   newKey,
			operation: Finalize,
			expected:  ErrRotationNotPending,
		},
		{
			name:      "finalize mismatched recovery",
			primary:   newKey,
			recovery:  mismatched,
			operation: Finalize,
			expected:  ErrRecoveryInvalid,
		},
		{
			name:            "commit retry unreadable identities",
			primary:         newKey,
			operation:       Commit,
			expected:        errUnreadableIdentities,
			wantVerifyCalls: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, fileName)
			recoveryPath := path + ".recovery"
			writeFakeEncryptedCredential(t, path, test.primary)
			if test.recovery != nil {
				writeFakeEncryptedCredential(t, recoveryPath, test.recovery)
			}
			before := readIdentityCredentialFile(t, path)
			verifyCalls := 0
			verify := func(context.Context, []byte) error {
				verifyCalls++

				return errUnreadableIdentities
			}
			err := test.operation(t.Context(), Config{
				Path:         path,
				RecoveryPath: recoveryPath,
				run:          (&fakeRunner{}).Run,
			}, verify)
			if !errors.Is(err, test.expected) {
				t.Fatalf("retry operation error = %v, want %v", err, test.expected)
			}
			if verifyCalls != test.wantVerifyCalls {
				t.Fatalf("active verifier calls = %d, want %d", verifyCalls, test.wantVerifyCalls)
			}
			after := readIdentityCredentialFile(t, path)
			if !bytes.Equal(after, before) {
				t.Fatal("rejected retry changed the primary credential")
			}
		})
	}
}

func TestRotateResumesDurableRecoveryCopy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	recoveryPath := path + ".recovery"
	oldKey := bytes.Repeat([]byte{0x83}, secretstore.KeySize)
	newKey := bytes.Repeat([]byte{0x84}, secretstore.KeySize)
	keySet, err := secretstore.EncodeKeySet(newKey, oldKey)
	if err != nil {
		t.Fatalf("EncodeKeySet() error = %v", err)
	}
	defer clear(keySet)
	writeFakeEncryptedCredential(t, path, oldKey)
	writeFakeEncryptedCredential(t, recoveryPath, keySet)
	runner := &fakeRunner{}
	if err := Rotate(t.Context(), Config{
		Path:         path,
		RecoveryPath: recoveryPath,
		run:          runner.Run,
	}); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if runner.encryptCalls != 0 {
		t.Fatalf("resume encrypt calls = %d, want 0", runner.encryptCalls)
	}
	resumed := readFakeEncryptedCredential(t, path)
	defer clear(resumed)
	if !bytes.Equal(resumed, keySet) {
		t.Fatal("resumed primary does not match durable recovery copy")
	}
}

func TestFinalizeFailurePreservesRotatingCredential(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	recoveryPath := path + ".recovery"
	writeFakeEncryptedCredential(t, path, bytes.Repeat([]byte{0x85}, secretstore.KeySize))
	runner := &fakeRunner{}
	cfg := Config{
		Path:         path,
		RecoveryPath: recoveryPath,
		Random:       bytes.NewReader(bytes.Repeat([]byte{0x86}, secretstore.KeySize)),
		run:          runner.Run,
	}
	if err := Rotate(t.Context(), cfg); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	before := readIdentityCredentialFile(t, path)
	if err := Finalize(t.Context(), cfg, func(context.Context, []byte) error {
		return errors.New("injected identity verification failure")
	}); err == nil {
		t.Fatal("Finalize() error = nil, want verification failure")
	}
	after := readIdentityCredentialFile(t, path)
	if !bytes.Equal(after, before) {
		t.Fatal("failed Finalize() changed rotating credential")
	}
}

func TestRecoverRestoresVerifiedCopy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	recoveryPath := path + ".recovery"
	keySet, err := secretstore.EncodeKeySet(
		bytes.Repeat([]byte{0x87}, secretstore.KeySize),
		bytes.Repeat([]byte{0x88}, secretstore.KeySize),
	)
	if err != nil {
		t.Fatalf("EncodeKeySet() error = %v", err)
	}
	defer clear(keySet)
	writeFakeEncryptedCredential(t, path, []byte("corrupt"))
	writeFakeEncryptedCredential(t, recoveryPath, keySet)
	if err := Recover(t.Context(), Config{
		Path:         path,
		RecoveryPath: recoveryPath,
		run:          (&fakeRunner{}).Run,
	}); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	recovered := readFakeEncryptedCredential(t, path)
	defer clear(recovered)
	if !bytes.Equal(recovered, keySet) {
		t.Fatal("recovered primary does not match recovery copy")
	}
}

func TestRecoverRejectsSingleKeyCopy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	recoveryPath := path + ".recovery"
	writeFakeEncryptedCredential(
		t,
		recoveryPath,
		bytes.Repeat([]byte{0x8a}, secretstore.KeySize),
	)
	err := Recover(t.Context(), Config{
		Path:         path,
		RecoveryPath: recoveryPath,
		run:          (&fakeRunner{}).Run,
	})
	if !errors.Is(err, ErrRecoveryInvalid) {
		t.Fatalf("Recover() error = %v, want ErrRecoveryInvalid", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("primary after rejected recovery error = %v, want not exist", err)
	}
}

func TestCommitRejectsMismatchedRecoveryCopy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	recoveryPath := path + ".recovery"
	currentKey := bytes.Repeat([]byte{0x8b}, secretstore.KeySize)
	recovery, err := secretstore.EncodeKeySet(
		bytes.Repeat([]byte{0x8c}, secretstore.KeySize),
		bytes.Repeat([]byte{0x8d}, secretstore.KeySize),
	)
	if err != nil {
		t.Fatalf("EncodeKeySet() error = %v", err)
	}
	defer clear(recovery)
	writeFakeEncryptedCredential(t, path, currentKey)
	writeFakeEncryptedCredential(t, recoveryPath, recovery)
	verified := false
	err = Commit(t.Context(), Config{
		Path:         path,
		RecoveryPath: recoveryPath,
		run:          (&fakeRunner{}).Run,
	}, func(context.Context, []byte) error {
		verified = true

		return nil
	})
	if !errors.Is(err, ErrRecoveryInvalid) {
		t.Fatalf("Commit() error = %v, want ErrRecoveryInvalid", err)
	}
	if verified {
		t.Fatal("Commit() called verifier for mismatched recovery state")
	}
	if _, err := os.Lstat(recoveryPath); err != nil {
		t.Fatalf("recovery copy after rejected Commit() error = %v", err)
	}
}

func TestRotateRejectsDuplicateGeneratedKeyWithoutMutation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	key := bytes.Repeat([]byte{0x8e}, secretstore.KeySize)
	writeFakeEncryptedCredential(t, path, key)
	before := readIdentityCredentialFile(t, path)
	err := Rotate(t.Context(), Config{
		Path:   path,
		Random: bytes.NewReader(key),
		run:    (&fakeRunner{}).Run,
	})
	if err == nil {
		t.Fatal("Rotate() error = nil, want duplicate-key failure")
	}
	after := readIdentityCredentialFile(t, path)
	if !bytes.Equal(after, before) {
		t.Fatal("rejected Rotate() changed primary credential")
	}
	if _, err := os.Lstat(path + ".recovery"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery copy after rejected Rotate() error = %v, want not exist", err)
	}
}

func TestProvisionRefusesToOrphanRecoveryCopy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	writeFakeEncryptedCredential(
		t,
		path+".recovery",
		bytes.Repeat([]byte{0x89}, secretstore.KeySize),
	)
	runner := &fakeRunner{}
	err := Provision(t.Context(), Config{Path: path, run: runner.Run})
	if !errors.Is(err, ErrRecoveryAvailable) {
		t.Fatalf("Provision() error = %v, want ErrRecoveryAvailable", err)
	}
	if runner.encryptCalls != 0 {
		t.Fatalf("Provision() encrypt calls = %d, want 0", runner.encryptCalls)
	}
}

func writeFakeEncryptedCredential(t *testing.T, path string, plaintext []byte) {
	t.Helper()
	encoded := append([]byte("encrypted:"), plaintext...)
	defer clear(encoded)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func readFakeEncryptedCredential(t *testing.T, path string) []byte {
	t.Helper()
	encoded := readIdentityCredentialFile(t, path)
	if !bytes.HasPrefix(encoded, []byte("encrypted:")) {
		clear(encoded)
		t.Fatal("test credential is missing encrypted prefix")
	}
	plaintext := append([]byte(nil), encoded[len("encrypted:"):]...)
	clear(encoded)

	return plaintext
}

func readIdentityCredentialFile(t *testing.T, path string) []byte {
	t.Helper()
	//nolint:gosec // Tests read only paths created under their temporary directory.
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	return encoded
}
