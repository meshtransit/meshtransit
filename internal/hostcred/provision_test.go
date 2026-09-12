package hostcred

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meshtransit/meshd/internal/secretstore"
)

func TestProvisionCreatesAndReusesCredential(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "credentials", fileName)
	runner := &fakeRunner{}
	cfg := Config{
		Path:   path,
		Random: bytes.NewReader(bytes.Repeat([]byte{0x71}, secretstore.KeySize)),
		run:    runner.Run,
	}
	if err := Provision(t.Context(), cfg); err != nil {
		t.Fatalf("Provision(create) error = %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	if info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("credential mode = %v, want regular 0600", info.Mode())
	}
	if runner.encryptCalls != 1 || runner.decryptCalls != 1 || runner.setupCalls != 1 {
		t.Fatalf("first calls = setup:%d encrypt:%d decrypt:%d", runner.setupCalls, runner.encryptCalls, runner.decryptCalls)
	}

	if err := Provision(t.Context(), cfg); err != nil {
		t.Fatalf("Provision(existing) error = %v", err)
	}
	if runner.encryptCalls != 1 || runner.decryptCalls != 2 || runner.setupCalls != 2 {
		t.Fatalf("second calls = setup:%d encrypt:%d decrypt:%d", runner.setupCalls, runner.encryptCalls, runner.decryptCalls)
	}
}

func TestProvisionRejectsUnsafeExistingCredential(t *testing.T) {
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
				if err := os.WriteFile(target, []byte("encrypted"), 0o600); err != nil {
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
				//nolint:gosec // The test intentionally creates an unsafe permission mode.
				if err := os.WriteFile(path, []byte("encrypted"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "empty file",
			prepare: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			path := filepath.Join(dir, fileName)
			test.prepare(t, path)
			runner := &fakeRunner{}
			err := Provision(t.Context(), Config{
				Path: path,
				run:  runner.Run,
			})
			if err == nil {
				t.Fatal("Provision() error = nil")
			}
			if runner.encryptCalls != 0 || runner.decryptCalls != 0 {
				t.Fatalf("unsafe credential was processed: encrypt:%d decrypt:%d", runner.encryptCalls, runner.decryptCalls)
			}
		})
	}
}

func TestProvisionRoundTripFailureLeavesNoCredential(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	runner := &fakeRunner{decryptOverride: bytes.Repeat([]byte{0x99}, secretstore.KeySize)}
	err := Provision(t.Context(), Config{
		Path:   path,
		Random: bytes.NewReader(bytes.Repeat([]byte{0x72}, secretstore.KeySize)),
		run:    runner.Run,
	})
	if err == nil || !strings.Contains(err.Error(), "did not round trip") {
		t.Fatalf("Provision() error = %v, want round-trip failure", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential after failure error = %v, want not exist", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary files after failure = %v", entries)
	}
}

func TestProvisionHonorsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := Provision(ctx, Config{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Provision() error = %v, want context.Canceled", err)
	}
}

type fakeRunner struct {
	setupCalls      int
	encryptCalls    int
	decryptCalls    int
	decryptOverride []byte
}

func (r *fakeRunner) Run(
	_ context.Context,
	_ string,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
) error {
	switch {
	case len(args) == 2 && args[1] == "setup":
		r.setupCalls++

		return nil
	case len(args) == 6 && args[3] == "encrypt":
		r.encryptCalls++
		key, err := io.ReadAll(stdin)
		if err != nil {
			return err
		}
		defer clear(key)
		return os.WriteFile(args[5], append([]byte("encrypted:"), key...), 0o600)
	case len(args) == 5 && args[1] == "--name="+fileName && args[2] == "decrypt":
		r.decryptCalls++
		if r.decryptOverride != nil {
			_, err := stdout.Write(r.decryptOverride)

			return err
		}
		encoded, err := os.ReadFile(args[3])
		if err != nil {
			return err
		}
		if !bytes.HasPrefix(encoded, []byte("encrypted:")) {
			return errors.New("invalid test credential")
		}
		_, err = stdout.Write(encoded[len("encrypted:"):])

		return err
	default:
		return errors.New("unexpected command")
	}
}
