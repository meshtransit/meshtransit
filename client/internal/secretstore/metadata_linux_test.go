//go:build linux

package secretstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateSystemdCredentialMetadata(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "credential")
	//nolint:gosec // systemd intentionally exposes service credentials as mode 0440.
	if err := os.WriteFile(path, make([]byte, KeySize), 0o440); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	expectedSuccess := os.Getuid() == 0 && os.Getgid() == 0
	err = validateSystemdCredentialMetadata(info)
	if expectedSuccess && err != nil {
		t.Fatalf("validateSystemdCredentialMetadata() error = %v", err)
	}
	if !expectedSuccess && !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("validateSystemdCredentialMetadata() error = %v, want ErrKeyInvalid", err)
	}
}
