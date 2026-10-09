//go:build linux || darwin

package config

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
)

func TestReadPrivateIdentityKeyDoesNotBlockOnFIFO(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "key")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := (SecretFile{path: path}).readPrivateIdentityKey(t.Context())
	if !errors.Is(err, ErrInvalid) || key != ([32]byte{}) {
		t.Fatal("fifo admitted")
	}
}
