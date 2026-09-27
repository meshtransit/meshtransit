//go:build linux || darwin

package relayfile

import (
	"crypto/sha256"
	"errors"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLoadRejectsFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "relay-directory.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo() error = %v", err)
	}
	if _, err := Load(t.Context(), path, [sha256.Size]byte{1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load(fifo) error = %v, want ErrInvalid", err)
	}
}
