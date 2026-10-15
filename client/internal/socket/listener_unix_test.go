//go:build !windows

package socket

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestListen(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "meshd.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if got := listener.Addr().Network(); got != "unix" {
		t.Fatalf("listener network = %q, want unix", got)
	}

	connection, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestListenRefusesRegularFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "meshnetd.sock")
	if err := os.WriteFile(path, []byte("occupied"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := Listen(path); err == nil {
		t.Fatal("Listen() error = nil, want occupied-path error")
	}
}

func TestListenDoesNotCreateParentDirectories(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing")
	if listener, err := Listen(filepath.Join(missing, "meshd", "meshd.sock")); err == nil {
		_ = listener.Close()
		t.Fatal("Listen() created a socket under a missing parent")
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("Listen() created the missing parent: %v", err)
	}
}
