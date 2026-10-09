//go:build linux

package socket

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestListenPacket(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "meshnetd.sock")
	listener, err := ListenPacket(path)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if got := listener.Addr().Network(); got != "unixpacket" {
		t.Fatalf("listener network = %q, want unixpacket", got)
	}

	connection, err := (&net.Dialer{}).DialContext(t.Context(), "unixpacket", path)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestListenPacketRefusesRegularFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "meshnetd.sock")
	if err := os.WriteFile(path, []byte("occupied"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := ListenPacket(path); err == nil {
		t.Fatal("ListenPacket() error = nil, want occupied-path error")
	}
}
