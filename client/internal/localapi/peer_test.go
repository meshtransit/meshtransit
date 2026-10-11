//go:build linux || darwin

package localapi

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPeerFromConn(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socketPath)
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			acceptErr <- err

			return
		}
		accepted <- connection
	}()

	client, err := (&net.Dialer{}).DialContext(t.Context(), "unix", socketPath)
	if err != nil {
		t.Fatalf("net.Dial() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	var server net.Conn
	select {
	case server = <-accepted:
		t.Cleanup(func() { _ = server.Close() })
	case err := <-acceptErr:
		t.Fatalf("Accept() error = %v", err)
	case <-t.Context().Done():
		t.Fatalf("Accept() timeout = %v", t.Context().Err())
	}

	peer, err := peerFromConn(server)
	if err != nil {
		t.Fatalf("peerFromConn() error = %v", err)
	}
	if !peer.isPresent || !peer.isVerified {
		t.Fatalf("peer identity = %#v, want present and verified", peer)
	}
	if got, expected := peer.uid, testEffectiveUID(t); got != expected {
		t.Fatalf("peer uid = %d, want %d", got, expected)
	}
}

func testEffectiveUID(t *testing.T) uint32 {
	t.Helper()

	uid := os.Geteuid()
	if uid < 0 || uint64(uid) > uint64(^uint32(0)) {
		t.Fatalf("effective uid %d is outside uint32", uid)

		return 0
	}

	return uint32(uid)
}
