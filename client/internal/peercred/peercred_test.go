//go:build linux || darwin

package peercred

import (
	"net"
	"os"
	"testing"
)

func TestUIDReadsThePeer(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", directory+"/s")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- connection
		}
		close(accepted)
	}()
	client, err := (&net.Dialer{}).DialContext(t.Context(), "unix", directory+"/s")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = server.Close() })
	unixServer, ok := server.(*net.UnixConn)
	if !ok {
		t.Fatalf("accepted %T, want *net.UnixConn", server)
	}
	uid, err := UID(unixServer)
	if err != nil {
		t.Fatal(err)
	}
	if want := uint32(os.Geteuid()); uid != want { //nolint:gosec // uids are non-negative
		t.Fatalf("UID() = %d, want %d", uid, want)
	}
}
