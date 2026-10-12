//go:build integration && darwin

package netadmin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestKernelUTUNSurvivesTheHelperSocket opens utuns through a real meshnetd
// server and netadmin client, so each descriptor travels by SCM_RIGHTS while
// the helper closes its own copy and the connection, as in production. A
// healthy idle utun answers a nonblocking read with EAGAIN; one whose receive
// side was shut answers with 0 bytes at once. Needs root:
//
//	sudo go test -tags=integration -run TestKernelUTUNSurvivesTheHelperSocket -v ./internal/netadmin/
func TestKernelUTUNSurvivesTheHelperSocket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating utun interfaces needs root")
	}
	server, err := NewServer(ServerOptions{
		MTU:             1280,
		AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.127.250.0/24")},
		Logger:          slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	socketPath := fmt.Sprintf("/tmp/mt-netadmin-%d.sock", os.Getpid())
	_ = os.Remove(socketPath)
	listener, err := net.Listen(helperNetwork, socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = server.Serve(ctx, listener)
	}()
	t.Cleanup(func() {
		cancel()
		<-served
	})
	client, err := NewClient(socketPath, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	attempts := 40
	if value, err := strconv.Atoi(os.Getenv("MESHTRANSIT_UTUN_HANDOFFS")); err == nil && value > 0 {
		attempts = value
	}
	config := TUNConfig{
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.127.250.21/32")},
		Routes:    []netip.Prefix{netip.MustParsePrefix("100.127.250.22/32")},
	}
	shut := 0
	for attempt := range attempts {
		tun, err := client.OpenTUN(ctx, config)
		if err != nil {
			t.Fatalf("attempt %d: OpenTUN() error = %v", attempt, err)
		}
		state := probeUTUN(t, tun.File)
		if state != "idle" {
			shut++
			t.Errorf("attempt %d: %s %s", attempt, tun.Name, state)
		}
		_ = tun.File.Close()
		waitForLinkGone(tun.Name)
	}
	t.Logf("%d of %d utuns arrived with their receive side shut", shut, attempts)
}

// probeUTUN reads once without blocking: "idle" for EAGAIN, otherwise what
// came back.
func probeUTUN(t *testing.T, file *os.File) string {
	t.Helper()
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	state := ""
	buffer := make([]byte, 2048)
	if err := raw.Control(func(descriptor uintptr) {
		size, readErr := unix.Read(int(descriptor), buffer)
		queued, _ := unix.GetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_NREAD)
		switch {
		case errors.Is(readErr, unix.EAGAIN):
			state = "idle"
		case readErr != nil:
			state = fmt.Sprintf("read error %v (%d bytes queued)", readErr, queued)
		case size == 0:
			state = fmt.Sprintf("read 0 bytes (%d bytes queued): receive side shut", queued)
		default:
			state = "idle" // a packet the kernel sent (IPv6 or similar)
		}
	}); err != nil {
		t.Fatal(err)
	}
	return state
}

func waitForLinkGone(name string) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := net.InterfaceByName(name); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}
