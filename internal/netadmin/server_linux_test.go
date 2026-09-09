//go:build linux

package netadmin

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/meshtransit/meshd/internal/socket"
)

func TestNewServerRejectsUnsafeAllowedPrefixes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		prefixes []netip.Prefix
	}{
		{name: "missing allowlist", prefixes: []netip.Prefix{}},
		{
			name:     "non-canonical pool",
			prefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/10")},
		},
		{
			name:     "overly broad pool",
			prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/7")},
		},
		{
			name: "overlapping pools",
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.0/10"),
				netip.MustParsePrefix("100.64.0.0/24"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := newServer(ServerOptions{
				AllowedUID:      testEffectiveUID(t),
				InterfaceName:   "mesh0",
				MTU:             1280,
				AllowedPrefixes: test.prefixes,
				Logger:          slog.New(slog.DiscardHandler),
			}, &fakeTUNCreator{})
			if err == nil {
				t.Fatal("newServer() error = nil")
			}
		})
	}
}

func TestClientServerOpenTUN(t *testing.T) {
	t.Parallel()

	creator := &fakeTUNCreator{}
	address := netip.MustParsePrefix("100.64.0.3/32")
	route := netip.MustParsePrefix("100.64.0.4/32")
	server, err := newServer(ServerOptions{
		AllowedUID:      testEffectiveUID(t),
		InterfaceName:   "mesh0",
		MTU:             1280,
		AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		Logger:          slog.New(slog.DiscardHandler),
	}, creator)
	if err != nil {
		t.Fatalf("newServer() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "meshnetd.sock")
	listener, err := socket.ListenPacket(path)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		<-result
	})

	client, err := NewClient(path, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	tun, err := client.OpenTUN(t.Context(), TUNConfig{
		Addresses: []netip.Prefix{address},
		Routes:    []netip.Prefix{route},
	})
	if err != nil {
		t.Fatalf("OpenTUN() error = %v", err)
	}
	t.Cleanup(func() { _ = tun.File.Close() })
	if tun.Name != "mesh0" || tun.MTU != 1280 ||
		!slices.Equal(tun.Addresses, []netip.Prefix{address}) ||
		!slices.Equal(tun.Routes, []netip.Prefix{route}) {
		t.Fatalf("OpenTUN() = %#v", tun)
	}
	if creator.calls != 1 || !slices.Equal(creator.addresses, []netip.Prefix{address}) ||
		!slices.Equal(creator.routes, []netip.Prefix{route}) {
		t.Fatalf("creator config addresses=%v routes=%v calls=%d", creator.addresses, creator.routes, creator.calls)
	}

	if _, err := creator.writer.Write([]byte("packet")); err != nil {
		t.Fatalf("pipe Write() error = %v", err)
	}
	payload := make([]byte, len("packet"))
	if _, err := io.ReadFull(tun.File, payload); err != nil {
		t.Fatalf("received descriptor Read() error = %v", err)
	}
	if got := string(payload); got != "packet" {
		t.Fatalf("received payload = %q", got)
	}
	if err := creator.writer.Close(); err != nil {
		t.Fatalf("pipe writer Close() error = %v", err)
	}
}

func TestClientServerRejectsUnauthorizedUID(t *testing.T) {
	t.Parallel()

	server, err := newServer(ServerOptions{
		AllowedUID:      testEffectiveUID(t) ^ 1,
		InterfaceName:   "mesh0",
		MTU:             1280,
		AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		Logger:          slog.New(slog.DiscardHandler),
	}, &fakeTUNCreator{})
	if err != nil {
		t.Fatalf("newServer() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "meshnetd.sock")
	listener, err := socket.ListenPacket(path)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		<-result
	})

	client, err := NewClient(path, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if _, err := client.OpenTUN(t.Context(), TUNConfig{}); !errors.Is(err, ErrRemote) {
		t.Fatalf("OpenTUN() error = %v, want ErrRemote", err)
	}
}

func TestClientServerRejectsPrefixOutsideAllowlist(t *testing.T) {
	t.Parallel()

	creator := &fakeTUNCreator{}
	server, err := newServer(ServerOptions{
		AllowedUID:      testEffectiveUID(t),
		InterfaceName:   "mesh0",
		MTU:             1280,
		AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		Logger:          slog.New(slog.DiscardHandler),
	}, creator)
	if err != nil {
		t.Fatalf("newServer() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "meshnetd.sock")
	listener, err := socket.ListenPacket(path)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		<-result
	})

	client, err := NewClient(path, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = client.OpenTUN(t.Context(), TUNConfig{
		Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32")},
		Routes:    []netip.Prefix{},
	})
	if !errors.Is(err, ErrRemote) || creator.calls != 0 {
		t.Fatalf("OpenTUN() error = %v, creator calls = %d", err, creator.calls)
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

type fakeTUNCreator struct {
	calls     int
	writer    *os.File
	addresses []netip.Prefix
	routes    []netip.Prefix
}

func (f *fakeTUNCreator) Open(
	_ string,
	_ int,
	_ uint32,
	addresses []netip.Prefix,
	routes []netip.Prefix,
) (*os.File, error) {
	f.calls++
	f.addresses = append([]netip.Prefix{}, addresses...)
	f.routes = append([]netip.Prefix{}, routes...)
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	f.writer = writer

	return reader, nil
}
