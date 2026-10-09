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
	"sync"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/client/internal/socket"
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
			name:     "private LAN outside the overlay frame",
			prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		},
		{
			name:     "wider than the IPv6 overlay frame",
			prefixes: []netip.Prefix{netip.MustParsePrefix("fc00::/7")},
		},
		{
			name:     "global IPv6 outside the overlay frame",
			prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
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

func TestNewServerAcceptsTheWholeOverlayFrame(t *testing.T) {
	t.Parallel()

	server, err := newServer(ServerOptions{
		AllowedUID:      testEffectiveUID(t),
		InterfaceName:   "mesh0",
		MTU:             1280,
		AllowedPrefixes: SafeOverlayFrame(),
		Logger:          slog.New(slog.DiscardHandler),
	}, &fakeTUNCreator{})
	if err != nil {
		t.Fatalf("newServer() error = %v", err)
	}
	// A random Workspace ULA, a shared-Device alias and a CGNAT address all
	// fit without any per-Workspace configuration.
	config := TUNConfig{
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("100.64.0.7/32"),
			netip.MustParsePrefix("fdc3:91a0:5e12::7/128"),
		},
		Routes: []netip.Prefix{
			netip.MustParsePrefix("198.19.0.4/32"),
			netip.MustParsePrefix("fd02:48de:ec1b:2::4/128"),
		},
	}
	if err := validateAllowedTUNConfig(config, server.allowedPrefixes); err != nil {
		t.Fatalf("validateAllowedTUNConfig() error = %v", err)
	}
	outside := TUNConfig{Routes: []netip.Prefix{netip.MustParsePrefix("10.1.2.3/32")}}
	if err := validateAllowedTUNConfig(outside, server.allowedPrefixes); err == nil {
		t.Fatal("validateAllowedTUNConfig() accepted a route outside the overlay frame")
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
	creatorState := creator.snapshot()
	if creatorState.calls != 1 ||
		!slices.Equal(creatorState.addresses, []netip.Prefix{address}) ||
		!slices.Equal(creatorState.routes, []netip.Prefix{route}) {
		t.Fatalf(
			"creator config addresses=%v routes=%v calls=%d",
			creatorState.addresses,
			creatorState.routes,
			creatorState.calls,
		)
	}

	if _, err := creatorState.writer.Write([]byte("packet")); err != nil {
		t.Fatalf("pipe Write() error = %v", err)
	}
	payload := make([]byte, len("packet"))
	if _, err := io.ReadFull(tun.File, payload); err != nil {
		t.Fatalf("received descriptor Read() error = %v", err)
	}
	if got := string(payload); got != "packet" {
		t.Fatalf("received payload = %q", got)
	}
	if err := creatorState.writer.Close(); err != nil {
		t.Fatalf("pipe writer Close() error = %v", err)
	}
	newRoute := netip.MustParsePrefix("100.64.0.5/32")
	if err := client.ConfigureTUNRoutes(t.Context(), TUNConfig{
		Addresses: []netip.Prefix{address},
		Routes:    []netip.Prefix{newRoute},
	}); err != nil {
		t.Fatalf("ConfigureTUNRoutes() error = %v", err)
	}
	creatorState = creator.snapshot()
	if creatorState.updateCalls != 1 ||
		!slices.Equal(creatorState.previousRoutes, []netip.Prefix{route}) ||
		!slices.Equal(creatorState.routes, []netip.Prefix{newRoute}) {
		t.Fatalf(
			"route update calls=%d previous=%v routes=%v",
			creatorState.updateCalls,
			creatorState.previousRoutes,
			creatorState.routes,
		)
	}
}

func TestClientServerRejectsTUNRouteUpdateWithoutOwnedInterface(t *testing.T) {
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
	err = client.ConfigureTUNRoutes(t.Context(), TUNConfig{
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")},
		Routes:    []netip.Prefix{},
	})
	if !errors.Is(err, ErrRemote) || creator.snapshot().updateCalls != 0 {
		t.Fatalf("ConfigureTUNRoutes() error=%v updates=%d", err, creator.snapshot().updateCalls)
	}
}

func TestClientServerDNSLifecycle(t *testing.T) {
	t.Parallel()

	creator := &fakeTUNCreator{}
	configurator := &fakeDNSConfigurator{}
	endpoint := DNSEndpoint{
		InterfaceName: "meshdns0",
		Resolver:      netip.MustParseAddrPort("192.0.2.53:1053"),
	}
	server, err := newServerWithDNS(ServerOptions{
		AllowedUID:      testEffectiveUID(t),
		InterfaceName:   "mesh0",
		MTU:             1280,
		AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		DNS: &DNSOptions{
			InterfaceName: endpoint.InterfaceName,
			Resolver:      endpoint.Resolver,
		},
		Logger: slog.New(slog.DiscardHandler),
	}, creator, configurator)
	if err != nil {
		t.Fatalf("newServerWithDNS() error = %v", err)
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
	link, err := client.OpenDNS(t.Context())
	if err != nil {
		t.Fatalf("OpenDNS() error = %v", err)
	}
	t.Cleanup(func() { _ = link.File.Close() })
	if link.Endpoint != endpoint || link.File == nil {
		t.Fatalf("OpenDNS() = %#v", link)
	}
	config := DNSConfig{
		Endpoint:      endpoint,
		SearchDomains: []string{"mesh.example"},
		RouteDomains:  []string{"64.100.in-addr.arpa", "mesh.example.internal"},
	}
	if err := client.ConfigureDNS(t.Context(), config); err != nil {
		t.Fatalf("ConfigureDNS() error = %v", err)
	}
	if err := client.ResetDNS(t.Context()); err != nil {
		t.Fatalf("ResetDNS() error = %v", err)
	}
	dnsState := configurator.snapshot()
	if dnsState.applyCalls != 1 || dnsState.resetCalls != 1 ||
		dnsState.config.Endpoint != endpoint {
		t.Fatalf(
			"dns calls apply=%d reset=%d config=%#v",
			dnsState.applyCalls,
			dnsState.resetCalls,
			dnsState.config,
		)
	}
	creatorState := creator.snapshot()
	if creatorState.calls != 1 || !slices.Equal(creatorState.addresses, []netip.Prefix{
		netip.MustParsePrefix("192.0.2.53/32"),
	}) {
		t.Fatalf("dns link calls=%d addresses=%v", creatorState.calls, creatorState.addresses)
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
	creatorState := creator.snapshot()
	if !errors.Is(err, ErrRemote) || creatorState.calls != 0 {
		t.Fatalf("OpenTUN() error = %v, creator calls = %d", err, creatorState.calls)
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
	mu             sync.Mutex
	calls          int
	updateCalls    int
	writer         *os.File
	addresses      []netip.Prefix
	previousRoutes []netip.Prefix
	routes         []netip.Prefix
}

type fakeTUNCreatorState struct {
	calls          int
	updateCalls    int
	writer         *os.File
	addresses      []netip.Prefix
	previousRoutes []netip.Prefix
	routes         []netip.Prefix
}

type fakeDNSConfigurator struct {
	mu         sync.Mutex
	applyCalls int
	resetCalls int
	config     DNSConfig
}

type fakeDNSConfiguratorState struct {
	applyCalls int
	resetCalls int
	config     DNSConfig
}

func (f *fakeDNSConfigurator) Apply(_ context.Context, config DNSConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.applyCalls++
	f.config = cloneDNSConfig(config)

	return nil
}

func (f *fakeDNSConfigurator) Reset(_ context.Context, _ DNSEndpoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.resetCalls++

	return nil
}

func (f *fakeDNSConfigurator) snapshot() fakeDNSConfiguratorState {
	f.mu.Lock()
	defer f.mu.Unlock()

	return fakeDNSConfiguratorState{
		applyCalls: f.applyCalls,
		resetCalls: f.resetCalls,
		config:     cloneDNSConfig(f.config),
	}
}

func (f *fakeTUNCreator) Open(
	_ string,
	_ int,
	_ uint32,
	addresses []netip.Prefix,
	routes []netip.Prefix,
) (*os.File, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.calls++
	f.addresses = append([]netip.Prefix{}, addresses...)
	f.routes = append([]netip.Prefix{}, routes...)
	f.writer = writer
	f.mu.Unlock()

	return reader, nil
}

func (f *fakeTUNCreator) ReplaceRoutes(
	_ string,
	current []netip.Prefix,
	desired []netip.Prefix,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updateCalls++
	f.previousRoutes = append([]netip.Prefix(nil), current...)
	f.routes = append([]netip.Prefix(nil), desired...)

	return nil
}

func (f *fakeTUNCreator) snapshot() fakeTUNCreatorState {
	f.mu.Lock()
	defer f.mu.Unlock()

	return fakeTUNCreatorState{
		calls:          f.calls,
		updateCalls:    f.updateCalls,
		writer:         f.writer,
		addresses:      append([]netip.Prefix{}, f.addresses...),
		previousRoutes: append([]netip.Prefix{}, f.previousRoutes...),
		routes:         append([]netip.Prefix{}, f.routes...),
	}
}

func cloneDNSConfig(config DNSConfig) DNSConfig {
	config.SearchDomains = append([]string{}, config.SearchDomains...)
	config.RouteDomains = append([]string{}, config.RouteDomains...)

	return config
}
