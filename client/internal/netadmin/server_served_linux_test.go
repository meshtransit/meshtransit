//go:build linux

package netadmin

import (
	"context"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/routesettings"
	"meshtransit.net/client/internal/socket"
)

type fakeServedConfigurer struct {
	mu      sync.Mutex
	entries []routesettings.ServedEntry
	self    []netip.Prefix
	cleared int
	noRoute map[netip.Prefix]bool
}

func (f *fakeServedConfigurer) ReplaceServed(_ string, self []netip.Prefix, _ int, entries []routesettings.ServedEntry) (
	[]routesettings.ServedEntry, []routesettings.Refusal, error,
) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var served []routesettings.ServedEntry
	var refused []routesettings.Refusal
	for _, entry := range entries {
		if f.noRoute[entry.Prefix] {
			refused = append(refused, routesettings.Refusal{Prefix: entry.Prefix, Reason: ReasonNoRoute})
			continue
		}
		served = append(served, entry)
	}
	f.entries, f.self = served, slices.Clone(self)
	return served, refused, nil
}

func (f *fakeServedConfigurer) Present() (bool, error) { return true, nil }

func (f *fakeServedConfigurer) Clear() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = nil
	f.cleared++
	return nil
}

func (f *fakeServedConfigurer) state() []routesettings.ServedEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.entries)
}

func TestClientServerServesOnlyWhatTheHostOffers(t *testing.T) {
	t.Parallel()
	settings := routesettings.Settings{RouterMode: true, AdvertiseRoutes: []netip.Prefix{
		netip.MustParsePrefix("10.35.0.0/17"), netip.MustParsePrefix("10.37.0.0/24"),
	}}
	var settingsMu sync.Mutex
	server, err := newServer(ServerOptions{
		AllowedUID: testEffectiveUID(t), InterfaceName: "mesh0", MTU: 1280,
		AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		Routed: &RoutedOptions{
			SettingsPath: "/etc/meshtransit/routes.json", Table: 5267, Priority: 5400,
			NftTable: "meshtransit", StatePath: "/run/meshnetd/router-state.json",
		},
		Logger: slog.New(slog.DiscardHandler),
	}, &fakeTUNCreator{})
	if err != nil {
		t.Fatal(err)
	}
	configurer := &fakeServedConfigurer{noRoute: map[netip.Prefix]bool{netip.MustParsePrefix("10.37.0.0/24"): true}}
	server.servedConfigurer = configurer
	server.loadSettings = func(string) (routesettings.Settings, error) {
		settingsMu.Lock()
		defer settingsMu.Unlock()
		return settings, nil
	}
	path := filepath.Join(t.TempDir(), "meshnetd.sock")
	listener, err := socket.ListenPacket(path)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	requested := []netip.Prefix{
		netip.MustParsePrefix("10.35.0.0/16"), netip.MustParsePrefix("10.36.0.0/24"),
		netip.MustParsePrefix("10.37.0.0/24"),
	}
	if _, err := client.SetServedRoutes(t.Context(), requested, nil); err == nil {
		t.Fatal("served routes before the tun interface were accepted")
	}
	tun, err := client.OpenTUN(t.Context(), TUNConfig{
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")},
		Routes:    []netip.Prefix{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tun.File.Close() })
	served, err := client.SetServedRoutes(t.Context(), requested, []netip.Prefix{netip.MustParsePrefix("10.37.0.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	// Only the offered part of 10.35.0.0/16 is served; 10.36 is not
	// offered; 10.37 has no route out.
	if !slices.Equal(served.Installed, []netip.Prefix{netip.MustParsePrefix("10.35.0.0/17")}) || served.RefusedTotal != 2 {
		t.Fatalf("SetServedRoutes() = %+v", served)
	}
	reasons := map[string]string{}
	for _, refusal := range served.Refused {
		reasons[refusal.Prefix.String()] = refusal.Reason
	}
	if reasons["10.36.0.0/24"] != routesettings.ReasonNotAdvertised || reasons["10.37.0.0/24"] != ReasonNoRoute {
		t.Fatalf("refusals = %v", reasons)
	}
	if entries := configurer.state(); len(entries) != 1 || !entries[0].Masquerade {
		t.Fatalf("configured = %+v", entries)
	}
	// Router mode off stops forwarding for what meshd last asked.
	settingsMu.Lock()
	settings.RouterMode = false
	settingsMu.Unlock()
	server.mu.Lock()
	installed, refused, err := server.applyServed(*server.requestedServed)
	server.mu.Unlock()
	if err != nil || len(installed) != 0 || len(refused) != 3 || len(configurer.state()) != 0 {
		t.Fatalf("after router mode off: %v, %v, %v", installed, refused, err)
	}
}

func TestValidateServedRequest(t *testing.T) {
	t.Parallel()
	valid := request{
		Version: protocolVersion, Operation: operationSetServed, Routes: []string{"10.35.0.0/17"},
		Masquerade: "0",
	}
	if _, err := validateRequest(valid); err != nil {
		t.Fatalf("validateRequest(valid) error = %v", err)
	}
	for name, mutate := range map[string]func(*request){
		"flags miss a route": func(value *request) { value.Masquerade = "" },
		"unknown flag":       func(value *request) { value.Masquerade = "x" },
		"no routes":          func(value *request) { value.Routes = nil },
		"host bits":          func(value *request) { value.Routes = []string{"10.35.0.1/17"} },
		"addresses":          func(value *request) { value.Addresses = []string{} },
	} {
		value := valid
		mutate(&value)
		if _, err := validateRequest(value); err == nil {
			t.Errorf("%s: validateRequest() accepted %+v", name, value)
		}
	}
	routed := request{
		Version: protocolVersion, Operation: operationSetRouted, Routes: []string{},
		Masquerade: "0",
	}
	if _, err := validateRequest(routed); err == nil {
		t.Error("a routed request with served fields was accepted")
	}
}

// The largest served set, 4,096 IPv6 prefixes of the longest form, fits one
// message each way.
func TestClientServerCarriesTheLargestServedSet(t *testing.T) {
	t.Parallel()
	settings := routesettings.Settings{RouterMode: true, AdvertiseRoutes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}}
	server, err := newServer(ServerOptions{
		AllowedUID: testEffectiveUID(t), InterfaceName: "mesh0", MTU: 1280,
		AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		Routed: &RoutedOptions{
			SettingsPath: "/etc/meshtransit/routes.json", Table: 5267, Priority: 5400,
			NftTable: "meshtransit", StatePath: "/run/meshnetd/router-state.json",
		},
		Logger: slog.New(slog.DiscardHandler),
	}, &fakeTUNCreator{})
	if err != nil {
		t.Fatal(err)
	}
	server.servedConfigurer = &fakeServedConfigurer{}
	server.loadSettings = func(string) (routesettings.Settings, error) { return settings, nil }
	path := filepath.Join(t.TempDir(), "meshnetd.sock")
	listener, err := socket.ListenPacket(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		<-result
	})
	client, err := NewClient(path, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tun, err := client.OpenTUN(t.Context(), TUNConfig{
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")},
		Routes:    []netip.Prefix{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tun.File.Close() })
	served := make([]netip.Prefix, 0, routesettings.MaximumRoutes)
	for index := range routesettings.MaximumRoutes {
		address := netip.MustParseAddr("2001:db8:ffff:ffff:ffff:ffff:ffff:0").As16()
		address[14], address[15] = 0xe0|byte(index>>7), byte(index<<1)
		served = append(served, netip.PrefixFrom(netip.AddrFrom16(address), 127))
	}
	installed, err := client.SetServedRoutes(t.Context(), served, served[:10])
	if err != nil {
		t.Fatalf("SetServedRoutes(4096 IPv6) error = %v", err)
	}
	if len(installed.Installed) != routesettings.MaximumRoutes {
		t.Fatalf("installed %d of %d", len(installed.Installed), routesettings.MaximumRoutes)
	}
}
