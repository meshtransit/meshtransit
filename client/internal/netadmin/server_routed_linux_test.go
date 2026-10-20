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

type fakeRoutedConfigurer struct {
	mu      sync.Mutex
	calls   int
	current []netip.Prefix
	desired []netip.Prefix
	throws  []netip.Prefix
	uid     uint32
}

type fakeHostRouting struct {
	local     []LocalRoute
	resolvers []netip.Addr
	err       error
}

// state returns what the configurer last recorded.
func (f *fakeRoutedConfigurer) state() (current, desired, throws []netip.Prefix, uid uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.current), slices.Clone(f.desired), slices.Clone(f.throws), f.uid
}

func (f fakeHostRouting) LocalRoutes(string) ([]LocalRoute, error) {
	return slices.Clone(f.local), f.err
}

func (f fakeHostRouting) Resolvers() []netip.Addr { return slices.Clone(f.resolvers) }

func (f *fakeRoutedConfigurer) Clear(RoutedOptions, uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.current, f.desired, f.throws = nil, nil, nil
	return nil
}

func (f *fakeRoutedConfigurer) ReplaceRouted(_ string, _ RoutedOptions, uid uint32, current, desired routedState) (
	routedState, []routesettings.Refusal, error,
) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.current, f.desired, f.throws = slices.Clone(current.Routes), slices.Clone(desired.Routes), slices.Clone(desired.Throws)
	f.uid = uid
	return desired, nil, nil
}

func TestClientServerSetsRoutedRoutesAsSettingsAdmit(t *testing.T) {
	t.Parallel()
	settings := routesettings.Settings{AcceptRoutes: true}
	var settingsMu sync.Mutex
	server, err := newServer(ServerOptions{
		AllowedUID: testEffectiveUID(t), InterfaceName: "mesh0", MTU: 1280,
		AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		Routed:          &RoutedOptions{SettingsPath: "/etc/meshtransit/routes.json", Table: 5267, Priority: 5400},
		Logger:          slog.New(slog.DiscardHandler),
	}, &fakeTUNCreator{})
	if err != nil {
		t.Fatal(err)
	}
	configurer := &fakeRoutedConfigurer{}
	server.routedConfigurer = configurer
	server.hostRouting = fakeHostRouting{
		local: []LocalRoute{
			{Prefix: netip.MustParsePrefix("192.168.1.0/24"), Connected: true},
			{Prefix: netip.MustParsePrefix("10.30.5.0/24")},
		},
		resolvers: []netip.Addr{netip.MustParseAddr("10.20.0.53"), netip.MustParseAddr("192.168.1.1")},
	}
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
		netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("8.8.8.0/24"),
		netip.MustParsePrefix("100.64.1.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("10.30.0.0/16"),
	}
	if _, err := client.SetRoutedRoutes(t.Context(), requested); err == nil {
		t.Fatal("routed routes before the tun interface were accepted")
	}
	tun, err := client.OpenTUN(t.Context(), TUNConfig{
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")},
		Routes:    []netip.Prefix{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tun.File.Close() })
	installed, err := client.SetRoutedRoutes(t.Context(), requested)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(installed.Installed, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}) ||
		len(installed.Refused) != 4 {
		t.Fatalf("SetRoutedRoutes() = %+v", installed)
	}
	reasons := map[string]string{}
	for _, refusal := range installed.Refused {
		reasons[refusal.Prefix.String()] = refusal.Reason
	}
	if reasons["8.8.8.0/24"] != routesettings.ReasonPublic || reasons["100.64.1.0/24"] != routesettings.ReasonReserved ||
		reasons["192.168.0.0/16"] != routesettings.ReasonLocalConflict || reasons["10.30.0.0/16"] != routesettings.ReasonLocalConflict {
		t.Fatalf("refusals = %v", reasons)
	}
	_, desired, throws, uid := configurer.state()
	if uid != testEffectiveUID(t) || !slices.Equal(desired, installed.Installed) ||
		!slices.Equal(throws, []netip.Prefix{netip.MustParsePrefix("10.20.0.53/32")}) {
		t.Fatalf("configurer = %v %v %d", desired, throws, uid)
	}
	// Routes off: thousands refused still fit one response, counted.
	settingsMu.Lock()
	settings = routesettings.Settings{}
	settingsMu.Unlock()
	many := make([]netip.Prefix, 0, routesettings.MaximumRoutes)
	for index := range routesettings.MaximumRoutes {
		many = append(many, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(index >> 8), byte(index), 0}), 24))
	}
	if refusedAll, err := client.SetRoutedRoutes(t.Context(), many); err != nil ||
		len(refusedAll.Installed) != 0 || refusedAll.RefusedTotal != len(many) || len(refusedAll.Refused) != 64 {
		t.Fatalf("SetRoutedRoutes(4096, off) = %d installed, %d listed of %d, error %v",
			len(refusedAll.Installed), len(refusedAll.Refused), refusedAll.RefusedTotal, err)
	}
	settingsMu.Lock()
	settings = routesettings.Settings{AcceptRoutes: true}
	settingsMu.Unlock()
	if _, err := client.SetRoutedRoutes(t.Context(), requested); err != nil {
		t.Fatal(err)
	}
	// Turning routes off removes them at once for what meshd last asked.
	settingsMu.Lock()
	settings = routesettings.Settings{}
	settingsMu.Unlock()
	server.mu.Lock()
	if _, _, err := server.applyRouted(server.requestedRouted); err != nil {
		t.Fatal(err)
	}
	server.mu.Unlock()
	if current, desired, _, _ := configurer.state(); len(desired) != 0 || !slices.Equal(current, installed.Installed) {
		t.Fatalf("after routes off configurer = %v %v", current, desired)
	}
}

func TestNewServerRejectsUnsafeRoutedOptions(t *testing.T) {
	t.Parallel()
	for _, options := range []RoutedOptions{
		{SettingsPath: "", Table: 5267, Priority: 5400},
		{SettingsPath: "/etc/x", Table: 254, Priority: 5400},
		{SettingsPath: "/etc/x", Table: 0, Priority: 5400},
		{SettingsPath: "/etc/x", Table: 5267, Priority: 32766},
	} {
		if _, err := newServer(ServerOptions{
			AllowedUID: testEffectiveUID(t), InterfaceName: "mesh0", MTU: 1280,
			AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}, Routed: &options,
			Logger: slog.New(slog.DiscardHandler),
		}, &fakeTUNCreator{}); err == nil {
			t.Errorf("routed options %+v were accepted", options)
		}
	}
}

func TestApplyRoutedRefusesEverythingWhenLocalRoutesAreUnknown(t *testing.T) {
	t.Parallel()
	server, err := newServer(ServerOptions{
		AllowedUID: testEffectiveUID(t), InterfaceName: "mesh0", MTU: 1280,
		AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		Routed:          &RoutedOptions{SettingsPath: "/etc/meshtransit/routes.json", Table: 5267, Priority: 5400},
		Logger:          slog.New(slog.DiscardHandler),
	}, &fakeTUNCreator{})
	if err != nil {
		t.Fatal(err)
	}
	configurer := &fakeRoutedConfigurer{}
	server.routedConfigurer = configurer
	server.hostRouting = fakeHostRouting{err: errTooManyLocalRoutes}
	server.loadSettings = func(string) (routesettings.Settings, error) {
		return routesettings.Settings{AcceptRoutes: true}, nil
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	accepted, refused, err := server.applyRouted([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	_, desired, _, _ := configurer.state()
	if len(accepted) != 0 || len(refused) != 1 ||
		refused[0].Reason != routesettings.ReasonLocalConflict || len(desired) != 0 {
		t.Fatalf("applyRouted() = %v, %v; configurer desired %v", accepted, refused, desired)
	}
}
