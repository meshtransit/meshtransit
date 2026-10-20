//go:build linux

package netadmin

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/routesettings"
	"meshtransit.net/client/internal/socket"
)

// fakeExitRouteConfigurer records what the helper installs.
type fakeExitRouteConfigurer struct {
	mu       sync.Mutex
	replaced []string
	clears   int
	present  bool
	fail     error
}

func (f *fakeExitRouteConfigurer) Replace(name string, ipv6, allowLAN bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.replaced = append(f.replaced, name+map[bool]string{true: " ipv6", false: ""}[ipv6]+
		map[bool]string{true: " lan", false: ""}[allowLAN])
	f.present = true
	return nil
}

func (f *fakeExitRouteConfigurer) Present() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.present, nil
}

func (*fakeExitRouteConfigurer) Stamp(string) string { return "" }

func (f *fakeExitRouteConfigurer) Clear() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clears++
	f.present = false
	return nil
}

func (f *fakeExitRouteConfigurer) state() ([]string, int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.replaced...), f.clears, f.present
}

// The helper routes the host through an exit node only while root's
// settings name one to use, and removes the route and kill switch once
// they no longer do or meshd asks it to stop.
func TestClientServerExitRouteFollowsTheHostSettings(t *testing.T) {
	t.Parallel()
	settings := routesettings.Settings{}
	var settingsMu sync.Mutex
	setSettings := func(value routesettings.Settings) {
		settingsMu.Lock()
		defer settingsMu.Unlock()
		settings = value
	}
	server, err := newServer(ServerOptions{
		AllowedUID: testEffectiveUID(t), InterfaceName: "mesh0", MTU: 1280,
		AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		Routed: &RoutedOptions{
			SettingsPath: "/etc/meshtransit/routes.json", Table: 5267, Priority: 5400,
			ExitTable: 5268, ExitPriority: 5402, ExitNftTable: "meshtransit_exit",
		},
		Logger: slog.New(slog.DiscardHandler),
	}, &fakeTUNCreator{})
	if err != nil {
		t.Fatal(err)
	}
	configurer := &fakeExitRouteConfigurer{}
	server.exitRouteConfigurer = configurer
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
	use := ExitRouteRequest{Use: true, IPv6: true}
	if _, err := client.SetExitRoute(t.Context(), use); err == nil {
		t.Fatal("an exit route before the tun interface was accepted")
	}
	tun, err := client.OpenTUN(t.Context(), TUNConfig{
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")}, Routes: []netip.Prefix{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tun.File.Close() })

	// Root has not chosen an exit node: nothing is installed.
	routing, err := client.SetExitRoute(t.Context(), use)
	if err != nil || routing != (ExitRouting{Refused: ExitRouteRefusedOff}) {
		t.Fatalf("SetExitRoute() without the setting = %+v, %v", routing, err)
	}
	if replaced, _, present := configurer.state(); len(replaced) != 0 || present {
		t.Fatalf("installed without the setting: %v", replaced)
	}

	setSettings(routesettings.Settings{ExitUse: "pool", ExitAllowLAN: true})
	routing, err = client.SetExitRoute(t.Context(), use)
	if err != nil || !routing.Routing {
		t.Fatalf("SetExitRoute() = %+v, %v", routing, err)
	}
	if replaced, _, _ := configurer.state(); len(replaced) != 1 || replaced[0] != "mesh0 ipv6 lan" {
		t.Fatalf("installed %v", replaced)
	}

	// Root turns the exit off: the next settings check removes everything.
	setSettings(routesettings.Settings{})
	server.mu.Lock()
	server.applyExitRoute()
	server.mu.Unlock()
	if _, clears, present := configurer.state(); present || clears == 0 {
		t.Fatal("the exit route outlived the setting")
	}

	// While root names a pool, meshd cannot lift the kill switch.
	setSettings(routesettings.Settings{ExitUse: "pool"})
	if _, err := client.SetExitRoute(t.Context(), use); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SetExitRoute(t.Context(), ExitRouteRequest{}); err != nil {
		t.Fatal(err)
	}
	if replaced, _, present := configurer.state(); !present || replaced[len(replaced)-1] != "mesh0" {
		t.Fatalf("meshd lifted root's exit route: %v, present %t", replaced, present)
	}

	// A host following managed pools follows meshd.
	setSettings(routesettings.Settings{ExitAllowManaged: true})
	if routing, err := client.SetExitRoute(t.Context(), use); err != nil || !routing.Routing {
		t.Fatalf("SetExitRoute() with managed exits = %+v, %v", routing, err)
	}
	routing, err = client.SetExitRoute(t.Context(), ExitRouteRequest{})
	if err != nil || routing != (ExitRouting{}) {
		t.Fatalf("stopping = %+v, %v", routing, err)
	}
	if _, _, present := configurer.state(); present {
		t.Fatal("stopping left the kill switch")
	}
}

// A kill switch another tool removed is installed again; a failed install
// is reported and keeps what is there.
func TestServerRepairsTheExitKillSwitch(t *testing.T) {
	t.Parallel()
	server, err := newServer(ServerOptions{
		AllowedUID: testEffectiveUID(t), InterfaceName: "mesh0", MTU: 1280,
		AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		Routed: &RoutedOptions{
			SettingsPath: "/etc/meshtransit/routes.json", Table: 5267, Priority: 5400,
			ExitTable: 5268, ExitPriority: 5402, ExitNftTable: "meshtransit_exit",
		},
		Logger: slog.New(slog.DiscardHandler),
	}, &fakeTUNCreator{})
	if err != nil {
		t.Fatal(err)
	}
	configurer := &fakeExitRouteConfigurer{}
	server.exitRouteConfigurer = configurer
	server.loadSettings = func(string) (routesettings.Settings, error) {
		return routesettings.Settings{ExitUse: routesettings.ExitUseAuto}, nil
	}
	server.hasActiveTUN, server.activeName = true, "mesh0"
	server.requestedExitRoute = &ExitRouteRequest{Use: true}
	server.applyExitRoute()
	configurer.mu.Lock()
	configurer.present = false
	configurer.mu.Unlock()
	server.checkExitRoute()
	if replaced, _, present := configurer.state(); len(replaced) != 2 || !present {
		t.Fatalf("repair installed %v", replaced)
	}
	configurer.mu.Lock()
	configurer.fail = errors.New("nft refused")
	configurer.mu.Unlock()
	server.exitRouteKey = "" // the host changed
	server.applyExitRoute()
	if server.activeExitRoute != (ExitRouting{Refused: ExitRouteRefusedFailed}) {
		t.Fatalf("after a failed install: %+v", server.activeExitRoute)
	}
	if _, clears, _ := configurer.state(); clears != 0 {
		t.Fatal("a failed install removed the kill switch")
	}
}

func TestValidateExitRouteOptions(t *testing.T) {
	t.Parallel()
	base := RoutedOptions{SettingsPath: "/etc/meshtransit/routes.json", Table: 5267, Priority: 5400}
	cases := []struct {
		name  string
		edit  func(*RoutedOptions)
		valid bool
	}{
		{"none", func(*RoutedOptions) {}, true},
		{"set", func(o *RoutedOptions) { o.ExitTable, o.ExitPriority, o.ExitNftTable = 5268, 5402, "meshtransit_exit" }, true},
		{"same table", func(o *RoutedOptions) { o.ExitTable, o.ExitPriority, o.ExitNftTable = 5267, 5402, "x" }, false},
		{"before routed rule", func(o *RoutedOptions) { o.ExitTable, o.ExitPriority, o.ExitNftTable = 5268, 5399, "x" }, false},
		{"router's nft table", func(o *RoutedOptions) {
			o.NftTable, o.StatePath = "meshtransit", "/run/state.json"
			o.ExitTable, o.ExitPriority, o.ExitNftTable = 5268, 5402, "meshtransit"
		}, false},
		{"priority without table", func(o *RoutedOptions) { o.ExitPriority = 5402 }, false},
		{"main table", func(o *RoutedOptions) { o.ExitTable, o.ExitPriority, o.ExitNftTable = 254, 5402, "x" }, false},
	}
	for _, test := range cases {
		options := base
		test.edit(&options)
		if got := validRoutedOptions(options); got != test.valid {
			t.Errorf("%s: valid = %t, want %t", test.name, got, test.valid)
		}
	}
}

func TestValidateExitRouteRequests(t *testing.T) {
	t.Parallel()
	valid, err := validateRequest(request{
		Version: protocolVersion, Operation: operationSetExitRoute,
		ExitRoute: true, ExitRouteIPv6: true,
	})
	if err != nil || valid.exitRoute != (ExitRouteRequest{Use: true, IPv6: true}) {
		t.Fatalf("valid request = %+v, %v", valid, err)
	}
	for name, value := range map[string]request{
		"ipv6 alone":  {Version: protocolVersion, Operation: operationSetExitRoute, ExitRouteIPv6: true},
		"routes":      {Version: protocolVersion, Operation: operationSetExitRoute, Routes: []string{}},
		"other op":    {Version: protocolVersion, Operation: operationCheckServed, ExitRoute: true},
		"exit fields": {Version: protocolVersion, Operation: operationSetExitRoute, Exit: true},
	} {
		if _, err := validateRequest(value); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, value := range map[string]response{
		"refused while routing": {Version: protocolVersion, OK: true, ExitRouting: true, ExitRouteRefused: ExitRouteRefusedOff},
		"unknown reason":        {Version: protocolVersion, OK: true, ExitRouteRefused: "maybe"},
	} {
		if err := validateResponse(value, operationSetExitRoute); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := validateResponse(response{Version: protocolVersion, OK: true, ExitRouting: true},
		operationCheckServed); err == nil {
		t.Error("exit route fields on another operation were accepted")
	}
}

// The kill switch outlives the helper while root names a pool: a new helper
// keeps it, before meshd or its TUN, and one that stops leaves it.
func TestServerKeepsTheExitKillSwitchAcrossRestarts(t *testing.T) {
	t.Parallel()
	settings := routesettings.Settings{ExitUse: "pool"}
	server, err := newServer(ServerOptions{
		AllowedUID: testEffectiveUID(t), InterfaceName: "mesh0", MTU: 1280,
		AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		Routed: &RoutedOptions{
			SettingsPath: "/etc/meshtransit/routes.json", Table: 5267, Priority: 5400,
			ExitTable: 5268, ExitPriority: 5402, ExitNftTable: "meshtransit_exit",
		},
		Logger: slog.New(slog.DiscardHandler),
	}, &fakeTUNCreator{})
	if err != nil {
		t.Fatal(err)
	}
	configurer := &fakeExitRouteConfigurer{}
	server.exitRouteConfigurer = configurer
	server.loadSettings = func(string) (routesettings.Settings, error) { return settings, nil }
	if err := server.startExitRoute(); err != nil {
		t.Fatal(err)
	}
	if replaced, clears, present := configurer.state(); len(replaced) != 1 || replaced[0] != "" || clears != 0 ||
		!present {
		t.Fatalf("start with a pool named: %v, clears %d", replaced, clears)
	}
	server.stopExitRoute()
	if _, clears, present := configurer.state(); clears != 0 || !present {
		t.Fatal("a stopping helper lifted root's kill switch")
	}
	// Unreadable settings change nothing.
	server.loadSettings = func(string) (routesettings.Settings, error) { return settings, errors.New("unreadable") }
	server.applyExitRoute()
	server.stopExitRoute()
	if _, clears, _ := configurer.state(); clears != 0 {
		t.Fatal("unreadable settings lifted the kill switch")
	}
	// Root turns it off: a new helper starts clean.
	server.loadSettings = func(string) (routesettings.Settings, error) { return routesettings.Settings{}, nil }
	if err := server.startExitRoute(); err != nil {
		t.Fatal(err)
	}
	if _, clears, present := configurer.state(); clears != 1 || present {
		t.Fatal("a helper kept a kill switch nobody wants")
	}
}
