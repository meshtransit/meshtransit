//go:build linux

package netadmin

import (
	"context"
	"log/slog"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/routesettings"
	"meshtransit.net/client/internal/socket"
)

// The helper forwards as an exit node only while the host's exit mode is on,
// with Core's limits narrowed by the host's, keeps Sites it serves, and
// stops at once when exit mode is turned off.
func TestClientServerExitNodeFollowsTheHostSettings(t *testing.T) {
	t.Parallel()
	settings := routesettings.Settings{
		ExitMode: false, ExitConntrackPerConsumerMax: 4096, RouterMode: true,
		AdvertiseRoutes: []netip.Prefix{netip.MustParsePrefix("10.35.0.0/17")},
	}
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
	configurer := &fakeServedConfigurer{}
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
	request := ExitRequest{
		Serve: true, ConntrackPerConsumer: 65536, SMTP: true,
		Excluded: []netip.Prefix{netip.MustParsePrefix("198.51.100.77/32")},
	}
	if _, err := client.SetServedExit(t.Context(), request); err == nil {
		t.Fatal("exit forwarding before the tun interface was accepted")
	}
	tun, err := client.OpenTUN(t.Context(), TUNConfig{
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")},
		Routes:    []netip.Prefix{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tun.File.Close() })
	if _, err := client.SetServedRoutes(t.Context(), []netip.Prefix{netip.MustParsePrefix("10.35.0.0/17")}, nil); err != nil {
		t.Fatal(err)
	}
	// Exit mode off: refused, and the Site still served.
	serving, err := client.SetServedExit(t.Context(), request)
	if err != nil || serving.Serving || serving.Refused != ExitRefusedOff || configurer.exitState() != nil ||
		len(configurer.state()) != 1 {
		t.Fatalf("exit with exit mode off = %+v, %v, configured %+v", serving, err, configurer.exitState())
	}
	settingsMu.Lock()
	settings.ExitMode = true
	settingsMu.Unlock()
	serving, err = client.SetServedExit(t.Context(), request)
	// The host's 4096 bounds Core's 65,536; SMTP needs the host too.
	if err != nil || !serving.Serving || serving.ConntrackPerConsumer != 4096 || serving.SMTP ||
		serving.MaxConsumers != routesettings.DefaultExitMaxConsumers {
		t.Fatalf("exit with exit mode on = %+v, %v", serving, err)
	}
	if exit := configurer.exitState(); exit == nil || exit.ConntrackPerConsumer != 4096 || exit.SMTP ||
		len(exit.Excluded) != 1 || len(configurer.state()) != 1 {
		t.Fatalf("configured exit = %+v", exit)
	}
	if health, err := client.CheckServedRoutes(t.Context()); err != nil || !health.Exit.Serving ||
		health.Exit.ConntrackPerConsumer != 4096 {
		t.Fatalf("CheckServedRoutes() exit = %+v, %v", health.Exit, err)
	}
	// Stopping keeps the Site.
	if serving, err := client.SetServedExit(t.Context(), ExitRequest{}); err != nil || serving.Serving ||
		serving.Refused != "" || configurer.exitState() != nil || len(configurer.state()) != 1 {
		t.Fatalf("stopping = %+v, %v", serving, err)
	}
}

func TestValidateExitRequest(t *testing.T) {
	t.Parallel()
	valid := request{
		Version: protocolVersion, Operation: operationSetServedExit, Exit: true, ExitConntrack: 4096,
		Routes: []string{"198.51.100.77/32"},
	}
	if validated, err := validateRequest(valid); err != nil || !validated.exit.Serve ||
		validated.exit.ConntrackPerConsumer != 4096 || len(validated.exit.Excluded) != 1 {
		t.Fatalf("validateRequest(valid) = %+v, %v", validated.exit, err)
	}
	stop := request{Version: protocolVersion, Operation: operationSetServedExit, Routes: []string{}}
	if validated, err := validateRequest(stop); err != nil || validated.exit.Serve {
		t.Fatalf("validateRequest(stop) = %+v, %v", validated.exit, err)
	}
	for name, change := range map[string]func(*request){
		"low limit":        func(value *request) { value.ExitConntrack = 10 },
		"a range":          func(value *request) { value.Routes = []string{"198.51.100.0/24"} },
		"not canonical":    func(value *request) { value.Routes = []string{"198.051.100.77/32"} },
		"no routes list":   func(value *request) { value.Routes = nil },
		"exit fields else": func(value *request) { value.Operation = operationSetServed },
		"stop with limits": func(value *request) { value.Exit = false },
	} {
		value := valid
		change(&value)
		if _, err := validateRequest(value); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, value := range map[string]response{
		"serving without limits": {Version: protocolVersion, OK: true, ExitServing: true},
		"unknown reason":         {Version: protocolVersion, OK: true, ExitRefused: "core_said_so"},
		"limits while stopped":   {Version: protocolVersion, OK: true, ExitConntrack: 4096},
	} {
		if err := validateResponse(value, operationSetServedExit); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := validateResponse(response{
		Version: protocolVersion, OK: true, Routes: []string{}, ExitServing: true,
		ExitConntrack: 4096, ExitMaxConsumers: 8,
	}, operationSetServed); err == nil {
		t.Error("exit fields on set_served_routes were accepted")
	}
}
