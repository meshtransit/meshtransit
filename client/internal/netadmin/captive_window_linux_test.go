//go:build linux

package netadmin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/captive"
	"meshtransit.net/client/internal/routesettings"
	"meshtransit.net/client/internal/socket"
)

// captiveHarness is a helper whose exit route uses a fake configurer, a
// window file in a temporary directory and a clock the test moves.
type captiveHarness struct {
	t          *testing.T
	server     *Server
	configurer *fakeExitRouteConfigurer
	client     *Client
	window     string
	mu         sync.Mutex
	now        time.Time
	settings   routesettings.Settings
}

func newCaptiveHarness(t *testing.T) *captiveHarness {
	t.Helper()
	h := &captiveHarness{
		t: t, now: time.Date(2026, time.October, 21, 23, 0, 0, 0, time.UTC),
		settings: routesettings.Settings{ExitUse: "World"},
		window:   filepath.Join(t.TempDir(), "captive.json"),
	}
	server, err := newServer(ServerOptions{
		AllowedUID: testEffectiveUID(t), InterfaceName: "mesh0", MTU: 1280,
		AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		Routed: &RoutedOptions{
			SettingsPath: "/etc/meshtransit/routes.json", Table: 5267, Priority: 5400,
			ExitTable: 5268, ExitPriority: 5402, ExitNftTable: "meshtransit_exit", CaptiveWindowPath: h.window,
		},
		Logger: slog.New(slog.DiscardHandler),
	}, &fakeTUNCreator{})
	if err != nil {
		t.Fatal(err)
	}
	h.server, h.configurer = server, &fakeExitRouteConfigurer{}
	server.exitRouteConfigurer = h.configurer
	server.loadSettings = func(string) (routesettings.Settings, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.settings, nil
	}
	server.captiveNow = func() time.Time {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.now
	}
	// The test's files are not root's: read them as the helper would.
	server.readWindow = func(path string) (captive.Window, error) {
		encoded, err := os.ReadFile(path) //nolint:gosec // the test's own file
		if err != nil {
			return captive.Window{}, err
		}
		var window captive.Window
		if err := json.Unmarshal(encoded, &window); err != nil {
			return captive.Window{}, captive.ErrWindowInvalid
		}
		return window, nil
	}
	socketPath := filepath.Join(t.TempDir(), "meshnetd.sock")
	listener, err := socket.ListenPacket(socketPath)
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
	if h.client, err = NewClient(socketPath, time.Second); err != nil {
		t.Fatal(err)
	}
	tun, err := h.client.OpenTUN(t.Context(), TUNConfig{
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")}, Routes: []netip.Prefix{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tun.File.Close() })
	if routing := h.ask(ExitRouteRequest{Use: true}); !routing.Routing {
		t.Fatalf("exit route not installed: %+v", routing)
	}
	return h
}

func (h *captiveHarness) ask(request ExitRouteRequest) ExitRouting {
	h.t.Helper()
	routing, err := h.client.SetExitRoute(h.t.Context(), request)
	if err != nil {
		h.t.Fatal(err)
	}
	return routing
}

func (h *captiveHarness) open(duration time.Duration) captive.Window {
	h.t.Helper()
	window, err := captive.OpenWindow(h.window, duration, h.now)
	if err != nil {
		h.t.Fatal(err)
	}
	h.poll()
	return window
}

func (h *captiveHarness) poll() {
	h.server.mu.Lock()
	defer h.server.mu.Unlock()
	h.server.pollCaptiveWindow()
}

func (h *captiveHarness) advance(by time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(by)
	h.mu.Unlock()
	h.poll()
}

// lastWindow is what the last Replace was given.
func (h *captiveHarness) lastWindow() *exitCaptive {
	h.configurer.mu.Lock()
	defer h.configurer.mu.Unlock()
	return h.configurer.windows[len(h.configurer.windows)-1]
}

func (h *captiveHarness) replaces() int {
	h.configurer.mu.Lock()
	defer h.configurer.mu.Unlock()
	return len(h.configurer.windows)
}

func (h *captiveHarness) fileGone() bool {
	_, err := os.Stat(h.window)
	return errors.Is(err, os.ErrNotExist)
}

// A window root opens holds for its time on the helper's clock, carries the
// portal meshd found, ends early only when meshd names it, and opening
// again starts a new window rather than adding to the last.
func TestCaptiveWindowLifecycle(t *testing.T) {
	t.Parallel()
	h := newCaptiveHarness(t)
	window := h.open(2 * time.Minute)
	if got := h.lastWindow(); got == nil || got.Remaining != 2*time.Minute {
		t.Fatalf("window installed = %+v", got)
	}
	portal := netip.MustParseAddrPort("10.0.0.1:8880")
	routing := h.ask(ExitRouteRequest{Use: true, CaptivePortals: [2]netip.AddrPort{portal}})
	if routing.Captive != (CaptiveWindow{ID: window.ID, Remaining: 2 * time.Minute, Interface: "wlan0"}) {
		t.Fatalf("captive reported = %+v", routing.Captive)
	}
	if got := h.lastWindow(); got == nil || got.Portals[0] != portal {
		t.Fatalf("portal not let through: %+v", got)
	}

	replaced := h.replaces()
	h.advance(time.Minute)
	if h.replaces() != replaced || h.server.captiveWindow == nil {
		t.Fatal("an unchanged window was applied again or closed")
	}
	// Opening again: a new window of its own length, from now.
	again := h.open(time.Minute)
	if got := h.lastWindow(); again.ID == window.ID || got == nil || got.Remaining != time.Minute {
		t.Fatalf("reopened window = %+v", got)
	}

	// meshd closes only the window it names.
	h.ask(ExitRouteRequest{Use: true, CaptiveClose: window.ID})
	if h.server.captiveWindow == nil {
		t.Fatal("meshd closed a window it did not name")
	}
	routing = h.ask(ExitRouteRequest{Use: true, CaptiveClose: again.ID})
	if h.lastWindow() != nil || routing.Captive != (CaptiveWindow{}) || !h.fileGone() {
		t.Fatalf("early close left %+v, captive %+v", h.lastWindow(), routing.Captive)
	}
	// The file is gone: polling does not open it again; nor does a file
	// that stayed (a delete that failed), nor one older than any window.
	h.poll()
	if h.server.captiveWindow != nil {
		t.Fatal("a closed window opened again")
	}
	stayed, err := json.Marshal(again)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.window, stayed, 0o600); err != nil {
		t.Fatal(err)
	}
	h.poll()
	if h.server.captiveWindow != nil || !h.fileGone() {
		t.Fatal("a window whose file stayed opened again")
	}
	old := captive.Window{ID: strings.Repeat("cd", 16), Seconds: 60, Opened: h.now.Add(-time.Hour)}
	if stale, err := json.Marshal(old); err != nil || os.WriteFile(h.window, stale, 0o600) != nil {
		t.Fatal(err)
	}
	h.poll()
	if h.server.captiveWindow != nil {
		t.Fatal("a stale window opened")
	}

	// The window ends on time.
	h.open(time.Minute)
	h.advance(59 * time.Second)
	if h.server.captiveWindow == nil {
		t.Fatal("the window ended early")
	}
	h.advance(time.Second)
	if h.server.captiveWindow != nil || h.lastWindow() != nil || !h.fileGone() {
		t.Fatal("the window outlived its time")
	}
}

// Root's exit-captive off refuses windows; a host using no exit node opens
// none; a window left by a previous run is never opened again.
func TestCaptiveWindowRefusals(t *testing.T) {
	t.Parallel()
	h := newCaptiveHarness(t)
	h.mu.Lock()
	h.settings.ExitCaptiveOff = true
	h.mu.Unlock()
	h.open(time.Minute)
	if h.server.captiveWindow != nil || !h.fileGone() || h.lastWindow() != nil {
		t.Fatal("a window opened with exit-captive off")
	}

	h.mu.Lock()
	h.settings = routesettings.Settings{ExitUse: "World"}
	h.mu.Unlock()
	h.open(time.Minute)
	if h.server.captiveWindow == nil {
		t.Fatal("no window opened")
	}
	// Root stops using an exit node: the window goes with the route.
	h.mu.Lock()
	h.settings = routesettings.Settings{}
	h.mu.Unlock()
	h.server.mu.Lock()
	h.server.applyExitRoute()
	h.server.mu.Unlock()
	if h.server.captiveWindow != nil || !h.fileGone() {
		t.Fatal("the window outlived the exit route")
	}
	h.open(time.Minute)
	if h.server.captiveWindow != nil {
		t.Fatal("a window opened without an exit node")
	}

	if _, err := captive.OpenWindow(h.window, time.Minute, h.now); err != nil {
		t.Fatal(err)
	}
	h.server.mu.Lock()
	err := h.server.startExitRoute()
	h.server.mu.Unlock()
	if err != nil || !h.fileGone() {
		t.Fatalf("a starting helper kept the window file: %v", err)
	}
}
