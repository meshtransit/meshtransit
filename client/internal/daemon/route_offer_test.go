package daemon

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/routesettings"
)

func TestOfferedRoutesFollowRouterMode(t *testing.T) {
	t.Parallel()
	advertised := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
	tests := []struct {
		name     string
		settings routesettings.Settings
		err      error
		want     []netip.Prefix
		exit     bool
	}{
		{"router", routesettings.Settings{RouterMode: true, AdvertiseRoutes: advertised}, nil, advertised, false},
		{"router mode off", routesettings.Settings{AdvertiseRoutes: advertised}, nil, []netip.Prefix{}, false},
		{"exit node", routesettings.Settings{ExitMode: true}, nil, []netip.Prefix{}, true},
		{"unsafe file", routesettings.Settings{ExitMode: true}, routesettings.ErrUnsafeFile, []netip.Prefix{}, false},
	}
	for _, test := range tests {
		load := func(string) (routesettings.Settings, error) { return test.settings, test.err }
		got := offeredRoutes(load, "/etc/meshtransit/routes.json", nil)
		if got.Prefixes == nil || !slices.Equal(got.Prefixes, test.want) || got.Exit != test.exit {
			t.Errorf("%s: offeredRoutes() = %v, want %v and exit %t", test.name, got, test.want, test.exit)
		}
	}
}

func TestWatchRouteOfferSendsOnlyChanges(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	settings := routesettings.Settings{RouterMode: true, AdvertiseRoutes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}}
	load := func(string) (routesettings.Settings, error) {
		mu.Lock()
		defer mu.Unlock()
		return settings, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	offers := make(chan controlplane.HostOffer)
	go watchRouteOffer(ctx, load, "routes.json", time.Millisecond, nil, offers)
	if first := <-offers; len(first.Prefixes) != 1 {
		t.Fatalf("first offer = %v", first)
	}
	select {
	case again := <-offers:
		t.Fatalf("an unchanged offer was sent again: %v", again)
	case <-time.After(20 * time.Millisecond):
	}
	mu.Lock()
	settings.RouterMode = false
	mu.Unlock()
	select {
	case changed := <-offers:
		if changed.Prefixes == nil || len(changed.Prefixes) != 0 {
			t.Fatalf("offer after router mode off = %v", changed)
		}
	case <-time.After(time.Second):
		t.Fatal("a change was not sent")
	}
	cancel()
}
