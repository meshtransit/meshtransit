package daemon

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

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
	}{
		{"router", routesettings.Settings{RouterMode: true, AdvertiseRoutes: advertised}, nil, advertised},
		{"router mode off", routesettings.Settings{AdvertiseRoutes: advertised}, nil, []netip.Prefix{}},
		{"unsafe file", routesettings.Settings{}, routesettings.ErrUnsafeFile, []netip.Prefix{}},
	}
	for _, test := range tests {
		load := func(string) (routesettings.Settings, error) { return test.settings, test.err }
		got := offeredRoutes(load, "/etc/meshtransit/routes.json", nil)
		if got == nil || !slices.Equal(got, test.want) {
			t.Errorf("%s: offeredRoutes() = %v, want %v", test.name, got, test.want)
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
	offers := make(chan []netip.Prefix)
	go watchRouteOffer(ctx, load, "routes.json", time.Millisecond, nil, offers)
	if first := <-offers; len(first) != 1 {
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
		if changed == nil || len(changed) != 0 {
			t.Fatalf("offer after router mode off = %v", changed)
		}
	case <-time.After(time.Second):
		t.Fatal("a change was not sent")
	}
	cancel()
}
