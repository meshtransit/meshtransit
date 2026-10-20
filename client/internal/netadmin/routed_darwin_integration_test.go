//go:build integration && darwin

package netadmin

import (
	"net/netip"
	"os"
	"slices"
	"testing"

	"meshtransit.net/client/internal/hostroute"
)

// TestKernelRoutedRoutesDarwin needs root: sudo go test -tags=integration
// -run TestKernelRoutedRoutesDarwin ./client/internal/netadmin/
func TestKernelRoutedRoutesDarwin(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("installing routes needs root")
	}
	creator := kernelTUNCreator{}
	file, name, err := creator.Open("", 1280, 0,
		[]netip.Prefix{netip.MustParsePrefix("100.127.251.1/32")}, nil)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = file.Close() }()
	configurer := kernelRoutedConfigurer{}
	options := RoutedOptions{SettingsPath: "/nonexistent"}
	t.Cleanup(func() { _ = configurer.Clear(options, 0) })

	site := netip.MustParsePrefix("10.254.250.0/24")
	other := netip.MustParsePrefix("10.254.251.0/24")
	pin := netip.MustParsePrefix("10.254.250.53/32")
	table, err := hostroute.Read()
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	desired := routedState{Routes: []netip.Prefix{site, other}}
	if _, found := hostroute.Physical(table, nil, pin.Addr()); found {
		desired.Throws = []netip.Prefix{pin}
	}
	installed, refused, err := configurer.ReplaceRouted(name, options, 0, routedState{}, desired)
	if err != nil || len(refused) != 0 {
		t.Fatalf("ReplaceRouted() error = %v, refused %v", err, refused)
	}
	if !slices.Equal(installed.Routes, desired.Routes) || !slices.Equal(installed.Throws, desired.Throws) {
		t.Fatalf("ReplaceRouted() installed %+v, want %+v", installed, desired)
	}
	assertMarked(t, map[netip.Prefix]bool{site: true, other: true, pin: len(desired.Throws) == 1})

	// A second call keeps what is there and removes what is no longer asked.
	desired.Routes = []netip.Prefix{site}
	installed, _, err = configurer.ReplaceRouted(name, options, 0, installed, desired)
	if err != nil || !slices.Equal(installed.Routes, desired.Routes) {
		t.Fatalf("second ReplaceRouted() = %+v, %v", installed, err)
	}
	assertMarked(t, map[netip.Prefix]bool{site: true, other: false, pin: len(desired.Throws) == 1})

	if err := configurer.Clear(options, 0); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}
	assertMarked(t, map[netip.Prefix]bool{site: false, other: false, pin: false})
}

func assertMarked(t *testing.T, want map[netip.Prefix]bool) {
	t.Helper()
	table, err := hostroute.Read()
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	for prefix, present := range want {
		found := slices.ContainsFunc(table, func(entry hostroute.Route) bool { return entry.Owned() && entry.Prefix == prefix })
		if found != present {
			t.Errorf("marked route %s present = %t, want %t", prefix, found, present)
		}
	}
}
