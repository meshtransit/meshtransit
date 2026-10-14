package dataplane

import (
	"net/netip"
	"slices"
	"testing"
)

func TestPlatformHostAddressesKeepOnlyUnderlayAddresses(t *testing.T) {
	t.Parallel()
	parse := func(values ...string) []netip.Addr {
		addresses := make([]netip.Addr, 0, len(values))
		for _, value := range values {
			addresses = append(addresses, netip.MustParseAddr(value))
		}
		return addresses
	}
	got := platformHostAddresses(parse(
		"10.63.186.255",    // Wi-Fi LAN
		"100.64.0.3",       // a mesh address
		"127.0.0.1", "::1", // loopback
		"fe80::b87a:8fff:fe54:e9a4", // link-local
		"0.0.0.0", "224.0.0.1",
		"::ffff:192.168.1.20",    // mapped
		"2001:db8::5", "fd00::7", // global and unique-local
	))
	want := parse("10.63.186.255", "192.168.1.20", "2001:db8::5", "fd00::7")
	if !slices.Equal(got, want) {
		t.Fatalf("platformHostAddresses() = %v, want %v", got, want)
	}
}

func TestSetHostAddressSourceReplacesInterfaceListing(t *testing.T) {
	t.Parallel()
	engine := &WireGuardEngine{hostAddresses: func() ([]netip.Addr, error) {
		t.Fatal("the system interface list was used")
		return nil, nil
	}}
	engine.SetHostAddressSource(func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.168.1.20")} })
	addresses, err := engine.hostAddresses()
	if err != nil || len(addresses) != 1 || addresses[0] != netip.MustParseAddr("192.168.1.20") {
		t.Fatalf("hostAddresses() = %v, %v", addresses, err)
	}
	engine.SetHostAddressSource(nil) // ignored
	if addresses, _ := engine.hostAddresses(); len(addresses) != 1 {
		t.Fatal("a nil source replaced the platform source")
	}
}
