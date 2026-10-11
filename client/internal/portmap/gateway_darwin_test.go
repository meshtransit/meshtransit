package portmap

import (
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestDefaultIPv4GatewaySkipsScopedAndLinkRoutes(t *testing.T) {
	t.Parallel()
	messages := []route.Message{
		&route.RouteMessage{
			Flags: unix.RTF_UP | unix.RTF_GATEWAY | rtfIfscope,
			Addrs: []route.Addr{unix.RTAX_DST: &route.Inet4Addr{}, unix.RTAX_GATEWAY: &route.Inet4Addr{IP: [4]byte{10, 0, 0, 1}}},
		},
		&route.RouteMessage{
			Flags: unix.RTF_UP,
			Addrs: []route.Addr{unix.RTAX_DST: &route.Inet4Addr{}, unix.RTAX_GATEWAY: &route.LinkAddr{Index: 3}},
		},
		&route.RouteMessage{
			Flags: unix.RTF_UP | unix.RTF_GATEWAY,
			Addrs: []route.Addr{unix.RTAX_DST: &route.Inet4Addr{}, unix.RTAX_GATEWAY: &route.Inet4Addr{IP: [4]byte{192, 168, 1, 1}}},
		},
	}
	gateway, ok := defaultIPv4Gateway(messages)
	if !ok || gateway != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("defaultIPv4Gateway() = %s, %v", gateway, ok)
	}
}

func TestDefaultGatewayOnThisHost(t *testing.T) {
	t.Parallel()
	gateway, err := DefaultGateway()
	if errors.Is(err, ErrNoGateway) {
		t.Skip("no IPv4 default route on this host")
	}
	if err != nil || !gateway.Valid() {
		t.Fatalf("DefaultGateway() = %+v, %v", gateway, err)
	}
	t.Logf("gateway %s via %s", gateway.Addr, gateway.Local)
}
