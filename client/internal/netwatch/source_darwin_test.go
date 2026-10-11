package netwatch

import (
	"testing"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestDefaultRouteTokensKeepUnscopedDefaults(t *testing.T) {
	t.Parallel()
	gateway := &route.Inet4Addr{IP: [4]byte{192, 168, 1, 1}}
	messages := []route.Message{
		&route.RouteMessage{
			Flags: unix.RTF_UP | unix.RTF_GATEWAY, Index: 4,
			Addrs: []route.Addr{unix.RTAX_DST: &route.Inet4Addr{}, unix.RTAX_GATEWAY: gateway},
		},
		&route.RouteMessage{
			Flags: unix.RTF_UP | unix.RTF_GATEWAY | rtfIfscope, Index: 9,
			Addrs: []route.Addr{unix.RTAX_DST: &route.Inet4Addr{}, unix.RTAX_GATEWAY: gateway},
		},
		&route.RouteMessage{
			Flags: unix.RTF_UP, Index: 5,
			Addrs: []route.Addr{unix.RTAX_DST: &route.Inet4Addr{IP: [4]byte{10, 0, 0, 0}}},
		},
		&route.RouteMessage{
			Flags: unix.RTF_UP, Index: 7,
			Addrs: []route.Addr{unix.RTAX_DST: &route.Inet6Addr{}, unix.RTAX_GATEWAY: &route.LinkAddr{Index: 7}},
		},
	}
	tokens, indexes, err := defaultRouteTokensFrom(messages, map[int]struct{}{7: {}})
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 1 || tokens[0] != "default|family=2|link=4|gateway=192.168.1.1" {
		t.Fatalf("tokens = %q", tokens)
	}
	if _, ok := indexes[4]; !ok || len(indexes) != 1 {
		t.Fatalf("indexes = %v", indexes)
	}
}

func TestRoutingSocketSourceOpensAndReadsTheTable(t *testing.T) {
	t.Parallel()
	source, err := newNativeSource(time.Second)
	if err != nil {
		t.Fatalf("newNativeSource() error = %v", err)
	}
	// Draining an idle or busy routing socket must not fail.
	routeSource, ok := source.(*routeSocketSource)
	if !ok {
		t.Fatalf("source %T", source)
	}
	if err := routeSource.drain(); err != nil {
		t.Fatalf("drain() error = %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := defaultRouteTokens(nil); err != nil {
		t.Fatalf("defaultRouteTokens() error = %v", err)
	}
}
