package dataplane

import (
	"errors"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/conn"

	"meshtransit.net/client/internal/routesettings"
	"meshtransit.net/client/internal/underlay"
)

// Not parallel: the subnet routes underlay records are process-wide.
func TestSharedBindRefusesDestinationsInsideSubnetRoutes(t *testing.T) {
	inner := newFakeInnerBind()
	shared, err := newSharedBind(inner)
	if err != nil {
		t.Fatalf("newSharedBind() error = %v", err)
	}
	if _, _, err := shared.Open(41641); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	underlay.SetRouted([]netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")})
	t.Cleanup(func() { underlay.SetRouted(nil) })

	inside := netip.MustParseAddrPort("198.51.100.7:41641")
	outside := netip.MustParseAddrPort("203.0.113.2:41641")
	if _, err := shared.SendDatagram([]byte{1}, inside); !errors.Is(err, errRoutedDestination) {
		t.Fatalf("SendDatagram(inside) error = %v, want errRoutedDestination", err)
	}
	if err := shared.Send([][]byte{{2}}, &fakeBindEndpoint{destination: inside.String()}); !errors.Is(err, errRoutedDestination) {
		t.Fatalf("Send(inside) error = %v, want errRoutedDestination", err)
	}
	if _, sentTo := inner.sentSnapshot(); sentTo.IsValid() {
		t.Fatalf("a datagram into the subnet route reached the socket: %v", sentTo)
	}
	if err := shared.Send([][]byte{{3}}, conn.Endpoint(&fakeBindEndpoint{destination: outside.String()})); err != nil {
		t.Fatalf("Send(outside) error = %v", err)
	}
	if _, sentTo := inner.sentSnapshot(); sentTo != outside {
		t.Fatalf("Send(outside) went to %v", sentTo)
	}

	underlay.SetRouted(nil)
	if _, err := shared.SendDatagram([]byte{4}, inside); err != nil {
		t.Fatalf("SendDatagram(inside) after the routes went error = %v", err)
	}
}

func TestRoutedGuardLeavesOutLocalConflicts(t *testing.T) {
	t.Parallel()
	site := netip.MustParsePrefix("10.35.0.0/17")
	lan := netip.MustParsePrefix("192.168.35.0/24")
	off := netip.MustParsePrefix("10.40.0.0/16")
	guard := routedGuard([]netip.Prefix{site, lan, off}, []routesettings.Refusal{
		{Prefix: lan, Reason: routesettings.ReasonLocalConflict},
		{Prefix: off, Reason: routesettings.ReasonRoutesOff},
	})
	if len(guard) != 2 || guard[0] != site || guard[1] != off {
		t.Fatalf("routedGuard() = %v, want [%s %s]", guard, site, off)
	}
}
