package dataplane

import (
	"errors"
	"net/netip"
	"sync"
	"testing"

	"meshtransit.net/client/internal/underlay"
)

// interfaceBind records the interface its sockets are bound to.
type interfaceBind struct {
	*fakeInnerBind
	mu        sync.Mutex
	calls     int
	index4    uint32
	blackhole bool
	// fail4 and fail6, when set, fail the binding of that family.
	fail4, fail6 error
}

func (b *interfaceBind) BindSocketToInterface4(index uint32, blackhole bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if b.fail4 != nil {
		return b.fail4
	}
	b.index4, b.blackhole = index, blackhole
	return nil
}

func (b *interfaceBind) BindSocketToInterface6(uint32, bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.fail6
}

// physicalAt replaces the bind's lookup of the physical interface: index for
// IPv4 and IPv6 alike, 0 for none.
func physicalAt(bind *sharedBind, index uint32) {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	bind.physicalIndex = func(netip.Addr) uint32 { return index }
}

func (b *interfaceBind) state() (calls int, index uint32, blackhole bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls, b.index4, b.blackhole
}

func TestSharedBindFollowsTheExitRouteBeforeSending(t *testing.T) {
	if !underlay.FollowsRoutes {
		t.Skip("the client's sockets do not follow the host's routes here")
	}
	t.Cleanup(func() { underlay.SetExitBound(underlay.ExitRequested|underlay.ExitHeld, false) })
	inner := &interfaceBind{fakeInnerBind: newFakeInnerBind()}
	bind, err := newSharedBind(inner)
	if err != nil {
		t.Fatal(err)
	}
	physicalAt(bind, 7)
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bind.Close() })
	if calls, _, _ := inner.state(); calls != 0 {
		t.Fatalf("open touched sockets never bound (%d calls)", calls)
	}
	endpoint, err := bind.ParseEndpoint("203.0.113.7:41641")
	if err != nil {
		t.Fatal(err)
	}
	if err := bind.Send([][]byte{{1}}, endpoint); err != nil {
		t.Fatal(err)
	}
	if calls, _, _ := inner.state(); calls != 0 {
		t.Fatalf("an unchanged route bound the sockets (%d calls)", calls)
	}

	underlay.SetExitBound(underlay.ExitHeld, true)
	// Kept on the physical path the socket sends straight to its peers.
	if err := bind.Send([][]byte{{2}}, endpoint); err != nil {
		t.Fatal(err)
	}
	if calls, index, blackhole := inner.state(); calls != 1 || index != 7 || blackhole {
		t.Fatalf("exit route bound to %d (blackhole %v, %d calls), want 7", index, blackhole, calls)
	}

	underlay.SetExitBound(underlay.ExitHeld, false)
	if _, err := bind.SendDatagram([]byte{3}, netip.MustParseAddrPort("203.0.113.7:41641")); err != nil {
		t.Fatal(err)
	}
	if calls, index, blackhole := inner.state(); calls != 2 || index != 0 || blackhole {
		t.Fatalf("after the exit route bound to %d (blackhole %v, %d calls), want unbound", index, blackhole, calls)
	}
}

func TestSharedBindSendsNothingStraightUnlessKeptOffTheExitRoutes(t *testing.T) {
	if !underlay.FollowsRoutes {
		t.Skip("the client's sockets do not follow the host's routes here")
	}
	t.Cleanup(func() { underlay.SetExitBound(underlay.ExitRequested|underlay.ExitHeld, false) })
	inner := &interfaceBind{fakeInnerBind: newFakeInnerBind(), fail6: errors.New("setsockopt failed")}
	bind, err := newSharedBind(inner)
	if err != nil {
		t.Fatal(err)
	}
	physicalAt(bind, 7)
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bind.Close() })
	v4, v6 := netip.MustParseAddrPort("203.0.113.7:41641"), netip.MustParseAddrPort("[2001:db8::7]:41641")
	send := func(destination netip.AddrPort) error {
		endpoint, err := bind.ParseEndpoint(destination.String())
		if err != nil {
			t.Fatal(err)
		}
		return bind.Send([][]byte{{1}}, endpoint)
	}
	// Without an exit route nothing is bound and everything follows the
	// host's routes.
	if err := send(v6); err != nil {
		t.Fatalf("Send(IPv6) without an exit route = %v", err)
	}

	underlay.SetExitBound(underlay.ExitHeld, true)
	if err := send(v4); err != nil {
		t.Fatalf("Send(IPv4) kept on the physical path = %v", err)
	}
	// An unbound socket would send into the exit routes, through the mesh
	// that carries it.
	if err := send(v6); !errors.Is(err, errDirectBlocked) {
		t.Fatalf("Send(IPv6) from a socket left on the exit routes = %v, want errDirectBlocked", err)
	}
	if _, err := bind.SendDatagram([]byte{2}, v6); !errors.Is(err, errDirectBlocked) {
		t.Fatalf("SendDatagram(IPv6) = %v, want errDirectBlocked", err)
	}
	if bind.physicalRetry.Load() == 0 {
		t.Fatal("a failed IPv6 binding is not tried again")
	}

	// No physical route: macOS would unbind the sockets into the exit
	// routes, so they send nothing.
	inner.mu.Lock()
	inner.fail6 = nil
	inner.mu.Unlock()
	physicalAt(bind, 0)
	underlay.RebindPhysical()
	if err := send(v4); !errors.Is(err, errDirectBlocked) {
		t.Fatalf("Send(IPv4) without a physical route = %v, want errDirectBlocked", err)
	}
	if err := send(v6); !errors.Is(err, errDirectBlocked) {
		t.Fatalf("Send(IPv6) without a physical route = %v, want errDirectBlocked", err)
	}
	physicalAt(bind, 7)
	underlay.RebindPhysical()
	if err := send(v6); err != nil {
		t.Fatalf("Send(IPv6) once the route is back = %v", err)
	}

	inner.mu.Lock()
	inner.fail4 = errors.New("interface gone")
	inner.mu.Unlock()
	underlay.RebindPhysical()
	if err := send(v4); !errors.Is(err, errDirectBlocked) {
		t.Fatalf("Send(IPv4) after a failed binding = %v, want errDirectBlocked", err)
	}

	underlay.SetExitBound(underlay.ExitHeld, false)
	if err := send(v4); err != nil {
		t.Fatalf("Send(IPv4) once the exit route went = %v", err)
	}
}
