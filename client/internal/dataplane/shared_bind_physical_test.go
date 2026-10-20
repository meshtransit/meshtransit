package dataplane

import (
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
}

func (b *interfaceBind) BindSocketToInterface4(index uint32, blackhole bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	b.index4, b.blackhole = index, blackhole
	return nil
}

func (*interfaceBind) BindSocketToInterface6(uint32, bool) error { return nil }

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
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bind.Close() })
	if calls, index, blackhole := inner.state(); calls != 1 || index != 0 || blackhole {
		t.Fatalf("open bound to %d (blackhole %v, %d calls), want unbound", index, blackhole, calls)
	}
	endpoint, err := bind.ParseEndpoint("203.0.113.7:41641")
	if err != nil {
		t.Fatal(err)
	}
	if err := bind.Send([][]byte{{1}}, endpoint); err != nil {
		t.Fatal(err)
	}
	if calls, _, _ := inner.state(); calls != 1 {
		t.Fatalf("an unchanged route bound the sockets again (%d calls)", calls)
	}

	underlay.SetExitBound(underlay.ExitHeld, true)
	if err := bind.Send([][]byte{{2}}, endpoint); err != nil {
		t.Fatal(err)
	}
	calls, index, blackhole := inner.state()
	want := underlay.PhysicalIndex(netip.IPv4Unspecified())
	if calls != 2 || index != want || blackhole != (want == 0) {
		t.Fatalf("exit route bound to %d (blackhole %v, %d calls), want %d", index, blackhole, calls, want)
	}

	underlay.SetExitBound(underlay.ExitHeld, false)
	if _, err := bind.SendDatagram([]byte{3}, netip.MustParseAddrPort("203.0.113.7:41641")); err != nil {
		t.Fatal(err)
	}
	if calls, index, blackhole := inner.state(); calls != 3 || index != 0 || blackhole {
		t.Fatalf("after the exit route bound to %d (blackhole %v, %d calls), want unbound", index, blackhole, calls)
	}
}
