package natlab

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"meshtransit.net/shared/disco"
)

// world is an Internet with one host behind a NAT and two public peers that
// share an address (so filtering by address and by port can be told apart).
type world struct {
	clock    *ManualClock
	nat      *NAT
	inside   *Conn
	peer     *Conn // 198.51.100.50:7000
	peerPort *Conn // 198.51.100.50:7001
	other    *Conn // 198.51.100.60:7000
}

func newWorld(t *testing.T, cfg NATConfig) *world {
	t.Helper()
	clock := NewManualClock(time.Unix(1_800_000_000, 0))
	n := NewNetwork(clock)
	nat, lan, err := n.NewNAT("nat", cfg, n.Internet, netip.MustParseAddr("198.51.100.1"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := n.NewHost("h", lan, LANHost)
	if err != nil {
		t.Fatal(err)
	}
	p1, err := n.NewHost("p1", n.Internet, netip.MustParseAddr("198.51.100.50"))
	if err != nil {
		t.Fatal(err)
	}
	p2, err := n.NewHost("p2", n.Internet, netip.MustParseAddr("198.51.100.60"))
	if err != nil {
		t.Fatal(err)
	}
	w := &world{clock: clock, nat: nat}
	w.inside = listen(t, h, 41641)
	w.peer = listen(t, p1, 7000)
	w.peerPort = listen(t, p1, 7001)
	w.other = listen(t, p2, 7000)
	return w
}

func listen(t *testing.T, h *Host, port uint16) *Conn {
	t.Helper()
	c, err := h.Listen(port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func send(t *testing.T, from *Conn, to netip.AddrPort) {
	t.Helper()
	if _, err := from.WriteToUDPAddrPort([]byte("x"), to); err != nil {
		t.Fatal(err)
	}
}

// recv returns the source of a queued datagram, or false if none is queued.
func recv(c *Conn) (netip.AddrPort, bool) {
	select {
	case p := <-c.queue:
		return p.src, true
	default:
		return netip.AddrPort{}, false
	}
}

func TestNATMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		mapping       disco.Mapping
		samePortPeer  bool // peer:7000 and peer:7001 see one external port
		sameAddrPeers bool // peer and other see one external port
	}{
		{disco.MappingEndpointIndependent, true, true},
		{disco.MappingAddressDependent, true, false},
		{disco.MappingAddressAndPortDependent, false, false},
	}
	for _, tt := range tests {
		w := newWorld(t, NATConfig{Mapping: tt.mapping, Filtering: disco.FilteringEndpointIndependent, Allocation: disco.AllocationRandom, Seed: 1})
		send(t, w.inside, w.peer.LocalAddrPort())
		send(t, w.inside, w.peerPort.LocalAddrPort())
		send(t, w.inside, w.other.LocalAddrPort())
		a, _ := recv(w.peer)
		b, _ := recv(w.peerPort)
		c, _ := recv(w.other)
		if a.Addr() != netip.MustParseAddr("198.51.100.1") {
			t.Fatalf("mapping %d: external address %s", tt.mapping, a)
		}
		if (a == b) != tt.samePortPeer || (a == c) != tt.sameAddrPeers {
			t.Fatalf("mapping %d: endpoints %s %s %s", tt.mapping, a, b, c)
		}
	}
}

func TestNATFiltering(t *testing.T) {
	t.Parallel()
	tests := []struct {
		filtering        disco.Filtering
		fromOtherPort    bool
		fromOtherAddress bool
	}{
		{disco.FilteringEndpointIndependent, true, true},
		{disco.FilteringAddressDependent, true, false},
		{disco.FilteringAddressAndPortDependent, false, false},
	}
	for _, tt := range tests {
		w := newWorld(t, NATConfig{Mapping: disco.MappingEndpointIndependent, Filtering: tt.filtering, Allocation: disco.AllocationPreserving})
		send(t, w.inside, w.peer.LocalAddrPort())
		ext, ok := recv(w.peer)
		if !ok || ext.Port() != 41641 {
			t.Fatalf("filtering %d: preserved mapping missing: %s", tt.filtering, ext)
		}
		send(t, w.peer, ext)
		if _, ok := recv(w.inside); !ok {
			t.Fatalf("filtering %d: reply from contacted peer dropped", tt.filtering)
		}
		send(t, w.peerPort, ext)
		_, gotPort := recv(w.inside)
		send(t, w.other, ext)
		_, gotAddr := recv(w.inside)
		if gotPort != tt.fromOtherPort || gotAddr != tt.fromOtherAddress {
			t.Fatalf("filtering %d: other port %v, other address %v", tt.filtering, gotPort, gotAddr)
		}
	}
}

func TestNATUnsolicitedAndTimeout(t *testing.T) {
	t.Parallel()
	w := newWorld(t, NATConfig{Mapping: disco.MappingEndpointIndependent, Filtering: disco.FilteringEndpointIndependent, Allocation: disco.AllocationPreserving, Timeout: time.Minute})
	ext := netip.MustParseAddrPort("198.51.100.1:41641")
	send(t, w.peer, ext)
	if _, ok := recv(w.inside); ok {
		t.Fatal("unsolicited packet passed a NAT without a mapping")
	}
	send(t, w.inside, w.peer.LocalAddrPort())
	recv(w.peer)
	w.clock.Advance(59 * time.Second)
	send(t, w.peer, ext)
	if _, ok := recv(w.inside); !ok {
		t.Fatal("live mapping dropped a packet")
	}
	if w.nat.Mappings() != 1 {
		t.Fatalf("Mappings = %d", w.nat.Mappings())
	}
	w.clock.Advance(2 * time.Second)
	send(t, w.peer, ext)
	if _, ok := recv(w.inside); ok {
		t.Fatal("expired mapping still forwards")
	}
	if w.nat.Mappings() != 0 {
		t.Fatalf("Mappings after expiry = %d", w.nat.Mappings())
	}
}

func TestNATAllocation(t *testing.T) {
	t.Parallel()
	w := newWorld(t, NATConfig{Mapping: disco.MappingAddressAndPortDependent, Filtering: disco.FilteringEndpointIndependent, Allocation: disco.AllocationSequential, Seed: 7})
	send(t, w.inside, w.peer.LocalAddrPort())
	send(t, w.inside, w.peerPort.LocalAddrPort())
	a, _ := recv(w.peer)
	b, _ := recv(w.peerPort)
	wrapped := a.Port() == defaultPortMax && b.Port() == defaultPortMin
	if b.Port() != a.Port()+1 && !wrapped {
		t.Fatalf("sequential allocation gave %d then %d", a.Port(), b.Port())
	}
}

func TestNATExhaustion(t *testing.T) {
	t.Parallel()
	w := newWorld(t, NATConfig{Mapping: disco.MappingAddressAndPortDependent, Filtering: disco.FilteringEndpointIndependent, Allocation: disco.AllocationRandom, MaxMappings: 2})
	send(t, w.inside, w.peer.LocalAddrPort())
	send(t, w.inside, w.peerPort.LocalAddrPort())
	send(t, w.inside, w.other.LocalAddrPort())
	if _, ok := recv(w.other); ok {
		t.Fatal("NAT exceeded MaxMappings")
	}
	if w.nat.Mappings() != 2 {
		t.Fatalf("Mappings = %d", w.nat.Mappings())
	}
}

func TestNATHairpin(t *testing.T) {
	t.Parallel()
	for _, hairpin := range []bool{true, false} {
		n := NewNetwork(nil)
		_, lan, err := n.NewNAT("nat", NATConfig{
			Mapping: disco.MappingEndpointIndependent, Filtering: disco.FilteringEndpointIndependent,
			Allocation: disco.AllocationPreserving, Hairpin: hairpin,
		}, n.Internet, netip.MustParseAddr("198.51.100.1"))
		if err != nil {
			t.Fatal(err)
		}
		h1, _ := n.NewHost("h1", lan, netip.MustParseAddr("192.168.1.10"))
		h2, _ := n.NewHost("h2", lan, netip.MustParseAddr("192.168.1.11"))
		a, b := listen(t, h1, 41000), listen(t, h2, 42000)
		send(t, b, netip.MustParseAddrPort("192.0.2.1:9")) // open b's mapping
		send(t, a, netip.MustParseAddrPort("198.51.100.1:42000"))
		src, ok := recv(b)
		if ok != hairpin {
			t.Fatalf("hairpin=%v: delivered %v", hairpin, ok)
		}
		if ok && src != netip.MustParseAddrPort("198.51.100.1:41000") {
			t.Fatalf("hairpinned source %s, want the external endpoint", src)
		}
	}
}

func TestFirewallIPv6(t *testing.T) {
	t.Parallel()
	n := NewNetwork(nil)
	if _, _, err := n.NewFirewall("bad", NATConfig{}, n.Internet, netip.MustParsePrefix("2001:db8:9::/64")); err == nil {
		t.Fatal("firewall without filtering accepted")
	}
	_, lan, err := n.NewFirewall("fw", NATConfig{Filtering: disco.FilteringAddressAndPortDependent}, n.Internet, netip.MustParsePrefix("2001:db8:1::/64"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := n.NewHost("h", lan, netip.MustParseAddr("2001:db8:1::10"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := n.NewHost("p", n.Internet, netip.MustParseAddr("2001:db8:2::20"))
	if err != nil {
		t.Fatal(err)
	}
	in, out := listen(t, h, 41641), listen(t, p, 7000)
	send(t, out, in.LocalAddrPort())
	if _, ok := recv(in); ok {
		t.Fatal("firewall passed unsolicited traffic")
	}
	send(t, in, out.LocalAddrPort())
	if src, ok := recv(out); !ok || src != in.LocalAddrPort() {
		t.Fatalf("firewall translated or dropped: %s %v", src, ok)
	}
	send(t, out, in.LocalAddrPort())
	if _, ok := recv(in); !ok {
		t.Fatal("firewall dropped a reply")
	}
	if _, err := in.WriteToUDPAddrPort([]byte("x"), netip.MustParseAddrPort("192.0.2.1:1")); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("v6-only host sent to v4: %v", err)
	}
}

func TestConnLifecycle(t *testing.T) {
	t.Parallel()
	n := NewNetwork(nil)
	h, err := n.NewHost("h", n.Internet, netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := h.Listen(9)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Listen(9); !errors.Is(err, ErrAddressInUse) {
		t.Fatalf("double bind: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ReadFromUDPAddrPort(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	_ = c.SetReadDeadline(time.Time{})
	done := make(chan error, 1)
	go func() {
		_, _, err := c.ReadFromUDPAddrPort(make([]byte, 1))
		done <- err
	}()
	_ = c.Close()
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after close: %v", err)
	}
	if _, err := c.WriteToUDPAddrPort([]byte("x"), netip.MustParseAddrPort("192.0.2.2:1")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
	if _, err := h.Listen(9); err != nil {
		t.Fatalf("port not released: %v", err)
	}
}
