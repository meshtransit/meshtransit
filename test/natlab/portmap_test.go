package natlab

import (
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/shared/disco"
)

func TestNATPortMapping(t *testing.T) {
	t.Parallel()
	w := newWorld(t, NATConfig{
		Mapping: disco.MappingAddressAndPortDependent, Filtering: disco.FilteringAddressAndPortDependent,
		Allocation: disco.AllocationRandom, Seed: 3,
	})
	if w.nat.External() != netip.MustParseAddr("198.51.100.1") {
		t.Fatalf("external %s", w.nat.External())
	}
	internal := w.inside.LocalAddrPort()
	// Without a mapping, a symmetric NAT drops unsolicited packets.
	send(t, w.peer, netip.AddrPortFrom(w.nat.External(), 41641))
	if _, ok := recv(w.inside); ok {
		t.Fatal("unsolicited packet crossed the NAT")
	}

	external, err := w.nat.AddPortMapping(internal, 41641, time.Hour)
	if err != nil || external != netip.AddrPortFrom(w.nat.External(), 41641) {
		t.Fatalf("mapping %s %v", external, err)
	}
	// Every remote reaches the mapping, and the inside host's traffic to any
	// remote leaves from it: the mapping is endpoint independent.
	for _, remote := range []*Conn{w.peer, w.peerPort, w.other} {
		send(t, remote, external)
		if _, ok := recv(w.inside); !ok {
			t.Fatalf("%s could not reach the mapping", remote.LocalAddrPort())
		}
		send(t, w.inside, remote.LocalAddrPort())
		if source, ok := recv(remote); !ok || source != external {
			t.Fatalf("outbound to %s left from %s", remote.LocalAddrPort(), source)
		}
	}
	if renewed, err := w.nat.AddPortMapping(internal, 50000, time.Hour); err != nil || renewed != external {
		t.Fatalf("renewal moved the mapping to %s (%v)", renewed, err)
	}

	w.clock.Advance(2 * time.Hour)
	send(t, w.other, external)
	if _, ok := recv(w.inside); ok {
		t.Fatal("an expired mapping still forwards")
	}
	if _, err := w.nat.AddPortMapping(internal, 41641, time.Hour); err != nil {
		t.Fatal(err)
	}
	w.nat.RemovePortMapping(internal)
	send(t, w.other, external)
	if _, ok := recv(w.inside); ok {
		t.Fatal("a removed mapping still forwards")
	}
}
