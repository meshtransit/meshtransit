package underlay

import (
	"net/netip"
	"testing"
)

func TestPhysicalBoundFollowsTheExitRoute(t *testing.T) {
	t.Cleanup(func() { SetExitBound(ExitRequested|ExitHeld, false) })
	public := netip.MustParseAddr("203.0.113.9")
	if physicalBound(public) {
		t.Fatal("a public address is not bound without an exit route")
	}
	SetExitBound(ExitHeld, true)
	for address, want := range map[string]bool{
		"203.0.113.9": true, "2001:db8::1": true, "192.168.1.1": true, "::ffff:198.51.100.1": true,
		"127.0.0.1": false, "::1": false, "0.0.0.0": false, "224.0.0.251": false, "fe80::1": false,
		"100.100.1.2": false,
	} {
		if got := physicalBound(netip.MustParseAddr(address)); got != want {
			t.Errorf("physicalBound(%s) = %v, want %v", address, got, want)
		}
	}
}

func TestExitSourcesHoldTheBindingTogether(t *testing.T) {
	t.Cleanup(func() { SetExitBound(ExitRequested|ExitHeld, false) })
	start := PhysicalGeneration()
	SetExitBound(ExitRequested, true)
	SetExitBound(ExitHeld, true)
	if !ExitBound() || PhysicalGeneration() != start+1 {
		t.Fatalf("bound %v generation %d, want bound once at %d", ExitBound(), PhysicalGeneration(), start+1)
	}
	SetExitBound(ExitRequested, false)
	if !ExitBound() || PhysicalGeneration() != start+1 {
		t.Fatal("the routes still hold the binding")
	}
	SetExitBound(ExitHeld, false)
	if ExitBound() || PhysicalGeneration() != start+2 {
		t.Fatalf("bound %v generation %d after both let go", ExitBound(), PhysicalGeneration())
	}
	RebindPhysical()
	if PhysicalGeneration() != start+3 {
		t.Fatal("RebindPhysical must ask for a new binding")
	}
}
