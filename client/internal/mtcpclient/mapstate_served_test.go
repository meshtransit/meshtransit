package mtcpclient

import (
	"net/netip"
	"testing"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

func servedRoutes(refs ...string) *mtcpv1.ServedRoutes {
	served := &mtcpv1.ServedRoutes{}
	for index, ref := range refs {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(20 + index), 0, 0}), 16)
		served.Sites = append(served.Sites, &mtcpv1.ServedSite{
			SiteRef: ref, Masquerade: true, Prefixes: []*mtcpv1.Prefix{sharedmtcp.AppendPrefix(prefix)},
			Probes: []*mtcpv1.RouteProbe{
				{Ip: prefix.Addr().Next().AsSlice(), Kind: mtcpv1.RouteProbe_TCP, Port: 443},
			},
		})
	}
	return served
}

func TestMapStateKeepsServedRoutesAcrossDeltas(t *testing.T) {
	t.Parallel()
	state := newMapState(false)
	state.takesServed = true
	snapshot := snapshotMessage(7)
	snapshot.Served = servedRoutes("hq")
	if err := state.applySnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	served := build(t, state).Served
	if len(served) != 1 || served[0].Ref != "hq" || !served[0].Masquerade ||
		served[0].Prefixes[0] != netip.MustParsePrefix("10.20.0.0/16") || len(served[0].Probes) != 1 ||
		!served[0].Probes[0].TCP || served[0].Probes[0].Port != 443 ||
		served[0].Probes[0].Address != netip.MustParseAddr("10.20.0.1") {
		t.Fatalf("served = %+v", served)
	}
	step := func(seq uint64, served *mtcpv1.ServedRoutes) int {
		t.Helper()
		if err := state.applyDelta(&mtcpv1.MapDelta{View: &mtcpv1.View{Epoch: 7, Seq: seq}, Served: served}); err != nil {
			t.Fatal(err)
		}
		return len(build(t, state).Served)
	}
	if kept := step(2, nil); kept != 1 {
		t.Fatalf("a delta without served routes left %d", kept)
	}
	if replaced := step(3, servedRoutes("hq", "lab")); replaced != 2 {
		t.Fatalf("replaced served routes = %d", replaced)
	}
	if cleared := step(4, &mtcpv1.ServedRoutes{}); cleared != 0 {
		t.Fatalf("an empty served message kept %d", cleared)
	}
}

func TestMapStateServedRoutesNeedTheCapabilityAndValidProbes(t *testing.T) {
	t.Parallel()
	snapshot := snapshotMessage(7)
	snapshot.Served = servedRoutes("hq")
	ignoring := newMapState(true)
	if err := ignoring.applySnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	if served := build(t, ignoring).Served; served != nil {
		t.Fatalf("a node without router.subnet.v1 took served routes: %+v", served)
	}
	for name, probe := range map[string]*mtcpv1.RouteProbe{
		"unknown kind": {Ip: []byte{10, 20, 0, 1}},
		"bad address":  {Ip: []byte{10, 20, 0}, Kind: mtcpv1.RouteProbe_ICMP},
		"big port":     {Ip: []byte{10, 20, 0, 1}, Kind: mtcpv1.RouteProbe_TCP, Port: 70000},
		"outside site": {Ip: []byte{10, 99, 0, 1}, Kind: mtcpv1.RouteProbe_ICMP},
	} {
		malformed := snapshotMessage(7)
		malformed.Served = servedRoutes("hq")
		malformed.Served.Sites[0].Probes = []*mtcpv1.RouteProbe{probe}
		state := newMapState(false)
		state.takesServed = true
		if err := state.applySnapshot(malformed); err != nil {
			t.Fatal(err)
		}
		if _, err := state.build(snapshotInput{revision: 1}); err == nil {
			t.Errorf("%s: a malformed probe was accepted", name)
		}
	}
}
