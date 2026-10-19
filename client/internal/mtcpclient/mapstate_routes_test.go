package mtcpclient

import (
	"net/netip"
	"testing"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/networkmap"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

func routeConfig(refs ...string) *mtcpv1.RouteConfig {
	config := &mtcpv1.RouteConfig{}
	for index, ref := range refs {
		config.Sites = append(config.Sites, &mtcpv1.SiteRoute{
			SiteRef: ref, Candidates: []string{"peer-a"}, Primary: "peer-a", Generation: 4,
			Status: mtcpv1.SiteRoute_SERVED,
			Prefixes: []*mtcpv1.Prefix{sharedmtcp.AppendPrefix(netip.PrefixFrom(
				netip.AddrFrom4([4]byte{10, byte(20 + index), 0, 0}), 16,
			))},
		})
	}
	return config
}

func TestMapStateKeepsRoutesAcrossDeltas(t *testing.T) {
	t.Parallel()
	state := newMapState(true)
	snapshot := snapshotMessage(7)
	snapshot.Routes = routeConfig("hq")
	if err := state.applySnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	routes := build(t, state).Routes
	if len(routes) != 1 || routes[0].Ref != "hq" || routes[0].Primary != "peer-a" ||
		routes[0].Status != networkmap.RouteServed || routes[0].Prefixes[0] != netip.MustParsePrefix("10.20.0.0/16") {
		t.Fatalf("routes = %+v", routes)
	}
	step := func(seq uint64, routes *mtcpv1.RouteConfig) []networkmap.SiteRoute {
		t.Helper()
		if err := state.applyDelta(&mtcpv1.MapDelta{View: &mtcpv1.View{Epoch: 7, Seq: seq}, Routes: routes}); err != nil {
			t.Fatal(err)
		}
		return build(t, state).Routes
	}
	if kept := step(2, nil); len(kept) != 1 {
		t.Fatalf("a delta without routes changed them: %+v", kept)
	}
	if replaced := step(3, routeConfig("hq", "lab")); len(replaced) != 2 || replaced[1].Ref != "lab" {
		t.Fatalf("replaced routes = %+v", replaced)
	}
	if cleared := step(4, &mtcpv1.RouteConfig{}); len(cleared) != 0 {
		t.Fatalf("an empty routes message kept %+v", cleared)
	}
}

func TestMapStateRoutesNeedTheCapabilityAndCanonicalPrefixes(t *testing.T) {
	t.Parallel()
	snapshot := snapshotMessage(7)
	snapshot.Routes = routeConfig("hq")
	ignoring := newMapState(false)
	if err := ignoring.applySnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	if routes := build(t, ignoring).Routes; routes != nil {
		t.Fatalf("a node without routes.subnet.v1 took routes: %+v", routes)
	}
	for name, prefix := range map[string]*mtcpv1.Prefix{
		"host bits":   {Ip: []byte{10, 20, 0, 1}, Bits: 16},
		"IPv4-mapped": {Ip: netip.MustParseAddr("::ffff:10.20.0.0").AsSlice(), Bits: 112},
		"too long":    {Ip: []byte{10, 20, 0, 0}, Bits: 33},
		"odd length":  {Ip: []byte{10, 20, 0}, Bits: 16},
	} {
		malformed := snapshotMessage(7)
		malformed.Routes = routeConfig("hq")
		malformed.Routes.Sites[0].Prefixes = []*mtcpv1.Prefix{prefix}
		state := newMapState(true)
		if err := state.applySnapshot(malformed); err != nil {
			t.Fatal(err)
		}
		if _, err := state.build(snapshotInput{revision: 1}); err == nil {
			t.Errorf("%s: a malformed route prefix was accepted", name)
		}
	}
}
