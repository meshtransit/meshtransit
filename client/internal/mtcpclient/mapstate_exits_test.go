package mtcpclient

import (
	"net/netip"
	"testing"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

func servedExits(ref string) *mtcpv1.ServedExits {
	ports := []*mtcpv1.PortRange{{First: 443, Last: 443}}
	return &mtcpv1.ServedExits{Pools: []*mtcpv1.ServedExit{{
		PoolRef: ref, ConntrackPerConsumer: 4096,
		Probes:       []*mtcpv1.ExitProbe{{Ip: []byte{9, 9, 9, 9}, Port: 443}},
		DnsUpstreams: [][]byte{{1, 1, 1, 1}},
		Rules: []*mtcpv1.FilterRule{{
			Sources: []*mtcpv1.Prefix{sharedmtcp.AppendPrefix(netip.MustParsePrefix("100.64.0.2/32"))},
			Destinations: []*mtcpv1.Destination{
				{Prefix: sharedmtcp.AppendPrefix(netip.MustParsePrefix("0.0.0.0/0")), Ports: ports},
				{Prefix: sharedmtcp.AppendPrefix(netip.MustParsePrefix("::/0")), Ports: ports},
			},
			Protocols: []uint32{6},
		}},
	}}}
}

func TestMapStateKeepsServedExitsAcrossDeltas(t *testing.T) {
	t.Parallel()
	state := newMapState(false)
	state.takesServedExits = true
	snapshot := snapshotMessage(7)
	snapshot.ServedExits = servedExits("p-main")
	if err := state.applySnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	served := build(t, state).ServedExits
	if len(served) != 1 || served[0].Ref != "p-main" || served[0].ConntrackPerConsumer != 4096 ||
		served[0].SMTPAllowed || len(served[0].Probes) != 1 ||
		served[0].Probes[0] != netip.MustParseAddrPort("9.9.9.9:443") || len(served[0].DNSUpstreams) != 1 ||
		len(served[0].Rules) != 1 || len(served[0].Rules[0].Destinations) != 2 {
		t.Fatalf("served exits = %+v", served)
	}
	step := func(seq uint64, served *mtcpv1.ServedExits) int {
		t.Helper()
		if err := state.applyDelta(&mtcpv1.MapDelta{View: &mtcpv1.View{Epoch: 7, Seq: seq}, ServedExits: served}); err != nil {
			t.Fatal(err)
		}
		return len(build(t, state).ServedExits)
	}
	if kept := step(2, nil); kept != 1 {
		t.Fatalf("a delta without served exits left %d", kept)
	}
	if cleared := step(3, &mtcpv1.ServedExits{}); cleared != 0 {
		t.Fatalf("an empty served exits message kept %d", cleared)
	}
}

func TestMapStateServedExitsNeedTheCapabilityAndTheInternet(t *testing.T) {
	t.Parallel()
	snapshot := snapshotMessage(7)
	snapshot.ServedExits = servedExits("p-main")
	ignoring := newMapState(false)
	ignoring.takesServed = true
	if err := ignoring.applySnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	if served := build(t, ignoring).ServedExits; served != nil {
		t.Fatalf("a node without router.exit.v1 took served exits: %+v", served)
	}
	for name, change := range map[string]func(*mtcpv1.ServedExit){
		"private probe": func(pool *mtcpv1.ServedExit) { pool.Probes[0].Ip = []byte{10, 0, 0, 1} },
		"probe port 0":  func(pool *mtcpv1.ServedExit) { pool.Probes[0].Port = 0 },
		"metadata DNS":  func(pool *mtcpv1.ServedExit) { pool.DnsUpstreams = [][]byte{{169, 254, 169, 254}} },
		"low conntrack": func(pool *mtcpv1.ServedExit) { pool.ConntrackPerConsumer = 10 },
		"no reference":  func(pool *mtcpv1.ServedExit) { pool.PoolRef = "" },
		"rule to the LAN": func(pool *mtcpv1.ServedExit) {
			pool.Rules[0].Destinations[0].Prefix = sharedmtcp.AppendPrefix(netip.MustParsePrefix("10.0.0.0/8"))
		},
		"rule from a range": func(pool *mtcpv1.ServedExit) {
			pool.Rules[0].Sources[0] = sharedmtcp.AppendPrefix(netip.MustParsePrefix("100.64.0.0/24"))
		},
	} {
		malformed := snapshotMessage(7)
		malformed.ServedExits = servedExits("p-main")
		change(malformed.ServedExits.Pools[0])
		state := newMapState(false)
		state.takesServedExits = true
		if err := state.applySnapshot(malformed); err != nil {
			t.Fatal(err)
		}
		if _, err := state.build(snapshotInput{revision: 1}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	two := snapshotMessage(7)
	two.ServedExits = servedExits("a")
	two.ServedExits.Pools = append(two.ServedExits.Pools, servedExits("b").Pools...)
	state := newMapState(false)
	state.takesServedExits = true
	if err := state.applySnapshot(two); err != nil {
		t.Fatal(err)
	}
	if _, err := state.build(snapshotInput{revision: 1}); err == nil {
		t.Error("two served Exit Pools were accepted")
	}
}
