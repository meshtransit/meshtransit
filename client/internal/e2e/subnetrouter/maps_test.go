//go:build e2e && linux

package subnetrouter

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/networkmap"
)

// The nodes of the topology, their mesh and underlay addresses, and the
// Site behind the routers.
const (
	consumer = "consumer"
	// consumer2 is the second consumer of the spread scenario.
	consumer2 = "consumer-2"
	routerA   = "router-a"
	routerB   = "router-b"
	siteRef   = "lab"
	// unserved, as a consumer's primary, is a map where no router can serve
	// the Site.
	unserved = "unserved"
	// wireGuardPort is each node's listen port, in its own namespace.
	wireGuardPort = 41641
	// The exit nodes of the exit scenario and their pool; none, as the
	// consumer's exit node, is a map where no exit node carries its traffic.
	exitA   = "exit-a"
	exitB   = "exit-b"
	poolRef = "world"
	none    = "none"
)

var (
	sitePrefix = netip.MustParsePrefix("10.50.0.0/24")
	lanHost    = netip.MustParseAddr("10.50.0.10")
	nodes      = map[string]struct {
		id       uint64
		mesh     netip.Prefix
		underlay netip.Addr
		lan      netip.Addr // a router's address in the Site
	}{
		consumer: {id: 1, mesh: netip.MustParsePrefix("100.64.0.1/32"), underlay: netip.MustParseAddr("10.99.0.1")},
		routerA: {
			id: 2, mesh: netip.MustParsePrefix("100.64.0.2/32"), underlay: netip.MustParseAddr("10.99.0.2"),
			lan: netip.MustParseAddr("10.50.0.2"),
		},
		routerB: {
			id: 3, mesh: netip.MustParsePrefix("100.64.0.3/32"), underlay: netip.MustParseAddr("10.99.0.3"),
			lan: netip.MustParseAddr("10.50.0.3"),
		},
		// An exit node's lan is its egress address towards the Internet.
		exitA: {
			id: 4, mesh: netip.MustParsePrefix("100.64.0.4/32"), underlay: netip.MustParseAddr("10.99.0.4"),
			lan: netip.MustParseAddr("45.76.20.2"),
		},
		exitB: {
			id: 5, mesh: netip.MustParsePrefix("100.64.0.5/32"), underlay: netip.MustParseAddr("10.99.0.5"),
			lan: netip.MustParseAddr("45.76.20.3"),
		},
		consumer2: {id: 6, mesh: netip.MustParsePrefix("100.64.0.6/32"), underlay: netip.MustParseAddr("10.99.0.6")},
	}
	// netHost stands for the Internet, behind the hub's router; egressGateway
	// is the hub on the exit nodes' egress network.
	netHost       = netip.MustParseAddr("34.10.0.10")
	netGateway    = netip.MustParseAddr("34.10.0.1")
	egressGateway = netip.MustParseAddr("45.76.20.1")
)

// privateKey is a node's fixed test key.
func privateKey(name string) dataplane.NodePrivateKey {
	return dataplane.NodePrivateKey(sha256.Sum256([]byte("meshtransit e2e " + name)))
}

func publicKey(name string) string {
	secret := privateKey(name)
	private, err := ecdh.X25519().NewPrivateKey(secret[:])
	if err != nil {
		panic(err)
	}
	return "nodekey:" + hex.EncodeToString(private.PublicKey().Bytes())
}

func node(name string) networkmap.Node {
	facts := nodes[name]
	return networkmap.Node{
		ID: facts.id, StableID: name, Name: name, PublicKey: publicKey(name),
		Addresses: []netip.Prefix{facts.mesh}, AllowedIPs: []netip.Prefix{facts.mesh},
		Endpoints:   []netip.AddrPort{netip.AddrPortFrom(facts.underlay, wireGuardPort)},
		OnlineKnown: true, Online: true, KeyExpiry: time.Now().Add(24 * time.Hour), MachineAuthorized: true,
	}
}

// mapFor is the network map Core would send name while primary is the
// Site's primary router; revision orders the maps of one node.
func mapFor(name, primary string, revision uint64) networkmap.Snapshot {
	self := node(name)
	snapshot := networkmap.Snapshot{Revision: revision, NetworkName: "e2e", ControlTime: time.Now(), Self: self}
	if name == consumer {
		snapshot.Peers = []networkmap.Node{node(routerA), node(routerB)}
		route := networkmap.SiteRoute{
			Ref: siteRef, Prefixes: []netip.Prefix{sitePrefix}, Candidates: []string{routerA, routerB},
			Primary: primary, Generation: revision, Status: networkmap.RouteServed,
		}
		if primary == unserved {
			route.Primary, route.Status = "", networkmap.RouteUnserved
		}
		snapshot.Routes = []networkmap.SiteRoute{route}
		return snapshot
	}
	// A router: the consumer is its peer, it serves the Site with
	// masquerade, and the routed rule admits the consumer into it.
	snapshot.Peers = []networkmap.Node{node(consumer)}
	snapshot.Served = []networkmap.ServedSite{{Ref: siteRef, Prefixes: []netip.Prefix{sitePrefix}, Masquerade: true}}
	snapshot.Policy = []networkmap.Rule{{
		Sources: []networkmap.Selector{{Kind: networkmap.SelectorPrefix, Prefix: nodes[consumer].mesh}},
		Destinations: []networkmap.Destination{{
			Selector: networkmap.Selector{Kind: networkmap.SelectorPrefix, Prefix: sitePrefix}, PortFrom: 0, PortTo: 65535,
		}},
	}}
	return snapshot
}

// exitMapFor is the network map Core would send name in the exit scenario
// while the consumer's local choice is the exit node used (none: no exit
// node carries its traffic).
func exitMapFor(name, used string, revision uint64) networkmap.Snapshot {
	return exitMap([]string{consumer}, false, name, used, revision)
}

// spreadPrimaries are the consumers' primaries in the spread scenario, as
// Core's assignment would name them.
var spreadPrimaries = map[string]string{consumer: exitA, consumer2: exitB}

// spreadMapFor is the network map Core would send name in the spread
// scenario: the pool spreads both consumers over its exit nodes (exit node
// design §16), and used is name's local choice.
func spreadMapFor(name, used string, revision uint64) networkmap.Snapshot {
	return exitMap([]string{consumer, consumer2}, true, name, used, revision)
}

// exitMap is the network map Core would send name when consumers use the
// pool, spread or not, and used is a consumer's local choice.
func exitMap(consumers []string, spread bool, name, used string, revision uint64) networkmap.Snapshot {
	self := node(name)
	snapshot := networkmap.Snapshot{Revision: revision, NetworkName: "e2e", ControlTime: time.Now(), Self: self}
	if slices.Contains(consumers, name) {
		snapshot.Peers = []networkmap.Node{node(exitA), node(exitB)}
		pool := networkmap.ExitPool{Ref: poolRef, Name: "World", Primary: exitA, Generation: 1, Status: networkmap.ExitServed}
		if spread {
			pool.Primary, pool.Spread = spreadPrimaries[name], true
		}
		for _, exit := range []string{exitA, exitB} {
			pool.Candidates = append(pool.Candidates, networkmap.ExitCandidate{
				DeviceID: exit, State: networkmap.ExitStateOK, IPv4: true, DNS4: nodes[exit].mesh.Addr(),
			})
		}
		snapshot.Exits = []networkmap.ExitPool{pool}
		route := &networkmap.ExitRoute{Pool: poolRef}
		if used != none {
			route.Node = used
		}
		snapshot.ExitRoute = route
		return snapshot
	}
	// An exit node: the consumers are its peers and the pool's rule lets
	// them reach the whole Internet.
	var sources []networkmap.Selector
	for _, name := range consumers {
		snapshot.Peers = append(snapshot.Peers, node(name))
		sources = append(sources, networkmap.Selector{Kind: networkmap.SelectorPrefix, Prefix: nodes[name].mesh})
	}
	everywhere := func(prefix string) networkmap.Destination {
		return networkmap.Destination{
			Selector: networkmap.Selector{Kind: networkmap.SelectorPrefix, Prefix: netip.MustParsePrefix(prefix)},
			PortFrom: 0, PortTo: 65535,
		}
	}
	snapshot.ServedExits = []networkmap.ServedExit{{
		Ref: poolRef, ConntrackPerConsumer: 4096,
		Rules: []networkmap.Rule{{
			Sources:      sources,
			Destinations: []networkmap.Destination{everywhere("0.0.0.0/0"), everywhere("::/0")},
		}},
	}}
	return snapshot
}
