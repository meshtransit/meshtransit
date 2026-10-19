//go:build e2e && linux

package subnetrouter

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"time"

	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/networkmap"
)

// The nodes of the topology, their mesh and underlay addresses, and the
// Site behind the routers.
const (
	consumer = "consumer"
	routerA  = "router-a"
	routerB  = "router-b"
	siteRef  = "lab"
	// unserved, as a consumer's primary, is a map where no router can serve
	// the Site.
	unserved = "unserved"
	// wireGuardPort is each node's listen port, in its own namespace.
	wireGuardPort = 41641
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
	}
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
