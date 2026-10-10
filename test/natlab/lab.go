package natlab

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"slices"
	"sync"

	"meshtransit.net/shared/disco"
)

// Profile is a named network position: the NATs between a host and the
// Internet, innermost first. No NATs means a host with a public address.
type Profile struct {
	Name string
	NATs []NATConfig
}

// Common profiles. Names follow RFC 4787 terms: eim/adm/apdm for mapping,
// eif/adf/apdf for filtering.
var (
	Public              = Profile{Name: "public"}
	FullCone            = cone("eim-eif", disco.FilteringEndpointIndependent)
	RestrictedCone      = cone("eim-adf", disco.FilteringAddressDependent)
	PortRestrictedCone  = cone("eim-apdf", disco.FilteringAddressAndPortDependent)
	SymmetricSequential = symmetric("apdm-apdf-seq", disco.AllocationSequential)
	SymmetricRandom     = symmetric("apdm-apdf-random", disco.AllocationRandom)
	// DoubleNAT is a home router behind a carrier-grade NAT that keeps
	// endpoint-independent mappings.
	DoubleNAT = Profile{Name: "cgnat-eim", NATs: []NATConfig{
		PortRestrictedCone.NATs[0],
		{Mapping: disco.MappingEndpointIndependent, Filtering: disco.FilteringAddressAndPortDependent, Allocation: disco.AllocationRandom},
	}}
	// CGNATSymmetric is a home router behind a symmetric carrier-grade NAT,
	// common on mobile networks.
	CGNATSymmetric = Profile{Name: "cgnat-apdm", NATs: []NATConfig{
		PortRestrictedCone.NATs[0],
		SymmetricRandom.NATs[0],
	}}
)

func cone(name string, f disco.Filtering) Profile {
	return Profile{Name: name, NATs: []NATConfig{{
		Mapping: disco.MappingEndpointIndependent, Filtering: f, Allocation: disco.AllocationPreserving,
	}}}
}

func symmetric(name string, a disco.Allocation) Profile {
	return Profile{Name: name, NATs: []NATConfig{{
		Mapping: disco.MappingAddressAndPortDependent, Filtering: disco.FilteringAddressAndPortDependent, Allocation: a,
	}}}
}

// Profiles returns the profiles of the traversal matrix.
func Profiles() []Profile {
	return []Profile{
		Public, FullCone, RestrictedCone, PortRestrictedCone,
		SymmetricSequential, SymmetricRandom, DoubleNAT, CGNATSymmetric,
	}
}

// Lab is an Internet with two RFC 5780 STUN servers, onto which nodes with
// different profiles are placed.
type Lab struct {
	Net *Network

	mu       sync.Mutex
	servers  []*STUNServer
	servers6 []*STUNServer
	public   int // last public host number handed out in 198.51.100.0/24
	carrier  int // last carrier NAT number handed out in 100.64.0.0/24
	site6    int // last IPv6 site prefix handed out in 2001:db8:100::/40
}

// STUN server addresses (documentation ranges, RFC 5737).
var (
	stunAddrs = [][2]netip.Addr{
		{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")},
		{netip.MustParseAddr("203.0.113.3"), netip.MustParseAddr("203.0.113.4")},
	}
	// stun6Addrs are the IPv6 STUN servers (documentation range, RFC 3849).
	stun6Addrs = [][2]netip.Addr{
		{netip.MustParseAddr("2001:db8:ffff::1"), netip.MustParseAddr("2001:db8:ffff::2")},
	}
	// LANHost is the address every node gets on its home LAN, so that
	// identical private candidates on both sides are part of every test.
	LANHost = netip.MustParseAddr("192.168.1.10")
)

// STUN ports.
const (
	STUNPort    = 3478
	STUNAltPort = 3479
)

// NewLab builds an Internet with its STUN servers. A nil clock means wall time.
func NewLab(clock Clock) (*Lab, error) {
	l := &Lab{Net: NewNetwork(clock)}
	for i, pair := range stunAddrs {
		h, err := l.Net.NewHost(fmt.Sprintf("stun%d", i+1), l.Net.Internet, pair[0], pair[1])
		if err != nil {
			l.Close()
			return nil, err
		}
		s, err := NewSTUNServer(h, STUNPort, STUNAltPort)
		if err != nil {
			l.Close()
			return nil, err
		}
		l.servers = append(l.servers, s)
	}
	for i, pair := range stun6Addrs {
		h, err := l.Net.NewHost(fmt.Sprintf("stun6-%d", i+1), l.Net.Internet, pair[0], pair[1])
		if err != nil {
			l.Close()
			return nil, err
		}
		s, err := NewSTUNServer(h, STUNPort, STUNAltPort)
		if err != nil {
			l.Close()
			return nil, err
		}
		l.servers6 = append(l.servers6, s)
	}
	return l, nil
}

// STUN6 returns the primary endpoints of the lab's IPv6 STUN servers.
func (l *Lab) STUN6() []netip.AddrPort {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]netip.AddrPort, 0, len(l.servers6))
	for _, s := range l.servers6 {
		out = append(out, s.Addr())
	}
	return out
}

// STUN returns the primary endpoints of the lab's STUN servers.
func (l *Lab) STUN() []netip.AddrPort {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]netip.AddrPort, 0, len(l.servers))
	for _, s := range l.servers {
		out = append(out, s.Addr())
	}
	return out
}

// Close stops the STUN servers.
func (l *Lab) Close() {
	l.mu.Lock()
	servers := slices.Concat(l.servers, l.servers6)
	l.servers, l.servers6 = nil, nil
	l.mu.Unlock()
	for _, s := range servers {
		s.Close()
	}
}

// AddNode places a host named name behind the NATs of p and returns it.
func (l *Lab) AddNode(name string, p Profile) (*Host, error) {
	node, err := l.AddHomeNode(name, p)
	return node.Host, err
}

// HomeNode is a host with its home router: the innermost NAT of its profile
// and the LAN segment they share. Router and LAN are nil for a public host.
type HomeNode struct {
	Host   *Host
	Router *NAT
	LAN    *Segment
}

// HomeGateway is the router's address on every home LAN.
var HomeGateway = netip.MustParseAddr("192.168.1.1")

// AddHomeNode is AddNode returning the home router and LAN too, so a test
// can add a gateway service (port mapping) at HomeGateway.
func (l *Lab) AddHomeNode(name string, p Profile) (HomeNode, error) {
	if len(p.NATs) == 0 {
		host, err := l.Net.NewHost(name, l.Net.Internet, l.nextPublic())
		return HomeNode{Host: host}, err
	}
	outside := l.Net.Internet
	var router *NAT
	for i := len(p.NATs) - 1; i >= 0; i-- {
		cfg := p.NATs[i]
		cfg.Seed = seed(name, p.Name, i)
		var ext netip.Addr
		if outside == l.Net.Internet {
			ext = l.nextPublic()
		} else {
			ext = l.nextCarrier()
		}
		nat, inside, err := l.Net.NewNAT(fmt.Sprintf("%s-nat%d", name, i), cfg, outside, ext)
		if err != nil {
			return HomeNode{}, err
		}
		router, outside = nat, inside
	}
	host, err := l.Net.NewHost(name, outside, LANHost)
	return HomeNode{Host: host, Router: router, LAN: outside}, err
}

// AddFirewalledNode places an IPv6-only host behind a stateful firewall
// with filtering f, as on an IPv6 home or mobile network: the host has a
// global address, but unsolicited inbound packets are dropped. The firewall
// is returned as the node's router.
func (l *Lab) AddFirewalledNode(name string, f disco.Filtering) (HomeNode, error) {
	l.mu.Lock()
	l.site6++
	site := l.site6
	l.mu.Unlock()
	prefix := netip.PrefixFrom(netip.AddrFrom16([16]byte{
		0x20, 0x01, 0x0d, 0xb8, 0x01, byte(site), //nolint:gosec // labs hold far fewer than 255 nodes
	}), 64)
	firewall, lan, err := l.Net.NewFirewall(name+"-fw", NATConfig{Filtering: f, Seed: seed(name, "ipv6")}, l.Net.Internet, prefix)
	if err != nil {
		return HomeNode{}, err
	}
	address := prefix.Addr().As16()
	address[15] = 0x10
	host, err := l.Net.NewHost(name, lan, netip.AddrFrom16(address))
	return HomeNode{Host: host, Router: firewall, LAN: lan}, err
}

func (l *Lab) nextPublic() netip.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.public++
	return netip.AddrFrom4([4]byte{198, 51, 100, byte(l.public)}) //nolint:gosec // labs hold far fewer than 255 nodes
}

func (l *Lab) nextCarrier() netip.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.carrier++
	return netip.AddrFrom4([4]byte{100, 64, 0, byte(l.carrier)}) //nolint:gosec // labs hold far fewer than 255 nodes
}

func seed(parts ...any) uint64 {
	h := fnv.New64a()
	_, _ = fmt.Fprint(h, parts...)
	return h.Sum64()
}
