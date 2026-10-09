package natlab

import (
	"errors"
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"

	"meshtransit.net/shared/disco"
)

// NAT defaults. RFC 4787 REQ-5 asks for a UDP mapping timeout of at least two
// minutes.
const (
	DefaultMappingTimeout = 2 * time.Minute
	DefaultMaxMappings    = 8192
	defaultPortMin        = 1024
	defaultPortMax        = 65535
	randomAttempts        = 64
)

// NATConfig describes a NAT or, with MappingNone, a stateful firewall.
type NATConfig struct {
	Mapping    disco.Mapping    // MappingNone: forward without translation (firewall)
	Filtering  disco.Filtering  // inbound filter for established mappings
	Allocation disco.Allocation // external port choice (ignored by firewalls)
	Hairpin    bool             // deliver inside→own-outside-address packets back inside
	Timeout    time.Duration    // idle mapping lifetime, refreshed by outbound packets
	PortMin    uint16
	PortMax    uint16
	// MaxMappings bounds state; new flows are dropped when it is reached.
	MaxMappings int
	Seed        uint64 // seeds random and sequential allocation
}

// NAT translates between an inside and an outside segment.
type NAT struct {
	cfg     NATConfig
	clock   Clock
	inside  *Segment
	outside *Segment
	ext     netip.Addr // outside address; invalid for a firewall

	mu       sync.Mutex
	byKey    map[mapKey]*mapping
	byExt    map[netip.AddrPort]*mapping
	nextPort uint16
	rng      *rand.Rand
}

// mapKey selects a mapping: the internal endpoint plus the part of the
// destination the mapping behaviour depends on.
type mapKey struct {
	internal netip.AddrPort
	remote   netip.AddrPort
}

type mapping struct {
	key      mapKey
	external netip.AddrPort
	permits  map[netip.AddrPort]struct{} // remotes allowed in (ADF: port 0)
	lastOut  time.Time
}

type natInside struct{ n *NAT }

func (i natInside) receive(p packet) { i.n.outbound(p) }

type natOutside struct{ n *NAT }

func (o natOutside) receive(p packet) { o.n.inbound(p) }

// NewNAT creates a NAT whose outside address ext is attached to outside.
// It returns the NAT and its new inside segment.
func (n *Network) NewNAT(name string, cfg NATConfig, outside *Segment, ext netip.Addr) (*NAT, *Segment, error) {
	if cfg.Mapping == disco.MappingNone || cfg.Mapping == disco.MappingUnknown {
		return nil, nil, errors.New("natlab: NAT needs a translating mapping; use NewFirewall")
	}
	if err := validFiltering(cfg.Filtering); err != nil {
		return nil, nil, err
	}
	nat := n.newNAT(name, cfg, outside)
	nat.ext = ext.Unmap()
	if err := outside.attach(nat.ext, natOutside{nat}); err != nil {
		return nil, nil, err
	}
	return nat, nat.inside, nil
}

// NewFirewall creates a stateful firewall routing prefix from outside to a
// new inside segment, as an IPv6 home router does.
func (n *Network) NewFirewall(name string, cfg NATConfig, outside *Segment, prefix netip.Prefix) (*NAT, *Segment, error) {
	if err := validFiltering(cfg.Filtering); err != nil {
		return nil, nil, err
	}
	cfg.Mapping = disco.MappingNone
	nat := n.newNAT(name, cfg, outside)
	outside.addRoute(prefix, natOutside{nat})
	return nat, nat.inside, nil
}

// validFiltering rejects an unset filtering behaviour, which would silently
// drop every inbound packet.
func validFiltering(f disco.Filtering) error {
	if f < disco.FilteringEndpointIndependent || f > disco.FilteringAddressAndPortDependent {
		return errors.New("natlab: NAT filtering must be set")
	}
	return nil
}

func (n *Network) newNAT(name string, cfg NATConfig, outside *Segment) *NAT {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultMappingTimeout
	}
	if cfg.PortMin == 0 {
		cfg.PortMin = defaultPortMin
	}
	if cfg.PortMax == 0 || cfg.PortMax < cfg.PortMin {
		cfg.PortMax = defaultPortMax
	}
	if cfg.MaxMappings <= 0 {
		cfg.MaxMappings = DefaultMaxMappings
	}
	nat := &NAT{
		cfg:     cfg,
		clock:   n.clock,
		outside: outside,
		byKey:   make(map[mapKey]*mapping),
		byExt:   make(map[netip.AddrPort]*mapping),
		rng:     rand.New(rand.NewPCG(cfg.Seed, cfg.Seed^0x9e3779b97f4a7c15)), //nolint:gosec // reproducible port allocation, not secrets
	}
	nat.nextPort = nat.randomPort()
	nat.inside = n.NewSegment(name + "-inside")
	// A fresh segment has no gateway, so this cannot fail.
	_ = nat.inside.setGateway(natInside{nat})
	return nat
}

// Mappings returns the number of live mappings.
func (n *NAT) Mappings() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.clock.Now()
	live := 0
	for _, m := range n.byKey {
		if !n.expired(m, now) {
			live++
		}
	}
	return live
}

func (n *NAT) outbound(p packet) {
	if p.dst.Addr() == n.ext && !n.cfg.Hairpin {
		return
	}
	n.mu.Lock()
	now := n.clock.Now()
	m := n.mappingFor(p.src, p.dst, now)
	if m == nil {
		n.mu.Unlock()
		return // port space or state table exhausted
	}
	m.lastOut = now
	if k, ok := n.permitKey(p.dst); ok {
		m.permits[k] = struct{}{}
	}
	p.src = m.external
	n.mu.Unlock()
	n.outside.send(p)
}

func (n *NAT) inbound(p packet) {
	n.mu.Lock()
	now := n.clock.Now()
	m, ok := n.byExt[p.dst]
	if ok && n.expired(m, now) {
		n.remove(m)
		ok = false
	}
	if !ok || !n.permitted(m, p.src) {
		n.mu.Unlock()
		return
	}
	p.dst = m.key.internal
	n.mu.Unlock()
	n.inside.send(p)
}

// mappingFor finds or creates the mapping for a flow. Called with n.mu held.
func (n *NAT) mappingFor(src, dst netip.AddrPort, now time.Time) *mapping {
	key := mapKey{internal: src}
	switch n.cfg.Mapping {
	case disco.MappingAddressDependent:
		key.remote = netip.AddrPortFrom(dst.Addr(), 0)
	case disco.MappingAddressAndPortDependent:
		key.remote = dst
	}
	if m, ok := n.byKey[key]; ok {
		if !n.expired(m, now) {
			return m
		}
		n.remove(m)
	}
	if len(n.byKey) >= n.cfg.MaxMappings {
		n.sweep(now)
		if len(n.byKey) >= n.cfg.MaxMappings {
			return nil
		}
	}
	external := src // firewall: addresses pass unchanged
	if n.ext.IsValid() {
		port, ok := n.allocate(src.Port())
		if !ok {
			return nil
		}
		external = netip.AddrPortFrom(n.ext, port)
	}
	if _, taken := n.byExt[external]; taken {
		return nil // firewall: the same internal endpoint already has state
	}
	m := &mapping{key: key, external: external, permits: make(map[netip.AddrPort]struct{}), lastOut: now}
	n.byKey[key] = m
	n.byExt[external] = m
	return m
}

func (n *NAT) permitKey(remote netip.AddrPort) (netip.AddrPort, bool) {
	switch n.cfg.Filtering {
	case disco.FilteringAddressDependent:
		return netip.AddrPortFrom(remote.Addr(), 0), true
	case disco.FilteringAddressAndPortDependent:
		return remote, true
	default:
		return netip.AddrPort{}, false
	}
}

func (n *NAT) permitted(m *mapping, remote netip.AddrPort) bool {
	k, filtered := n.permitKey(remote)
	if !filtered {
		return n.cfg.Filtering == disco.FilteringEndpointIndependent
	}
	_, ok := m.permits[k]
	return ok
}

func (n *NAT) expired(m *mapping, now time.Time) bool {
	return now.Sub(m.lastOut) > n.cfg.Timeout
}

func (n *NAT) remove(m *mapping) {
	delete(n.byKey, m.key)
	delete(n.byExt, m.external)
}

func (n *NAT) sweep(now time.Time) {
	for _, m := range n.byKey {
		if n.expired(m, now) {
			n.remove(m)
		}
	}
}

// allocate picks a free external port. Called with n.mu held.
func (n *NAT) allocate(internal uint16) (uint16, bool) {
	switch n.cfg.Allocation {
	case disco.AllocationPreserving:
		if n.free(internal) {
			return internal, true
		}
		return n.sequential()
	case disco.AllocationSequential:
		return n.sequential()
	default:
		for range randomAttempts {
			if p := n.randomPort(); n.free(p) {
				return p, true
			}
		}
		n.nextPort = n.randomPort()
		return n.sequential()
	}
}

func (n *NAT) sequential() (uint16, bool) {
	span := int(n.cfg.PortMax-n.cfg.PortMin) + 1
	for range span {
		p := n.nextPort
		if n.nextPort == n.cfg.PortMax {
			n.nextPort = n.cfg.PortMin
		} else {
			n.nextPort++
		}
		if n.free(p) {
			return p, true
		}
	}
	return 0, false
}

func (n *NAT) randomPort() uint16 {
	span := uint32(n.cfg.PortMax-n.cfg.PortMin) + 1
	return n.cfg.PortMin + uint16(n.rng.Uint32N(span)) //nolint:gosec // span ≤ 65536, result < span
}

func (n *NAT) free(port uint16) bool {
	if port < n.cfg.PortMin || port > n.cfg.PortMax {
		return false
	}
	_, used := n.byExt[netip.AddrPortFrom(n.ext, port)]
	return !used
}
