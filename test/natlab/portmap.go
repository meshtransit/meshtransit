package natlab

import (
	"errors"
	"net/netip"
	"time"
)

// ErrNoPortMapping reports a NAT that cannot hold the requested mapping.
var ErrNoPortMapping = errors.New("natlab: port mapping unavailable")

// External returns the NAT's outside address; invalid for a firewall.
func (n *NAT) External() netip.Addr { return n.ext }

// AddPortMapping installs or renews an explicit mapping for internal, as a
// router does for a PCP, NAT-PMP or UPnP request. The mapping uses suggested
// when it is free, admits every remote and lives for lifetime. It returns
// the external endpoint.
func (n *NAT) AddPortMapping(internal netip.AddrPort, suggested uint16, lifetime time.Duration) (netip.AddrPort, error) {
	if !n.ext.IsValid() || lifetime <= 0 {
		return netip.AddrPort{}, ErrNoPortMapping
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.clock.Now()
	if m, ok := n.explicit[internal]; ok && !n.expired(m, now) {
		m.expires = now.Add(lifetime)
		return m.external, nil
	}
	port := suggested
	if !n.free(port) {
		var ok bool
		if port, ok = n.allocate(internal.Port()); !ok {
			return netip.AddrPort{}, ErrNoPortMapping
		}
	}
	m := &mapping{
		key:      mapKey{internal: internal},
		external: netip.AddrPortFrom(n.ext, port),
		permits:  make(map[netip.AddrPort]struct{}),
		lastOut:  now,
		explicit: true,
		expires:  now.Add(lifetime),
	}
	n.explicit[internal] = m
	n.byExt[m.external] = m
	return m.external, nil
}

// RemovePortMapping deletes the explicit mapping for internal, if any.
func (n *NAT) RemovePortMapping(internal netip.AddrPort) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if m, ok := n.explicit[internal]; ok {
		n.remove(m)
	}
}
