package mobile

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

// mobileDNS is the DNS the VPN interface carries (DNS design D4 §3.4): the
// in-process resolver as its only server, the plan's search domains, and
// the names an iOS tunnel sends it (all of them when match is empty).
type mobileDNS struct {
	on     bool
	search []string
	match  []string
}

func (dns mobileDNS) equal(other mobileDNS) bool {
	return dns.on == other.on && slices.Equal(dns.search, other.search) && slices.Equal(dns.match, other.match)
}

// interfaceDNS returns the DNS of an interface carrying exit: what the host
// configurator wants, and the in-process resolver whenever the Internet
// goes into the VPN, which nothing else may take off the interface (§3.4).
// Without an in-process resolver, the exit node's own resolvers.
func (opener *platformTUN) interfaceDNS(exit mobileExit, wanted mobileDNS) (mobileDNS, []netip.Addr) {
	if opener.answer == nil {
		return mobileDNS{}, exit.dns
	}
	if !wanted.on {
		wanted = mobileDNS{}
	}
	if len(exit.routes) != 0 {
		// Every name goes to the resolver, which sends the Internet's to
		// the exit node.
		wanted.on, wanted.match = true, nil
	}
	if !wanted.on {
		return mobileDNS{}, nil
	}
	return wanted, []netip.Addr{resolverAddress}
}

// setDNS gives the open interface the DNS the host configurator wants,
// making a new interface only when the DNS on it changes; with no
// interface open, the next one gets it.
func (opener *platformTUN) setDNS(ctx context.Context, wanted mobileDNS) error {
	opener.change.Lock()
	defer opener.change.Unlock()
	opener.mu.Lock()
	current, addresses, routes, routed, exit, installed := opener.open, opener.addresses, opener.routes,
		opener.routed, opener.exit, opener.dnsInstalled
	next, _ := opener.interfaceDNS(exit, wanted)
	if current == nil || current.isClosed() || next.equal(installed) {
		opener.dnsWanted = wanted
		opener.mu.Unlock()
		return nil
	}
	opener.mu.Unlock()
	// The wanted DNS is kept only once on the interface: a failed change
	// leaves the other rebuilds with the DNS the resolver still has.
	if err := current.Replace(func() (tun.Device, error) {
		return opener.openDevice(ctx, addresses, routes, routed, exit, wanted)
	}); err != nil {
		return fmt.Errorf("mobile: changing the interface dns: %w", err)
	}
	opener.mu.Lock()
	opener.dnsWanted = wanted
	if opener.open == current {
		opener.dnsInstalled = next
	}
	opener.mu.Unlock()
	return nil
}

// dnsOnInterface reports whether the open interface sends its DNS to the
// in-process resolver.
func (opener *platformTUN) dnsOnInterface() bool {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	return opener.open != nil && !opener.open.isClosed() && opener.dnsInstalled.on
}

// recordInstalled notes the DNS of the interface just opened for exit,
// when it is still the open one.
func (opener *platformTUN) recordInstalled(current *replaceableTUN, exit mobileExit) {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	if opener.open == current {
		opener.dnsInstalled, _ = opener.interfaceDNS(exit, opener.dnsWanted)
	}
}

// joinDomains writes names as the comma-separated list TunProvider receives.
func joinDomains(names []string) string {
	return strings.Join(names, ",")
}
