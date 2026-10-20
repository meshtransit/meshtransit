package networkmap

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"unicode/utf8"

	"meshtransit.net/shared/internet"
)

// Bounds of the Exit Pool a node serves (mtcp-v1 §7.7).
const (
	maxServedExits     = 1
	maxExitReference   = 64
	maxExitProbes      = 8
	maxExitUpstreams   = 4
	minExitConntrack   = 1024
	maxExitConntrack   = 262144
	maxServedExitRules = 1024
)

// ServedExit is the Exit Pool the node forwards other Devices' Internet
// traffic for as an exit node (mtcp-v1 §7.7).
type ServedExit struct {
	Ref string
	// Probes are Internet addresses and TCP ports the exit node connects to
	// through its own forwarding path.
	Probes []netip.AddrPort
	// ConntrackPerConsumer is Core's limit of one consumer's connections;
	// the host's settings only lower it.
	ConntrackPerConsumer int
	// SMTPAllowed is Core's permission for TCP port 25; the host's settings
	// may refuse it.
	SMTPAllowed bool
	// DNSUpstreams are Internet resolvers, tried in order.
	DNSUpstreams []netip.Addr
	// Rules admit the pool's consumers to the Internet: their destinations
	// are 0.0.0.0/0 and ::/0 only, and the exit node subtracts what is not
	// the Internet itself.
	Rules []Rule
}

// internetDestinations are the only destinations an exit rule names.
var internetDestinations = [...]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

// validateServedExits checks served as mtcp-v1 §7.7 requires: at most one
// pool with a valid reference, at most 8 Internet probes with a port, at most
// 4 distinct Internet resolvers, a connection limit within bounds and rules
// whose destinations are 0.0.0.0/0 or ::/0.
func validateServedExits(served []ServedExit) error {
	if len(served) > maxServedExits {
		return fmt.Errorf("more than %d served Exit Pools", maxServedExits)
	}
	for _, pool := range served {
		if pool.Ref == "" || len(pool.Ref) > maxExitReference || !utf8.ValidString(pool.Ref) {
			return errors.New("served Exit Pool reference is invalid")
		}
		if pool.ConntrackPerConsumer < minExitConntrack || pool.ConntrackPerConsumer > maxExitConntrack {
			return fmt.Errorf("served Exit Pool %q has an invalid connection limit", pool.Ref)
		}
		if len(pool.Probes) > maxExitProbes {
			return fmt.Errorf("served Exit Pool %q has more than %d probes", pool.Ref, maxExitProbes)
		}
		for _, probe := range pool.Probes {
			if !internet.Contains(probe.Addr()) || probe.Port() == 0 {
				return fmt.Errorf("served Exit Pool %q has a probe off the Internet", pool.Ref)
			}
		}
		if len(pool.DNSUpstreams) > maxExitUpstreams {
			return fmt.Errorf("served Exit Pool %q has more than %d resolvers", pool.Ref, maxExitUpstreams)
		}
		for index, upstream := range pool.DNSUpstreams {
			if !internet.Contains(upstream) || slices.Contains(pool.DNSUpstreams[:index], upstream) {
				return fmt.Errorf("served Exit Pool %q has a resolver off the Internet", pool.Ref)
			}
		}
		if len(pool.Rules) > maxServedExitRules {
			return fmt.Errorf("served Exit Pool %q has too many rules", pool.Ref)
		}
		for _, rule := range pool.Rules {
			if len(rule.Sources) == 0 || len(rule.Destinations) == 0 {
				return fmt.Errorf("served Exit Pool %q has an empty rule", pool.Ref)
			}
			for _, destination := range rule.Destinations {
				if destination.Selector.Kind != SelectorPrefix ||
					!slices.Contains(internetDestinations[:], destination.Selector.Prefix) {
					return fmt.Errorf("served Exit Pool %q has a rule to an address", pool.Ref)
				}
			}
			for _, source := range rule.Sources {
				if source.Kind != SelectorPrefix || !source.Prefix.IsSingleIP() {
					return fmt.Errorf("served Exit Pool %q has a rule from a range", pool.Ref)
				}
			}
		}
	}
	return nil
}

func cloneServedExits(served []ServedExit) []ServedExit {
	if served == nil {
		return nil
	}
	cloned := make([]ServedExit, len(served))
	for index, pool := range served {
		cloned[index] = pool
		cloned[index].Probes = slices.Clone(pool.Probes)
		cloned[index].DNSUpstreams = slices.Clone(pool.DNSUpstreams)
		cloned[index].Rules = make([]Rule, len(pool.Rules))
		for position, rule := range pool.Rules {
			cloned[index].Rules[position] = Rule{
				Sources:      slices.Clone(rule.Sources),
				Destinations: slices.Clone(rule.Destinations), Protocols: slices.Clone(rule.Protocols),
			}
		}
	}
	return cloned
}
