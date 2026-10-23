package networkmap

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"meshtransit.net/client/internal/overlayframe"
	"meshtransit.net/shared/internet"
)

// Bounds of the Exit Pool a node serves (mtcp-v1 §7.7).
const (
	maxServedExits     = 1
	maxExitReference   = 64
	maxExitProbes      = 8
	maxExitUpstreams   = 4
	maxRelayTargets    = 256
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
	// DNSRelayTargets are the Internet resolvers of the Network's zones the
	// node's DNS forwarder relays consumers' questions to (DNS design D1c).
	DNSRelayTargets []netip.Addr
	// Rules admit the pool's consumers to the Internet: their destinations
	// are 0.0.0.0/0 and ::/0 only, and the exit node subtracts what is not
	// the Internet itself.
	Rules []Rule
}

// internetDestinations are the only destinations an exit rule names.
var internetDestinations = [...]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

// validateServedExits checks served as mtcp-v1 §7.7 requires: at most one
// pool with a valid reference, at most 8 Internet probes with a port, at most
// 4 distinct Internet resolvers, at most 256 distinct Internet relay targets,
// a connection limit within bounds and rules
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
		if len(pool.DNSRelayTargets) > maxRelayTargets {
			return fmt.Errorf("served Exit Pool %q has more than %d relay targets", pool.Ref, maxRelayTargets)
		}
		for index, target := range pool.DNSRelayTargets {
			if !internet.Contains(target) || slices.Contains(pool.DNSRelayTargets[:index], target) {
				return fmt.Errorf("served Exit Pool %q has a relay target off the Internet", pool.Ref)
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
		cloned[index].DNSRelayTargets = slices.Clone(pool.DNSRelayTargets)
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

// Bounds of the Exit Pools a node may use (mtcp-v1 §7.7).
const (
	maxExitPools      = 64
	maxExitCandidates = 16
)

// ExitStatus is what Core says a node may do with an Exit Pool.
type ExitStatus uint8

const (
	// ExitStatusUnknown is invalid in a map.
	ExitStatusUnknown ExitStatus = iota
	// ExitServed means send through the primary.
	ExitServed
	// ExitUnserved means granted, but no exit node can serve now.
	ExitUnserved
	// ExitCapacity means the exit nodes' maps cannot hold this node.
	ExitCapacity
)

// ExitCandidateState is an exit node's last health as Core heard it.
type ExitCandidateState uint8

const (
	// ExitStateUnknown: no recent report.
	ExitStateUnknown ExitCandidateState = iota
	ExitStateOK
	ExitStateDegraded
	ExitStateFailed
)

// ExitCandidate is one exit node of a pool (a peer by StableID).
type ExitCandidate struct {
	DeviceID string
	State    ExitCandidateState
	// IPv4 and IPv6 are the families it reaches the Internet in; both
	// false when not known.
	IPv4, IPv6 bool
	// DNS4 and DNS6 are the overlay addresses of its DNS forwarder; zero
	// when none.
	DNS4, DNS6 netip.Addr
	// Draining: the administrator is taking it out of the pool.
	Draining bool
}

// ExitPool is one Exit Pool the node may send its Internet traffic
// through (mtcp-v1 §7.7).
type ExitPool struct {
	Ref        string
	Name       string
	Candidates []ExitCandidate
	Primary    string // empty: none
	Generation uint64
	Status     ExitStatus
	// Managed: the administrator asks the node to use this pool; it
	// follows only when its own settings allow managed exits.
	Managed bool
	// Spread: Primary is the exit node Core assigned to this node, and
	// Candidates come in this node's own order (exit node design §16).
	Spread bool
	// CaptiveOff: root on this node may not open captive portal windows
	// while it uses the pool (exit node design §17.4).
	CaptiveOff bool
}

// validateExits checks exits as mtcp-v1 §7.7 requires: at most 64 pools,
// sorted by reference and listed once, each with 1 to 16 distinct
// candidates other than self, known states, a primary among them, and a
// primary whenever SERVED.
func validateExits(exits []ExitPool, self string) error {
	if len(exits) > maxExitPools {
		return fmt.Errorf("more than %d Exit Pools", maxExitPools)
	}
	for index, pool := range exits {
		if pool.Ref == "" || len(pool.Ref) > maxExitReference || !utf8.ValidString(pool.Ref) ||
			(index > 0 && exits[index-1].Ref >= pool.Ref) {
			return errors.New("exit pool references must be valid, sorted and listed once")
		}
		if pool.Name == "" || utf8.RuneCountInString(pool.Name) > 64 || !utf8.ValidString(pool.Name) ||
			strings.IndexFunc(pool.Name, unicode.IsControl) >= 0 {
			return fmt.Errorf("exit pool %q has an invalid name", pool.Ref)
		}
		if len(pool.Candidates) == 0 || len(pool.Candidates) > maxExitCandidates {
			return fmt.Errorf("exit pool %q has no or too many candidates", pool.Ref)
		}
		for position, candidate := range pool.Candidates {
			if candidate.DeviceID == "" || candidate.DeviceID == self || candidate.State > ExitStateFailed ||
				slices.ContainsFunc(pool.Candidates[:position], func(other ExitCandidate) bool {
					return other.DeviceID == candidate.DeviceID
				}) {
				return fmt.Errorf("exit pool %q candidates must be distinct peers", pool.Ref)
			}
			if (candidate.DNS4.IsValid() && !candidate.DNS4.Is4()) || (candidate.DNS6.IsValid() && !candidate.DNS6.Is6()) {
				return fmt.Errorf("exit pool %q has a malformed DNS address", pool.Ref)
			}
		}
		if (pool.Primary != "" && !slices.ContainsFunc(pool.Candidates, func(candidate ExitCandidate) bool {
			return candidate.DeviceID == pool.Primary
		})) || (pool.Status == ExitServed && pool.Primary == "") ||
			pool.Status < ExitServed || pool.Status > ExitCapacity {
			return fmt.Errorf("exit pool %q has an invalid primary or status", pool.Ref)
		}
	}
	return nil
}

func cloneExits(exits []ExitPool) []ExitPool {
	if exits == nil {
		return nil
	}
	cloned := make([]ExitPool, len(exits))
	for index, pool := range exits {
		cloned[index] = pool
		cloned[index].Candidates = slices.Clone(pool.Candidates)
	}
	return cloned
}

// ExitRoute is the exit node a node chose to send its Internet traffic
// through.
type ExitRoute struct {
	// Pool is the chosen pool's reference.
	Pool string
	// Node is the exit node (a device ID), a candidate of Pool; empty while
	// none can carry the traffic, which is then dropped rather than sent
	// outside the mesh.
	Node string
	// IPv6 is whether the exit node carries IPv6 too; otherwise the node's
	// IPv6 Internet traffic is refused.
	IPv6 bool
}

// ExitResolvers returns the addresses the chosen exit node's DNS forwarder
// answers on: its DNS4 and DNS6 when each is one of the node's own mesh
// addresses, inside the overlay frame; Core's addresses are no reason to
// send names anywhere else (exit node design §7.2). None while no exit node
// carries the traffic.
func (s Snapshot) ExitResolvers() []netip.Addr {
	route := s.ExitRoute
	if route == nil || route.Node == "" {
		return nil
	}
	var own []netip.Prefix
	for _, peer := range s.Peers {
		if peer.StableID == route.Node {
			own = peer.Addresses
		}
	}
	var resolvers []netip.Addr
	for _, pool := range s.Exits {
		if pool.Ref != route.Pool {
			continue
		}
		for _, candidate := range pool.Candidates {
			if candidate.DeviceID != route.Node {
				continue
			}
			for _, address := range []netip.Addr{candidate.DNS4, candidate.DNS6} {
				host := netip.PrefixFrom(address, address.BitLen())
				if address.IsValid() && slices.Contains(own, host) && overlayframe.Contains(host) {
					resolvers = append(resolvers, address)
				}
			}
		}
	}
	return resolvers
}

// validateExitRoute requires a chosen exit node to be a candidate of a
// pool of exits.
func validateExitRoute(route *ExitRoute, exits []ExitPool) error {
	if route == nil || route.Node == "" {
		return nil // none carries the traffic: any pool, even one not granted
	}
	index := slices.IndexFunc(exits, func(pool ExitPool) bool { return pool.Ref == route.Pool })
	if index < 0 {
		return errors.New("the chosen exit pool is not granted")
	}
	if route.Node != "" && !slices.ContainsFunc(exits[index].Candidates, func(candidate ExitCandidate) bool {
		return candidate.DeviceID == route.Node
	}) {
		return errors.New("the chosen exit node is not a candidate of its pool")
	}
	return nil
}

// ExitCaptiveOff reports whether the pool the node chose turns captive
// portal windows off.
func (s Snapshot) ExitCaptiveOff() bool {
	if s.ExitRoute == nil {
		return false
	}
	for _, pool := range s.Exits {
		if pool.Ref == s.ExitRoute.Pool {
			return pool.CaptiveOff
		}
	}
	return false
}
