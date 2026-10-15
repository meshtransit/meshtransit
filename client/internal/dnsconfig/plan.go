// Package dnsconfig compiles validated network maps into deterministic DNS
// plans without depending on a control-protocol or operating-system backend.
package dnsconfig

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"meshtransit.net/client/internal/networkmap"
)

var ErrInvalid = errors.New("dnsconfig: invalid plan")

const maxAddressesPerHost = 32

// sharedZone holds the names of shared Devices. One locally authoritative
// route covers all of them, so the number of shares never reaches the
// host's route limit, and an unknown shared name is answered NXDOMAIN
// instead of leaving for the host's resolvers.
const sharedZone = "shared.mesh"

// Plan is an immutable-by-convention DNS configuration ready for a local
// resolver and an operating-system configurator.
type Plan struct {
	Revision          uint64
	Enabled           bool
	Proxied           bool
	DefaultResolvers  []netip.AddrPort
	FallbackResolvers []netip.AddrPort
	Routes            []Route
	SearchDomains     []string
	Hosts             []Host
	Reverse           []Reverse
}

// Route is one canonical suffix and its ordered resolver set. An empty
// Resolvers slice marks a locally authoritative suffix.
type Route struct {
	Suffix    string
	Resolvers []netip.AddrPort
}

// Host groups all address records for one canonical DNS name.
type Host struct {
	Name      string
	Addresses []netip.Addr
}

// Reverse maps one node address to its canonical node name. Extra records do
// not create reverse mappings because control supplied only forward records.
type Reverse struct {
	Address netip.Addr
	Name    string
}

// Compile turns one already-validated network snapshot into a deterministic,
// defensively-owned DNS plan. It rejects ambiguous local names and ensures
// every local record is covered by a locally authoritative route.
func Compile(snapshot networkmap.Snapshot) (Plan, error) {
	plan := Plan{Revision: snapshot.Revision}
	if snapshot.DNS == nil {
		return plan, nil
	}

	config := snapshot.DNS
	plan.Proxied = config.Proxied
	plan.DefaultResolvers = resolverAddresses(config.Resolvers)
	plan.FallbackResolvers = resolverAddresses(config.FallbackResolvers)
	plan.Routes = make([]Route, len(config.Routes))
	for index, route := range config.Routes {
		plan.Routes[index] = Route{
			Suffix:    route.Suffix,
			Resolvers: resolverAddresses(route.Resolvers),
		}
	}
	plan.SearchDomains = append([]string(nil), config.SearchDomains...)

	hosts := make(map[string][]netip.Addr)
	for _, record := range config.Records {
		if err := addHostAddress(hosts, record.Name, record.Address); err != nil {
			return Plan{}, err
		}
	}
	if config.Proxied {
		nodes := make([]networkmap.Node, 0, len(snapshot.Peers)+1)
		nodes = append(nodes, snapshot.Self)
		nodes = append(nodes, snapshot.Peers...)
		seenNodeNames := make(map[string]struct{}, len(nodes))
		for _, node := range nodes {
			name, err := canonicalNodeName(node.Name)
			if err != nil {
				return Plan{}, fmt.Errorf("%w: node %d name: %w", ErrInvalid, node.ID, err)
			}
			if _, exists := seenNodeNames[name]; exists {
				return Plan{}, fmt.Errorf("%w: duplicate node dns name %q", ErrInvalid, name)
			}
			seenNodeNames[name] = struct{}{}
			if _, collides := hosts[name]; collides {
				return Plan{}, fmt.Errorf("%w: extra record shadows node name %q", ErrInvalid, name)
			}
			for _, prefix := range node.Addresses {
				address := prefix.Addr().Unmap()
				if err := addHostAddress(hosts, name, address); err != nil {
					return Plan{}, err
				}
				plan.Reverse = append(plan.Reverse, Reverse{Address: address, Name: name})
			}
		}
	}

	hostNames := make([]string, 0, len(hosts))
	for name := range hosts {
		hostNames = append(hostNames, name)
	}
	sort.Strings(hostNames)
	for _, name := range hostNames {
		addresses := hosts[name]
		if len(addresses) > maxAddressesPerHost {
			return Plan{}, fmt.Errorf(
				"%w: host %q has more than %d addresses",
				ErrInvalid,
				name,
				maxAddressesPerHost,
			)
		}
		slices.SortFunc(addresses, func(left, right netip.Addr) int {
			return left.Compare(right)
		})
		plan.Hosts = append(plan.Hosts, Host{Name: name, Addresses: addresses})
		if !locallyAuthoritative(plan.Routes, name) && dnsSuffixContains(sharedZone, name) && name != sharedZone &&
			!hasRouteSuffix(plan.Routes, sharedZone) {
			plan.Routes = append(plan.Routes, Route{Suffix: sharedZone, Resolvers: []netip.AddrPort{}})
		}
		if !locallyAuthoritative(plan.Routes, name) {
			if _, isNode := findReverseName(plan.Reverse, name); isNode {
				return Plan{}, fmt.Errorf(
					"%w: node name %q has no locally authoritative route",
					ErrInvalid,
					name,
				)
			}
			plan.Routes = append(plan.Routes, Route{Suffix: name, Resolvers: []netip.AddrPort{}})
		}
	}
	sort.Slice(plan.Routes, func(left, right int) bool {
		return plan.Routes[left].Suffix < plan.Routes[right].Suffix
	})
	sort.Slice(plan.Reverse, func(left, right int) bool {
		return plan.Reverse[left].Address.Compare(plan.Reverse[right].Address) < 0
	})
	for _, domain := range plan.SearchDomains {
		if len(plan.DefaultResolvers) == 0 && !hasRoute(plan.Routes, domain) {
			return Plan{}, fmt.Errorf(
				"%w: search domain %q has no resolver route",
				ErrInvalid,
				domain,
			)
		}
	}
	plan.Enabled = len(plan.DefaultResolvers) != 0 || len(plan.Routes) != 0 ||
		len(plan.SearchDomains) != 0 || len(plan.Hosts) != 0

	return plan, nil
}

func resolverAddresses(resolvers []networkmap.DNSResolver) []netip.AddrPort {
	addresses := make([]netip.AddrPort, len(resolvers))
	for index, resolver := range resolvers {
		addresses[index] = resolver.Address
	}

	return addresses
}

func addHostAddress(hosts map[string][]netip.Addr, name string, address netip.Addr) error {
	for _, existing := range hosts[name] {
		if existing == address {
			return fmt.Errorf("%w: duplicate address for %q", ErrInvalid, name)
		}
	}
	hosts[name] = append(hosts[name], address)

	return nil
}

func canonicalNodeName(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(raw, "."))
	if name == "" || len(name) > 253 || strings.HasSuffix(name, ".") {
		return "", errors.New("name is empty or too long")
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("label is malformed")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') && character != '-' {
				return "", errors.New("label contains an unsupported character")
			}
		}
	}

	return name, nil
}

func locallyAuthoritative(routes []Route, name string) bool {
	bestLength := -1
	local := false
	for _, route := range routes {
		if !dnsSuffixContains(route.Suffix, name) || len(route.Suffix) < bestLength {
			continue
		}
		bestLength = len(route.Suffix)
		local = len(route.Resolvers) == 0
	}

	return bestLength >= 0 && local
}

func dnsSuffixContains(suffix, name string) bool {
	return suffix == "." || name == suffix || strings.HasSuffix(name, "."+suffix)
}

func findReverseName(records []Reverse, name string) (Reverse, bool) {
	for _, record := range records {
		if record.Name == name {
			return record, true
		}
	}

	return Reverse{}, false
}

func hasRouteSuffix(routes []Route, suffix string) bool {
	return slices.ContainsFunc(routes, func(route Route) bool { return route.Suffix == suffix })
}

func hasRoute(routes []Route, name string) bool {
	return slices.ContainsFunc(routes, func(route Route) bool {
		return dnsSuffixContains(route.Suffix, name)
	})
}
