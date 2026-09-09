package pathdiscovery

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/meshtransit/meshd/internal/networkmap"
)

const defaultSTUNPort = 3478

// ServersFromRelayMap derives a bounded and deterministic probe set from the
// currently validated relay topology. It spreads probes across regions before
// adding another address from the same region.
func ServersFromRelayMap(
	relays map[int]networkmap.RelayRegion,
) ([]netip.AddrPort, error) {
	if len(relays) == 0 {
		return nil, ErrNoSTUNServers
	}

	regionIDs := make([]int, 0, len(relays))
	for id := range relays {
		regionIDs = append(regionIDs, id)
	}
	slices.Sort(regionIDs)

	byRegion := make([][]netip.AddrPort, 0, len(regionIDs))
	for _, id := range regionIDs {
		region := relays[id]
		if id <= 0 || region.ID != id {
			return nil, errors.New("pathdiscovery: relay region identity is invalid")
		}
		servers, err := relayRegionServers(region)
		if err != nil {
			return nil, err
		}
		if len(servers) != 0 {
			byRegion = append(byRegion, servers)
		}
	}

	servers := make([]netip.AddrPort, 0, maxSTUNServers)
	seen := make(map[netip.AddrPort]struct{}, maxSTUNServers)
	for offset := 0; len(servers) < maxSTUNServers; offset++ {
		added := false
		for _, regionServers := range byRegion {
			if offset >= len(regionServers) {
				continue
			}
			added = true
			server := regionServers[offset]
			if _, exists := seen[server]; exists {
				continue
			}
			seen[server] = struct{}{}
			servers = append(servers, server)
			if len(servers) == maxSTUNServers {
				break
			}
		}
		if !added {
			break
		}
	}
	if len(servers) == 0 {
		return nil, ErrNoSTUNServers
	}

	return servers, nil
}

func relayRegionServers(region networkmap.RelayRegion) ([]netip.AddrPort, error) {
	nodes := slices.Clone(region.Nodes)
	slices.SortFunc(nodes, func(left, right networkmap.RelayNode) int {
		if left.Name != right.Name {
			return compareText(left.Name, right.Name)
		}
		if left.HostName != right.HostName {
			return compareText(left.HostName, right.HostName)
		}
		if left.IPv4 != right.IPv4 {
			return compareText(left.IPv4, right.IPv4)
		}

		return compareText(left.IPv6, right.IPv6)
	})

	servers := make([]netip.AddrPort, 0, len(nodes)*2)
	for _, node := range nodes {
		if node.STUNPort < -1 || node.STUNPort > 65535 {
			return nil, errors.New("pathdiscovery: relay stun port is invalid")
		}
		if node.STUNPort < 0 {
			continue
		}
		port := node.STUNPort
		if port == 0 {
			port = defaultSTUNPort
		}
		for family, rawAddress := range []string{node.IPv4, node.IPv6} {
			if rawAddress == "" || rawAddress == "none" {
				continue
			}
			address, err := netip.ParseAddr(rawAddress)
			if err != nil || (family == 0 && !address.Is4()) ||
				(family == 1 && !address.Is6()) {
				return nil, errors.New("pathdiscovery: relay stun address is invalid")
			}
			server := netip.AddrPortFrom(address, uint16(port))
			if err := validateEndpoint(server); err != nil {
				return nil, fmt.Errorf("pathdiscovery: unsafe relay stun address: %w", err)
			}
			servers = append(servers, server)
		}
	}

	return servers, nil
}

func compareText(left, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}
