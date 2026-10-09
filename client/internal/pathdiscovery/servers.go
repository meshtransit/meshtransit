package pathdiscovery

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"meshtransit.net/client/internal/networkmap"
)

const (
	defaultSTUNPort   = 3478
	maxKnownSTUNNodes = 2_048
)

// RelayServer binds one control-authorized STUN endpoint to its relay region.
// The region association is used only for reachability and latency selection.
type RelayServer struct {
	RegionID int
	Endpoint netip.AddrPort
}

// ServersFromRelayMap derives a bounded and deterministic probe set from the
// currently validated relay topology. It spreads probes across regions before
// adding another address from the same region.
func ServersFromRelayMap(
	relays map[int]networkmap.RelayRegion,
) ([]RelayServer, error) {
	if len(relays) == 0 {
		return nil, ErrNoSTUNServers
	}

	regionIDs := make([]int, 0, len(relays))
	for id := range relays {
		regionIDs = append(regionIDs, id)
	}
	slices.Sort(regionIDs)

	byRegion := make([][]RelayServer, 0, len(regionIDs))
	for _, id := range regionIDs {
		region := relays[id]
		if id <= 0 || region.ID != id {
			return nil, errors.New("pathdiscovery: relay region identity is invalid")
		}
		endpoints, err := relayRegionServers(region)
		if err != nil {
			return nil, err
		}
		servers := make([]RelayServer, 0, len(endpoints))
		for _, endpoint := range endpoints {
			servers = append(servers, RelayServer{
				RegionID: id,
				Endpoint: endpoint,
			})
		}
		if len(servers) != 0 {
			byRegion = append(byRegion, servers)
		}
	}

	servers := make([]RelayServer, 0, min(len(relays)*2, maxKnownSTUNNodes))
	seen := make(map[netip.AddrPort]struct{}, maxKnownSTUNNodes)
	for offset := 0; len(servers) < maxKnownSTUNNodes; offset++ {
		added := false
		for _, regionServers := range byRegion {
			if offset >= len(regionServers) {
				continue
			}
			added = true
			server := regionServers[offset]
			if _, exists := seen[server.Endpoint]; exists {
				continue
			}
			seen[server.Endpoint] = struct{}{}
			servers = append(servers, server)
			if len(servers) == maxKnownSTUNNodes {
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

// NextServerBatch returns one bounded rotating probe batch. A usable current
// home region is sampled through each available address family every round
// while the remaining slots walk the full signed topology without unbounded
// fan-out.
func NextServerBatch(
	servers []RelayServer,
	homeRegion int,
	cursor int,
) ([]RelayServer, int, error) {
	if len(servers) == 0 {
		return nil, 0, nil
	}
	if len(servers) > maxKnownSTUNNodes || cursor < 0 {
		return nil, 0, ErrInvalidSTUNServers
	}
	seen := make(map[netip.AddrPort]struct{}, min(len(servers), maxSTUNServers))
	for _, server := range servers {
		if server.RegionID <= 0 || validateEndpoint(server.Endpoint) != nil {
			return nil, 0, ErrInvalidSTUNServers
		}
		if _, exists := seen[server.Endpoint]; exists {
			return nil, 0, ErrInvalidSTUNServers
		}
		seen[server.Endpoint] = struct{}{}
	}

	cursor %= len(servers)
	batch := make([]RelayServer, 0, min(len(servers), maxSTUNServers))
	selected := make(map[netip.AddrPort]struct{}, cap(batch))
	if homeRegion > 0 {
		var homeIPv4Selected, homeIPv6Selected bool
		for offset := range len(servers) {
			server := servers[(cursor+offset)%len(servers)]
			if server.RegionID != homeRegion {
				continue
			}

			switch {
			case server.Endpoint.Addr().Is4():
				if homeIPv4Selected {
					continue
				}
				homeIPv4Selected = true
			case server.Endpoint.Addr().Is6():
				if homeIPv6Selected {
					continue
				}
				homeIPv6Selected = true
			}
			batch = append(batch, server)
			selected[server.Endpoint] = struct{}{}
			if homeIPv4Selected && homeIPv6Selected {
				break
			}
		}
	}

	visited := 0
	for visited < len(servers) && len(batch) < maxSTUNServers {
		server := servers[(cursor+visited)%len(servers)]
		visited++
		if _, exists := selected[server.Endpoint]; exists {
			continue
		}
		batch = append(batch, server)
		selected[server.Endpoint] = struct{}{}
	}

	return batch, (cursor + visited) % len(servers), nil
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
