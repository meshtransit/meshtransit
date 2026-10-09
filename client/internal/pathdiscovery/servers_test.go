package pathdiscovery

import (
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"testing"

	"meshtransit.net/client/internal/networkmap"
)

func TestServersFromRelayMap(t *testing.T) {
	t.Parallel()

	relays := map[int]networkmap.RelayRegion{
		2: {
			ID: 2,
			Nodes: []networkmap.RelayNode{
				{Name: "z", IPv4: "192.0.2.22", STUNPort: -1},
				{Name: "b", IPv4: "192.0.2.21", IPv6: "2001:db8:2::21", STUNPort: 5349},
			},
		},
		1: {
			ID: 1,
			Nodes: []networkmap.RelayNode{
				{Name: "b", IPv4: "192.0.2.12"},
				{Name: "a", IPv4: "192.0.2.11", IPv6: "2001:db8:1::11"},
			},
		},
	}

	got, err := ServersFromRelayMap(relays)
	if err != nil {
		t.Fatalf("ServersFromRelayMap() error = %v", err)
	}
	want := []RelayServer{
		{RegionID: 1, Endpoint: netip.MustParseAddrPort("192.0.2.11:3478")},
		{RegionID: 2, Endpoint: netip.MustParseAddrPort("192.0.2.21:5349")},
		{RegionID: 1, Endpoint: netip.MustParseAddrPort("[2001:db8:1::11]:3478")},
		{RegionID: 2, Endpoint: netip.MustParseAddrPort("[2001:db8:2::21]:5349")},
		{RegionID: 1, Endpoint: netip.MustParseAddrPort("192.0.2.12:3478")},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ServersFromRelayMap() = %v, want %v", got, want)
	}
}

func TestServersFromRelayMapBoundsAndDeduplicates(t *testing.T) {
	t.Parallel()

	relays := make(map[int]networkmap.RelayRegion)
	for regionID := 1; regionID <= 10; regionID++ {
		relays[regionID] = networkmap.RelayRegion{
			ID: regionID,
			Nodes: []networkmap.RelayNode{{
				Name:     "primary",
				IPv4:     "192.0.2." + strconv.Itoa(regionID),
				STUNPort: 3478,
			}},
		}
	}
	relays[10] = networkmap.RelayRegion{
		ID: 10,
		Nodes: []networkmap.RelayNode{{
			Name:     "duplicate",
			IPv4:     "192.0.2.1",
			STUNPort: 3478,
		}},
	}

	got, err := ServersFromRelayMap(relays)
	if err != nil {
		t.Fatalf("ServersFromRelayMap() error = %v", err)
	}
	if len(got) != 9 {
		t.Fatalf("len(ServersFromRelayMap()) = %d, want 9", len(got))
	}
	seen := make(map[netip.AddrPort]struct{}, len(got))
	for _, server := range got {
		if _, exists := seen[server.Endpoint]; exists {
			t.Fatalf("duplicate server %v", server)
		}
		seen[server.Endpoint] = struct{}{}
	}
}

func TestNextServerBatchKeepsHomeAndRotates(t *testing.T) {
	t.Parallel()

	servers := make([]RelayServer, 0, 12)
	for regionID := 1; regionID <= 12; regionID++ {
		servers = append(servers, RelayServer{
			RegionID: regionID,
			Endpoint: netip.MustParseAddrPort(
				"192.0.2." + strconv.Itoa(regionID) + ":3478",
			),
		})
	}
	first, cursor, err := NextServerBatch(servers, 12, 0)
	if err != nil {
		t.Fatalf("NextServerBatch() error = %v", err)
	}
	if len(first) != maxSTUNServers || first[0].RegionID != 12 || cursor != 7 {
		t.Fatalf("first batch = %#v, cursor %d", first, cursor)
	}
	second, cursor, err := NextServerBatch(servers, 12, cursor)
	if err != nil {
		t.Fatalf("NextServerBatch() second error = %v", err)
	}
	if len(second) != maxSTUNServers || second[0].RegionID != 12 || cursor != 3 {
		t.Fatalf("second batch = %#v, cursor %d", second, cursor)
	}
	seen := make(map[int]struct{}, len(first)+len(second))
	for _, server := range append(first, second...) {
		seen[server.RegionID] = struct{}{}
	}
	if len(seen) != len(servers) {
		t.Fatalf("rotating batches covered %d regions, want %d", len(seen), len(servers))
	}
}

func TestNextServerBatchKeepsBothHomeAddressFamilies(t *testing.T) {
	t.Parallel()

	servers := make([]RelayServer, 0, 24)
	for regionID := 1; regionID <= 12; regionID++ {
		servers = append(servers, RelayServer{
			RegionID: regionID,
			Endpoint: netip.MustParseAddrPort(
				"192.0.2." + strconv.Itoa(regionID) + ":3478",
			),
		})
	}
	for regionID := 1; regionID <= 12; regionID++ {
		servers = append(servers, RelayServer{
			RegionID: regionID,
			Endpoint: netip.MustParseAddrPort(
				"[2001:db8:" + strconv.Itoa(regionID) + "::1]:3478",
			),
		})
	}

	batch, _, err := NextServerBatch(servers, 1, 12)
	if err != nil {
		t.Fatalf("NextServerBatch() error = %v", err)
	}
	if len(batch) != maxSTUNServers {
		t.Fatalf("len(NextServerBatch()) = %d, want %d", len(batch), maxSTUNServers)
	}

	var hasHomeIPv4, hasHomeIPv6 bool
	for _, server := range batch {
		if server.RegionID != 1 {
			continue
		}
		hasHomeIPv4 = hasHomeIPv4 || server.Endpoint.Addr().Is4()
		hasHomeIPv6 = hasHomeIPv6 || server.Endpoint.Addr().Is6()
	}
	if !hasHomeIPv4 || !hasHomeIPv6 {
		t.Fatalf(
			"NextServerBatch() home families = IPv4:%t IPv6:%t, want both",
			hasHomeIPv4,
			hasHomeIPv6,
		)
	}
}

func TestNextServerBatchRejectsAmbiguousServers(t *testing.T) {
	t.Parallel()

	endpoint := netip.MustParseAddrPort("192.0.2.1:3478")
	_, _, err := NextServerBatch([]RelayServer{
		{RegionID: 1, Endpoint: endpoint},
		{RegionID: 2, Endpoint: endpoint},
	}, 1, 0)
	if !errors.Is(err, ErrInvalidSTUNServers) {
		t.Fatalf("NextServerBatch() error = %v, want ErrInvalidSTUNServers", err)
	}
}

func TestServersFromRelayMapRejectsUnsafeTopology(t *testing.T) {
	t.Parallel()

	tests := map[string]map[int]networkmap.RelayRegion{
		"empty": {},
		"mismatched region": {
			1: {ID: 2, Nodes: []networkmap.RelayNode{{Name: "a", IPv4: "192.0.2.1"}}},
		},
		"invalid family": {
			1: {ID: 1, Nodes: []networkmap.RelayNode{{Name: "a", IPv4: "2001:db8::1"}}},
		},
		"unsafe address": {
			1: {ID: 1, Nodes: []networkmap.RelayNode{{Name: "a", IPv4: "127.0.0.1"}}},
		},
		"no literal address": {
			1: {ID: 1, Nodes: []networkmap.RelayNode{{Name: "a", HostName: "relay.example"}}},
		},
	}
	for name, relays := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ServersFromRelayMap(relays); err == nil {
				t.Fatal("ServersFromRelayMap() error = nil")
			} else if (name == "empty" || name == "no literal address") &&
				!errors.Is(err, ErrNoSTUNServers) {
				t.Fatalf("ServersFromRelayMap() error = %v", err)
			}
		})
	}
}
