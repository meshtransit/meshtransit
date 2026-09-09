package pathdiscovery

import (
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"testing"

	"github.com/meshtransit/meshd/internal/networkmap"
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
	want := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.11:3478"),
		netip.MustParseAddrPort("192.0.2.21:5349"),
		netip.MustParseAddrPort("[2001:db8:1::11]:3478"),
		netip.MustParseAddrPort("[2001:db8:2::21]:5349"),
		netip.MustParseAddrPort("192.0.2.12:3478"),
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
	if len(got) != maxSTUNServers {
		t.Fatalf("len(ServersFromRelayMap()) = %d, want %d", len(got), maxSTUNServers)
	}
	seen := make(map[netip.AddrPort]struct{}, len(got))
	for _, server := range got {
		if _, exists := seen[server]; exists {
			t.Fatalf("duplicate server %v", server)
		}
		seen[server] = struct{}{}
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
