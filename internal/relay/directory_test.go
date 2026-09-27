package relay

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestNewDirectoryCanonicalizesAndDefensivelyCopies(t *testing.T) {
	t.Parallel()

	second := mustTestRegion(t, RegionParams{
		ID:   2,
		Code: "hkg",
		Name: "Hong Kong",
		Nodes: []Node{mustTestNode(t, NodeParams{
			Name:       "2b",
			HostName:   "relay-hkg.example.com",
			IPv4:       "198.51.100.20",
			IPv6:       "2001:db8:2::20",
			STUNPort:   3478,
			RelayPort:  443,
			IsSTUNOnly: false,
		})},
	})
	first := mustTestRegion(t, RegionParams{
		ID:   1,
		Code: "sin",
		Name: "Singapore",
		Nodes: []Node{
			mustTestNode(t, NodeParams{
				Name:       "1b",
				HostName:   "relay-sin-b.example.com",
				IPv4:       "192.0.2.11",
				IPv6:       "2001:db8:1::11",
				STUNPort:   3478,
				RelayPort:  443,
				IsSTUNOnly: false,
			}),
			mustTestNode(t, NodeParams{
				Name:       "1a",
				HostName:   "relay-sin-a.example.com",
				IPv4:       "192.0.2.10",
				IPv6:       "2001:db8:1::10",
				STUNPort:   3478,
				RelayPort:  443,
				IsSTUNOnly: false,
			}),
		},
	})
	input := []Region{second, first}
	directory, err := NewDirectory(DirectoryParams{Revision: 7, Regions: input})
	if err != nil {
		t.Fatalf("NewDirectory() error = %v", err)
	}
	input[0] = Region{}

	regions := directory.Regions()
	if directory.Revision() != 7 || !directory.IsValid() || len(regions) != 2 ||
		regions[0].ID() != 1 || regions[1].ID() != 2 {
		t.Fatalf("directory = revision %d regions %+v", directory.Revision(), regions)
	}
	nodes := regions[0].Nodes()
	if len(nodes) != 2 || nodes[0].Name() != "1a" || nodes[1].Name() != "1b" {
		t.Fatalf("canonical nodes = %+v", nodes)
	}
	regions[0] = Region{}
	nodes[0] = Node{}
	if got, found := directory.Region(1); !found || got.ID() != 1 || got.Nodes()[0].Name() != "1a" {
		t.Fatalf("Region(1) = %+v, %t", got, found)
	}
	if _, found := directory.Region(3); found {
		t.Fatal("Region(3) unexpectedly found")
	}

	sameTopology, err := NewDirectory(DirectoryParams{Revision: 8, Regions: []Region{first, second}})
	if err != nil {
		t.Fatalf("NewDirectory(same topology) error = %v", err)
	}
	if directory.Fingerprint() != sameTopology.Fingerprint() {
		t.Fatal("topology fingerprint changed with revision only")
	}
}

func TestDirectoryFormattingDoesNotExposeTopology(t *testing.T) {
	t.Parallel()

	node := mustTestNode(t, testNodeParams())
	region := mustTestRegion(t, RegionParams{
		ID: 1, Code: "sin", Name: "Singapore", Nodes: []Node{node},
	})
	directory, err := NewDirectory(DirectoryParams{Revision: 1, Regions: []Region{region}})
	if err != nil {
		t.Fatalf("NewDirectory() error = %v", err)
	}
	for name, value := range map[string]any{
		"node":      node,
		"region":    region,
		"directory": directory,
	} {
		for _, formatted := range []string{fmt.Sprint(value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)} {
			if strings.Contains(formatted, "relay.example.com") || formatted != redactedValue {
				t.Fatalf("%s formatting exposed topology: %q", name, formatted)
			}
		}
		if encoded, err := json.Marshal(value); err == nil || encoded != nil {
			t.Fatalf("json.Marshal(%s) = %q, %v", name, encoded, err)
		}
	}
	for name, value := range map[string]string{
		"node":      node.LogValue().String(),
		"region":    region.LogValue().String(),
		"directory": directory.LogValue().String(),
	} {
		if value != redactedValue {
			t.Fatalf("%s LogValue() = %q", name, value)
		}
	}
}

func TestNewDirectoryRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	validNode := mustTestNode(t, testNodeParams())
	validRegion := mustTestRegion(t, RegionParams{
		ID: 1, Code: "sin", Name: "Singapore", Nodes: []Node{validNode},
	})
	tests := []struct {
		name   string
		params DirectoryParams
	}{
		{name: "zero revision", params: DirectoryParams{Regions: []Region{validRegion}}},
		{name: "missing regions", params: DirectoryParams{Revision: 1}},
		{name: "zero region", params: DirectoryParams{Revision: 1, Regions: []Region{{}}}},
		{name: "duplicate region id", params: DirectoryParams{Revision: 1, Regions: []Region{validRegion, validRegion}}},
		{name: "duplicate region code", params: DirectoryParams{Revision: 1, Regions: []Region{
			validRegion,
			mustTestRegion(t, RegionParams{ID: 2, Code: "sin", Name: "Second", Nodes: []Node{
				mustTestNode(t, NodeParams{
					Name: "2a", HostName: "relay-2.example.com", IPv4: "198.51.100.2",
					IPv6: "2001:db8:2::2", STUNPort: 3478, RelayPort: 443,
				}),
			}}),
		}}},
		{name: "duplicate node name", params: DirectoryParams{Revision: 1, Regions: []Region{
			validRegion,
			mustTestRegion(t, RegionParams{ID: 2, Code: "hkg", Name: "Second", Nodes: []Node{
				mustTestNode(t, testNodeParams()),
			}}),
		}}},
		{name: "too many regions", params: DirectoryParams{
			Revision: 1,
			Regions:  repeatedTestRegions(t, MaximumRegions+1),
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewDirectory(test.params); err == nil {
				t.Fatal("NewDirectory() error = nil")
			}
		})
	}
}

func TestNewNodeRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		change func(*NodeParams)
	}{
		{name: "missing name", change: func(p *NodeParams) { p.Name = "" }},
		{name: "noncanonical name", change: func(p *NodeParams) { p.Name = "Node_A" }},
		{name: "uppercase hostname", change: func(p *NodeParams) { p.HostName = "Relay.Example.com" }},
		{name: "ip hostname", change: func(p *NodeParams) { p.HostName = "192.0.2.1" }},
		{name: "invalid certificate name", change: func(p *NodeParams) { p.CertName = "bad name" }},
		{name: "zero certificate pin", change: func(p *NodeParams) {
			p.CertName = "sha256-raw:" + strings.Repeat("0", 64)
		}},
		{name: "ipv4 family mismatch", change: func(p *NodeParams) { p.IPv4 = "2001:db8::1" }},
		{name: "ipv6 family mismatch", change: func(p *NodeParams) { p.IPv6 = "192.0.2.1" }},
		{name: "multicast ipv4", change: func(p *NodeParams) { p.IPv4 = "224.0.0.1" }},
		{name: "loopback ipv6", change: func(p *NodeParams) { p.IPv6 = "::1" }},
		{name: "invalid stun port", change: func(p *NodeParams) { p.STUNPort = -2 }},
		{name: "invalid relay port", change: func(p *NodeParams) { p.RelayPort = -1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			params := testNodeParams()
			test.change(&params)
			if _, err := NewNode(params); err == nil {
				t.Fatal("NewNode() error = nil")
			}
		})
	}
}

func TestNewRegionRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	validNode := mustTestNode(t, testNodeParams())
	tests := []struct {
		name   string
		params RegionParams
	}{
		{name: "zero id", params: RegionParams{Code: "sin", Name: "Singapore", Nodes: []Node{validNode}}},
		{name: "id outside wire range", params: RegionParams{ID: 65_536, Code: "sin", Name: "Singapore", Nodes: []Node{validNode}}},
		{name: "invalid code", params: RegionParams{ID: 1, Code: "Singapore_1", Name: "Singapore", Nodes: []Node{validNode}}},
		{name: "missing display name", params: RegionParams{ID: 1, Code: "sin", Nodes: []Node{validNode}}},
		{name: "missing nodes", params: RegionParams{ID: 1, Code: "sin", Name: "Singapore"}},
		{name: "duplicate node hostname", params: RegionParams{ID: 1, Code: "sin", Name: "Singapore", Nodes: []Node{validNode, validNode}}},
		{name: "too many nodes", params: RegionParams{ID: 1, Code: "sin", Name: "Singapore", Nodes: repeatedTestNodes(t, MaximumNodesPerRegion+1)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewRegion(test.params); err == nil {
				t.Fatal("NewRegion() error = nil")
			}
		})
	}
}

func testNodeParams() NodeParams {
	return NodeParams{
		Name:       "1a",
		HostName:   "relay.example.com",
		IPv4:       "192.0.2.10",
		IPv6:       "2001:db8::10",
		STUNPort:   3478,
		RelayPort:  443,
		IsSTUNOnly: false,
	}
}

func mustTestNode(t *testing.T, params NodeParams) Node {
	t.Helper()
	node, err := NewNode(params)
	if err != nil {
		t.Fatalf("NewNode() error = %v", err)
	}
	return node
}

func mustTestRegion(t *testing.T, params RegionParams) Region {
	t.Helper()
	region, err := NewRegion(params)
	if err != nil {
		t.Fatalf("NewRegion() error = %v", err)
	}
	return region
}

func repeatedTestNodes(t *testing.T, count int) []Node {
	t.Helper()
	nodes := make([]Node, 0, count)
	for index := range count {
		params := testNodeParams()
		params.Name = "node-" + strings.Repeat("a", index/26) + string(rune('a'+index%26))
		params.HostName = params.Name + ".example.com"
		params.IPv4 = "none"
		params.IPv6 = "none"
		nodes = append(nodes, mustTestNode(t, params))
	}
	return nodes
}

func repeatedTestRegions(t *testing.T, count int) []Region {
	t.Helper()
	regions := make([]Region, 0, count)
	for index := range count {
		regions = append(regions, mustTestRegion(t, RegionParams{
			ID:    index + 1,
			Code:  "r" + strings.Repeat("a", index/26) + string(rune('a'+index%26)),
			Name:  "Region " + strings.Repeat("a", index/26) + string(rune('A'+index%26)),
			Nodes: repeatedTestNodes(t, 1),
		}))
	}
	if slices.ContainsFunc(regions, func(region Region) bool { return !region.IsValid() }) {
		t.Fatal("repeatedTestRegions() built invalid fixture")
	}
	return regions
}
