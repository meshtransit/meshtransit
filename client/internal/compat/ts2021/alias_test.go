package ts2021

import (
	"embed"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/client/internal/networkmap"
	"tailscale.com/tailcfg"
)

func testAliasResponse(t *testing.T) (tailcfg.MapResponse, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	self, peer := testWireNode(1, 1), testWireNode(2, 2)
	self.KeyExpiry, peer.KeyExpiry = now.Add(time.Hour), now.Add(time.Hour)
	self.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.10.1/32"), netip.MustParsePrefix("fd00:1::1/128")}
	self.AllowedIPs = append([]netip.Prefix{}, self.Addresses...)
	peer.Addresses = []netip.Prefix{netip.MustParsePrefix("100.96.0.1/32"), netip.MustParsePrefix("fd00:2::1/128")}
	peer.AllowedIPs = append([]netip.Prefix{}, peer.Addresses...)
	ipv4, ipv6 := netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("fd00:2::2")
	peer.SelfNodeV4MasqAddrForThisPeer, peer.SelfNodeV6MasqAddrForThisPeer = &ipv4, &ipv6
	document := aliasDocument{
		Version: 1, ContractID: "00000000-0000-4000-8000-000000000001",
		EndpointID: "00000000-0000-4000-8000-000000000002",
		Generation: 3, GrantRevision: 4, RecoveryEpoch: 1,
		SelfKey: self.Key.String(), PeerKey: peer.Key.String(), Role: networkmap.AliasConsumer,
		ExpiresAt: now.Add(time.Minute), Services: []aliasService{{Protocol: 6, PortFrom: 443, PortTo: 443}},
	}
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	peer.CapMap = tailcfg.NodeCapMap{deviceAliasCapability: {tailcfg.RawMessage(body)}}
	return tailcfg.MapResponse{Node: self, Peers: []*tailcfg.Node{peer}, PacketFilter: []tailcfg.FilterRule{}}, now
}

func TestAliasMapConversionAndRemoval(t *testing.T) {
	t.Parallel()
	response, now := testAliasResponse(t)
	accumulator := newMapAccumulator()
	snapshot, changed, err := accumulator.apply(response, now)
	if err != nil || !changed || snapshot.Peers[0].Alias == nil {
		t.Fatalf("alias full map: changed=%t error=%v", changed, err)
	}
	response.Peers[0].SelfNodeV4MasqAddrForThisPeer = nil
	snapshot.Peers[0].Alias.Services[0].PortTo = 65535
	if accumulator.peers[2].Alias.Services[0].PortTo != 443 {
		t.Fatal("published alias mutated accumulated authority")
	}
	removed, changed, err := accumulator.apply(tailcfg.MapResponse{PeersRemoved: []tailcfg.NodeID{2}}, now)
	if err != nil || !changed || len(removed.Peers) != 0 {
		t.Fatalf("alias removal: changed=%t error=%v", changed, err)
	}
}

func TestAliasMapRejectsUnqualifiedOrAmbiguousWire(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		edit func(*tailcfg.Node)
	}{
		{"legacy fields alone", func(n *tailcfg.Node) { n.CapMap = nil }},
		{"grant without fields", func(n *tailcfg.Node) { n.SelfNodeV4MasqAddrForThisPeer = nil; n.SelfNodeV6MasqAddrForThisPeer = nil }},
		{"multiple documents", func(n *tailcfg.Node) {
			n.CapMap[deviceAliasCapability] = append(n.CapMap[deviceAliasCapability], n.CapMap[deviceAliasCapability][0])
		}},
		{"oversize", func(n *tailcfg.Node) {
			n.CapMap[deviceAliasCapability] = []tailcfg.RawMessage{tailcfg.RawMessage(strings.Repeat(" ", maxAliasDocumentBytes+1))}
		}},
		{"unknown field", func(n *tailcfg.Node) { n.CapMap[deviceAliasCapability][0] = `{"version":1,"unexpected":true}` }},
		{"case variant", func(n *tailcfg.Node) {
			n.CapMap[deviceAliasCapability][0] = tailcfg.RawMessage(strings.Replace(string(n.CapMap[deviceAliasCapability][0]), `"version"`, `"Version"`, 1))
		}},
		{"duplicate alternate case", func(n *tailcfg.Node) {
			body := string(n.CapMap[deviceAliasCapability][0])
			n.CapMap[deviceAliasCapability][0] = tailcfg.RawMessage(body[:len(body)-1] + `,"Version":2}`)
		}},
		{"service case variant", func(n *tailcfg.Node) {
			n.CapMap[deviceAliasCapability][0] = tailcfg.RawMessage(strings.Replace(string(n.CapMap[deviceAliasCapability][0]), `"port_to"`, `"Port_to"`, 1))
		}},
		{"duplicate version", func(n *tailcfg.Node) { n.CapMap[deviceAliasCapability][0] = `{"version":2,"version":1}` }},
		{"duplicate nested port", func(n *tailcfg.Node) {
			n.CapMap[deviceAliasCapability][0] = `{"version":1,"services":[{"port_to":22,"port_to":443}]}`
		}},
		{"future version", func(n *tailcfg.Node) { n.CapMap[deviceAliasCapability][0] = `{"version":2}` }},
		{"trailing document", func(n *tailcfg.Node) { n.CapMap[deviceAliasCapability][0] += `{}` }},
		{"null root", func(n *tailcfg.Node) { n.CapMap[deviceAliasCapability][0] = `null` }},
		{"array root", func(n *tailcfg.Node) { n.CapMap[deviceAliasCapability][0] = `[]` }},
		{"excess nesting", func(n *tailcfg.Node) { n.CapMap[deviceAliasCapability][0] = `{"a":[[[[[1]]]]]}` }},
		{"wrong key", func(n *tailcfg.Node) {
			var document aliasDocument
			if err := json.Unmarshal([]byte(n.CapMap[deviceAliasCapability][0]), &document); err != nil {
				panic(err)
			}
			document.PeerKey = document.SelfKey
			body, err := json.Marshal(document)
			if err != nil {
				panic(err)
			}
			n.CapMap[deviceAliasCapability][0] = tailcfg.RawMessage(body)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response, now := testAliasResponse(t)
			test.edit(response.Peers[0])
			accumulator := newMapAccumulator()
			if _, _, err := accumulator.apply(response, now); !errors.Is(err, ErrNetmapInvalid) {
				t.Fatalf("unsafe alias error = %v", err)
			}
			if accumulator.initialized || len(accumulator.peers) != 0 {
				t.Fatal("invalid initial map changed accumulated authority")
			}
		})
	}
}

func TestAliasDeltaCannotDowngradeOrRegress(t *testing.T) {
	t.Parallel()
	for _, downgrade := range []bool{true, false} {
		name := "regress"
		if downgrade {
			name = "downgrade"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			response, now := testAliasResponse(t)
			accumulator := newMapAccumulator()
			if _, _, err := accumulator.apply(response, now); err != nil {
				t.Fatal(err)
			}
			peer := response.Peers[0]
			if downgrade {
				peer.CapMap = nil
				peer.SelfNodeV4MasqAddrForThisPeer, peer.SelfNodeV6MasqAddrForThisPeer = nil, nil
			} else {
				var document aliasDocument
				if err := json.Unmarshal([]byte(peer.CapMap[deviceAliasCapability][0]), &document); err != nil {
					t.Fatal(err)
				}
				document.Generation--
				body, err := json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				peer.CapMap[deviceAliasCapability][0] = tailcfg.RawMessage(body)
			}
			if _, _, err := accumulator.apply(tailcfg.MapResponse{PeersChanged: []*tailcfg.Node{peer}}, now); !errors.Is(err, ErrNetmapInvalid) {
				t.Fatalf("unsafe delta error = %v", err)
			}
			if accumulator.peers[2].Alias == nil || accumulator.peers[2].Alias.Generation != 3 {
				t.Fatal("invalid delta changed accumulated authority")
			}
		})
	}
}

func FuzzAliasDocument(f *testing.F) {
	f.Add(`{"version":1}`)
	f.Add(`{"version":1,"version":2}`)
	f.Add(`null`)
	f.Fuzz(func(t *testing.T, body string) {
		node := testWireNode(2, 2)
		address := netip.MustParseAddr("100.96.0.2")
		node.SelfNodeV4MasqAddrForThisPeer = &address
		node.CapMap = tailcfg.NodeCapMap{deviceAliasCapability: {tailcfg.RawMessage(body)}}
		if alias, err := convertAlias(node); err == nil && alias == nil {
			t.Fatal("alias fields silently dropped")
		}
	})
}

//go:embed testdata/core-device-alias-v1/*.json
var coreDeviceAliasFixtures embed.FS

func TestCoreDeviceAliasV1Fixtures(t *testing.T) {
	t.Parallel()
	for _, role := range []string{"provider", "consumer"} {
		for _, protocol := range []string{"tcp", "udp", "icmp"} {
			t.Run(role+"/"+protocol, func(t *testing.T) {
				t.Parallel()
				body, err := coreDeviceAliasFixtures.ReadFile("testdata/core-device-alias-v1/" + role + "-" + protocol + ".json")
				if err != nil {
					t.Fatal(err)
				}
				var response tailcfg.MapResponse
				if err := json.Unmarshal(body, &response); err != nil {
					t.Fatal(err)
				}
				now := time.Date(2026, 9, 14, 4, 0, 0, 0, time.UTC)
				snapshot, changed, err := newMapAccumulator().apply(response, now)
				if err != nil || !changed || len(snapshot.Peers) != 1 || snapshot.Peers[0].Alias == nil {
					t.Fatalf("Core fixture: changed=%t error=%v", changed, err)
				}
				peer := snapshot.Peers[0]
				grant := peer.Alias
				if grant.Role != networkmap.AliasRole(role) || grant.GrantRevision != 14 || grant.SelfKey != snapshot.Self.PublicKey || grant.PeerKey != peer.PublicKey ||
					snapshot.Self.Addresses[0] != netip.MustParsePrefix("100.64.0.1/32") || snapshot.Self.Addresses[1] != netip.MustParsePrefix("fd00:10::1/128") {
					t.Fatal("Core and client alias contract disagree")
				}
				expected := uint8(6)
				if protocol == "udp" {
					expected = 17
				}
				if protocol == "icmp" {
					expected = 1
				}
				if grant.Services[0].Protocol != expected || (protocol != "icmp" && (grant.Services[0].PortFrom != 8443 || grant.Services[0].PortTo != 8443)) {
					t.Fatal("Core service widened")
				}
				if role == "consumer" {
					if len(snapshot.Policy) != 0 {
						t.Fatal("Core granted reverse initiation")
					}
					return
				}
				if len(snapshot.Policy) != 1 {
					t.Fatal("provider has no exact inbound filter")
				}
			})
		}
	}
}
