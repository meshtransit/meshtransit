package packetmeta

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"testing"
)

type rewriteVector struct {
	Name        string `json:"name"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	NewSource   string `json:"new_source"`
	NewTarget   string `json:"new_destination"`
	Input       string `json:"input_hex"`
	Output      string `json:"output_hex"`
}

func rewriteVectors(t testing.TB) []rewriteVector {
	t.Helper()
	contents, err := os.ReadFile("testdata/alias_packets_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version int             `json:"version"`
		Cases   []rewriteVector `json:"cases"`
	}
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 || len(fixture.Cases) != 8 {
		t.Fatal("invalid fixture version or case count")
	}
	return fixture.Cases
}

func TestRewriteAddressesConformance(t *testing.T) {
	t.Parallel()
	for _, vector := range rewriteVectors(t) {
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()
			packet, err := hex.DecodeString(vector.Input)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := hex.DecodeString(vector.Output)
			if err != nil {
				t.Fatal(err)
			}
			original := AddressPair{Source: netip.MustParseAddr(vector.Source), Destination: netip.MustParseAddr(vector.Destination)}
			target := AddressPair{Source: netip.MustParseAddr(vector.NewSource), Destination: netip.MustParseAddr(vector.NewTarget)}
			if err := RewriteAddresses(packet, original, target); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(packet, expected) {
				t.Fatalf("rewritten packet = %x, want %x", packet, expected)
			}
			if _, err := CheckAliasPacket(packet); err != nil {
				t.Fatal(err)
			}
			if err := RewriteAddresses(packet, target, original); err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(packet) != vector.Input {
				t.Fatal("round trip changed packet")
			}
		})
	}
}

func TestRewriteAddressesRejectsWithoutMutation(t *testing.T) {
	t.Parallel()
	for _, vector := range rewriteVectors(t) {
		for _, mutation := range []struct {
			name string
			edit func([]byte, *AddressPair, *AddressPair) []byte
		}{
			{"corrupt transport", func(p []byte, _, _ *AddressPair) []byte { p[len(p)-1] ^= 0x20; return p }},
			{"truncated", func(p []byte, _, _ *AddressPair) []byte { return p[:len(p)-1] }},
			{"trailing data", func(p []byte, _, _ *AddressPair) []byte { return append(p, 0) }},
			{"wrong source", func(p []byte, pair, _ *AddressPair) []byte { pair.Source = netip.MustParseAddr("192.0.2.10"); return p }},
			{"wrong destination", func(p []byte, pair, _ *AddressPair) []byte {
				pair.Destination = netip.MustParseAddr("192.0.2.10")
				return p
			}},
			{"invalid replacement", func(p []byte, _, pair *AddressPair) []byte { pair.Source = netip.Addr{}; return p }},
			{"loopback replacement", func(p []byte, _, pair *AddressPair) []byte {
				pair.Destination = netip.MustParseAddr("127.0.0.1")
				return p
			}},
		} {
			if vector.Name == "ipv4-udp-no-checksum" && mutation.name == "corrupt transport" {
				continue // IPv4 deliberately permits an absent UDP checksum.
			}
			t.Run(vector.Name+"/"+mutation.name, func(t *testing.T) {
				t.Parallel()
				packet, err := hex.DecodeString(vector.Input)
				if err != nil {
					t.Fatal(err)
				}
				original := AddressPair{Source: netip.MustParseAddr(vector.Source), Destination: netip.MustParseAddr(vector.Destination)}
				target := AddressPair{Source: netip.MustParseAddr(vector.NewSource), Destination: netip.MustParseAddr(vector.NewTarget)}
				packet = mutation.edit(packet, &original, &target)
				before := bytes.Clone(packet)
				if err := RewriteAddresses(packet, original, target); err == nil {
					t.Fatal("invalid rewrite accepted")
				}
				if !bytes.Equal(packet, before) {
					t.Fatal("rejected rewrite mutated input")
				}
			})
		}
	}
}

func TestCheckAliasPacketUnsupportedForms(t *testing.T) {
	t.Parallel()
	vectors := rewriteVectors(t)
	for _, test := range []struct {
		name string
		edit func() []byte
	}{
		{"ipv4 fragment", func() []byte { p, _ := hex.DecodeString(vectors[0].Input); p[6] |= 0x20; return p }},
		{"ipv4 options", func() []byte { p, _ := hex.DecodeString(vectors[0].Input); p[0] = 0x46; return p }},
		{"ipv6 fragment", func() []byte { p, _ := hex.DecodeString(vectors[4].Input); p[6] = 44; return p }},
		{"ipv6 authentication", func() []byte { p, _ := hex.DecodeString(vectors[4].Input); p[6] = 51; return p }},
		{"ipv6 routing", func() []byte { p, _ := hex.DecodeString(vectors[4].Input); p[6] = 43; return p }},
		{"ipv6 udp zero checksum", func() []byte { p, _ := hex.DecodeString(vectors[5].Input); p[46], p[47] = 0, 0; return p }},
		{"icmp error", func() []byte { p, _ := hex.DecodeString(vectors[3].Input); p[20] = 3; return p }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := CheckAliasPacket(test.edit()); err == nil {
				t.Fatal("unsupported form accepted")
			}
		})
	}
}

func FuzzRewriteAddresses(f *testing.F) {
	for _, vector := range rewriteVectors(f) {
		packet, err := hex.DecodeString(vector.Input)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(packet)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		packet := bytes.Clone(input)
		before := bytes.Clone(packet)
		header, err := Parse(packet)
		if err != nil {
			return
		}
		source, destination := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20")
		if header.Source.Is6() {
			source, destination = netip.MustParseAddr("fd00:2::10"), netip.MustParseAddr("fd00:2::20")
		}
		original := AddressPair{Source: header.Source, Destination: header.Destination}
		replacement := AddressPair{Source: source, Destination: destination}
		if err := RewriteAddresses(packet, original, replacement); err != nil {
			if !bytes.Equal(packet, before) {
				t.Fatal("invalid packet was mutated")
			}
			return
		}
		rewritten, err := CheckAliasPacket(packet)
		if err != nil || rewritten.Source != source || rewritten.Destination != destination {
			t.Fatal("successful rewrite has invalid checksum or tuple")
		}
		if err := RewriteAddresses(packet, replacement, original); err != nil || !bytes.Equal(packet, before) {
			t.Fatalf("successful rewrite did not round trip: original=%+v err=%v before=%x after=%x", original, err, before, packet)
		}
	})
}
