package prefixset

import (
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
)

// randomHost draws an address in 100.64.0.0 plus a block of size hosts from
// a seeded generator, so a failure replays exactly.
func randomHost(random *rand.Rand, size uint32) netip.Addr {
	var address [4]byte
	binary.BigEndian.PutUint32(address[:], 100<<24|64<<16|random.Uint32N(size))
	return netip.AddrFrom4(address)
}

func TestSummarizeMergesOnlyFullyCoveredSiblings(t *testing.T) {
	t.Parallel()
	got := Summarize([]netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/32"),
		netip.MustParsePrefix("100.64.0.1/32"),
		netip.MustParsePrefix("100.64.0.2/32"),
		netip.MustParsePrefix("100.64.0.3/32"),
		netip.MustParsePrefix("100.64.0.5/32"),
		netip.MustParsePrefix("100.64.0.5/32"),
		netip.MustParsePrefix("fd07::1/128"),
		netip.MustParsePrefix("fd07::/128"),
		netip.MustParsePrefix("198.18.0.4/30"),
		netip.MustParsePrefix("198.18.0.6/32"),
	})
	want := []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/30"),
		netip.MustParsePrefix("100.64.0.5/32"),
		netip.MustParsePrefix("198.18.0.4/30"),
		netip.MustParsePrefix("fd07::/127"),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Summarize() = %v, want %v", got, want)
	}
}

func TestSummarizeSkipsInvalidAndUnmapsIPv4(t *testing.T) {
	t.Parallel()
	got := Summarize([]netip.Prefix{{}, netip.MustParsePrefix("::ffff:100.64.0.1/128")})
	if !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}) {
		t.Fatalf("Summarize() = %v", got)
	}
}

// TestSummarizeCoversExactlyTheInput checks on random host sets that the
// result covers every input address and nothing else, without overlaps.
func TestSummarizeCoversExactlyTheInput(t *testing.T) {
	t.Parallel()
	random := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // seeded test input, not a secret
	for round := range 200 {
		size := 1 + random.IntN(600)
		hosts := make(map[netip.Addr]struct{}, size)
		input := make([]netip.Prefix, 0, size)
		for range size {
			address := randomHost(random, 1024)
			hosts[address] = struct{}{}
			input = append(input, netip.PrefixFrom(address, 32))
		}
		got := Summarize(input)
		for index, prefix := range got {
			if index > 0 && got[index-1].Overlaps(prefix) {
				t.Fatalf("round %d: %s overlaps %s", round, got[index-1], prefix)
			}
			for address := prefix.Addr(); prefix.Contains(address); address = address.Next() {
				if _, ok := hosts[address]; !ok {
					t.Fatalf("round %d: %s covers %s, which is no input", round, prefix, address)
				}
			}
		}
		for address := range hosts {
			if !slices.ContainsFunc(got, func(prefix netip.Prefix) bool { return prefix.Contains(address) }) {
				t.Fatalf("round %d: %s is not covered", round, address)
			}
		}
	}
}

func TestSummarizeTenThousandSequentialHosts(t *testing.T) {
	t.Parallel()
	input := make([]netip.Prefix, 0, 10_000)
	address := netip.MustParseAddr("100.64.0.1")
	for range 10_000 {
		input = append(input, netip.PrefixFrom(address, 32))
		address = address.Next()
	}
	if got := Summarize(input); len(got) > 32 {
		t.Fatalf("Summarize() of 10,000 sequential hosts = %d prefixes", len(got))
	}
}

func BenchmarkSummarizeTenThousandHosts(b *testing.B) {
	random := rand.New(rand.NewPCG(3, 4)) //nolint:gosec // seeded benchmark input, not a secret
	input := make([]netip.Prefix, 0, 10_000)
	for range 10_000 {
		input = append(input, netip.PrefixFrom(randomHost(random, 64*256), 32))
	}
	b.ResetTimer()
	for range b.N {
		Summarize(input)
	}
}
