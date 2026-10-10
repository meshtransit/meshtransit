package policydigest

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func prefix(text string) Selector {
	return Selector{Kind: KindPrefix, Prefix: netip.MustParsePrefix(text)}
}

func to(text string, from, until uint16) Destination {
	return Destination{Selector: prefix(text), PortFrom: from, PortTo: until}
}

func mustCompute(t *testing.T, rules []Rule) (Digest, int) {
	t.Helper()
	digest, count, err := Compute(rules)
	if err != nil {
		t.Fatal(err)
	}
	return digest, count
}

// vectorRules is the filter of the published test vector
// (docs/protocol/policy-digest-v1.md §5).
func vectorRules() []Rule {
	return []Rule{
		{
			Sources:      []Selector{prefix("100.64.0.2/32"), prefix("fd7a:115c:a1e0::2/128")},
			Destinations: []Destination{to("100.64.0.1/32", 22, 22), to("fd7a:115c:a1e0::1/128", 22, 22)},
			Protocols:    []uint8{6},
		},
		{
			Sources:      []Selector{prefix("100.64.0.3/32")},
			Destinations: []Destination{to("100.64.0.1/32", 0, 65535)},
			Protocols:    []uint8{1},
		},
	}
}

func TestComputeVector(t *testing.T) {
	digest, count := mustCompute(t, vectorRules())
	const want = "sha256:65c3166a6062804e3b2a55acd157d70ce0ebf6fdd91130eecd280654a714251a"
	if count != 5 {
		t.Fatalf("grants = %d, want 5", count)
	}
	if digest.String() != want {
		t.Fatalf("digest = %s, want %s", digest, want)
	}
}

func TestComputeIgnoresGroupingOrderAndDuplicates(t *testing.T) {
	base, _ := mustCompute(t, vectorRules())
	regrouped := []Rule{
		{
			Sources:      []Selector{prefix("100.64.0.3/32")},
			Destinations: []Destination{to("100.64.0.1/32", 0, 65535)},
			Protocols:    []uint8{1, 1},
		},
		{
			Sources:      []Selector{prefix("fd7a:115c:a1e0::2/128")},
			Destinations: []Destination{to("fd7a:115c:a1e0::1/128", 22, 22), to("100.64.0.1/32", 22, 22)},
			Protocols:    []uint8{6},
		},
		{
			Sources:      []Selector{prefix("100.64.0.2/32"), prefix("100.64.0.2/32")},
			Destinations: []Destination{to("100.64.0.1/32", 22, 22), to("fd7a:115c:a1e0::1/128", 22, 22)},
			Protocols:    []uint8{6},
		},
		{Sources: []Selector{prefix("100.64.0.9/32")}, Protocols: []uint8{6}}, // no destinations
	}
	if got, _ := mustCompute(t, regrouped); got != base {
		t.Fatalf("regrouped digest %s differs from %s", got, base)
	}
}

func TestComputeCanonicalizesAddresses(t *testing.T) {
	plain, _ := mustCompute(t, []Rule{{
		Sources:      []Selector{prefix("100.64.0.0/10")},
		Destinations: []Destination{to("100.64.0.1/32", 80, 80)},
	}})
	mapped, _ := mustCompute(t, []Rule{{
		Sources: []Selector{{Kind: KindPrefix, Prefix: netip.PrefixFrom(
			netip.MustParseAddr("::ffff:100.64.1.7").Unmap(), 10,
		)}},
		Destinations: []Destination{{
			Selector: Selector{Kind: KindPrefix, Prefix: netip.PrefixFrom(netip.MustParseAddr("::ffff:100.64.0.1"), 32)},
			PortFrom: 80, PortTo: 80,
		}},
	}})
	if plain != mapped {
		t.Fatal("unmasked or mapped addresses changed the digest")
	}
}

func TestComputeDistinguishesGrants(t *testing.T) {
	base, _ := mustCompute(t, vectorRules())
	mutations := map[string]func([]Rule){
		"port":        func(rules []Rule) { rules[0].Destinations[0].PortTo = 23 },
		"protocol":    func(rules []Rule) { rules[0].Protocols = []uint8{17} },
		"default":     func(rules []Rule) { rules[0].Protocols = nil },
		"source":      func(rules []Rule) { rules[1].Sources[0] = prefix("100.64.0.4/32") },
		"width":       func(rules []Rule) { rules[1].Sources[0] = prefix("100.64.0.0/24") },
		"any":         func(rules []Rule) { rules[1].Sources[0] = Selector{Kind: KindAny} },
		"missing":     func(rules []Rule) { rules[1].Destinations = nil },
		"destination": func(rules []Rule) { rules[0].Destinations[1] = to("fd7a:115c:a1e0::5/128", 22, 22) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			rules := vectorRules()
			mutate(rules)
			if got, _ := mustCompute(t, rules); got == base {
				t.Fatal("a different filter produced the same digest")
			}
		})
	}
}

func TestComputeEmptyFilter(t *testing.T) {
	empty, count := mustCompute(t, nil)
	if count != 0 || empty.IsZero() {
		t.Fatalf("empty filter: count %d digest %s", count, empty)
	}
	if again, _ := mustCompute(t, []Rule{{Sources: []Selector{{Kind: KindAny}}}}); again != empty {
		t.Fatal("a rule without destinations changed the empty digest")
	}
}

func TestComputeSelectorKinds(t *testing.T) {
	rules := []Rule{{
		Sources: []Selector{
			{Kind: KindAny},
			{Kind: KindRange, RangeStart: netip.MustParseAddr("100.64.0.1"), RangeEnd: netip.MustParseAddr("100.64.0.9")},
			{Kind: KindCapability, Capability: "meshtransit.io/cap/example"},
		},
		Destinations: []Destination{to("100.64.0.1/32", 0, 65535)},
	}}
	if _, count := mustCompute(t, rules); count != 3 {
		t.Fatalf("grants = %d, want 3", count)
	}
}

func TestComputeRejectsInvalidRules(t *testing.T) {
	cases := map[string]Rule{
		"kind":       {Sources: []Selector{{Kind: 9}}, Destinations: []Destination{to("100.64.0.1/32", 1, 1)}},
		"prefix":     {Sources: []Selector{{Kind: KindPrefix}}, Destinations: []Destination{to("100.64.0.1/32", 1, 1)}},
		"ports":      {Sources: []Selector{{Kind: KindAny}}, Destinations: []Destination{to("100.64.0.1/32", 9, 1)}},
		"capability": {Sources: []Selector{{Kind: KindCapability}}, Destinations: []Destination{to("100.64.0.1/32", 1, 1)}},
		"range": {Sources: []Selector{{
			Kind: KindRange, RangeStart: netip.MustParseAddr("100.64.0.9"),
			RangeEnd: netip.MustParseAddr("100.64.0.1"),
		}}, Destinations: []Destination{to("100.64.0.1/32", 1, 1)}},
		"family": {Sources: []Selector{{
			Kind: KindRange, RangeStart: netip.MustParseAddr("100.64.0.1"),
			RangeEnd: netip.MustParseAddr("fd00::1"),
		}}, Destinations: []Destination{to("100.64.0.1/32", 1, 1)}},
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Compute([]Rule{rule}); !errors.Is(err, ErrInvalidRule) {
				t.Fatalf("err = %v, want ErrInvalidRule", err)
			}
		})
	}
}

func TestComputeBoundsExpansion(t *testing.T) {
	sources := make([]Selector, 1025)
	for index := range sources {
		sources[index] = Selector{Kind: KindAny}
	}
	destinations := make([]Destination, 1025)
	for index := range destinations {
		destinations[index] = to("100.64.0.1/32", 1, 1)
	}
	if _, _, err := Compute([]Rule{{Sources: sources, Destinations: destinations}}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestParseRoundTrip(t *testing.T) {
	digest, _ := mustCompute(t, vectorRules())
	parsed, err := Parse(digest.String())
	if err != nil || parsed != digest {
		t.Fatalf("Parse(%s) = %s, %v", digest, parsed, err)
	}
	var unmarshaled Digest
	if err := unmarshaled.UnmarshalText([]byte(digest.String())); err != nil || unmarshaled != digest {
		t.Fatalf("UnmarshalText = %s, %v", unmarshaled, err)
	}
	for _, bad := range []string{
		"", "sha256:", strings.ToUpper(digest.String()), "sha512:" + digest.String()[7:],
		digest.String()[:70], "sha256:" + strings.Repeat("0", 64), digest.String() + "0",
	} {
		if _, err := Parse(bad); !errors.Is(err, ErrInvalidDigest) {
			t.Errorf("Parse(%q) err = %v", bad, err)
		}
	}
}
