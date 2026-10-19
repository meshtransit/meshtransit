package site

import (
	"net/netip"
	"slices"
	"testing"
)

func TestParseOfferKeepsUsablePrefixes(t *testing.T) {
	t.Parallel()
	parse := func(texts ...string) []netip.Prefix {
		prefixes := make([]netip.Prefix, len(texts))
		for index, text := range texts {
			prefixes[index] = netip.MustParsePrefix(text)
		}
		return prefixes
	}
	kept, dropped := ParseOffer(parse(
		"2001:db8:20::/48", "10.20.0.0/16", "10.20.0.0/16", "192.168.1.0/24",
		"0.0.0.0/0", "::/0", "10.20.0.1/16", "100.64.0.0/24", "fd00:1::/48", "::ffff:10.0.0.0/104", "8.0.0.0/7",
	))
	want := parse("10.20.0.0/16", "192.168.1.0/24", "2001:db8:20::/48")
	if !slices.Equal(kept, want) || dropped != 7 {
		t.Fatalf("ParseOffer() = %v, %d dropped; want %v, 7", kept, dropped, want)
	}
	if empty, none := ParseOffer(nil); len(empty) != 0 || none != 0 {
		t.Fatalf("ParseOffer(nil) = %v, %d", empty, none)
	}
}
