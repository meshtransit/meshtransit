//go:build linux

package netadmin

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
)

func TestMergedRanges(t *testing.T) {
	t.Parallel()
	prefixes := func(texts ...string) []netip.Prefix {
		var parsed []netip.Prefix
		for _, text := range texts {
			parsed = append(parsed, netip.MustParsePrefix(text))
		}
		return parsed
	}
	tests := []struct {
		name     string
		prefixes []netip.Prefix
		ipv4     bool
		want     []string
	}{
		{"adjacent", prefixes("10.0.1.0/24", "10.0.0.0/24"), true, []string{"10.0.0.0-10.0.1.255"}},
		{"contained", prefixes("10.0.0.0/16", "10.0.5.0/24"), true, []string{"10.0.0.0-10.0.255.255"}},
		{"apart", prefixes("10.0.0.0/24", "10.0.2.0/24"), true, []string{"10.0.0.0-10.0.0.255", "10.0.2.0-10.0.2.255"}},
		{"top of ipv4", prefixes("255.255.255.0/24", "255.255.254.0/24"), true, []string{"255.255.254.0-255.255.255.255"}},
		{"other family left out", prefixes("10.0.0.0/24", "fd12::/64"), true, []string{"10.0.0.0-10.0.0.255"}},
		{"top of ipv6", prefixes("ffff:ffff:ffff:ffff::/64"), false, []string{"ffff:ffff:ffff:ffff::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}},
	}
	for _, test := range tests {
		var got []string
		for _, merged := range mergedRanges(test.prefixes, test.ipv4) {
			got = append(got, fmt.Sprintf("%s-%s", merged.first, merged.last))
		}
		if !slices.Equal(got, test.want) {
			t.Errorf("%s: mergedRanges() = %v, want %v", test.name, got, test.want)
		}
	}
	// The top range has no end element; others end after their last address.
	elements := intervalElements(prefixes("10.0.0.0/24", "255.255.255.0/24"), true)
	if len(elements) != 3 || !elements[1].IntervalEnd || netip.AddrFrom4([4]byte(elements[1].Key)) != netip.MustParseAddr("10.0.1.0") ||
		elements[2].IntervalEnd {
		t.Fatalf("intervalElements() = %+v", elements)
	}
	many := make([]netip.Prefix, 0, 4096)
	for index := range 4096 {
		many = append(many, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(index >> 8), byte(index), 0}), 24))
	}
	if merged := mergedRanges(many, true); len(merged) != 1 || merged[0].last != netip.MustParseAddr("10.15.255.255") {
		t.Fatalf("4096 adjacent /24 merged into %v", merged)
	}
}
