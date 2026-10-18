package routedigest

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// The vector of route-digest-v1 §4, cross-checked with an independent Python
// implementation of §2–3.
func TestComputeMatchesTheVector(t *testing.T) {
	t.Parallel()
	entries := []Entry{
		{SiteRef: "site-hq", Prefix: netip.MustParsePrefix("10.20.0.0/16"), Masquerade: true},
		{SiteRef: "site-hq", Prefix: netip.MustParsePrefix("fd10:20::/48"), Masquerade: true},
		{SiteRef: "site-lab", Prefix: netip.MustParsePrefix("192.168.50.0/24")},
		{SiteRef: "site-hq", Prefix: netip.MustParsePrefix("10.20.0.0/16"), Masquerade: true},
	}
	digest, count, err := Compute(entries)
	if err != nil {
		t.Fatal(err)
	}
	if got := digest.String(); got != "sha256:3b577c0036777a664548ccd90580209560832faa9b06fc08d70adb047db0adbb" || count != 3 {
		t.Fatalf("Compute() = %s, %d", got, count)
	}
	empty, count, err := Compute(nil)
	if err != nil || count != 0 ||
		empty.String() != "sha256:76486304a2b5099aec5f5731de6baaa2dc2231046e5ea3b5c9ba964994f5e6e1" {
		t.Fatalf("Compute(nil) = %s, %d, %v", empty, count, err)
	}
}

func TestComputeIgnoresOrder(t *testing.T) {
	t.Parallel()
	first := []Entry{
		{SiteRef: "a", Prefix: netip.MustParsePrefix("10.0.0.0/8")},
		{SiteRef: "b", Prefix: netip.MustParsePrefix("172.16.0.0/12"), Masquerade: true},
	}
	second := []Entry{first[1], first[0], first[1]}
	one, _, _ := Compute(first)
	two, _, _ := Compute(second)
	if one != two {
		t.Fatal("order or duplicates changed the digest")
	}
	changed := []Entry{first[0], {SiteRef: "b", Prefix: first[1].Prefix}}
	if three, _, _ := Compute(changed); three == one {
		t.Fatal("masquerade did not change the digest")
	}
}

func TestComputeRejectsInvalidEntries(t *testing.T) {
	t.Parallel()
	for name, entry := range map[string]Entry{
		"empty site":         {Prefix: netip.MustParsePrefix("10.0.0.0/8")},
		"long site":          {SiteRef: strings.Repeat("s", 65), Prefix: netip.MustParsePrefix("10.0.0.0/8")},
		"zero prefix":        {SiteRef: "s"},
		"host bits":          {SiteRef: "s", Prefix: netip.MustParsePrefix("10.0.0.1/8")},
		"default route":      {SiteRef: "s", Prefix: netip.MustParsePrefix("0.0.0.0/0")},
		"IPv4-mapped prefix": {SiteRef: "s", Prefix: netip.MustParsePrefix("::ffff:10.0.0.0/104")},
		"invalid UTF-8 site": {SiteRef: "s\xff", Prefix: netip.MustParsePrefix("10.0.0.0/8")},
	} {
		if _, _, err := Compute([]Entry{entry}); !errors.Is(err, ErrInvalidEntry) {
			t.Errorf("%s: error = %v, want ErrInvalidEntry", name, err)
		}
	}
}

func TestComputeRejectsConflictingMasquerade(t *testing.T) {
	t.Parallel()
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	if _, _, err := Compute([]Entry{{SiteRef: "s", Prefix: prefix, Masquerade: true}, {SiteRef: "s", Prefix: prefix}}); !errors.Is(err, ErrInvalidEntry) {
		t.Fatalf("error = %v, want ErrInvalidEntry", err)
	}
}

func TestComputeBoundsEntries(t *testing.T) {
	t.Parallel()
	entries := make([]Entry, 0, MaximumEntries+1)
	for index := range MaximumEntries + 1 {
		entries = append(entries, Entry{SiteRef: "s", Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(index >> 8), byte(index), 0}), 24)})
	}
	if _, _, err := Compute(entries); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("error = %v, want ErrTooLarge", err)
	}
	if _, count, err := Compute(entries[:MaximumEntries]); err != nil || count != MaximumEntries {
		t.Fatalf("Compute(maximum) = %d, %v", count, err)
	}
}
