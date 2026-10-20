package site

import (
	"errors"
	"net/netip"
	"testing"
)

func TestValidatePrefixAcceptsSitePrefixes(t *testing.T) {
	t.Parallel()
	for _, text := range []string{
		"10.0.0.0/8", "10.20.0.0/16", "172.16.5.0/24", "192.168.1.10/32",
		"203.0.113.0/24", "2001:db8:10::/48", "2001:db8::1/128", "fc00:1::/32",
		"fd12:3456:789a::/48", "fd07:d4de:9d87:ff::/64", // unique local; the database checks the mesh pools
	} {
		if err := ValidatePrefix(netip.MustParsePrefix(text), nil); err != nil {
			t.Errorf("ValidatePrefix(%s) = %v", text, err)
		}
	}
}

func TestValidatePrefixRejectsUnsafePrefixes(t *testing.T) {
	t.Parallel()
	denied := []netip.Prefix{netip.MustParsePrefix("18.142.253.199/32"), netip.MustParsePrefix("129.212.209.14/32")}
	for _, text := range []string{
		"0.0.0.0/0", "::/0", "10.0.0.0/7", "2001:db8::/31",
		"10.0.0.1/8",                                                   // host bits
		"100.64.0.0/16", "100.0.0.0/8", "198.18.0.0/24", "198.0.0.0/8", // overlay and alias frame
		"fd00::/48", "fd00::/40", "fd00::1/128", // the mesh's self-test address
		"127.0.0.0/8", "169.254.1.0/24", "224.0.0.0/4", "240.0.0.0/8", "0.1.0.0/16",
		"::1/128", "fe80::/64", "ff02::/16", "::ffff:10.0.0.0/104",
		"18.142.0.0/16",     // covers a denied address (relay)
		"129.212.209.14/32", // is a denied address (Core ingress)
	} {
		if err := ValidatePrefix(netip.MustParsePrefix(text), denied); !errors.Is(err, ErrInvalidPrefix) {
			t.Errorf("ValidatePrefix(%s) = %v, want ErrInvalidPrefix", text, err)
		}
	}
	if err := ValidatePrefix(netip.Prefix{}, nil); !errors.Is(err, ErrInvalidPrefix) {
		t.Errorf("zero prefix = %v", err)
	}
}

func TestValidatePrefixSetRejectsOverlapAndBounds(t *testing.T) {
	t.Parallel()
	ok := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("10.21.0.0/16")}
	if err := ValidatePrefixSet(ok, nil, MaximumPrefixesPerSite); err != nil {
		t.Fatalf("ValidatePrefixSet(ok) = %v", err)
	}
	nested := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("10.20.5.0/24")}
	if err := ValidatePrefixSet(nested, nil, MaximumPrefixesPerSite); !errors.Is(err, ErrInvalidPrefix) {
		t.Fatalf("nested = %v", err)
	}
	if err := ValidatePrefixSet(nil, nil, MaximumPrefixesPerSite); !errors.Is(err, ErrInvalidPrefix) {
		t.Fatalf("empty = %v", err)
	}
	if err := ValidatePrefixSet(ok, nil, 1); !errors.Is(err, ErrPrefixLimit) {
		t.Fatalf("over the limit = %v", err)
	}
}

func TestPrefixesCover(t *testing.T) {
	t.Parallel()
	offered := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("2001:db8::/32")}
	if !Covers(offered, []netip.Prefix{netip.MustParsePrefix("10.20.5.0/24"), netip.MustParsePrefix("2001:db8:1::/48")}) {
		t.Fatal("offered prefixes did not cover narrower ones")
	}
	if Covers(offered, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}) {
		t.Fatal("a narrower offer covered a wider prefix")
	}
	if Covers(nil, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}) {
		t.Fatal("no offer covered a prefix")
	}
}

func TestOverlaps(t *testing.T) {
	t.Parallel()
	a := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
	if !Overlaps(a, []netip.Prefix{netip.MustParsePrefix("10.20.5.0/24")}) ||
		!Overlaps(a, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}) {
		t.Fatal("nested prefixes did not overlap")
	}
	if Overlaps(a, []netip.Prefix{netip.MustParsePrefix("10.21.0.0/16"), netip.MustParsePrefix("2001:db8::/32")}) {
		t.Fatal("disjoint prefixes overlapped")
	}
}
