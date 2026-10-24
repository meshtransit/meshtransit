package dnszone

import (
	"errors"
	"net/netip"
	"testing"
)

func TestParseZoneDomainTakesReverseRanges(t *testing.T) {
	t.Parallel()
	names := testNames(t)
	for input, want := range map[string]struct {
		prefix string
		class  Class
		err    error
	}{
		"10.in-addr.arpa":          {prefix: "10.0.0.0/8", class: ClassPrivate},
		"168.192.IN-ADDR.ARPA.":    {prefix: "192.168.0.0/16", class: ClassPrivate},
		"5.35.10.in-addr.arpa":     {prefix: "10.35.5.0/24", class: ClassPrivate},
		"113.0.203.in-addr.arpa":   {prefix: "203.0.113.0/24", class: ClassPublic},
		"c.f.ip6.arpa":             {prefix: "fc00::/8", class: ClassPrivate},
		"8.b.d.0.1.0.0.2.ip6.arpa": {prefix: "2001:db8::/32", class: ClassPublic},
		"100.in-addr.arpa":         {err: ErrReverseMeshRange},
		"18.198.in-addr.arpa":      {err: ErrReverseMeshRange},
		"d.f.ip6.arpa":             {err: ErrReverseMeshRange},
		"127.in-addr.arpa":         {err: ErrReverseReservedRange},
		"254.169.in-addr.arpa":     {err: ErrReverseReservedRange},
		"in-addr.arpa":             {err: ErrDomainSpecialUse},
		"1.2.3.4.in-addr.arpa":     {err: ErrInvalid},
		"010.in-addr.arpa":         {err: ErrInvalid},
		"256.in-addr.arpa":         {err: ErrInvalid},
		"ab.ip6.arpa":              {err: ErrInvalid},
	} {
		domain, class, err := ParseZoneDomain(input, names)
		if want.err != nil {
			if !errors.Is(err, want.err) {
				t.Fatalf("%s: %v, want %v", input, err, want.err)
			}
			continue
		}
		prefix, ok := ReversePrefix(domain)
		if err != nil || !ok || prefix != netip.MustParsePrefix(want.prefix) || class != want.class {
			t.Fatalf("%s: %s %s %s %v", input, domain, prefix, class, err)
		}
	}
	// A share's name is never a reverse domain.
	if _, _, err := ParseDomain("10.in-addr.arpa", names); !errors.Is(err, ErrDomainSpecialUse) {
		t.Fatalf("ParseDomain took a reverse domain: %v", err)
	}
}
