package ipam_test

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"meshtransit.net/core/internal/domain/ipam"
)

func aliasAllocationParams() ipam.DeviceAliasAllocationParams {
	return ipam.DeviceAliasAllocationParams{
		IPv4Pool:         netip.MustParsePrefix("192.0.2.0/29"),
		IPv6Pool:         netip.MustParsePrefix("fd00:2::/125"),
		ExcludedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16"), netip.MustParsePrefix("fd00:1::/64")},
		CandidateLimit:   16,
	}
}

func TestNextDeviceAliasesReturnsCompleteDistinctPairs(t *testing.T) {
	t.Parallel()
	params := aliasAllocationParams()
	params.InUse = parseAddresses([]string{"192.0.2.1", "fd00:2::1"})
	params.Quarantined = parseAddresses([]string{"192.0.2.2", "fd00:2::2"})
	params.Reserved = parseAddresses([]string{"192.0.2.3", "fd00:2::3", "100.64.0.1", "fd00:1::1"})
	prefixes, inUse := slices.Clone(params.ExcludedPrefixes), slices.Clone(params.InUse)
	quarantined, reserved := slices.Clone(params.Quarantined), slices.Clone(params.Reserved)
	got, err := ipam.NextDeviceAliases(params)
	want := ipam.DeviceAliases{
		ResourceIPv4: netip.MustParseAddr("192.0.2.4"), ConsumerSourceIPv4: netip.MustParseAddr("192.0.2.5"),
		ResourceIPv6: netip.MustParseAddr("fd00:2::4"), ConsumerSourceIPv6: netip.MustParseAddr("fd00:2::5"),
	}
	if err != nil || got != want {
		t.Fatalf("proposal = (%+v, %v), want %+v", got, err, want)
	}
	if !slices.Equal(params.ExcludedPrefixes, prefixes) || !slices.Equal(params.InUse, inUse) ||
		!slices.Equal(params.Quarantined, quarantined) || !slices.Equal(params.Reserved, reserved) {
		t.Fatal("allocation changed the authoritative exclusion snapshot")
	}
	repeated, err := ipam.NextDeviceAliases(params)
	if err != nil || repeated != got {
		t.Fatal("identical snapshot did not produce the same proposal")
	}
}

func TestNextDeviceAliasesRequiresExplicitFamilies(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		ipv4, ipv6 bool
	}{
		{name: "ipv4", ipv4: true}, {name: "ipv6", ipv6: true}, {name: "both", ipv4: true, ipv6: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			params := aliasAllocationParams()
			if !test.ipv4 {
				params.IPv4Pool = netip.Prefix{}
			}
			if !test.ipv6 {
				params.IPv6Pool = netip.Prefix{}
			}
			got, err := ipam.NextDeviceAliases(params)
			if err != nil || got.ResourceIPv4.IsValid() != test.ipv4 || got.ConsumerSourceIPv4.IsValid() != test.ipv4 ||
				got.ResourceIPv6.IsValid() != test.ipv6 || got.ConsumerSourceIPv6.IsValid() != test.ipv6 {
				t.Fatalf("family-specific proposal = (%+v, %v)", got, err)
			}
		})
	}
}

func TestNextDeviceAliasesNeverReturnsPartialAuthority(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		edit func(*ipam.DeviceAliasAllocationParams)
	}{
		{name: "ipv4 exhaustion", edit: func(p *ipam.DeviceAliasAllocationParams) {
			p.IPv4Pool = netip.MustParsePrefix("192.0.2.0/30")
			p.InUse = parseAddresses([]string{"192.0.2.1"})
		}},
		{name: "ipv6 exhaustion after ipv4 proposal", edit: func(p *ipam.DeviceAliasAllocationParams) {
			p.IPv6Pool = netip.MustParsePrefix("fd00:2::/127")
		}},
		{name: "bounded search exhaustion", edit: func(p *ipam.DeviceAliasAllocationParams) {
			p.CandidateLimit = 4
			p.InUse = parseAddresses([]string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			params := aliasAllocationParams()
			test.edit(&params)
			got, err := ipam.NextDeviceAliases(params)
			if !errors.Is(err, ipam.ErrAddressExhausted) || got != (ipam.DeviceAliases{}) {
				t.Fatalf("failed proposal = (%+v, %v), want empty exhausted result", got, err)
			}
		})
	}
}

func TestNextDeviceAliasesRejectsUnsafeOrAmbiguousPools(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		edit func(*ipam.DeviceAliasAllocationParams)
	}{
		{name: "no default pools", edit: func(p *ipam.DeviceAliasAllocationParams) { p.IPv4Pool, p.IPv6Pool = netip.Prefix{}, netip.Prefix{} }},
		{name: "unmasked", edit: func(p *ipam.DeviceAliasAllocationParams) { p.IPv4Pool = netip.MustParsePrefix("192.0.2.1/29") }},
		{name: "wrong family", edit: func(p *ipam.DeviceAliasAllocationParams) { p.IPv4Pool = p.IPv6Pool }},
		{name: "mapped ipv4", edit: func(p *ipam.DeviceAliasAllocationParams) { p.IPv6Pool = netip.MustParsePrefix("::ffff:192.0.2.0/125") }},
		{name: "ipv4 loopback", edit: func(p *ipam.DeviceAliasAllocationParams) { p.IPv4Pool = netip.MustParsePrefix("127.0.0.0/24") }},
		{name: "loopback inside broader pool", edit: func(p *ipam.DeviceAliasAllocationParams) { p.IPv4Pool = netip.MustParsePrefix("126.0.0.0/7") }},
		{name: "ipv4 linklocal", edit: func(p *ipam.DeviceAliasAllocationParams) { p.IPv4Pool = netip.MustParsePrefix("169.254.0.0/16") }},
		{name: "ipv4 multicast", edit: func(p *ipam.DeviceAliasAllocationParams) { p.IPv4Pool = netip.MustParsePrefix("224.0.0.0/4") }},
		{name: "ipv6 unspecified", edit: func(p *ipam.DeviceAliasAllocationParams) { p.IPv6Pool = netip.MustParsePrefix("::/64") }},
		{name: "ipv6 loopback", edit: func(p *ipam.DeviceAliasAllocationParams) { p.IPv6Pool = netip.MustParsePrefix("::1/128") }},
		{name: "ipv6 linklocal", edit: func(p *ipam.DeviceAliasAllocationParams) { p.IPv6Pool = netip.MustParsePrefix("fe80::/10") }},
		{name: "ipv6 multicast", edit: func(p *ipam.DeviceAliasAllocationParams) { p.IPv6Pool = netip.MustParsePrefix("ff00::/8") }},
		{name: "contained overlay", edit: func(p *ipam.DeviceAliasAllocationParams) {
			p.ExcludedPrefixes = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/30")}
		}},
		{name: "containing overlay", edit: func(p *ipam.DeviceAliasAllocationParams) {
			p.ExcludedPrefixes = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
		}},
		{name: "ipv6 overlay", edit: func(p *ipam.DeviceAliasAllocationParams) {
			p.ExcludedPrefixes = []netip.Prefix{netip.MustParsePrefix("fd00:2::/64")}
		}},
		{name: "invalid exclusion", edit: func(p *ipam.DeviceAliasAllocationParams) { p.ExcludedPrefixes = []netip.Prefix{{}} }},
		{name: "unmasked exclusion", edit: func(p *ipam.DeviceAliasAllocationParams) {
			p.ExcludedPrefixes = []netip.Prefix{netip.MustParsePrefix("100.64.0.1/16")}
		}},
		{name: "invalid active address", edit: func(p *ipam.DeviceAliasAllocationParams) { p.InUse = []netip.Addr{{}} }},
		{name: "invalid quarantine address", edit: func(p *ipam.DeviceAliasAllocationParams) { p.Quarantined = []netip.Addr{{}} }},
		{name: "mapped reservation", edit: func(p *ipam.DeviceAliasAllocationParams) { p.Reserved = parseAddresses([]string{"::ffff:192.0.2.1"}) }},
		{name: "zoned reservation", edit: func(p *ipam.DeviceAliasAllocationParams) { p.Reserved = parseAddresses([]string{"fe80::1%eth0"}) }},
		{name: "zero search bound", edit: func(p *ipam.DeviceAliasAllocationParams) { p.CandidateLimit = 0 }},
		{name: "excessive search bound", edit: func(p *ipam.DeviceAliasAllocationParams) { p.CandidateLimit = ipam.MaxCandidateLimit + 1 }},
		{name: "excessive prefixes", edit: func(p *ipam.DeviceAliasAllocationParams) {
			p.ExcludedPrefixes = make([]netip.Prefix, ipam.MaxAliasExcludedPrefixes+1)
		}},
		{name: "excessive combined addresses", edit: func(p *ipam.DeviceAliasAllocationParams) {
			p.InUse = make([]netip.Addr, ipam.MaxAliasExcludedAddresses)
			p.Quarantined = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			params := aliasAllocationParams()
			test.edit(&params)
			got, err := ipam.NextDeviceAliases(params)
			if !errors.Is(err, ipam.ErrInvalidAllocation) || got != (ipam.DeviceAliases{}) {
				t.Fatalf("unsafe proposal = (%+v, %v), want invalid empty result", got, err)
			}
		})
	}
}

func TestNextDeviceAliasesKeepsQuarantineAndDeduplicatesExclusions(t *testing.T) {
	t.Parallel()
	params := aliasAllocationParams()
	params.Quarantined = parseAddresses([]string{"192.0.2.1", "fd00:2::1"})
	params.InUse = slices.Clone(params.Quarantined)
	params.Reserved = slices.Clone(params.Quarantined)
	got, err := ipam.NextDeviceAliases(params)
	if err != nil || got.ResourceIPv4 != netip.MustParseAddr("192.0.2.2") || got.ResourceIPv6 != netip.MustParseAddr("fd00:2::2") {
		t.Fatalf("quarantined address reused: (%+v, %v)", got, err)
	}
	// No clock can release quarantine. Only a changed durable snapshot can.
	again, err := ipam.NextDeviceAliases(params)
	if err != nil || again != got {
		t.Fatal("unchanged quarantine was not retained")
	}
}

func FuzzNextDeviceAliases(f *testing.F) {
	f.Add("192.0.2.0/29", "fd00:2::/125", "192.0.2.1", uint16(16))
	f.Add("126.0.0.0/7", "::/64", "::1", uint16(4))
	f.Fuzz(func(t *testing.T, ipv4, ipv6, excluded string, limit uint16) {
		if len(ipv4)+len(ipv6)+len(excluded) > 256 {
			return
		}
		v4, _ := netip.ParsePrefix(ipv4)
		v6, _ := netip.ParsePrefix(ipv6)
		address, addressErr := netip.ParseAddr(excluded)
		params := ipam.DeviceAliasAllocationParams{IPv4Pool: v4, IPv6Pool: v6, CandidateLimit: int(limit)}
		if addressErr == nil {
			params.Quarantined = []netip.Addr{address}
		}
		got, err := ipam.NextDeviceAliases(params)
		if err != nil {
			if got != (ipam.DeviceAliases{}) {
				t.Fatal("failed allocation returned a partial pair")
			}
			return
		}
		for _, pair := range []struct {
			prefix             netip.Prefix
			resource, consumer netip.Addr
		}{
			{prefix: v4, resource: got.ResourceIPv4, consumer: got.ConsumerSourceIPv4},
			{prefix: v6, resource: got.ResourceIPv6, consumer: got.ConsumerSourceIPv6},
		} {
			if !pair.prefix.IsValid() {
				if pair.resource.IsValid() || pair.consumer.IsValid() {
					t.Fatal("inferred unrequested family")
				}
				continue
			}
			for _, candidate := range []netip.Addr{pair.resource, pair.consumer} {
				if !candidate.IsValid() || !candidate.IsGlobalUnicast() || candidate.IsLoopback() || candidate.IsLinkLocalUnicast() ||
					candidate == address || !pair.prefix.Contains(candidate) || candidate == pair.prefix.Addr() {
					t.Fatal("successful allocation escaped pool or exclusions")
				}
			}
			if pair.resource == pair.consumer {
				t.Fatal("resource and source aliases collided")
			}
		}
	})
}
