package site

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func validDefinition() Definition {
	return Definition{
		Name:       "HQ LAN",
		Prefixes:   []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("2001:db8:20::/48")},
		Masquerade: true,
		Probes:     []Probe{{Address: netip.MustParseAddr("10.20.0.1"), Kind: ProbeICMP}},
	}
}

func TestDefinitionValidate(t *testing.T) {
	t.Parallel()
	if err := validDefinition().Validate(DefaultLimits(), nil); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	for name, mutate := range map[string]func(*Definition){
		"empty name":        func(d *Definition) { d.Name = "" },
		"padded name":       func(d *Definition) { d.Name = " HQ" },
		"long name":         func(d *Definition) { d.Name = strings.Repeat("n", MaximumNameLength+1) },
		"control in name":   func(d *Definition) { d.Name = "HQ\n" },
		"no prefixes":       func(d *Definition) { d.Prefixes = nil },
		"overlay prefix":    func(d *Definition) { d.Prefixes = []netip.Prefix{netip.MustParsePrefix("100.64.1.0/24")} },
		"probe outside":     func(d *Definition) { d.Probes[0].Address = netip.MustParseAddr("10.21.0.1") },
		"probe kind":        func(d *Definition) { d.Probes[0].Kind = 0 },
		"ICMP probe port":   func(d *Definition) { d.Probes[0].Port = 22 },
		"TCP probe no port": func(d *Definition) { d.Probes[0].Kind = ProbeTCP },
		"duplicate probe": func(d *Definition) {
			d.Probes = append(d.Probes, d.Probes[0])
		},
	} {
		definition := validDefinition()
		definition.Prefixes = append([]netip.Prefix(nil), definition.Prefixes...)
		definition.Probes = append([]Probe(nil), definition.Probes...)
		mutate(&definition)
		if err := definition.Validate(DefaultLimits(), nil); err == nil {
			t.Errorf("%s: Validate() = nil", name)
		}
	}
	tcp := validDefinition()
	tcp.Probes = []Probe{{Address: netip.MustParseAddr("10.20.0.5"), Kind: ProbeTCP, Port: 443}}
	if err := tcp.Validate(DefaultLimits(), nil); err != nil {
		t.Fatalf("TCP probe = %v", err)
	}
	small := Limits{RoutersPerSite: 1, PrefixesPerSite: 1, SitesPerNetwork: 1, ProbesPerSite: 1}
	if err := validDefinition().Validate(small, nil); !errors.Is(err, ErrPrefixLimit) {
		t.Fatalf("plan prefix limit = %v", err)
	}
}

func TestDefinitionCanonicalSortsPrefixesAndProbes(t *testing.T) {
	t.Parallel()
	definition := Definition{
		Name:     "Lab",
		Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("10.0.0.0/8")},
		Probes: []Probe{
			{Address: netip.MustParseAddr("192.168.0.1"), Kind: ProbeICMP},
			{Address: netip.MustParseAddr("10.0.0.1"), Kind: ProbeTCP, Port: 22},
		},
	}
	canonical := definition.Canonical()
	if got := canonical.Prefixes; got[0].String() != "10.0.0.0/8" || got[1].String() != "192.168.0.0/16" || got[2].String() != "2001:db8::/32" {
		t.Fatalf("prefixes = %v", got)
	}
	if canonical.Probes[0].Address.String() != "10.0.0.1" {
		t.Fatalf("probes = %v", canonical.Probes)
	}
	if definition.Prefixes[0].String() != "2001:db8::/32" {
		t.Fatal("Canonical() changed its receiver")
	}
}

func TestRouterValidate(t *testing.T) {
	t.Parallel()
	device := validDeviceID(t)
	if err := (RouterAssignment{DeviceID: device, Priority: 10, State: RouterActive}).Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	for name, router := range map[string]RouterAssignment{
		"no device":         {Priority: 1, State: RouterActive},
		"negative priority": {DeviceID: device, Priority: -1, State: RouterActive},
		"high priority":     {DeviceID: device, Priority: MaximumPriority + 1, State: RouterActive},
		"unknown state":     {DeviceID: device, Priority: 1},
	} {
		if err := router.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Validate() = %v", name, err)
		}
	}
}
