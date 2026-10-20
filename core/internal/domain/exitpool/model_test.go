package exitpool

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/node"
)

func validDefinition() Definition {
	return Definition{
		Name: "Singapore", ConntrackPerConsumer: DefaultConntrackPerConsumer,
		DNSUpstreams: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")},
		Probes:       []Probe{{Address: netip.MustParseAddr("8.8.8.8"), Port: 443}},
	}
}

func TestDefinitionValidate(t *testing.T) {
	t.Parallel()
	limits := DefaultLimits()
	for name, test := range map[string]struct {
		change func(*Definition)
		want   error
	}{
		"valid":                {change: func(*Definition) {}},
		"no upstreams, probes": {change: func(d *Definition) { d.DNSUpstreams, d.Probes = nil, nil }},
		"empty name":           {change: func(d *Definition) { d.Name = "" }, want: ErrInvalid},
		"untrimmed name":       {change: func(d *Definition) { d.Name = " SG" }, want: ErrInvalid},
		"long name":            {change: func(d *Definition) { d.Name = strings.Repeat("x", 65) }, want: ErrInvalid},
		"control in name":      {change: func(d *Definition) { d.Name = "S\x07G" }, want: ErrInvalid},
		"conntrack too low":    {change: func(d *Definition) { d.ConntrackPerConsumer = 1023 }, want: ErrInvalid},
		"conntrack too high": {change: func(d *Definition) {
			d.ConntrackPerConsumer = MaximumConntrackPerConsumer + 1
		}, want: ErrInvalid},
		"private upstream": {change: func(d *Definition) {
			d.DNSUpstreams = []netip.Addr{netip.MustParseAddr("10.0.0.2")}
		}, want: ErrNotInternet},
		"metadata upstream": {change: func(d *Definition) {
			d.DNSUpstreams = []netip.Addr{netip.MustParseAddr("169.254.169.253")}
		}, want: ErrNotInternet},
		"duplicate upstream": {change: func(d *Definition) {
			d.DNSUpstreams = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.1.1.1")}
		}, want: ErrInvalid},
		"too many upstreams": {change: func(d *Definition) {
			d.DNSUpstreams = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1"),
				netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("9.9.9.9")}
		}, want: ErrInvalid},
		"private probe": {change: func(d *Definition) {
			d.Probes = []Probe{{Address: netip.MustParseAddr("192.168.1.1"), Port: 443}}
		}, want: ErrNotInternet},
		"probe without port": {change: func(d *Definition) {
			d.Probes = []Probe{{Address: netip.MustParseAddr("8.8.8.8")}}
		}, want: ErrInvalid},
		"duplicate probe": {change: func(d *Definition) {
			d.Probes = append(d.Probes, d.Probes[0])
		}, want: ErrInvalid},
		"too many probes": {change: func(d *Definition) {
			d.Probes = nil
			for port := range MaximumProbesPerPool + 1 {
				d.Probes = append(d.Probes, Probe{Address: netip.MustParseAddr("8.8.8.8"), Port: uint16(port + 1)})
			}
		}, want: ErrInvalid},
	} {
		definition := validDefinition()
		test.change(&definition)
		if err := definition.Validate(limits); !errors.Is(err, test.want) {
			t.Errorf("%s: Validate = %v, want %v", name, err, test.want)
		}
	}
}

func TestDefinitionCanonicalSortsProbesWithoutChangingTheCaller(t *testing.T) {
	t.Parallel()
	definition := validDefinition()
	definition.DNSUpstreams = []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("1.1.1.1")}
	definition.Probes = []Probe{
		{Address: netip.MustParseAddr("8.8.8.8"), Port: 443},
		{Address: netip.MustParseAddr("1.1.1.1"), Port: 443},
	}
	canonical := definition.Canonical()
	// Resolvers keep their order (exit nodes try them in it); probes sort.
	if canonical.DNSUpstreams[0] != netip.MustParseAddr("2606:4700:4700::1111") ||
		canonical.Probes[0].Address != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("canonical = %+v", canonical)
	}
	if definition.Probes[0].Address != netip.MustParseAddr("8.8.8.8") {
		t.Fatal("Canonical changed its receiver's slices")
	}
}

func TestNodeAssignmentValidate(t *testing.T) {
	t.Parallel()
	device, err := node.ParseID("01a144c0-4852-7022-87a5-57e5cdc78c7f")
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		assignment NodeAssignment
		valid      bool
	}{
		"active":         {NodeAssignment{DeviceID: device, Priority: 10, State: NodeActive}, true},
		"draining":       {NodeAssignment{DeviceID: device, Priority: MaximumPriority, State: NodeDraining}, true},
		"no Device":      {NodeAssignment{Priority: 1, State: NodeActive}, false},
		"negative":       {NodeAssignment{DeviceID: device, Priority: -1, State: NodeActive}, false},
		"too large":      {NodeAssignment{DeviceID: device, Priority: MaximumPriority + 1, State: NodeActive}, false},
		"unknown state":  {NodeAssignment{DeviceID: device, Priority: 1}, false},
		"unknown state2": {NodeAssignment{DeviceID: device, Priority: 1, State: 9}, false},
	} {
		if err := test.assignment.Validate(); (err == nil) != test.valid {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
}

func TestLimitsValidate(t *testing.T) {
	t.Parallel()
	if err := DefaultLimits().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, limits := range []Limits{
		{PoolsPerNetwork: 0, NodesPerPool: 1},
		{PoolsPerNetwork: MaximumPoolsPerNetwork + 1, NodesPerPool: 1},
		{PoolsPerNetwork: 1, NodesPerPool: 0},
		{PoolsPerNetwork: 1, NodesPerPool: MaximumNodesPerPool + 1},
	} {
		if limits.Validate() == nil {
			t.Errorf("limits %+v accepted", limits)
		}
	}
}

func TestEligible(t *testing.T) {
	t.Parallel()
	if !Eligible("active", "workspace", true) {
		t.Fatal("an active Workspace Device offering exit is not eligible")
	}
	for _, facts := range []struct {
		state, ownership string
		offered          bool
	}{{"suspended", "workspace", true}, {"active", "user", true}, {"active", "workspace", false}} {
		if Eligible(facts.state, facts.ownership, facts.offered) {
			t.Errorf("%+v is eligible", facts)
		}
	}
}
