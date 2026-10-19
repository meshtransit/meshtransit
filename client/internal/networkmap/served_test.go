package networkmap

import (
	"net/netip"
	"testing"
)

func TestValidateServed(t *testing.T) {
	t.Parallel()
	valid := func() []ServedSite {
		return []ServedSite{
			{
				Ref: "a", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("fd12::/48")},
				Masquerade: true,
				Probes:     []RouteProbe{{Address: netip.MustParseAddr("10.20.0.5")}, {Address: netip.MustParseAddr("fd12::5"), TCP: true, Port: 443}},
			},
			{Ref: "b", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")}},
		}
	}
	if err := validateServed(valid()); err != nil {
		t.Fatalf("validateServed(valid) error = %v", err)
	}
	tests := map[string]func([]ServedSite){
		"unsorted":    func(served []ServedSite) { served[0].Ref, served[1].Ref = "c", "b" },
		"duplicate":   func(served []ServedSite) { served[1].Ref = "a" },
		"no prefixes": func(served []ServedSite) { served[1].Prefixes = nil },
		"host bits": func(served []ServedSite) {
			served[1].Prefixes[0] = netip.PrefixFrom(netip.MustParseAddr("10.30.0.1"), 16)
		},
		"default route":       func(served []ServedSite) { served[1].Prefixes[0] = netip.MustParsePrefix("0.0.0.0/0") },
		"overlap across":      func(served []ServedSite) { served[1].Prefixes[0] = netip.MustParsePrefix("10.20.5.0/24") },
		"probe outside":       func(served []ServedSite) { served[0].Probes[0].Address = netip.MustParseAddr("10.99.0.1") },
		"icmp probe port":     func(served []ServedSite) { served[0].Probes[0].Port = 7 },
		"tcp probe zero port": func(served []ServedSite) { served[0].Probes[1].Port = 0 },
		"too many probes": func(served []ServedSite) {
			served[0].Probes = append(served[0].Probes, served[0].Probes...)
			served[0].Probes = append(served[0].Probes, served[0].Probes[0])
		},
	}
	for name, mutate := range tests {
		served := valid()
		mutate(served)
		if err := validateServed(served); err == nil {
			t.Errorf("%s: validateServed() accepted %+v", name, served)
		}
	}
	nested := valid()
	nested[0].Prefixes = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("10.20.1.0/24")}
	nested[0].Probes = nil
	if err := validateServed(nested); err == nil {
		t.Error("overlapping prefixes within a Site were accepted")
	}
}
