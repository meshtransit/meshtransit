package netcheck

import (
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/shared/disco"
)

var (
	s1  = netip.MustParseAddrPort("203.0.113.1:3478")
	s1p = netip.MustParseAddrPort("203.0.113.1:3479")
	s2  = netip.MustParseAddrPort("203.0.113.3:3478")
	s2p = netip.MustParseAddrPort("203.0.113.3:3479")
)

func ob(server netip.AddrPort, mapped string) Observation {
	return Observation{Server: server, Mapped: netip.MustParseAddrPort(mapped)}
}

func TestClassifyMapping(t *testing.T) {
	t.Parallel()
	local := []netip.AddrPort{netip.MustParseAddrPort("192.168.1.10:41641")}
	public := []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:41641")}
	tests := []struct {
		name  string
		local []netip.AddrPort
		obs   []Observation
		want  disco.Mapping
	}{
		{"nothing", local, nil, disco.MappingUnknown},
		{"one server", local, []Observation{ob(s1, "198.51.100.1:5000")}, disco.MappingUnknown},
		{"one server two ports agree", local, []Observation{ob(s1, "198.51.100.1:5000"), ob(s1p, "198.51.100.1:5000")}, disco.MappingUnknown},
		{"public", public, []Observation{ob(s1, "198.51.100.7:41641"), ob(s2, "198.51.100.7:41641")}, disco.MappingNone},
		{"endpoint independent", local, []Observation{
			ob(s1, "198.51.100.1:5000"), ob(s1p, "198.51.100.1:5000"), ob(s2, "198.51.100.1:5000"),
		}, disco.MappingEndpointIndependent},
		{"address dependent", local, []Observation{
			ob(s1, "198.51.100.1:5000"), ob(s1p, "198.51.100.1:5000"), ob(s2, "198.51.100.1:5001"), ob(s2p, "198.51.100.1:5001"),
		}, disco.MappingAddressDependent},
		{"address and port dependent", local, []Observation{
			ob(s1, "198.51.100.1:5000"), ob(s1p, "198.51.100.1:5001"), ob(s2, "198.51.100.1:5002"),
		}, disco.MappingAddressAndPortDependent},
		{"same server alt port differs", local, []Observation{ob(s1, "198.51.100.1:5000"), ob(s1p, "198.51.100.1:7000")}, disco.MappingAddressAndPortDependent},
		{"no alt port, servers differ: stricter", local, []Observation{ob(s1, "198.51.100.1:5000"), ob(s2, "198.51.100.1:5001")}, disco.MappingAddressAndPortDependent},
		{"dual stack compares per family", local, []Observation{
			ob(s1, "198.51.100.1:5000"), ob(s2, "198.51.100.1:5000"),
			ob(netip.MustParseAddrPort("[2001:db8::1]:3478"), "[2001:db8:1::10]:41641"),
		}, disco.MappingEndpointIndependent},
		{"duplicate observation ignored", local, []Observation{ob(s1, "198.51.100.1:5000"), ob(s1, "198.51.100.1:5000"), ob(s2, "198.51.100.1:5000")}, disco.MappingEndpointIndependent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ClassifyMapping(tt.local, tt.obs); got != tt.want {
				t.Fatalf("ClassifyMapping = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestClassifyAllocation(t *testing.T) {
	t.Parallel()
	eim, apdm := disco.MappingEndpointIndependent, disco.MappingAddressAndPortDependent
	tests := []struct {
		name     string
		m        disco.Mapping
		local    uint16
		ports    []uint16
		want     disco.Allocation
		wantStep uint16
	}{
		{"easy preserving", eim, 41641, []uint16{41641, 41641}, disco.AllocationPreserving, 0},
		{"easy translated", eim, 41641, []uint16{5000}, disco.AllocationRandom, 0},
		{"easy nothing", eim, 41641, nil, disco.AllocationUnknown, 0},
		{"unknown mapping", disco.MappingUnknown, 1, []uint16{1, 2, 3}, disco.AllocationUnknown, 0},
		{"hard too few", apdm, 1, []uint16{5000, 5001}, disco.AllocationUnknown, 0},
		{"hard sequential", apdm, 1, []uint16{5000, 5001, 5002, 5003}, disco.AllocationSequential, 1},
		{"hard sequential step 2 with repeat", apdm, 1, []uint16{5000, 5000, 5002, 5004}, disco.AllocationSequential, 2},
		{"hard sequential median", apdm, 1, []uint16{5000, 5001, 5004, 5005, 5008}, disco.AllocationSequential, 3},
		{"hard sequential wraps", apdm, 1, []uint16{65534, 65535, 0, 1}, disco.AllocationSequential, 1},
		{"hard random", apdm, 1, []uint16{5000, 31000, 12000}, disco.AllocationRandom, 0},
		{"hard descending", apdm, 1, []uint16{5003, 5002, 5001}, disco.AllocationRandom, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, step := ClassifyAllocation(tt.m, tt.local, tt.ports)
			if got != tt.want || step != tt.wantStep {
				t.Fatalf("ClassifyAllocation = %d step %d, want %d step %d", got, step, tt.want, tt.wantStep)
			}
		})
	}
}

func TestClassifyFiltering(t *testing.T) {
	t.Parallel()
	const (
		n = ProbeNotTried
		r = ProbeReceived
		l = ProbeLost
	)
	want := map[[2]Probe]disco.Filtering{
		{r, r}: disco.FilteringEndpointIndependent,
		{l, r}: disco.FilteringAddressDependent,
		{n, r}: disco.FilteringAddressDependent,
		{r, l}: disco.FilteringAddressAndPortDependent, // contradictory: stricter
		{l, l}: disco.FilteringAddressAndPortDependent,
		{n, l}: disco.FilteringAddressAndPortDependent,
		{r, n}: disco.FilteringEndpointIndependent,
		{l, n}: disco.FilteringUnknown,
		{n, n}: disco.FilteringUnknown,
	}
	for in, w := range want {
		if got := ClassifyFiltering(in[0], in[1]); got != w {
			t.Errorf("ClassifyFiltering(%d, %d) = %d, want %d", in[0], in[1], got, w)
		}
	}
}

func TestRefineMapping(t *testing.T) {
	t.Parallel()
	a := netip.MustParseAddrPort("198.51.100.1:5000")
	b := netip.MustParseAddrPort("198.51.100.1:5001")
	if got := RefineMapping(disco.MappingEndpointIndependent, []netip.AddrPort{a, b}); got != disco.MappingAddressAndPortDependent {
		t.Fatalf("differing peer observations: %d", got)
	}
	if got := RefineMapping(disco.MappingEndpointIndependent, []netip.AddrPort{a, a}); got != disco.MappingEndpointIndependent {
		t.Fatalf("agreeing peer observations: %d", got)
	}
	if got := RefineMapping(disco.MappingAddressDependent, []netip.AddrPort{a, b}); got != disco.MappingAddressDependent {
		t.Fatalf("hard mapping changed: %d", got)
	}
}

func TestReportCurrent(t *testing.T) {
	t.Parallel()
	at := time.Unix(1_800_000_000, 0)
	r := Report{NAT: disco.NATInfo{Mapping: disco.MappingEndpointIndependent}, At: at}
	if r.Current(at.Add(time.Minute)) != r.NAT {
		t.Fatal("fresh report not current")
	}
	if r.Current(at.Add(MaxReportAge+time.Second)) != (disco.NATInfo{}) {
		t.Fatal("stale report still current")
	}
	if r.Current(at.Add(-time.Second)) != (disco.NATInfo{}) {
		t.Fatal("report from the future accepted")
	}
	if (Report{}).Current(at) != (disco.NATInfo{}) {
		t.Fatal("empty report current")
	}
}
