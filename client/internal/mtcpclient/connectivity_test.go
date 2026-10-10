package mtcpclient

import (
	"net/netip"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/shared/disco"
)

func TestAddConnectivity(t *testing.T) {
	t.Parallel()
	candidate := func(addr string, source pathdiscovery.Source) pathdiscovery.Candidate {
		c, err := pathdiscovery.NewCandidate(netip.MustParseAddrPort(addr), source)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	set, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{
		candidate("198.51.100.7:41641", pathdiscovery.SourceServerReflexive),
		candidate("[2001:db8::10]:41641", pathdiscovery.SourceServerReflexive),
		candidate("[fd00::10]:41641", pathdiscovery.SourceHost),
	})
	if err != nil {
		t.Fatal(err)
	}
	observed := time.UnixMilli(1_800_000_000_000)
	expires := observed.Add(time.Hour)
	report := &mtcpv1.EndpointReport{}
	addConnectivity(report, controlplane.EndpointUpdate{Candidates: set, Connectivity: controlplane.Connectivity{
		NATKnown: true, NATStep: 2, NATObservedAt: observed,
		NAT:         disco.NATInfo{Mapping: disco.MappingAddressAndPortDependent, Filtering: disco.FilteringAddressAndPortDependent, Allocation: disco.AllocationSequential},
		PortMapping: controlplane.PortMappingState{Protocol: "upnp", State: "mapped", ExpiresAt: expires},
	}})
	if report.Nat.GetMapping() != uint32(disco.MappingAddressAndPortDependent) || report.Nat.GetSequentialStep() != 2 ||
		report.NatObservedMs != observed.UnixMilli() {
		t.Fatalf("nat %+v at %d", report.Nat, report.NatObservedMs)
	}
	if !report.Ipv6Global || !report.Ipv6Stun {
		t.Fatalf("ipv6 global %v stun %v", report.Ipv6Global, report.Ipv6Stun)
	}
	if report.PortMapping.GetProtocol() != 3 || report.PortMapping.GetState() != 3 || report.PortMapping.GetExpiresMs() != expires.UnixMilli() {
		t.Fatalf("port mapping %+v", report.PortMapping)
	}

	// Nothing known: no NAT, no mapping, no IPv6 from a unique-local address.
	only := &mtcpv1.EndpointReport{}
	local, _ := pathdiscovery.NewSet([]pathdiscovery.Candidate{candidate("[fd00::10]:41641", pathdiscovery.SourceHost)})
	addConnectivity(only, controlplane.EndpointUpdate{Candidates: local})
	if only.Nat != nil || only.PortMapping != nil || only.Ipv6Global || only.NatObservedMs != 0 {
		t.Fatalf("report %+v", only)
	}
}
