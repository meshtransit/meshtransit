package mapsession

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
)

// BenchmarkRoutesForDNSNames measures one map's names at the D2 ceiling
// (DNS design D2 §4.2): 100,000 Devices in 1,000 Device Groups of 100, 1,000
// rules from group to group, and 10,000 names in one zone sent to every
// Device, half to a Device, a quarter fixed addresses, a quarter CNAMEs.
// The budget is 2 ms a map.
func BenchmarkRoutesForDNSNames(b *testing.B) {
	const devices, groups, rules, names = 100_000, 1_000, 1_000, 10_000
	now := policyNow
	params := NetworkPolicyParams{Scope: snapshotFixture(b).Scope(), Revision: 4, ReleaseActive: true,
		RouteRevision: 9, RoutePeerLimit: DefaultPeerLimit}
	ids := make([]node.ID, devices+1)
	for device := int64(1); device <= devices; device++ {
		ids[device] = must(node.ParseID(fmt.Sprintf("01890f00-0000-7000-8000-%012d", device)))
		params.Devices = append(params.Devices, PolicyDevice{Device: device, NodeID: ids[device],
			ExpiresAt: now.Add(24 * time.Hour)})
		params.Members = append(params.Members, SelectorMember{Kind: SelectorDeviceGroup,
			Selector: (device-1)%groups + 1, Device: device})
	}
	ports := []policy.PortRange{must(policy.NewPortRange(443, 443))}
	for rule := int64(1); rule <= rules; rule++ {
		params.Rules = append(params.Rules, NetworkPolicyRule{
			ID:         must(policy.ParseRuleID(fmt.Sprintf("01890f00-0000-7000-8000-%012d", 900_000+rule))),
			SourceKind: SelectorDeviceGroup, SourceRef: rule, DestinationKind: SelectorDeviceGroup,
			DestinationRef: rule%groups + 1, Protocol: policy.ProtocolTCP, Ports: ports,
		})
	}
	params.DNSZones = []DNSZone{{Zone: 1, Domain: "corp.lan", OtherNames: DNSOtherNXDomain, FailOpen: true}}
	for index := range names {
		name := DNSName{Zone: 1, FQDN: fmt.Sprintf("name-%05d.corp.lan", index)}
		switch index % 4 {
		case 0, 1:
			device := int64(index*7%devices + 1)
			name.Device, name.NodeID = device, ids[device]
		case 2:
			name.Addresses = []netip.Addr{netip.AddrFrom4([4]byte{10, byte(index >> 8), byte(index), 1})}
		default:
			name.CNAME = fmt.Sprintf("name-%05d.corp.lan", index-1)
		}
		params.DNSNames = append(params.DNSNames, name)
	}
	networkPolicy, err := NewNetworkPolicy(params)
	if err != nil {
		b.Fatal(err)
	}
	self := ids[42]
	b.ResetTimer()
	for b.Loop() {
		if view := networkPolicy.RoutesFor(self, now); len(view.dnsNames) == 0 {
			b.Fatal("no names")
		}
	}
}
