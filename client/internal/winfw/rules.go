// Package winfw is the Windows kill switch of a host that sends its Internet
// traffic through an exit node (exit node design §6.4): Windows Filtering
// Platform filters in a sublayer of MeshTransit's own drop every new
// outbound connection but those of the MeshTransit service, on loopback, on
// the MeshTransit adapter, DHCP, neighbour discovery and the LAN when
// allowed. The filters are persistent: they outlive the service and a
// reboot, so the host stays closed until the service lifts them because the
// host stopped using an exit node, or an administrator runs
// "meshd release-exit". Connections opened from outside are left to the
// Windows firewall: their replies leave by the interface they came in on.
//
// The rules are described here, portably, and installed on Windows.
package winfw

import (
	"net/netip"
	"slices"
)

// maximumLAN bounds the LAN prefixes a kill switch admits.
const maximumLAN = 64

// Weights order the filters inside the sublayer: the highest that matches
// decides.
const (
	weightService  = 15
	weightLoopback = 13
	weightAdapter  = 12
	weightSystem   = 12
	weightLAN      = 11
	weightBlock    = 0
)

// Protocols the rules name.
const (
	protocolUDP    = 17
	protocolICMPv6 = 58
)

// Config is what the kill switch lets through besides the service and
// loopback.
type Config struct {
	// Adapter is the MeshTransit adapter's LUID, 0 while it is not open:
	// traffic routed into it is let through.
	Adapter uint64
	// LAN are the attached private subnets and link-local multicast let
	// through when the settings allow the LAN.
	LAN []netip.Prefix
}

// Rule is one filter at the outbound connection layer of one family. Every
// condition set must hold; Remote holds when any of its prefixes does.
type Rule struct {
	Name   string
	IPv6   bool
	Weight uint8
	Block  bool
	// Service matches the MeshTransit service: its executable running as
	// LocalSystem.
	Service  bool
	Loopback bool
	// Adapter matches traffic leaving by the interface of this LUID.
	Adapter    uint64
	Protocol   uint8
	LocalPort  uint16
	RemotePort uint16
	// ICMPType matches an ICMP type when MatchICMP is set.
	ICMPType  uint16
	MatchICMP bool
	Remote    []netip.Prefix
}

// Rules returns the filters of config, permits first.
func Rules(config Config) []Rule {
	var rules []Rule
	both := func(rule Rule) {
		v6 := rule
		v6.IPv6, v6.Name = true, rule.Name+" (IPv6)"
		rule.Name += " (IPv4)"
		rules = append(rules, rule, v6)
	}
	both(Rule{Name: "Permit the MeshTransit service", Weight: weightService, Service: true})
	both(Rule{Name: "Permit loopback", Weight: weightLoopback, Loopback: true})
	if config.Adapter != 0 {
		both(Rule{Name: "Permit the MeshTransit adapter", Weight: weightAdapter, Adapter: config.Adapter})
	}
	rules = append(rules,
		Rule{Name: "Permit DHCP (IPv4)", Weight: weightSystem, Protocol: protocolUDP, LocalPort: 68, RemotePort: 67},
		Rule{
			Name: "Permit DHCP (IPv6)", IPv6: true, Weight: weightSystem, Protocol: protocolUDP,
			LocalPort: 546, RemotePort: 547,
		})
	// Router solicitation, neighbour solicitation and advertisement.
	for _, icmpType := range []uint16{133, 135, 136} {
		rules = append(rules, Rule{
			Name: "Permit neighbour discovery", IPv6: true, Weight: weightSystem,
			Protocol: protocolICMPv6, ICMPType: icmpType, MatchICMP: true,
		})
	}
	lan4, lan6 := splitFamilies(config.LAN)
	if len(lan4) > 0 {
		rules = append(rules, Rule{Name: "Permit the LAN (IPv4)", Weight: weightLAN, Remote: lan4})
	}
	if len(lan6) > 0 {
		rules = append(rules, Rule{Name: "Permit the LAN (IPv6)", IPv6: true, Weight: weightLAN, Remote: lan6})
	}
	both(Rule{Name: "Block everything else", Weight: weightBlock, Block: true})
	return rules
}

// splitFamilies returns the valid prefixes of each family, masked, without
// repeats, at most maximumLAN in all.
func splitFamilies(prefixes []netip.Prefix) (v4, v6 []netip.Prefix) {
	seen := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		if !prefix.IsValid() || slices.Contains(seen, prefix) || len(seen) == maximumLAN {
			continue
		}
		seen = append(seen, prefix)
		if prefix.Addr().Is4() {
			v4 = append(v4, prefix)
		} else {
			v6 = append(v6, prefix)
		}
	}
	return v4, v6
}

// maximumRules bounds the filters any config installs: the filter keys are
// fixed, so the next install or a release removes every one of them.
const maximumRules = 32
