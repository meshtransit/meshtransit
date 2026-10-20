package main

import (
	"flag"
	"net/netip"

	"meshtransit.net/client/internal/netadmin"
)

// platformFlags are the Linux helper settings: root fixes the interface
// names and the resolvectl binary.
type platformFlags struct {
	interfaceNameValue *string
	dnsInterfaceName   *string
	resolvectlPath     *string
	routedTable        *int
	routedPriority     *int
	routerTable        *string
	routerState        *string
}

func registerPlatformFlags(flags *flag.FlagSet) platformFlags {
	return platformFlags{
		interfaceNameValue: flags.String("interface", "mesh0", "fixed tun interface name"),
		dnsInterfaceName:   flags.String("dns-interface", "meshdns0", "fixed dns service interface name"),
		resolvectlPath: flags.String(
			"resolvectl-path",
			"/usr/bin/resolvectl",
			"absolute trusted resolvectl binary path",
		),
		routedTable: flags.Int("routed-table", 0,
			"routing table for subnet routes, unique per helper on the host; 0 installs none"),
		routedPriority: flags.Int("routed-priority", 5400,
			"policy rule priority that keeps meshd's sockets out of the routed table"),
		routerTable: flags.String("router-nft-table", "meshtransit",
			"nftables table this helper owns to forward as a subnet router; empty forwards into no subnets"),
		routerState: flags.String("router-state", "/run/meshnetd/router-state.json",
			"where the helper records the host forwarding settings it changed, to restore them"),
	}
}

// routedOptions installs subnet routes in their own table when one is set.
func (p platformFlags) routedOptions(settingsPath string) *netadmin.RoutedOptions {
	if *p.routedTable == 0 {
		return nil
	}
	return &netadmin.RoutedOptions{
		SettingsPath: settingsPath, Table: *p.routedTable, Priority: *p.routedPriority,
		NftTable: *p.routerTable, StatePath: *p.routerState,
	}
}

func (p platformFlags) interfaceName() string { return *p.interfaceNameValue }

func (p platformFlags) dnsOptions(resolver netip.AddrPort) (*netadmin.DNSOptions, error) {
	return &netadmin.DNSOptions{
		InterfaceName:  *p.dnsInterfaceName,
		Resolver:       resolver,
		ResolvectlPath: *p.resolvectlPath,
	}, nil
}

// preparePlatform has nothing to do on Linux: systemd tmpfiles creates the
// runtime directories.
func preparePlatform(string, uint32) error { return nil }
