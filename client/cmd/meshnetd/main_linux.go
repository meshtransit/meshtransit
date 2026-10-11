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
