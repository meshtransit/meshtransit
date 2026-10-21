package main

import (
	"cmp"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"

	"meshtransit.net/client/internal/config"
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
	exitTable          *int
	exitPriority       *int
	exitNftTable       *string
	captiveWindow      *string
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
		exitTable: flags.Int("exit-table", 0,
			"routing table that sends the host's Internet traffic through an exit node, unique per helper; "+
				"0 uses no exit node"),
		exitPriority: flags.Int("exit-priority", 5402,
			"first of the four policy rule priorities of the exit route, after --routed-priority"),
		exitNftTable: flags.String("exit-nft-table", "meshtransit_exit",
			"nftables table this helper owns for the kill switch while the host uses an exit node"),
		captiveWindow: flags.String("captive-window", config.DefaultCaptiveWindowPath,
			"captive portal window file root writes (meshctl exit captive); empty opens none"),
	}
}

// routedOptions installs subnet routes in their own table when one is set.
func (p platformFlags) routedOptions(settingsPath string) *netadmin.RoutedOptions {
	if *p.routedTable == 0 {
		return nil
	}
	options := &netadmin.RoutedOptions{
		SettingsPath: settingsPath, Table: *p.routedTable, Priority: *p.routedPriority,
		NftTable: *p.routerTable, StatePath: *p.routerState,
	}
	if *p.exitTable != 0 {
		options.ExitTable, options.ExitPriority, options.ExitNftTable = *p.exitTable, *p.exitPriority, *p.exitNftTable
		options.CaptiveWindowPath = *p.captiveWindow
	}
	return options
}

// packagedExitTable is the exit table of the packaged helper unit, which
// --release-exit removes unless told another.
const packagedExitTable = 5268

// releaseExit removes the exit route and kill switch a helper with these
// flags installed, for root to run when that helper is gone and its kill
// switch keeps the host offline.
func (p platformFlags) releaseExit(settingsPath string) error {
	return netadmin.ReleaseExitRoute(netadmin.RoutedOptions{
		SettingsPath: settingsPath, Table: *p.routedTable, Priority: *p.routedPriority, NftTable: *p.routerTable,
		ExitTable: cmp.Or(*p.exitTable, packagedExitTable), ExitPriority: *p.exitPriority,
		ExitNftTable: *p.exitNftTable, CaptiveWindowPath: *p.captiveWindow,
	})
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

// routeOperator is macOS's: Linux has no operators group yet, so the route
// choices stay root's.
func (platformFlags) routeOperator(string, uint32, *slog.Logger) (func(context.Context) error, error) {
	return nil, nil
}

// runCaptive is macOS's: on Linux the kernel ends a captive portal window's
// holes by itself.
func runCaptive(_ []string, stderr io.Writer) int {
	_, _ = fmt.Fprintln(stderr, "meshnetd: captive is for macOS; the kernel ends a window's holes here")
	return 2
}
