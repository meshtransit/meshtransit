//go:build linux

// Command meshnetd owns the minimal privileged Linux TUN boundary.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/meshtransit/meshd/internal/netadmin"
	"github.com/meshtransit/meshd/internal/socket"
	"github.com/meshtransit/meshd/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("meshnetd", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socketPath := flags.String("socket", "/run/meshnetd/meshnetd.sock", "path to the privileged unixpacket socket")
	interfaceName := flags.String("interface", "mesh0", "fixed tun interface name")
	mtu := flags.Int("mtu", 1280, "fixed tun interface mtu")
	enableDNS := flags.Bool("enable-dns", false, "enable the systemd-resolved dns boundary")
	dnsInterfaceName := flags.String("dns-interface", "meshdns0", "fixed dns service interface name")
	dnsAddress := flags.String("dns-address", "192.0.2.53", "fixed dns service IPv4 or IPv6 address")
	dnsPort := flags.Uint64("dns-port", 1053, "unprivileged local dns service port")
	resolvectlPath := flags.String(
		"resolvectl-path",
		"/usr/bin/resolvectl",
		"absolute trusted resolvectl binary path",
	)
	showVersion := flags.Bool("version", false, "print version and exit")
	allowedPrefixes := prefixList{}
	flags.Var(
		&allowedPrefixes,
		"allow-prefix",
		"overlay prefix within which meshd may request host addresses and routes; repeatable",
	)
	var allowedUID uint64
	var hasAllowedUID bool
	allowedUser := flags.String("allow-user", "", "single meshd user allowed to open the tun")
	flags.Func("allow-uid", "single meshd uid allowed to open the tun", func(value string) error {
		if hasAllowedUID {
			return errors.New("allow-uid may be specified only once")
		}
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid uid: %w", err)
		}
		allowedUID = parsed
		hasAllowedUID = true

		return nil
	})
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "meshnetd: positional arguments are not supported")

		return 2
	}
	if *showVersion {
		_, _ = fmt.Fprintln(stdout, version.String())

		return 0
	}
	if os.Geteuid() != 0 {
		_, _ = fmt.Fprintln(stderr, "meshnetd: root privileges are required")

		return 1
	}
	resolvedUID, err := resolveAllowedUID(hasAllowedUID, allowedUID, *allowedUser, lookupLocalUser)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshnetd: %v\n", err)

		return 2
	}
	if len(allowedPrefixes) == 0 {
		_, _ = fmt.Fprintln(stderr, "meshnetd: at least one --allow-prefix is required")

		return 2
	}
	var dnsOptions *netadmin.DNSOptions
	if *enableDNS {
		address, parseErr := netip.ParseAddr(*dnsAddress)
		if parseErr != nil || address.String() != *dnsAddress || address.Is4In6() {
			_, _ = fmt.Fprintln(stderr, "meshnetd: --dns-address must be canonical")

			return 2
		}
		if *dnsPort < 1024 || *dnsPort > 65535 {
			_, _ = fmt.Fprintln(stderr, "meshnetd: --dns-port must be between 1024 and 65535")

			return 2
		}
		dnsOptions = &netadmin.DNSOptions{
			InterfaceName:  *dnsInterfaceName,
			Resolver:       netip.AddrPortFrom(address, uint16(*dnsPort)),
			ResolvectlPath: *resolvectlPath,
		}
	}

	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	server, err := netadmin.NewServer(netadmin.ServerOptions{
		AllowedUID:      resolvedUID,
		InterfaceName:   *interfaceName,
		MTU:             *mtu,
		AllowedPrefixes: allowedPrefixes,
		DNS:             dnsOptions,
		Logger:          logger,
	})
	if err != nil {
		logger.Error("creating privileged helper failed", "error", err)

		return 1
	}
	listener, err := socket.ListenPacket(*socketPath)
	if err != nil {
		logger.Error("opening privileged helper socket failed", "error", err)

		return 1
	}
	defer func() {
		if closeErr := listener.Close(); closeErr != nil {
			logger.Debug("closing helper socket failed", "error", closeErr)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Info(
		"meshnetd started",
		"socket", *socketPath,
		"interface", *interfaceName,
		"mtu", *mtu,
		"dns_enabled", *enableDNS,
	)
	if err := server.Serve(ctx, listener); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("meshnetd stopped unexpectedly", "error", err)

		return 1
	}
	logger.Info("meshnetd stopped")

	return 0
}

type prefixList []netip.Prefix

func lookupLocalUser(username string) (*user.User, error) {
	return user.Lookup(username)
}

func (p *prefixList) Set(value string) error {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return fmt.Errorf("invalid prefix %q: %w", value, err)
	}
	*p = append(*p, prefix)

	return nil
}

func (p *prefixList) String() string {
	values := make([]string, len(*p))
	for index, prefix := range *p {
		values[index] = prefix.String()
	}

	return strings.Join(values, ",")
}
