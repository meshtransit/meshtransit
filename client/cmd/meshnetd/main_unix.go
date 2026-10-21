//go:build linux || darwin

// Command meshnetd owns the minimal privileged tunnel boundary: it creates
// the tunnel interfaces, host routes and host DNS settings meshd needs, and
// nothing else.
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
	"time"

	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/routesettings/routescli"
	"meshtransit.net/client/internal/servicemanager"
	"meshtransit.net/client/internal/socket"
	"meshtransit.net/client/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "captive" {
		return runCaptive(args[1:], stderr)
	}
	if len(args) > 0 && args[0] == "routes" {
		command := routescli.Command{
			Program: "meshnetd", Privilege: "root privileges", Privileged: func() bool { return os.Geteuid() == 0 },
		}
		return command.Run(args[1:], stdout, stderr)
	}
	flags := flag.NewFlagSet("meshnetd", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socketPath := flags.String("socket", config.DefaultNetAdminSocketPath, "path to the privileged helper socket")
	mtu := flags.Int("mtu", 1280, "fixed tun interface mtu")
	enableDNS := flags.Bool("enable-dns", false, "enable the host dns boundary")
	dnsAddress := flags.String("dns-address", "192.0.2.53", "fixed dns service IPv4 or IPv6 address")
	dnsPort := flags.Uint64("dns-port", 1053, "unprivileged local dns service port")
	platform := registerPlatformFlags(flags)
	showVersion := flags.Bool("version", false, "print version and exit")
	releaseExit := flags.Bool("release-exit", false,
		"remove the exit route and kill switch a stopped helper left, then exit; pass the helper's flags")
	routesFile := flags.String("routes-file", config.DefaultRouteSettingsPath,
		"root-owned subnet route settings (meshnetd routes)")
	allowedPrefixes := prefixList{}
	flags.Var(
		&allowedPrefixes,
		"allow-prefix",
		"overlay prefix within which meshd may request host addresses and routes; repeatable; "+
			"must lie inside 100.64.0.0/10, 198.18.0.0/15 or fd00::/8, which is the default",
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
	if *releaseExit {
		if err := platform.releaseExit(*routesFile); err != nil {
			_, _ = fmt.Fprintf(stderr, "meshnetd: releasing the exit route: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintln(stdout, "exit route and kill switch removed")
		return 0
	}
	resolvedUID, err := resolveAllowedUID(hasAllowedUID, allowedUID, *allowedUser, lookupLocalUser)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshnetd: %v\n", err)

		return 2
	}
	if len(allowedPrefixes) == 0 {
		// Control assigns the Workspace ULA and alias pools; the fixed frame
		// admits them all without a per-Workspace drop-in.
		allowedPrefixes = netadmin.SafeOverlayFrame()
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
		dnsOptions, err = platform.dnsOptions(netip.AddrPortFrom(address, uint16(*dnsPort)))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "meshnetd: %v\n", err)

			return 2
		}
	}

	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	if err := preparePlatform(*socketPath, resolvedUID); err != nil {
		logger.Error("preparing helper runtime directories failed", "error", err)

		return 1
	}
	notifier, err := servicemanager.New()
	if err != nil {
		logger.Error("creating service-manager notifier failed", "error", err)

		return 1
	}
	routed := platform.routedOptions(*routesFile)
	server, err := netadmin.NewServer(netadmin.ServerOptions{
		AllowedUID:      resolvedUID,
		InterfaceName:   platform.interfaceName(),
		MTU:             *mtu,
		AllowedPrefixes: allowedPrefixes,
		DNS:             dnsOptions,
		Routed:          routed,
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
	if err := notifier.Ready(ctx); err != nil {
		logger.Error("reporting service readiness failed", "error", err)

		return 1
	}
	defer func() {
		notifyContext, cancelNotify := context.WithTimeout(context.Background(), time.Second)
		defer cancelNotify()
		if notifyErr := notifier.Stopping(notifyContext); notifyErr != nil {
			logger.Warn("reporting service shutdown failed", "error", notifyErr)
		}
	}()
	serveOperator, err := platform.routeOperator(*routesFile, resolvedUID, logger)
	if err != nil {
		// The tunnel matters more: run without the socket, choices root's.
		logger.Error("opening the route operator socket failed", "error", err)
	}
	if serveOperator != nil {
		operatorDone := make(chan struct{})
		go func() {
			defer close(operatorDone)
			if err := serveOperator(ctx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("route operator socket stopped", "error", err)
			}
		}()
		defer func() {
			stop()
			<-operatorDone
		}()
	}
	logger.Info(
		"meshnetd started",
		"socket", *socketPath,
		"interface", platform.interfaceName(),
		"mtu", *mtu,
		"dns_enabled", *enableDNS,
		"subnet_routes", routed != nil,
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
