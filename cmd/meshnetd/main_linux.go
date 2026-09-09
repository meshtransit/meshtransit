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
	socketPath := flags.String("socket", "/run/meshd/meshnetd.sock", "path to the privileged unixpacket socket")
	interfaceName := flags.String("interface", "mesh0", "fixed tun interface name")
	mtu := flags.Int("mtu", 1280, "fixed tun interface mtu")
	showVersion := flags.Bool("version", false, "print version and exit")
	allowedPrefixes := prefixList{}
	flags.Var(
		&allowedPrefixes,
		"allow-prefix",
		"overlay prefix within which meshd may request host addresses and routes; repeatable",
	)
	var allowedUID uint64
	var hasAllowedUID bool
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
	if !hasAllowedUID {
		_, _ = fmt.Fprintln(stderr, "meshnetd: --allow-uid is required")

		return 2
	}
	if len(allowedPrefixes) == 0 {
		_, _ = fmt.Fprintln(stderr, "meshnetd: at least one --allow-prefix is required")

		return 2
	}

	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	server, err := netadmin.NewServer(netadmin.ServerOptions{
		AllowedUID:      uint32(allowedUID),
		InterfaceName:   *interfaceName,
		MTU:             *mtu,
		AllowedPrefixes: allowedPrefixes,
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
	logger.Info("meshnetd started", "socket", *socketPath, "interface", *interfaceName, "mtu", *mtu)
	if err := server.Serve(ctx, listener); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("meshnetd stopped unexpectedly", "error", err)

		return 1
	}
	logger.Info("meshnetd stopped")

	return 0
}

type prefixList []netip.Prefix

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
