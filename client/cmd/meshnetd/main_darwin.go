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
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"meshtransit.net/client/internal/captive"
	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/routesettings/operator"
	"meshtransit.net/client/internal/socket"
)

// platformFlags are the macOS helper settings; the kernel names tunnels.
type platformFlags struct {
	scutilPath   *string
	subnetRoutes *bool
	exits        *bool
	exitState    *string
	// operatorSocket lets the meshtransit group change the host's own route
	// choices on config.DefaultOperatorSocketPath.
	operatorSocket *bool
}

func registerPlatformFlags(flags *flag.FlagSet) platformFlags {
	return platformFlags{
		scutilPath: flags.String("scutil-path", netadmin.DefaultScutilPath, "absolute trusted scutil binary path"),
		subnetRoutes: flags.Bool("enable-subnet-routes", false,
			"install the subnet routes meshd asks for, as the route settings admit"),
		exits: flags.Bool("enable-exits", false,
			"route the host through the exit node the route settings name, behind a pf kill switch"),
		exitState: flags.String("exit-state", netadmin.DarwinExitStatePath(config.DefaultNetAdminSocketPath),
			"file keeping the helper's pf enable reference"),
		operatorSocket: flags.Bool("operator-socket", true,
			"let the meshtransit group set exit-use, accept and exit-allow-lan on "+config.DefaultOperatorSocketPath),
	}
}

// routedOptions installs subnet and exit routes in the host's routing table
// when enabled: macOS has no other table to put them in.
func (p platformFlags) routedOptions(settingsPath string) *netadmin.RoutedOptions {
	if !*p.subnetRoutes && !*p.exits {
		return nil
	}
	options := &netadmin.RoutedOptions{SettingsPath: settingsPath}
	if *p.exits {
		options.Exits, options.StatePath = true, *p.exitState
		options.CaptiveWindowPath = config.DefaultCaptiveWindowPath
	}
	return options
}

func (platformFlags) interfaceName() string { return "" }

// releaseExit removes the exit routes and the pf kill switch any run left.
func (p platformFlags) releaseExit(string) error {
	return netadmin.ReleaseDarwinExitRoute(*p.exitState)
}

func (p platformFlags) dnsOptions(resolver netip.AddrPort) (*netadmin.DNSOptions, error) {
	if !resolver.Addr().Is4() {
		// The resolver address is an lo0 alias, IPv4 only for now.
		return nil, errors.New("--dns-address must be IPv4 on macOS")
	}
	return &netadmin.DNSOptions{Resolver: resolver, ScutilPath: *p.scutilPath}, nil
}

// meshtransitGroup holds the people allowed to run meshctl.
const meshtransitGroup = "meshtransit"

// preparePlatform recreates the runtime directories that /var/run loses at
// boot, which launchd cannot do: the helper's own (meshd connects through its
// group) and meshd's socket directory, which meshd as an unprivileged user
// cannot create there.
func preparePlatform(helperSocket string, meshdUID uint32) error {
	meshd, err := user.LookupId(strconv.FormatUint(uint64(meshdUID), 10))
	if err != nil {
		return fmt.Errorf("looking up meshd user: %w", err)
	}
	meshdGID, err := strconv.ParseUint(meshd.Gid, 10, 32)
	if err != nil {
		return fmt.Errorf("parsing meshd group: %w", err)
	}
	// On macOS a new socket takes its directory's group, so the directory
	// group decides who may connect.
	if err := ownedDirectory(filepath.Dir(helperSocket), 0, int(meshdGID)); err != nil {
		return err
	}
	clientGID := int(meshdGID)
	if gid, ok := meshtransitGroupID(); ok {
		clientGID = int(gid)
	}
	return ownedDirectory(filepath.Dir(config.DefaultSocketPath), int(meshdUID), clientGID)
}

// meshtransitGroupID returns the meshtransit group's ID, if the installer
// made the group.
func meshtransitGroupID() (uint32, bool) {
	group, err := user.LookupGroup(meshtransitGroup)
	if err != nil {
		return 0, false
	}
	parsed, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || parsed == 0 {
		return 0, false
	}
	return uint32(parsed), true
}

// routeOperator returns what serves the socket where the meshtransit group
// changes the host's own route choices, or nil when it is off. The
// directory and socket belong to root and the group, so only its members
// connect; the server checks them again and never takes meshd's user.
func (p platformFlags) routeOperator(settingsPath string, meshdUID uint32, logger *slog.Logger) (
	func(context.Context) error, error,
) {
	if !*p.operatorSocket {
		return nil, nil
	}
	path := config.DefaultOperatorSocketPath
	return func(ctx context.Context) error {
		gid, err := waitForMeshtransitGroup(ctx)
		if err != nil {
			logger.Warn("no meshtransit group: route choices stay root's", "socket", path, "error", err)
			return nil
		}
		// meshd in the group would reach the socket through its mode: the
		// server refuses it anyway, but such a host is misconfigured.
		if member, err := operator.UserInGroup(meshdUID, gid); err != nil || member {
			logger.Error("meshd's user is in the meshtransit group or unknown: route choices stay root's",
				"uid", meshdUID, "error", err)
			return nil
		}
		server, err := operator.NewServer(operator.ServerOptions{
			SettingsPath: settingsPath, GroupID: gid, DeniedUIDs: []uint32{meshdUID}, Logger: logger,
		})
		if err != nil {
			return err
		}
		if err := ownedDirectory(filepath.Dir(path), 0, int(gid)); err != nil {
			return err
		}
		listener, err := socket.Listen(path)
		if err != nil {
			return fmt.Errorf("opening the operator socket: %w", err)
		}
		if err := os.Lchown(path, 0, int(gid)); err != nil {
			_ = listener.Close()
			return fmt.Errorf("setting the operator socket's group: %w", err)
		}
		logger.Info("route operator socket ready", "socket", path)
		return server.Serve(ctx, listener)
	}, nil
}

// groupLookupPause is the first pause between looking the meshtransit group
// up at boot, when the directory service may not answer yet.
const groupLookupPause = 500 * time.Millisecond

// waitForMeshtransitGroup looks the group up, a few times over about a
// minute: a group that is still missing then was never made.
func waitForMeshtransitGroup(ctx context.Context) (uint32, error) {
	pause := groupLookupPause
	for attempt := 0; ; attempt++ {
		if gid, ok := meshtransitGroupID(); ok {
			return gid, nil
		}
		if attempt == 7 {
			return 0, errors.New("the group was not found")
		}
		select {
		case <-time.After(pause):
		case <-ctx.Done():
			return 0, ctx.Err()
		}
		pause *= 2
	}
}

// ownedDirectory creates or repairs a 0750 directory with the given owner.
// It works on the directory it opened without following a link, so no link
// swapped in turns the chown on another file, and refuses a directory owned
// by anyone but root or the intended owner: someone else made it.
func ownedDirectory(path string, uid, gid int) error {
	if err := os.Mkdir(path, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() { _ = unix.Close(descriptor) }()
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil {
		return fmt.Errorf("inspecting %s: %w", path, err)
	}
	if stat.Uid != 0 && int(stat.Uid) != uid {
		return fmt.Errorf("%s belongs to uid %d, not root or %d", path, stat.Uid, uid)
	}
	if err := unix.Fchown(descriptor, uid, gid); err != nil {
		return fmt.Errorf("setting owner of %s: %w", path, err)
	}
	// Group traversal is the point: meshd (or meshctl users) connect through it.
	if err := unix.Fchmod(descriptor, 0o750); err != nil {
		return fmt.Errorf("setting mode of %s: %w", path, err)
	}
	return nil
}

// captiveUsage is meshnetd captive's: what ends a captive portal window
// should the helper not (exit node design §17.6).
const captiveUsage = `usage: meshnetd captive close-at --state PATH --id ID --after DURATION
       meshnetd captive expire [--state PATH]`

// runCaptive ends a captive portal window outside the helper: close-at is
// the child process the helper starts for one window, expire the launchd
// job that ends any window past its time.
func runCaptive(args []string, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "close-at" && args[0] != "expire") {
		_, _ = fmt.Fprintln(stderr, captiveUsage)
		return 2
	}
	flags := flag.NewFlagSet("meshnetd captive "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	state := flags.String("state", netadmin.DarwinCaptiveStatePath(config.DefaultNetAdminSocketPath),
		"what ends the window, kept by the helper")
	id := flags.String("id", "", "the window to end")
	after := flags.Duration("after", 0, "when to end it")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, captiveUsage)
		return 2
	}
	if args[0] == "close-at" && (*id == "" || *after <= 0 || *after > captive.MaximumWindow) {
		_, _ = fmt.Fprintln(stderr, captiveUsage)
		return 2
	}
	if os.Geteuid() != 0 {
		_, _ = fmt.Fprintln(stderr, "meshnetd: root privileges are required")
		return 1
	}
	// The monotonic clock: a wall clock that jumps does not move it.
	time.Sleep(*after)
	if args[0] == "expire" {
		*id = ""
	}
	if err := netadmin.ExpireDarwinCaptive(*state, *id, time.Now()); err != nil {
		_, _ = fmt.Fprintf(stderr, "meshnetd: ending the captive portal window: %v\n", err)
		return 1
	}
	return 0
}
