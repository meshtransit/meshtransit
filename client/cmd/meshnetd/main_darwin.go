package main

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/netadmin"
)

// platformFlags are the macOS helper settings; the kernel names tunnels.
type platformFlags struct {
	scutilPath   *string
	subnetRoutes *bool
}

func registerPlatformFlags(flags *flag.FlagSet) platformFlags {
	return platformFlags{
		scutilPath: flags.String("scutil-path", netadmin.DefaultScutilPath, "absolute trusted scutil binary path"),
		subnetRoutes: flags.Bool("enable-subnet-routes", false,
			"install the subnet routes meshd asks for, as the route settings admit"),
	}
}

// routedOptions installs subnet routes in the host's routing table when
// enabled: macOS has no other table to put them in.
func (p platformFlags) routedOptions(settingsPath string) *netadmin.RoutedOptions {
	if !*p.subnetRoutes {
		return nil
	}
	return &netadmin.RoutedOptions{SettingsPath: settingsPath}
}

func (platformFlags) interfaceName() string { return "" }

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
	if group, err := user.LookupGroup(meshtransitGroup); err == nil {
		if parsed, parseErr := strconv.ParseUint(group.Gid, 10, 32); parseErr == nil {
			clientGID = int(parsed)
		}
	}
	return ownedDirectory(filepath.Dir(config.DefaultSocketPath), int(meshdUID), clientGID)
}

// ownedDirectory creates or repairs a 0750 directory with the given owner,
// refusing a symlink in its place.
func ownedDirectory(path string, uid, gid int) error {
	if err := os.Mkdir(path, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspecting %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("setting owner of %s: %w", path, err)
	}
	// Group traversal is the point: meshd (or meshctl users) connect through it.
	if err := os.Chmod(path, 0o750); err != nil { //nolint:gosec // see above
		return fmt.Errorf("setting mode of %s: %w", path, err)
	}
	return nil
}
