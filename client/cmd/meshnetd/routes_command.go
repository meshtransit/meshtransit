//go:build linux || darwin

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"

	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/routesettings"
)

const routesUsage = `usage: meshnetd routes [--routes-file PATH] COMMAND
  show                      print the subnet route settings
  accept on|off             install the private subnet routes Core grants
  accept-public on|off      also install granted routes to public ranges
  router-mode on|off        forward into the advertised subnets
  advertise PREFIX...       offer to forward these subnets
  withdraw PREFIX...        stop offering these subnets
Changes need root and apply within seconds, without a restart.`

// runRoutes shows or changes the host's subnet route settings. Only root may
// change them: meshd, Core and other users cannot turn routes on or make
// the host a router.
func runRoutes(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("meshnetd routes", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { _, _ = fmt.Fprintln(stderr, routesUsage) }
	path := flags.String("routes-file", config.DefaultRouteSettingsPath, "route settings file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	words := flags.Args()
	if len(words) == 0 {
		flags.Usage()
		return 2
	}
	settings, err := routesettings.Load(*path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshnetd: %v\n", err)
		return 1
	}
	command, operands := words[0], words[1:]
	if command == "show" && len(operands) == 0 {
		return printRouteSettings(stdout, stderr, settings)
	}
	changed, err := changeRouteSettings(settings, command, operands)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshnetd: %v\n", err)
		flags.Usage()
		return 2
	}
	if os.Geteuid() != 0 {
		_, _ = fmt.Fprintln(stderr, "meshnetd: root privileges are required to change route settings")
		return 1
	}
	if err := routesettings.Save(*path, changed); err != nil {
		_, _ = fmt.Fprintf(stderr, "meshnetd: %v\n", err)
		return 1
	}
	return printRouteSettings(stdout, stderr, changed)
}

func changeRouteSettings(settings routesettings.Settings, command string, operands []string) (
	routesettings.Settings, error,
) {
	switch command {
	case "accept", "accept-public", "router-mode":
		if len(operands) != 1 || (operands[0] != "on" && operands[0] != "off") {
			return settings, fmt.Errorf("%s takes on or off", command)
		}
		value := operands[0] == "on"
		switch command {
		case "accept":
			settings.AcceptRoutes = value
		case "accept-public":
			settings.AcceptPublicRoutes = value
		default:
			settings.RouterMode = value
		}
	case "advertise", "withdraw":
		if len(operands) == 0 {
			return settings, fmt.Errorf("%s takes at least one prefix", command)
		}
		advertised := slices.Clone(settings.AdvertiseRoutes)
		for _, operand := range operands {
			prefix, err := netip.ParsePrefix(operand)
			if err != nil || prefix != prefix.Masked() {
				return settings, fmt.Errorf("%q is not a canonical prefix", operand)
			}
			if command == "withdraw" {
				advertised = slices.DeleteFunc(advertised, func(other netip.Prefix) bool { return other == prefix })
			} else if !slices.Contains(advertised, prefix) {
				advertised = append(advertised, prefix)
			}
		}
		settings.AdvertiseRoutes = advertised
	default:
		return settings, errors.New("unknown command")
	}
	if err := settings.Validate(); err != nil {
		return settings, err
	}
	return settings.Canonical(), nil
}

func printRouteSettings(stdout, stderr io.Writer, settings routesettings.Settings) int {
	onOff := map[bool]string{true: "on", false: "off"}
	advertised := make([]string, len(settings.AdvertiseRoutes))
	for index, prefix := range settings.AdvertiseRoutes {
		advertised[index] = prefix.String()
	}
	if _, err := fmt.Fprintf(stdout, "accept: %s\naccept-public: %s\nrouter-mode: %s\nadvertise: %s\n",
		onOff[settings.AcceptRoutes], onOff[settings.AcceptPublicRoutes], onOff[settings.RouterMode],
		strings.Join(advertised, " ")); err != nil {
		_, _ = fmt.Fprintf(stderr, "meshnetd: %v\n", err)
		return 1
	}
	return 0
}
