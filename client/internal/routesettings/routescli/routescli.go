// Package routescli is the command that shows and changes the host's subnet
// route settings: meshnetd routes on Linux and macOS, meshd routes on
// Windows, where no helper runs.
package routescli

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/routesettings"
)

const usage = `usage: %[1]s routes [--routes-file PATH] COMMAND
  show                      print the subnet route settings
  accept on|off             install the private subnet routes Core grants
  accept-public on|off      also install granted routes to public ranges
  router-mode on|off        forward into the advertised subnets
  advertise PREFIX...       offer to forward these subnets
  withdraw PREFIX...        stop offering these subnets
  exit-mode on|off          offer to forward other Devices' Internet traffic
  exit-smtp on|off          let consumers open TCP port 25 (off by default)
  exit-conntrack-max N      connections per consumer, 1024 to 262144 (0: 16384)
  exit-max-consumers N      consumers forwarded for, up to 4096 (0: 256)
  exit-use POOL|auto|off    send this host's Internet traffic through an Exit Pool
  exit-allow-lan on|off     keep the attached private subnets off the exit node
  exit-allow-managed on|off let the administrator choose the Exit Pool
  exit-captive on|off       allow short windows to sign in to a captive portal
Changes need %[2]s and apply within seconds, without a restart.
`

// Command names the program and who may change the settings.
type Command struct {
	// Program is the command name in messages, such as meshnetd.
	Program string
	// Privilege names what a change needs, such as "root privileges".
	Privilege string
	// Privileged reports whether the caller may change the settings.
	Privileged func() bool
	// Elevate, when set, runs a valid change again with the privileges it
	// needs (meshctl through sudo) and returns its exit code; without it an
	// unprivileged change is refused.
	Elevate func() int
	// Quiet leaves out the settings printed after a change.
	Quiet bool
	// FixedPath, when set, is the only settings file: no --routes-file
	// flag, so a command run as root (meshctl through sudo) writes nowhere
	// else.
	FixedPath string
}

// Run shows or changes the host's subnet route settings, args following
// "routes". Only a privileged caller may change them: meshd, Core and other
// users cannot turn routes on or make the host a router.
func (c Command) Run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(c.Program+" routes", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		text := fmt.Sprintf(usage, c.Program, c.Privilege)
		if c.FixedPath != "" {
			text = strings.Replace(text, " [--routes-file PATH]", "", 1)
		}
		_, _ = io.WriteString(stderr, text)
	}
	path := &c.FixedPath
	if c.FixedPath == "" {
		path = flags.String("routes-file", config.DefaultRouteSettingsPath, "route settings file")
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	words := flags.Args()
	if len(words) == 0 {
		flags.Usage()
		return 2
	}
	command, operands := words[0], words[1:]
	settings, err := routesettings.Load(*path)
	if errors.Is(err, routesettings.ErrUnsafeFile) && command != "show" {
		// A change rewrites the file safely: start from everything off.
		_, _ = fmt.Fprintf(stderr, "%s: ignoring the unsafe settings file: %v\n", c.Program, err)
		settings, err = routesettings.Settings{}, nil
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", c.Program, err)
		return 1
	}
	if command == "show" && len(operands) == 0 {
		return c.print(stdout, stderr, settings)
	}
	changed, err := changeRouteSettings(settings, command, operands)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", c.Program, err)
		flags.Usage()
		return 2
	}
	if c.Privileged == nil || !c.Privileged() {
		if c.Elevate != nil {
			return c.Elevate()
		}
		_, _ = fmt.Fprintf(stderr, "%s: %s are required to change route settings\n", c.Program, c.Privilege)
		return 1
	}
	if err := routesettings.Save(*path, changed); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", c.Program, err)
		return 1
	}
	if c.Quiet {
		return 0
	}
	return c.print(stdout, stderr, changed)
}

func changeRouteSettings(settings routesettings.Settings, command string, operands []string) (
	routesettings.Settings, error,
) {
	switch command {
	case "exit-conntrack-max", "exit-max-consumers":
		if len(operands) != 1 {
			return settings, fmt.Errorf("%s takes a number", command)
		}
		value, err := strconv.Atoi(operands[0])
		if err != nil || value < 0 {
			return settings, fmt.Errorf("%s takes a number", command)
		}
		if command == "exit-conntrack-max" {
			settings.ExitConntrackPerConsumerMax = value
		} else {
			settings.ExitMaxConsumers = value
		}
	case "exit-use":
		if len(operands) != 1 || operands[0] == "" {
			return settings, errors.New("exit-use takes a pool, auto or off")
		}
		settings.ExitUse = operands[0]
		if operands[0] == "off" {
			settings.ExitUse = ""
		}
	case "accept", "accept-public", "router-mode", "exit-mode", "exit-smtp", "exit-allow-lan", "exit-allow-managed",
		"exit-captive":
		if len(operands) != 1 || (operands[0] != "on" && operands[0] != "off") {
			return settings, fmt.Errorf("%s takes on or off", command)
		}
		value := operands[0] == "on"
		switch command {
		case "accept":
			settings.AcceptRoutes = value
		case "accept-public":
			settings.AcceptPublicRoutes = value
		case "exit-mode":
			settings.ExitMode = value
		case "exit-smtp":
			settings.ExitSMTPAllowed = value
		case "exit-allow-lan":
			settings.ExitAllowLAN = value
		case "exit-allow-managed":
			settings.ExitAllowManaged = value
		case "exit-captive":
			settings.ExitCaptiveOff = !value
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

func (c Command) print(stdout, stderr io.Writer, settings routesettings.Settings) int {
	onOff := map[bool]string{true: "on", false: "off"}
	advertised := make([]string, len(settings.AdvertiseRoutes))
	for index, prefix := range settings.AdvertiseRoutes {
		advertised[index] = prefix.String()
	}
	if _, err := fmt.Fprintf(stdout,
		"accept: %s\naccept-public: %s\nrouter-mode: %s\nadvertise: %s\n"+
			"exit-mode: %s\nexit-smtp: %s\nexit-conntrack-max: %d\nexit-max-consumers: %d\n"+
			"exit-use: %s\nexit-allow-lan: %s\nexit-allow-managed: %s\nexit-captive: %s\n",
		onOff[settings.AcceptRoutes], onOff[settings.AcceptPublicRoutes], onOff[settings.RouterMode],
		strings.Join(advertised, " "), onOff[settings.ExitMode], onOff[settings.ExitSMTPAllowed],
		settings.ExitConntrackLimit(0), settings.ExitConsumerLimit(), cmp.Or(settings.ExitUse, "off"),
		onOff[settings.ExitAllowLAN], onOff[settings.ExitAllowManaged],
		onOff[!settings.ExitCaptiveOff]); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", c.Program, err)
		return 1
	}
	return 0
}
