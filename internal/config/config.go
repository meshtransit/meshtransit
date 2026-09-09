// Package config parses and validates daemon startup configuration.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultSocketPath is the local control socket used by meshctl.
	DefaultSocketPath = "/run/meshd/meshd.sock"
	// DefaultNetAdminSocketPath is the separate privileged-helper endpoint.
	DefaultNetAdminSocketPath = "/run/meshd/meshnetd.sock"
	// DefaultStateDir contains profile metadata and, later, encrypted key material.
	DefaultStateDir = "/var/lib/meshd"
)

// Config contains the complete startup configuration for meshd.
type Config struct {
	SocketPath                     string
	NetAdminSocketPath             string
	StateDir                       string
	LogLevel                       string
	ShowVersion                    bool
	AllowedUIDs                    []uint32
	UnsafeAllowUnverifiedLocalPeer bool
	EnableTUNPOC                   bool
	EnableWireGuardPOC             bool
	EnableDNSPOC                   bool
	WireGuardListenPort            uint16
	AdvertiseEndpoints             []netip.AddrPort
	EnableFlowLogs                 bool
	FlowLogURL                     string
	FlowLogInterval                time.Duration
	FlowLogTimeout                 time.Duration
}

// Parse parses daemon flags without reading global flag state.
func Parse(args []string, stderr io.Writer) (Config, error) {
	cfg := Config{}
	allowedUIDs := uidList{}
	advertiseEndpoints := endpointList{}
	listenPort := uint64(0)
	flags := flag.NewFlagSet("meshd", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&cfg.SocketPath, "socket", DefaultSocketPath, "path to the local Unix socket")
	flags.StringVar(
		&cfg.NetAdminSocketPath,
		"netadmin-socket",
		DefaultNetAdminSocketPath,
		"path to the privileged meshnetd unixpacket socket",
	)
	flags.StringVar(&cfg.StateDir, "state-dir", DefaultStateDir, "directory for persistent daemon state")
	flags.StringVar(&cfg.LogLevel, "log-level", "info", "log level: debug, info, warn, or error")
	flags.BoolVar(&cfg.ShowVersion, "version", false, "print version and exit")
	flags.BoolVar(
		&cfg.EnableTUNPOC,
		"enable-tun-poc",
		false,
		"enable the tun descriptor poc without packet forwarding",
	)
	flags.BoolVar(
		&cfg.EnableWireGuardPOC,
		"enable-wireguard-poc",
		false,
		"enable encrypted direct-path poc with fail-closed policy checks",
	)
	flags.BoolVar(
		&cfg.EnableDNSPOC,
		"enable-dns-poc",
		false,
		"enable MagicDNS and systemd-resolved integration",
	)
	flags.Uint64Var(
		&listenPort,
		"wireguard-listen-port",
		0,
		"fixed local UDP listen port for the WireGuard poc",
	)
	flags.Var(
		&advertiseEndpoints,
		"advertise-endpoint",
		"explicit public UDP endpoint advertised to control; repeatable",
	)
	flags.BoolVar(
		&cfg.EnableFlowLogs,
		"enable-flow-logs",
		false,
		"enable opt-in header-only data-plane flow logging",
	)
	flags.StringVar(
		&cfg.FlowLogURL,
		"flow-log-url",
		"",
		"HTTPS origin for native flow log uploads",
	)
	flags.DurationVar(
		&cfg.FlowLogInterval,
		"flow-log-interval",
		5*time.Second,
		"in-memory flow aggregation interval",
	)
	flags.DurationVar(
		&cfg.FlowLogTimeout,
		"flow-log-timeout",
		5*time.Second,
		"timeout for each flow log upload attempt",
	)
	flags.Var(&allowedUIDs, "allow-uid", "additional local uid allowed to call the api; repeatable")
	flags.BoolVar(
		&cfg.UnsafeAllowUnverifiedLocalPeer,
		"unsafe-allow-unverified-local-peer",
		false,
		"allow local api calls when the platform cannot verify peer credentials",
	)

	if err := flags.Parse(args); err != nil {
		return Config{}, fmt.Errorf("parsing flags: %w", err)
	}
	if flags.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	if listenPort > 65535 {
		return Config{}, errors.New("wireguard listen port is outside uint16")
	}
	cfg.WireGuardListenPort = uint16(listenPort)
	cfg.AdvertiseEndpoints = append([]netip.AddrPort(nil), advertiseEndpoints...)
	if err := validate(cfg); err != nil {
		return Config{}, err
	}
	cfg.AllowedUIDs = append([]uint32{}, allowedUIDs...)

	return cfg, nil
}

type uidList []uint32

type endpointList []netip.AddrPort

func (e *endpointList) Set(value string) error {
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil {
		return fmt.Errorf("invalid endpoint %q: %w", value, err)
	}
	*e = append(*e, endpoint)

	return nil
}

func (e *endpointList) String() string {
	values := make([]string, len(*e))
	for index, endpoint := range *e {
		values[index] = endpoint.String()
	}

	return strings.Join(values, ",")
}

func (u *uidList) Set(value string) error {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid uid %q: %w", value, err)
	}
	*u = append(*u, uint32(parsed))

	return nil
}

func (u *uidList) String() string {
	values := make([]string, 0, len(*u))
	for _, uid := range *u {
		values = append(values, strconv.FormatUint(uint64(uid), 10))
	}

	return strings.Join(values, ",")
}

func validate(cfg Config) error {
	if !filepath.IsAbs(cfg.SocketPath) {
		return errors.New("socket path must be absolute")
	}
	if !filepath.IsAbs(cfg.StateDir) {
		return errors.New("state directory must be absolute")
	}
	if filepath.Clean(cfg.StateDir) == string(filepath.Separator) {
		return errors.New("state directory cannot be the filesystem root")
	}
	if !filepath.IsAbs(cfg.NetAdminSocketPath) {
		return errors.New("netadmin socket path must be absolute")
	}
	if filepath.Clean(cfg.SocketPath) == filepath.Clean(cfg.NetAdminSocketPath) {
		return errors.New("local api and netadmin sockets must be different")
	}
	if cfg.EnableTUNPOC && cfg.EnableWireGuardPOC {
		return errors.New("tun-only and wireguard pocs cannot be enabled together")
	}
	if cfg.EnableWireGuardPOC {
		if cfg.WireGuardListenPort == 0 {
			return errors.New("wireguard poc requires a non-zero listen port")
		}
		if len(cfg.AdvertiseEndpoints) == 0 {
			return errors.New("wireguard poc requires at least one advertised endpoint")
		}
	} else if cfg.WireGuardListenPort != 0 || len(cfg.AdvertiseEndpoints) != 0 {
		return errors.New("wireguard endpoint options require --enable-wireguard-poc")
	}
	if cfg.EnableFlowLogs {
		if !cfg.EnableWireGuardPOC {
			return errors.New("flow logging requires the wireguard poc")
		}
		endpoint, err := url.Parse(cfg.FlowLogURL)
		if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" ||
			endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
			(endpoint.Path != "" && endpoint.Path != "/") {
			return errors.New("flow log URL must be an HTTPS origin")
		}
		if cfg.FlowLogInterval < time.Second || cfg.FlowLogInterval > 5*time.Minute {
			return errors.New("flow log interval must be between 1s and 5m")
		}
		if cfg.FlowLogTimeout <= 0 || cfg.FlowLogTimeout > time.Minute {
			return errors.New("flow log timeout must be between zero and 1m")
		}
	} else if cfg.FlowLogURL != "" {
		return errors.New("flow log URL requires --enable-flow-logs")
	}
	if len(cfg.AdvertiseEndpoints) > 16 {
		return errors.New("too many advertised endpoints")
	}
	seenEndpoints := make(map[netip.AddrPort]struct{}, len(cfg.AdvertiseEndpoints))
	for _, endpoint := range cfg.AdvertiseEndpoints {
		address := endpoint.Addr()
		if !endpoint.IsValid() || address.Is4In6() || !address.IsGlobalUnicast() ||
			address.IsLinkLocalUnicast() || endpoint.Port() != cfg.WireGuardListenPort {
			return errors.New("advertised endpoint must be a canonical global address using the listen port")
		}
		if _, exists := seenEndpoints[endpoint]; exists {
			return errors.New("advertised endpoint is duplicated")
		}
		seenEndpoints[endpoint] = struct{}{}
	}

	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("unsupported log level %q", cfg.LogLevel)
	}

	return nil
}
