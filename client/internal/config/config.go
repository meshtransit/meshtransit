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
	DefaultNetAdminSocketPath = "/run/meshnetd/meshnetd.sock"
	// DefaultStateDir contains profile metadata and encrypted identity envelopes.
	DefaultStateDir = "/var/lib/meshd"
	// DefaultIdentityKeyPath is the systemd credential exposed to meshd.
	DefaultIdentityKeyPath = "/run/credentials/meshd.service/meshd.identity-key"
)

// Config contains the complete startup configuration for meshd.
type Config struct {
	SocketPath          string
	NetAdminSocketPath  string
	StateDir            string
	IdentityKeyPath     string
	LogLevel            string
	ShowVersion         bool
	AllowedUIDs         []uint32
	AllowSocketPeers    bool
	EnableDataPlane     bool
	EnableDeviceAliases bool
	// ControlProtocol is accepted for existing unit files: auto and mtcp
	// both mean MTCP v1, the only control protocol.
	ControlProtocol string
	// PortMapping is auto (map the WireGuard port on the local gateway with
	// PCP, NAT-PMP or UPnP when the data plane runs) or off.
	PortMapping string
	// CloudMetadata is auto (read the instance's public addresses from the
	// cloud provider's metadata service on a recognised cloud) or off.
	CloudMetadata string
	// TestPolicyDrift makes the packet filter enforce one rule fewer than
	// Core sends, to demonstrate that Core reports the mismatch. Test only.
	TestPolicyDrift     bool
	EnableDNS           bool
	WireGuardListenPort uint16
	AdvertiseEndpoints  []netip.AddrPort
	EnableFlowLogs      bool
	FlowLogURL          string
	FlowLogInterval     time.Duration
	FlowLogTimeout      time.Duration
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
	flags.StringVar(
		&cfg.IdentityKeyPath,
		"identity-key-file",
		DefaultIdentityKeyPath,
		"owner-only file containing the 32-byte identity envelope key",
	)
	flags.StringVar(&cfg.LogLevel, "log-level", "info", "log level: debug, info, warn, or error")
	flags.BoolVar(&cfg.ShowVersion, "version", false, "print version and exit")
	flags.BoolVar(
		&cfg.EnableDataPlane,
		"enable-data-plane",
		false,
		"enable the encrypted mesh packet path with fail-closed policy checks",
	)
	flags.BoolVar(&cfg.EnableDeviceAliases, "enable-device-aliases", false,
		"enable qualification of peer-specific Device aliases; requires confined helper alias pools")
	flags.StringVar(&cfg.ControlProtocol, "control-protocol", "auto",
		"control protocol: auto or mtcp (both MTCP v1; kept for existing unit files)")
	flags.StringVar(&cfg.PortMapping, "port-mapping", "auto",
		"ask the local gateway to forward the WireGuard port with PCP, NAT-PMP or UPnP: auto or off")
	flags.StringVar(&cfg.CloudMetadata, "cloud-metadata", "auto",
		"read public addresses from the cloud metadata service on AWS, GCP, Azure or DigitalOcean: auto or off")
	flags.BoolVar(&cfg.TestPolicyDrift, "test-policy-drift", false,
		"TEST ONLY: enforce one packet-filter rule fewer than control sends, to demonstrate mismatch detection")
	flags.BoolVar(
		&cfg.EnableDNS,
		"enable-dns",
		false,
		"enable MeshTransit DNS and systemd-resolved integration",
	)
	flags.Uint64Var(
		&listenPort,
		"wireguard-listen-port",
		0,
		"fixed local UDP listen port for the encrypted packet path",
	)
	flags.Var(
		&advertiseEndpoints,
		"advertise-endpoint",
		"optional explicit UDP endpoint advertised to control; repeatable",
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
		&cfg.AllowSocketPeers,
		"allow-socket-peers",
		false,
		"authorize kernel-verified peers admitted by unix socket permissions",
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
	if !filepath.IsAbs(cfg.IdentityKeyPath) ||
		filepath.Clean(cfg.IdentityKeyPath) == string(filepath.Separator) {
		return errors.New("identity key path must be an absolute file")
	}
	if !filepath.IsAbs(cfg.NetAdminSocketPath) {
		return errors.New("netadmin socket path must be absolute")
	}
	if filepath.Clean(cfg.SocketPath) == filepath.Clean(cfg.NetAdminSocketPath) {
		return errors.New("local api and netadmin sockets must be different")
	}
	if cfg.EnableDataPlane {
		if cfg.WireGuardListenPort == 0 {
			return errors.New("data plane requires a non-zero listen port")
		}
	} else if cfg.WireGuardListenPort != 0 || len(cfg.AdvertiseEndpoints) != 0 {
		return errors.New("packet endpoint options require --enable-data-plane")
	}
	if cfg.EnableDeviceAliases && !cfg.EnableDataPlane {
		return errors.New("device aliases require --enable-data-plane")
	}
	switch cfg.ControlProtocol {
	case "auto", "mtcp":
	case "legacy":
		return errors.New("the legacy control protocol was removed; use --control-protocol=mtcp or leave it unset")
	default:
		return errors.New("control protocol must be auto or mtcp")
	}
	switch cfg.PortMapping {
	case "auto", "off":
	default:
		return errors.New("port mapping must be auto or off")
	}
	switch cfg.CloudMetadata {
	case "auto", "off":
	default:
		return errors.New("cloud metadata must be auto or off")
	}
	if cfg.TestPolicyDrift && !cfg.EnableDataPlane {
		return errors.New("policy drift testing requires --enable-data-plane")
	}
	if cfg.EnableFlowLogs {
		if !cfg.EnableDataPlane {
			return errors.New("flow logging requires the data plane")
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
