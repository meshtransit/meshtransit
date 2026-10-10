package config

import (
	"io"
	"path/filepath"
	"testing"
)

func TestDefaultSocketsUseSeparateDirectories(t *testing.T) {
	t.Parallel()

	if filepath.Dir(DefaultSocketPath) == filepath.Dir(DefaultNetAdminSocketPath) {
		t.Fatalf(
			"default socket directories are shared: %q and %q",
			DefaultSocketPath,
			DefaultNetAdminSocketPath,
		)
	}
}

func TestDefaultIdentityKeyUsesSystemdCredentialPath(t *testing.T) {
	t.Parallel()

	if !filepath.IsAbs(DefaultIdentityKeyPath) ||
		filepath.Base(DefaultIdentityKeyPath) != "meshd.identity-key" {
		t.Fatalf("default identity key path = %q", DefaultIdentityKeyPath)
	}
}

func TestParseDataPlane(t *testing.T) {
	t.Parallel()

	cfg, err := Parse(nil, io.Discard)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.EnableDataPlane || cfg.NetAdminSocketPath != DefaultNetAdminSocketPath {
		t.Fatalf("default config = %#v", cfg)
	}

	cfg, err = Parse([]string{
		"--enable-data-plane",
		"--wireguard-listen-port", "41641",
		"--netadmin-socket", "/tmp/meshnetd.sock",
	}, io.Discard)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.EnableDataPlane || cfg.NetAdminSocketPath != "/tmp/meshnetd.sock" {
		t.Fatalf("parsed config = %#v", cfg)
	}
}

func TestParseDNS(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]string{"--enable-dns"}, io.Discard)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.EnableDNS {
		t.Fatalf("parsed config = %#v", cfg)
	}
}

func TestParseSocketPeerAuthorization(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]string{"--allow-socket-peers"}, io.Discard)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.AllowSocketPeers {
		t.Fatalf("parsed config = %#v", cfg)
	}
}

func TestParseRejectsUnsafeNetAdminSocket(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "relative path",
			args: []string{"--netadmin-socket", "meshnetd.sock"},
		},
		{
			name: "shared local api path",
			args: []string{
				"--socket", "/tmp/shared.sock",
				"--netadmin-socket", "/tmp/shared.sock",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := Parse(test.args, io.Discard); err == nil {
				t.Fatal("Parse() error = nil")
			}
		})
	}
}

func TestParseRejectsUnsafeIdentityKeyPath(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"identity.key", "/"} {
		if _, err := Parse([]string{"--identity-key-file", path}, io.Discard); err == nil {
			t.Fatalf("Parse(identity key %q) error = nil", path)
		}
	}
}

func TestParseDataPlaneWithExplicitEndpoint(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]string{
		"--enable-data-plane",
		"--wireguard-listen-port", "41641",
		"--advertise-endpoint", "203.0.113.10:41641",
	}, io.Discard)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.EnableDataPlane || cfg.WireGuardListenPort != 41641 ||
		len(cfg.AdvertiseEndpoints) != 1 {
		t.Fatalf("parsed config = %#v", cfg)
	}
}

func TestParseDataPlaneWithAutomaticEndpointDiscovery(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]string{
		"--enable-data-plane",
		"--wireguard-listen-port", "41641",
	}, io.Discard)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.EnableDataPlane || cfg.WireGuardListenPort != 41641 ||
		len(cfg.AdvertiseEndpoints) != 0 {
		t.Fatalf("parsed config = %#v", cfg)
	}
}

func TestParseFlowLogging(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]string{
		"--enable-data-plane",
		"--wireguard-listen-port", "41641",
		"--advertise-endpoint", "203.0.113.10:41641",
		"--enable-flow-logs",
		"--flow-log-url", "https://log.pingoo.click",
		"--flow-log-interval", "10s",
	}, io.Discard)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.EnableFlowLogs || cfg.FlowLogURL != "https://log.pingoo.click" {
		t.Fatalf("parsed config = %#v", cfg)
	}
}

func TestParseRejectsUnsafeDataPlane(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{name: "missing listen port", args: []string{"--enable-data-plane"}},
		{
			name: "loopback endpoint",
			args: []string{
				"--enable-data-plane",
				"--wireguard-listen-port", "41641",
				"--advertise-endpoint", "127.0.0.1:41641",
			},
		},
		{
			name: "endpoint port mismatch",
			args: []string{
				"--enable-data-plane",
				"--wireguard-listen-port", "41641",
				"--advertise-endpoint", "203.0.113.10:41642",
			},
		},
		{name: "listen port without data plane", args: []string{"--wireguard-listen-port", "41641"}},
		{
			name: "flow logs without data plane",
			args: []string{"--enable-flow-logs", "--flow-log-url", "https://log.pingoo.click"},
		},
		{
			name: "plaintext flow log origin",
			args: []string{
				"--enable-data-plane",
				"--wireguard-listen-port", "41641",
				"--advertise-endpoint", "203.0.113.10:41641",
				"--enable-flow-logs",
				"--flow-log-url", "http://log.pingoo.click",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := Parse(test.args, io.Discard); err == nil {
				t.Fatalf("Parse(%v) error = nil", test.args)
			}
		})
	}
}

func TestParseRejectsRemovedDevelopmentFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		flag string
	}{
		{name: "tun poc", flag: "--enable-tun-poc"},
		{name: "wireguard poc", flag: "--enable-wireguard-poc"},
		{name: "dns poc", flag: "--enable-dns-poc"},
		{name: "unverified local peer", flag: "--unsafe-allow-unverified-local-peer"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := Parse([]string{test.flag}, io.Discard); err == nil {
				t.Fatalf("Parse(%q) error = nil", test.flag)
			}
		})
	}
}

func TestDeviceAliasFlagRequiresPacketEngine(t *testing.T) {
	t.Parallel()
	if _, err := Parse([]string{"--enable-device-aliases"}, io.Discard); err == nil {
		t.Fatal("aliases without packet engine accepted")
	}
	got, err := Parse([]string{"--enable-data-plane", "--wireguard-listen-port=42642", "--enable-device-aliases"}, io.Discard)
	if err != nil || !got.EnableDeviceAliases {
		t.Fatal("explicit alias opt-in rejected", err)
	}
	got, err = Parse(nil, io.Discard)
	if err != nil || got.EnableDeviceAliases {
		t.Fatal("alias support enabled by default", err)
	}
}

func TestParseControlProtocol(t *testing.T) {
	t.Parallel()

	cfg, err := Parse(nil, io.Discard)
	if err != nil || cfg.ControlProtocol != "auto" {
		t.Fatalf("default control protocol = %q, %v", cfg.ControlProtocol, err)
	}
	for _, value := range []string{"mtcp", "legacy"} {
		if cfg, err := Parse([]string{"--control-protocol", value}, io.Discard); err != nil || cfg.ControlProtocol != value {
			t.Fatalf("--control-protocol %s = %q, %v", value, cfg.ControlProtocol, err)
		}
	}
	if _, err := Parse([]string{"--control-protocol", "ts2021"}, io.Discard); err == nil {
		t.Fatal("an unknown control protocol was accepted")
	}
}

func TestParsePortMapping(t *testing.T) {
	t.Parallel()

	cfg, err := Parse(nil, io.Discard)
	if err != nil || cfg.PortMapping != "auto" {
		t.Fatalf("default port mapping = %q, %v", cfg.PortMapping, err)
	}
	if cfg, err := Parse([]string{"--port-mapping", "off"}, io.Discard); err != nil || cfg.PortMapping != "off" {
		t.Fatalf("--port-mapping off = %q, %v", cfg.PortMapping, err)
	}
	if _, err := Parse([]string{"--port-mapping", "upnp"}, io.Discard); err == nil {
		t.Fatal("an unknown port mapping mode was accepted")
	}
}
