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

func TestParseTUNPOC(t *testing.T) {
	t.Parallel()

	cfg, err := Parse(nil, io.Discard)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.EnableTUNPOC || cfg.NetAdminSocketPath != DefaultNetAdminSocketPath {
		t.Fatalf("default config = %#v", cfg)
	}

	cfg, err = Parse([]string{
		"--enable-tun-poc",
		"--netadmin-socket", "/tmp/meshnetd.sock",
	}, io.Discard)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.EnableTUNPOC || cfg.NetAdminSocketPath != "/tmp/meshnetd.sock" {
		t.Fatalf("parsed config = %#v", cfg)
	}
}

func TestParseDNSPOC(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]string{"--enable-dns-poc"}, io.Discard)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.EnableDNSPOC {
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

func TestParseWireGuardPOC(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]string{
		"--enable-wireguard-poc",
		"--wireguard-listen-port", "41641",
		"--advertise-endpoint", "203.0.113.10:41641",
	}, io.Discard)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.EnableWireGuardPOC || cfg.WireGuardListenPort != 41641 ||
		len(cfg.AdvertiseEndpoints) != 1 {
		t.Fatalf("parsed config = %#v", cfg)
	}
}

func TestParseWireGuardPOCWithAutomaticEndpointDiscovery(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]string{
		"--enable-wireguard-poc",
		"--wireguard-listen-port", "41641",
	}, io.Discard)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.EnableWireGuardPOC || cfg.WireGuardListenPort != 41641 ||
		len(cfg.AdvertiseEndpoints) != 0 {
		t.Fatalf("parsed config = %#v", cfg)
	}
}

func TestParseFlowLogging(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]string{
		"--enable-wireguard-poc",
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

func TestParseRejectsUnsafeWireGuardPOC(t *testing.T) {
	t.Parallel()

	tests := [][]string{
		{"--enable-wireguard-poc"},
		{
			"--enable-wireguard-poc",
			"--wireguard-listen-port", "41641",
			"--advertise-endpoint", "127.0.0.1:41641",
		},
		{
			"--enable-wireguard-poc",
			"--wireguard-listen-port", "41641",
			"--advertise-endpoint", "203.0.113.10:41642",
		},
		{"--wireguard-listen-port", "41641"},
		{"--enable-flow-logs", "--flow-log-url", "https://log.pingoo.click"},
		{
			"--enable-wireguard-poc",
			"--wireguard-listen-port", "41641",
			"--advertise-endpoint", "203.0.113.10:41641",
			"--enable-flow-logs",
			"--flow-log-url", "http://log.pingoo.click",
		},
		{
			"--enable-tun-poc",
			"--enable-wireguard-poc",
			"--wireguard-listen-port", "41641",
			"--advertise-endpoint", "203.0.113.10:41641",
		},
	}
	for _, args := range tests {
		if _, err := Parse(args, io.Discard); err == nil {
			t.Fatalf("Parse(%v) error = nil", args)
		}
	}
}
