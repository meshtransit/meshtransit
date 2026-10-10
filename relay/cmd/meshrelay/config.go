package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"meshtransit.net/shared/key"
)

// serveConfig is the relay configuration. Every flag can also be set with
// the environment variable MESHRELAY_<FLAG> (upper case, dashes as
// underscores); flags win.
type serveConfig struct {
	keyFile      string
	signingKeys  []key.SigningPublic
	udpAddr      string
	udpReaders   int
	stunAddr     string
	stunAltPort  string
	publicIP     netip.Addr
	publicIPv6   netip.Addr
	adminAddr    string
	drainTimeout time.Duration
	logLevel     string

	tlsAddr       string
	tlsCert       string
	tlsKey        string
	tlsSelfSigned bool
	acmeHost      string
	acmeCache     string
	acmeEmail     string
	tlsMaxConns   int
	tlsMaxPerIP   int
	coreURL       string
}

func parseServeConfig(args []string, env func(string) (string, bool), stderr io.Writer) (serveConfig, error) {
	fs := flag.NewFlagSet("meshrelay serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cfg serveConfig
	var signing, publicIP, publicIPv6 string
	fs.StringVar(&cfg.keyFile, "key-file", "", "relay private key file written by `meshrelay genkey` (mode 0600)")
	fs.StringVar(&signing, "trusted-signing-keys", "", "comma-separated Core signing keys (mtsign:...); with --core-url they only bootstrap trust")
	fs.StringVar(&cfg.coreURL, "core-url", "", "Core control URL (https://...) to poll for signing keys, revocations and drain")
	fs.StringVar(&cfg.udpAddr, "udp", "0.0.0.0:3479", "MTRP UDP listen address")
	fs.IntVar(&cfg.udpReaders, "udp-readers", 4, "UDP reader goroutines")
	fs.StringVar(&cfg.stunAddr, "stun", "0.0.0.0:3478", "STUN listen address (empty disables STUN)")
	fs.StringVar(&cfg.stunAltPort, "stun-alt", "0.0.0.0:3480", "STUN alternate-port listen address for RFC 5780 (empty disables)")
	fs.StringVar(&publicIP, "public-ip", "", "public IPv4 address clients reach (enables RFC 5780 attributes)")
	fs.StringVar(&publicIPv6, "public-ipv6", "", "public IPv6 address clients reach (RFC 5780 attributes for IPv6 clients; listen on [::] to serve IPv6)")
	fs.StringVar(&cfg.adminAddr, "admin", "127.0.0.1:9479", "metrics and health listen address")
	fs.DurationVar(&cfg.drainTimeout, "drain-timeout", 5*time.Second, "time clients get to move away on shutdown")
	fs.StringVar(&cfg.logLevel, "log-level", "info", "log level: debug, info, warn, error")
	fs.StringVar(&cfg.tlsAddr, "tls", "", "TLS/WebSocket listen address, for example 0.0.0.0:443 (empty disables)")
	fs.StringVar(&cfg.tlsCert, "tls-cert", "", "TLS certificate chain file (PEM)")
	fs.StringVar(&cfg.tlsKey, "tls-key", "", "TLS private key file (PEM)")
	fs.BoolVar(&cfg.tlsSelfSigned, "tls-self-signed", false, "use an ephemeral self-signed certificate (labs only)")
	fs.StringVar(&cfg.acmeHost, "acme-host", "", "obtain a certificate for this host name from Let's Encrypt (TLS-ALPN-01 on the TLS port)")
	fs.StringVar(&cfg.acmeCache, "acme-cache", "", "directory where ACME certificates are kept")
	fs.StringVar(&cfg.acmeEmail, "acme-email", "", "contact address for the ACME account (optional)")
	fs.IntVar(&cfg.tlsMaxConns, "tls-max-conns", 10_000, "maximum TLS/WebSocket connections")
	fs.IntVar(&cfg.tlsMaxPerIP, "tls-max-conns-per-ip", 64, "maximum TLS/WebSocket connections per source address (IPv6: per /64)")
	if err := applyEnv(fs, env); err != nil {
		return serveConfig{}, err
	}
	if err := fs.Parse(args); err != nil {
		return serveConfig{}, err
	}
	if fs.NArg() != 0 {
		return serveConfig{}, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if cfg.keyFile == "" {
		return serveConfig{}, errors.New("--key-file is required")
	}
	for _, text := range strings.Split(signing, ",") {
		if text = strings.TrimSpace(text); text == "" {
			continue
		}
		k, err := key.ParseSigningPublic(text)
		if err != nil {
			return serveConfig{}, fmt.Errorf("--trusted-signing-keys: %w", err)
		}
		cfg.signingKeys = append(cfg.signingKeys, k)
	}
	if len(cfg.signingKeys) == 0 {
		return serveConfig{}, errors.New("--trusted-signing-keys needs at least one key")
	}
	if publicIP != "" {
		ip, err := netip.ParseAddr(publicIP)
		if err != nil || !ip.Is4() {
			return serveConfig{}, fmt.Errorf("--public-ip %q is not an IPv4 address", publicIP)
		}
		cfg.publicIP = ip
	}
	if publicIPv6 != "" {
		ip, err := netip.ParseAddr(publicIPv6)
		if err != nil || !ip.Is6() || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return serveConfig{}, fmt.Errorf("--public-ipv6 %q is not a public IPv6 address", publicIPv6)
		}
		cfg.publicIPv6 = ip
	}
	if cfg.tlsMaxConns < 1 || cfg.tlsMaxPerIP < 1 {
		return serveConfig{}, errors.New("--tls-max-conns and --tls-max-conns-per-ip must be positive")
	}
	if cfg.udpReaders < 1 || cfg.udpReaders > 64 {
		return serveConfig{}, errors.New("--udp-readers must be between 1 and 64")
	}
	return cfg, nil
}

// applyEnv sets flag defaults from MESHRELAY_* variables.
func applyEnv(fs *flag.FlagSet, env func(string) (string, bool)) error {
	var err error
	fs.VisitAll(func(f *flag.Flag) {
		name := "MESHRELAY_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v, ok := env(name); ok && err == nil {
			if setErr := f.Value.Set(v); setErr != nil {
				err = fmt.Errorf("%s: %w", name, setErr)
			}
		}
	})
	return err
}

// loadRelayKey reads the key file, refusing files other users can read.
func loadRelayKey(path string) (key.RelayPrivate, error) {
	info, err := os.Stat(path)
	if err != nil {
		return key.RelayPrivate{}, fmt.Errorf("relay key: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return key.RelayPrivate{}, fmt.Errorf("relay key %s is readable by other users (mode %s); run chmod 600", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return key.RelayPrivate{}, fmt.Errorf("relay key: %w", err)
	}
	defer clear(raw)
	k, err := key.ParseRelayPrivateBytes(raw)
	if err != nil {
		return key.RelayPrivate{}, fmt.Errorf("relay key %s: %w", path, err)
	}
	return k, nil
}

// genkey writes a new relay key file and prints the public key.
func genkey(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("meshrelay genkey", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "key file to create (must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("--out is required")
	}
	k, err := key.NewRelayPrivate()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	if _, err := io.WriteString(f, k.PrivateText()+"\n"); err != nil {
		_ = f.Close()
		return fmt.Errorf("write key file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	_, err = fmt.Fprintln(stdout, k.Public().String())
	return err
}

func parseLevel(s string) (int, error) {
	switch s {
	case "debug":
		return -4, nil
	case "info":
		return 0, nil
	case "warn":
		return 4, nil
	case "error":
		return 8, nil
	default:
		return 0, fmt.Errorf("unknown log level %q", s)
	}
}
