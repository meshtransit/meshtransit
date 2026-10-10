package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"meshtransit.net/shared/key"
)

func noEnv(string) (string, bool) { return "", false }

func TestGenkeyAndLoad(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "relay.key")
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"genkey", "--out", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("genkey exit %d: %s", code, errOut.String())
	}
	public, err := key.ParseRelayPublic(strings.TrimSpace(out.String()))
	if err != nil {
		t.Fatalf("printed public key: %v", err)
	}
	k, err := loadRelayKey(path)
	if err != nil || k.Public() != public {
		t.Fatalf("load: %v", err)
	}
	if code := run(context.Background(), []string{"genkey", "--out", path}, noEnv, &out, &errOut); code == 0 {
		t.Fatal("genkey overwrote an existing key")
	}
	if err := os.Chmod(path, 0o640); err != nil { //nolint:gosec // deliberately too open: the loader must refuse it
		t.Fatal(err)
	}
	if _, err := loadRelayKey(path); err == nil || !strings.Contains(err.Error(), "readable by other users") {
		t.Fatalf("world-readable key accepted: %v", err)
	}
}

func TestParseServeConfig(t *testing.T) {
	t.Parallel()
	signer, _ := key.SigningPrivateFromSeed(bytes.Repeat([]byte{1}, 32))
	signing := signer.Public().String()
	env := func(name string) (string, bool) {
		if name == "MESHRELAY_TRUSTED_SIGNING_KEYS" {
			return signing, true
		}
		return "", false
	}
	cfg, err := parseServeConfig([]string{"--key-file", "k", "--public-ip", "203.0.113.5"}, env, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.signingKeys) != 1 || cfg.publicIP.String() != "203.0.113.5" || cfg.udpAddr != "0.0.0.0:3479" {
		t.Fatalf("cfg = %+v", cfg)
	}
	for _, args := range [][]string{
		{},
		{"--key-file", "k", "--trusted-signing-keys", "mtsign:bad"},
		{"--key-file", "k", "--trusted-signing-keys", signing, "--public-ip", "::1"},
		{"--key-file", "k", "--trusted-signing-keys", signing, "--udp-readers", "0"},
		{"--key-file", "k", "--trusted-signing-keys", signing, "extra"},
	} {
		if _, err := parseServeConfig(args, noEnv, &bytes.Buffer{}); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
	var errOut bytes.Buffer
	if code := run(context.Background(), []string{"nope"}, noEnv, &bytes.Buffer{}, &errOut); code != 2 {
		t.Fatalf("unknown command exit %d", code)
	}
}

func TestTLSConfigModes(t *testing.T) {
	t.Parallel()
	if _, err := tlsConfig(serveConfig{}, slog.New(slog.DiscardHandler), nil); err == nil {
		t.Fatal("no certificate mode accepted")
	}
	if _, err := tlsConfig(serveConfig{tlsSelfSigned: true, acmeHost: "relay.example"}, slog.New(slog.DiscardHandler), nil); err == nil {
		t.Fatal("two certificate modes accepted")
	}
	if _, err := tlsConfig(serveConfig{acmeHost: "relay.example"}, slog.New(slog.DiscardHandler), nil); err == nil {
		t.Fatal("ACME without a cache directory accepted")
	}
	if _, err := tlsConfig(serveConfig{tlsCert: "missing.pem", tlsKey: "missing.key"}, slog.New(slog.DiscardHandler), nil); err == nil {
		t.Fatal("missing certificate files accepted")
	}
	var expiry time.Time
	c, err := tlsConfig(serveConfig{tlsSelfSigned: true}, slog.New(slog.DiscardHandler), func(t time.Time) { expiry = t })
	if err != nil || len(c.Certificates) != 1 || time.Until(expiry) < 300*24*time.Hour {
		t.Fatalf("self-signed: %v (expiry %v)", err, expiry)
	}
	acme, err := tlsConfig(serveConfig{acmeHost: "relay.example", acmeCache: t.TempDir()}, slog.New(slog.DiscardHandler), func(time.Time) {})
	if err != nil || acme.GetCertificate == nil {
		t.Fatalf("acme: %v", err)
	}
}

func TestCertReloader(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func() {
		cert, err := selfSigned()
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(filepath.Join(dir, "c.pem"), certPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "k.pem"), keyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	r, err := newCertReloader(filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem"))
	if err != nil {
		t.Fatal(err)
	}
	first, _ := r.get(nil)
	write()
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "c.pem"), future, future); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.checked = time.Time{} // force the next call to look at the files
	r.mu.Unlock()
	second, _ := r.get(nil)
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("certificate not reloaded after the files changed")
	}
}

// systemd LoadCredential= hands the key over as a 0440 file in a directory
// only the service can open; group-read is accepted there and nowhere else.
func TestLoadRelayKeyAcceptsSystemdCredential(t *testing.T) {
	t.Parallel()
	credentials := t.TempDir()
	path := filepath.Join(credentials, "relay.key")
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"genkey", "--out", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("genkey exit %d: %s", code, errOut.String())
	}
	if err := os.Chmod(path, 0o440); err != nil { //nolint:gosec // systemd credential mode
		t.Fatal(err)
	}
	if _, err := loadRelayKeyFrom(path, credentials); err != nil {
		t.Fatalf("credential refused: %v", err)
	}
	if _, err := loadRelayKeyFrom(path, ""); err == nil {
		t.Fatal("group-readable key accepted outside a credentials directory")
	}
	if _, err := loadRelayKeyFrom(path, t.TempDir()); err == nil {
		t.Fatal("group-readable key accepted outside the credentials directory")
	}
	escaped := filepath.Join(credentials, "sub", "..", "..", filepath.Base(credentials), "relay.key")
	if _, err := loadRelayKeyFrom(escaped, filepath.Join(credentials, "sub")); err == nil {
		t.Fatal("a path leaving the credentials directory was accepted")
	}
	if err := os.Chmod(path, 0o444); err != nil { //nolint:gosec // deliberately too open
		t.Fatal(err)
	}
	if _, err := loadRelayKeyFrom(path, credentials); err == nil {
		t.Fatal("world-readable credential accepted")
	}
}
