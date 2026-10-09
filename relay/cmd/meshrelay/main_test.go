package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
