package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/deployment/entitlement"
)

func field(t *testing.T, output, name string) string {
	t.Helper()
	for line := range strings.SplitSeq(output, "\n") {
		if value, ok := strings.CutPrefix(line, name+"="); ok {
			return value
		}
	}
	t.Fatalf("missing %s in %q", name, output)
	return ""
}

func TestIssueRoundTripVerifiesInMeshcore(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	signingFile, installationFile := filepath.Join(directory, "signing.key"), filepath.Join(directory, "installation.key")

	var output bytes.Buffer
	if err := run([]string{"signing-key", "--out", signingFile, "--key-id", "meshtransit-poc-2026-10"}, &output, now); err != nil {
		t.Fatal(err)
	}
	signingPublic, err := base64.StdEncoding.DecodeString(field(t, output.String(), "public_key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"signing-key", "--out", signingFile, "--key-id", "meshtransit-poc-2026-10"}, &output, now); err == nil {
		t.Fatal("existing key file overwritten")
	}
	if info, err := os.Stat(signingFile); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("signing key is not private", err)
	}
	if strings.Contains(output.String(), mustRead(t, signingFile)) {
		t.Fatal("private key printed")
	}

	output.Reset()
	if err := run([]string{"installation-key", "--out", installationFile}, &output, now); err != nil {
		t.Fatal(err)
	}
	installationPublic := field(t, output.String(), "installation_public_key")

	output.Reset()
	deploymentText := "01890f00-0000-7000-8000-000000000001"
	if err := run([]string{"sign", "--signing-key", signingFile, "--key-id", "meshtransit-poc-2026-10",
		"--installation-public-key", installationPublic, "--deployment", deploymentText, "--profile", "cloud",
		"--max-active", "50", "--max-owned", "5", "--generation", "1", "--days", "90"}, &output, now); err != nil {
		t.Fatal(err)
	}
	envelope := bytes.TrimSuffix(output.Bytes(), []byte("\n"))
	if bytes.Contains(envelope, []byte("\n")) {
		t.Fatal("envelope is not one line")
	}

	seedText := strings.TrimSuffix(mustRead(t, installationFile), "\n")
	seed, err := base64.RawURLEncoding.DecodeString(seedText)
	if err != nil {
		t.Fatal(err)
	}
	installation, err := entitlement.NewInstallation([ed25519.SeedSize]byte(seed))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := entitlement.NewVerifier(map[string]ed25519.PublicKey{"meshtransit-poc-2026-10": signingPublic})
	if err != nil {
		t.Fatal(err)
	}
	deploymentID, _ := deployment.ParseID(deploymentText)
	verified, err := verifier.Verify(envelope, deploymentID, installation, now)
	if err != nil || verified.Limits.MaxActiveWorkspaces != 50 || verified.Generation != 1 ||
		!verified.ExpiresAt.Equal(now.AddDate(0, 0, 90)) {
		t.Fatalf("issued entitlement = %+v, %v", verified, err)
	}
}

func TestSignRejectsClaimsMeshcoreWouldReject(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	signingFile := filepath.Join(directory, "signing.key")
	var output bytes.Buffer
	if err := run([]string{"signing-key", "--out", signingFile, "--key-id", "poc"}, &output, now); err != nil {
		t.Fatal(err)
	}
	public := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	for name, extra := range map[string][]string{
		"owned above active": {"--max-active", "3", "--max-owned", "5", "--generation", "1", "--days", "30"},
		"zero generation":    {"--max-active", "3", "--max-owned", "1", "--generation", "0", "--days", "30"},
		"unknown capability": {"--max-active", "3", "--max-owned", "1", "--generation", "1", "--days", "30", "--capability", "vip"},
	} {
		args := append([]string{"sign", "--signing-key", signingFile, "--key-id", "poc", "--installation-public-key", public,
			"--deployment", "01890f00-0000-7000-8000-000000000001"}, extra...)
		if err := run(args, &output, now); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path) //nolint:gosec // test temp file
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}
