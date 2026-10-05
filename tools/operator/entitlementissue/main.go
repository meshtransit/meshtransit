// Command entitlementissue is the issuance boundary for signed Deployment
// Entitlements (ADR-050 D1). It is an operator tool and is never shipped in
// the meshcore image. Private keys are written only to new 0600 files and are
// never printed.
//
//	entitlementissue signing-key --out FILE --key-id ID
//	    creates an Ed25519 signing key and prints the public key to embed.
//	entitlementissue installation-key --out FILE
//	    creates the 32-byte installation seed for the Kubernetes Secret and
//	    prints its public key and fingerprint.
//	entitlementissue sign --signing-key FILE --key-id ID --installation-public-key B64
//	    --deployment UUID --profile cloud --max-active N --max-owned N
//	    --generation N --days N [--grace-days N] [--capability NAME]...
//	    prints one signed single-line envelope.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment/entitlement"
	"github.com/meshtransit/meshtransit/internal/deployment/entitlement/issuer"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, time.Now().UTC()); err != nil {
		fmt.Fprintln(os.Stderr, "entitlementissue:", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer, now time.Time) error {
	if len(args) == 0 {
		return errors.New("expected signing-key, installation-key or sign")
	}
	switch args[0] {
	case "signing-key":
		return signingKey(args[1:], output)
	case "installation-key":
		return installationKey(args[1:], output)
	case "sign":
		return sign(args[1:], output, now)
	default:
		return errors.New("unknown command")
	}
}

// writeNewSecret refuses to overwrite and creates the file with mode 0600.
func writeNewSecret(path string, contents []byte) error {
	if path == "" {
		return errors.New("--out is required")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // operator-chosen new key path
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	_, writeErr := file.Write(contents)
	return errors.Join(writeErr, file.Close())
}

func encodeSeed(seed []byte) []byte {
	return []byte(base64.RawURLEncoding.EncodeToString(seed) + "\n")
}

func readSeed(path string) ([]byte, error) {
	contents, err := os.ReadFile(path) //nolint:gosec // operator-supplied key path
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	seed, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSuffix(string(contents), "\n"))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("key file must hold one base64url Ed25519 seed")
	}
	return seed, nil
}

func signingKey(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("signing-key", flag.ContinueOnError)
	out := flags.String("out", "", "new private key file")
	keyID := flags.String("key-id", "", "signer key ID, for example meshtransit-poc-2026-10")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if _, err := entitlement.NewVerifier(map[string]ed25519.PublicKey{*keyID: make(ed25519.PublicKey, ed25519.PublicKeySize)}); err != nil {
		return errors.New("invalid --key-id")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(private)
	if err := writeNewSecret(*out, encodeSeed(private.Seed())); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "key_id=%s\npublic_key=%s\n", *keyID, base64.StdEncoding.EncodeToString(public))
	return err
}

func installationKey(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("installation-key", flag.ContinueOnError)
	out := flags.String("out", "", "new installation seed file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	defer clear(seed)
	installation, err := entitlement.NewInstallation([ed25519.SeedSize]byte(seed))
	if err != nil {
		return err
	}
	public, _ := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if err := writeNewSecret(*out, encodeSeed(seed)); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "installation_public_key=%s\ninstallation_key_sha256=%s\n",
		base64.StdEncoding.EncodeToString(public), installation.Fingerprint())
	return err
}

type capabilityFlags []entitlement.Capability

func (values *capabilityFlags) String() string { return fmt.Sprint(*values) }

func (values *capabilityFlags) Set(value string) error {
	*values = append(*values, entitlement.Capability(value))
	return nil
}

func sign(args []string, output io.Writer, now time.Time) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyFile := flags.String("signing-key", "", "signing key file")
	keyID := flags.String("key-id", "", "signer key ID embedded in meshcore")
	installationPublic := flags.String("installation-public-key", "", "base64 installation public key")
	deploymentID := flags.String("deployment", "", "Deployment installation public ID")
	profile := flags.String("profile", "cloud", "cloud or self_hosted")
	maxActive := flags.Int64("max-active", 0, "max active Workspaces in the Deployment")
	maxOwned := flags.Int64("max-owned", 0, "max owned Workspaces per Account")
	generation := flags.Int64("generation", 0, "strictly increasing generation")
	days := flags.Int("days", 0, "validity in days from now")
	graceDays := flags.Int("grace-days", 14, "grace period in days after expiry")
	var capabilities capabilityFlags
	flags.Var(&capabilities, "capability", "Cloud-only operation (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *days < 1 || *graceDays < 0 {
		return errors.New("--days must be positive and --grace-days not negative")
	}
	public, err := base64.StdEncoding.Strict().DecodeString(*installationPublic)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return errors.New("invalid --installation-public-key")
	}
	seed, err := readSeed(*keyFile)
	if err != nil {
		return err
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	clear(seed)
	id, err := publicid.New()
	if err != nil {
		return err
	}
	if capabilities == nil {
		capabilities = capabilityFlags{}
	}
	start := now.Truncate(time.Second)
	envelope, err := issuer.Sign(issuer.Claims{
		EntitlementID: id.String(), DeploymentID: *deploymentID, InstallationPublicKey: public,
		Profile: *profile, MaxActiveWorkspaces: *maxActive, MaxOwnedWorkspacesPerAccount: *maxOwned,
		Capabilities: capabilities, Generation: *generation,
		IssuedAt: start, NotBefore: start, ExpiresAt: start.AddDate(0, 0, *days),
		Grace: time.Duration(*graceDays) * 24 * time.Hour,
	}, *keyID, private)
	if err != nil {
		return err
	}
	if err := selfVerify(envelope, private, *keyID, *deploymentID, start); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "%s\n", envelope)
	return err
}

// selfVerify parses the envelope with the production verifier so the tool
// never emits an entitlement meshcore would reject for its claims.
func selfVerify(envelope []byte, private ed25519.PrivateKey, keyID, deploymentID string, now time.Time) error {
	public, _ := private.Public().(ed25519.PublicKey)
	verifier, err := entitlement.NewVerifier(map[string]ed25519.PublicKey{keyID: public})
	if err != nil {
		return errors.New("invalid --key-id")
	}
	if _, err := verifier.Parse(envelope, now); err != nil {
		return fmt.Errorf("claims rejected by verifier: %w (deployment %s)", err, deploymentID)
	}
	return nil
}
