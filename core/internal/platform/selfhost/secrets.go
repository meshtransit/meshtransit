package selfhost

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"
)

// ErrSecrets reports a secrets directory setup cannot use or write.
var ErrSecrets = errors.New("self-host secrets")

type secretKind int

const (
	secretPassword secretKind = iota + 1
	secretDigestKey
	secretIdentitySeed
	secretControlKey
	secretClientSecret
	secretBrowserKey
)

type secretSpec struct {
	name string
	kind secretKind
}

// secretCatalog is every generated secret, one file each (Core refuses two
// settings sharing a file). Formats follow configuration.md "Secret files".
var secretCatalog = []secretSpec{
	{name: "postgres-superuser-password", kind: secretPassword},
	{name: "postgres-migrator-password", kind: secretPassword},
	{name: "postgres-runtime-password", kind: secretPassword},
	{name: "postgres-worker-password", kind: secretPassword},
	{name: "identity-migrator-password", kind: secretPassword},
	{name: "identity-runtime-password", kind: secretPassword},
	{name: "redis-password", kind: secretPassword},
	{name: "enrollment-digest.key", kind: secretDigestKey},
	{name: "account-session-digest.key", kind: secretDigestKey},
	{name: "idempotency-digest.key", kind: secretDigestKey},
	{name: "rate-limit-digest.key", kind: secretDigestKey},
	{name: "control-noise.key", kind: secretControlKey},
	// Core's client secret at the identity broker and in the login profile:
	// one value, two files.
	{name: "identity-core-client-secret", kind: secretClientSecret},
	{name: "login-client-secret", kind: secretClientSecret},
	{name: "login-initiation.key", kind: secretIdentitySeed},
	{name: "login-capture.key", kind: secretIdentitySeed},
	{name: "login-continuation.key", kind: secretIdentitySeed},
	{name: "login-management-csrf.key", kind: secretIdentitySeed},
	{name: "login-transaction-digest.key", kind: secretIdentitySeed},
	{name: "login-verifier-encryption.key", kind: secretIdentitySeed},
	{name: "login-subject-active.key", kind: secretIdentitySeed},
	{name: "login-provider-session.key", kind: secretIdentitySeed},
	{name: "browser-registration.key", kind: secretBrowserKey},
}

// Owner is who owns the generated files: the images run as 65532.
type Owner struct{ UID, GID int }

// GenerateOptions bound one run.
type GenerateOptions struct {
	Now   time.Time
	Owner *Owner
}

// GenerateReport names the files a run created and kept, never contents.
type GenerateReport struct {
	Created []string
	Kept    []string
}

// GenerateSecrets creates every secret, certificate and the state file that
// dir lacks, and never changes one that exists: rotation is a separate,
// deliberate operation.
func GenerateSecrets(config Config, dir string, options GenerateOptions) (GenerateReport, error) {
	if options.Now.IsZero() {
		return GenerateReport{}, fmt.Errorf("%w: no time", ErrSecrets)
	}
	if err := prepareDirectory(dir, options.Owner); err != nil {
		return GenerateReport{}, err
	}
	report := GenerateReport{}
	record := func(name string, created bool) {
		if created {
			report.Created = append(report.Created, name)
		} else {
			report.Kept = append(report.Kept, name)
		}
	}
	for _, spec := range secretCatalog {
		value, err := secretValue(dir, spec)
		if err != nil {
			return report, err
		}
		created, err := writeIfAbsent(dir, spec.name, value, 0o600, options.Owner)
		clear(value)
		if err != nil {
			return report, err
		}
		record(spec.name, created)
	}
	if err := verifyClientSecretCopies(dir); err != nil {
		return report, err
	}
	if err := generateTLS(config, dir, options, record); err != nil {
		return report, err
	}
	if err := ensureState(dir, options); err != nil {
		return report, err
	}
	return report, nil
}

func prepareDirectory(dir string, owner *Owner) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%w: directory must be absolute", ErrSecrets)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("%w: create directory: %w", ErrSecrets, err)
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: directory must be a directory only its owner can read", ErrSecrets)
	}
	if owner != nil {
		if err := os.Chown(dir, owner.UID, owner.GID); err != nil {
			return fmt.Errorf("%w: chown directory: %w", ErrSecrets, err)
		}
	}
	return nil
}

// secretValue makes a new value, except for the second copy of Core's
// client secret, which repeats the first one's.
func secretValue(dir string, spec secretSpec) ([]byte, error) {
	if spec.name == "login-client-secret" {
		return readClientSecret(dir, "identity-core-client-secret")
	}
	random := make([]byte, 32)
	defer clear(random)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("%w: entropy: %w", ErrSecrets, err)
	}
	switch spec.kind {
	case secretPassword:
		return []byte(hex.EncodeToString(random[:24])), nil
	case secretDigestKey, secretIdentitySeed:
		return []byte(base64.RawURLEncoding.EncodeToString(random)), nil
	case secretControlKey:
		return []byte("privkey:" + hex.EncodeToString(random)), nil
	case secretClientSecret:
		return []byte(hex.EncodeToString(random)), nil
	case secretBrowserKey:
		return []byte(base64.StdEncoding.EncodeToString(random)), nil
	default:
		return nil, fmt.Errorf("%w: unknown kind", ErrSecrets)
	}
}

// writeIfAbsent writes name only if it does not exist: the content goes to a
// temporary file first, then a hard link claims the name, which fails when
// another file holds it. A crash leaves a temporary file, never a partial
// secret.
func writeIfAbsent(dir, name string, contents []byte, mode fs.FileMode, owner *Owner) (bool, error) {
	target := filepath.Join(dir, name)
	if _, err := os.Lstat(target); err == nil {
		return false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("%w: %s: %w", ErrSecrets, name, err)
	}
	temporary, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return false, fmt.Errorf("%w: %s: %w", ErrSecrets, name, err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := writeAndSync(temporary, contents, mode, owner); err != nil {
		return false, fmt.Errorf("%w: %s: %w", ErrSecrets, name, err)
	}
	if err := os.Link(temporaryName, target); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("%w: %s: %w", ErrSecrets, name, err)
	}
	return true, nil
}

func writeAndSync(file *os.File, contents []byte, mode fs.FileMode, owner *Owner) error {
	defer func() { _ = file.Close() }()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if owner != nil {
		if err := file.Chown(owner.UID, owner.GID); err != nil {
			return err
		}
	}
	if _, err := file.Write(slices.Concat(contents, []byte("\n"))); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

var clientSecretFormat = regexp.MustCompile(`^[0-9a-f]{64}$`)

// readClientSecret reads one copy of Core's OIDC client secret: a regular
// file (never through a link) holding the generated format.
func readClientSecret(dir, name string) ([]byte, error) {
	contents, err := readRegularFile(filepath.Join(dir, name), 256)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", ErrSecrets, name, err)
	}
	value := bytes.TrimSuffix(contents, []byte("\n"))
	if !clientSecretFormat.Match(value) {
		clear(contents)
		return nil, fmt.Errorf("%w: %s is not a generated client secret", ErrSecrets, name)
	}
	return value, nil
}

// verifyClientSecretCopies fails when the broker's and the login profile's
// copies of Core's client secret differ: every sign-in would be refused.
func verifyClientSecretCopies(dir string) error {
	broker, err := readClientSecret(dir, "identity-core-client-secret")
	if err != nil {
		return err
	}
	defer clear(broker)
	login, err := readClientSecret(dir, "login-client-secret")
	if err != nil {
		return err
	}
	defer clear(login)
	if !bytes.Equal(broker, login) {
		return fmt.Errorf("%w: the two copies of Core's client secret differ; remove login-client-secret to copy it again",
			ErrSecrets)
	}
	return nil
}
