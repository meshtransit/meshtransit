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
	secretRelayKey
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
	// The relay on this server ("meshrelay genkey" form) and Core's relay
	// signing seed, whose public key the relay trusts.
	{name: "relay.key", kind: secretRelayKey},
	{name: "relay-signing.key", kind: secretIdentitySeed},
}

// Owner is who owns the generated files: the images run as 65532.
type Owner struct{ UID, GID int }

// GenerateOptions bound one run of setup or of the TLS renewal.
type GenerateOptions struct {
	Now   time.Time
	Owner *Owner
	// fault fails a named point of a run: tests stop a run half way with it.
	fault func(point string) error
}

func (options GenerateOptions) inject(point string) error {
	if options.fault == nil {
		return nil
	}
	return options.fault(point)
}

// GenerateReport names the files a run created and kept, and the leaves it
// issued again, never contents.
type GenerateReport struct {
	Created []string
	Kept    []string
	Renewed []string
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
	if err := refuseLostSuperuserPassword(dir); err != nil {
		return GenerateReport{}, err
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
	// The bundled datastores' credential files: a SCRAM verifier and a
	// SHA-256, never the passwords. PostgreSQL runs its file once, on its
	// first start (setup migrate keeps the roles' verifiers current after
	// that); Redis reads its file at every start, so it follows the password.
	if err := writeDerived(dir, "postgres-init.sql", postgresInitSQL, false, options.Owner, record); err != nil {
		return report, err
	}
	if err := writeDerived(dir, "redis-users.acl", redisACL, true, options.Owner, record); err != nil {
		return report, err
	}
	renewed, err := generateTLS(config, dir, options, record)
	report.Renewed = renewed
	if err != nil {
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
	case secretRelayKey:
		return relayKeyText()
	default:
		return nil, fmt.Errorf("%w: unknown kind", ErrSecrets)
	}
}

// ErrSuperuserPasswordLost reports a database that outlived its superuser's
// password file.
var ErrSuperuserPasswordLost = errors.New("postgres-superuser-password is missing but the database exists: " +
	"restore it from the backup of secrets/")

// refuseLostSuperuserPassword stops setup from generating a new superuser
// password for a database that already exists: PostgreSQL took the password
// once, when it created the database, so a new file would lock setup
// migrate out for good.
func refuseLostSuperuserPassword(dir string) error {
	if _, err := os.Lstat(filepath.Join(dir, "postgres-superuser-password")); !errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	entries, err := os.ReadDir(filepath.Join(filepath.Dir(dir), "postgres"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: postgres data: %w", ErrSecrets, err)
	}
	if len(entries) != 0 {
		return ErrSuperuserPasswordLost
	}
	return nil
}

// writeDerived writes a file derived from the passwords when it is absent
// or, with follow set, when its content no longer matches them; a link is
// refused.
func writeDerived(dir, name string, build func(string) ([]byte, error), follow bool, owner *Owner,
	record func(string, bool),
) error {
	if !follow {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			record(name, false)
			return nil
		}
	}
	contents, err := build(dir)
	if err != nil {
		return err
	}
	if follow {
		return replaceDerived(dir, name, contents, owner, record)
	}
	created, err := writeIfAbsent(dir, name, contents, 0o600, owner)
	if err != nil {
		return err
	}
	record(name, created)
	return nil
}

// replaceDerived replaces name, atomically, only when its content differs.
func replaceDerived(dir, name string, contents []byte, owner *Owner, record func(string, bool)) error {
	existing, err := readRegularFile(filepath.Join(dir, name), 64<<10)
	if errors.Is(err, fs.ErrNotExist) {
		created, err := writeIfAbsent(dir, name, contents, 0o600, owner)
		if err != nil {
			return err
		}
		record(name, created)
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSecrets, name, err)
	}
	if bytes.Equal(existing, slices.Concat(contents, []byte("\n"))) {
		record(name, false)
		return nil
	}
	temporary, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSecrets, name, err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := writeAndSync(temporary, contents, 0o600, owner); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSecrets, name, err)
	}
	if err := os.Rename(temporaryName, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSecrets, name, err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSecrets, name, err)
	}
	record(name, true)
	return nil
}

// syncDirectory makes a rename in dir durable.
func syncDirectory(dir string) error {
	directory, err := os.Open(dir) // #nosec G304 -- the state directory setup owns.
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
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
