package selfhost

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	config, err := ParseConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestGenerateSecretsWritesEveryKindInItsFormat(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "secrets")
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	report, err := GenerateSecrets(testConfig(t), dir, GenerateOptions{Now: now})
	if err != nil {
		t.Fatalf("GenerateSecrets() error = %v", err)
	}
	if len(report.Created) != len(secretCatalog)+len(tlsLeaves)*2+2 || len(report.Kept) != 0 {
		t.Fatalf("report = %+v", report)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("secrets directory mode = %v, %v", info, err)
	}
	formats := map[secretKind]*regexp.Regexp{
		secretPassword:     regexp.MustCompile(`^[0-9a-f]{48}$`),
		secretDigestKey:    regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`),
		secretIdentitySeed: regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`),
		secretControlKey:   regexp.MustCompile(`^privkey:[0-9a-f]{64}$`),
		secretClientSecret: regexp.MustCompile(`^[0-9a-f]{64}$`),
		secretBrowserKey:   regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`),
	}
	for _, spec := range secretCatalog {
		contents := readFile(t, dir, spec.name)
		if !formats[spec.kind].Match(contents) {
			t.Errorf("%s: format of kind %d is wrong", spec.name, spec.kind)
		}
		info, _ := os.Stat(filepath.Join(dir, spec.name))
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v", spec.name, info.Mode().Perm())
		}
	}
	if decoded, err := base64.StdEncoding.DecodeString(string(readFile(t, dir, "browser-registration.key"))); err != nil ||
		len(decoded) != 32 {
		t.Errorf("browser registration key decodes to %d bytes, %v", len(decoded), err)
	}
	// The identity broker's copy of Core's client secret and the login
	// profile's are two files (Core refuses a shared file) with one value.
	if string(readFile(t, dir, "identity-core-client-secret")) != string(readFile(t, dir, "login-client-secret")) {
		t.Error("the two copies of Core's OIDC client secret differ")
	}
}

func TestGenerateSecretsIssuesTLSFromItsOwnCA(t *testing.T) {
	t.Parallel()
	dir := secretsDir(t)
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	if _, err := GenerateSecrets(testConfig(t), dir, GenerateOptions{Now: now}); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(readFile(t, dir, "ca.crt")) {
		t.Fatal("ca.crt does not parse")
	}
	for _, leaf := range tlsLeaves {
		certificate := parseCertificate(t, readFile(t, dir, leaf.name+".crt"))
		names := leaf.names(testConfig(t))
		if _, err := certificate.Verify(x509.VerifyOptions{
			DNSName: names[0], Roots: roots, CurrentTime: now.Add(time.Hour),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			t.Errorf("%s: %v", leaf.name, err)
		}
	}
	// The broker's certificate names only the issuer's host.
	identity := parseCertificate(t, readFile(t, dir, "identity.crt"))
	if len(identity.DNSNames) != 1 || identity.DNSNames[0] != "id.mesh.example.com" || len(identity.IPAddresses) != 0 {
		t.Fatalf("identity certificate names = %v %v", identity.DNSNames, identity.IPAddresses)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("ca.key: %v", err)
	}
}

func TestGenerateSecretsNeverReplacesWhatExists(t *testing.T) {
	t.Parallel()
	dir := secretsDir(t)
	options := GenerateOptions{Now: time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)}
	if _, err := GenerateSecrets(testConfig(t), dir, options); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, dir, "postgres-runtime-password")
	firstState, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "redis-password")); err != nil {
		t.Fatal(err)
	}
	report, err := GenerateSecrets(testConfig(t), dir, options)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Created) != 1 || report.Created[0] != "redis-password" {
		t.Fatalf("second run created %v", report.Created)
	}
	if string(readFile(t, dir, "postgres-runtime-password")) != string(before) {
		t.Fatal("an existing secret changed")
	}
	secondState, err := LoadState(dir)
	if err != nil || secondState != firstState {
		t.Fatalf("state changed: %+v != %+v (%v)", secondState, firstState, err)
	}
}

func TestStateHoldsTheDurableIdentities(t *testing.T) {
	t.Parallel()
	dir := secretsDir(t)
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	if _, err := GenerateSecrets(testConfig(t), dir, GenerateOptions{Now: now}); err != nil {
		t.Fatal(err)
	}
	state, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if state.RecoveryEpoch != 1 || state.ProviderGeneration != 1 || state.ConnectorGeneration != 1 ||
		state.CoreClientGeneration != 1 || state.IdentityFingerprint != "" ||
		!state.MTCPKeyNotAfter.Equal(now.AddDate(1, 0, 0)) {
		t.Fatalf("state = %+v", state)
	}
	ids := []string{state.DeploymentID, state.ProviderID, state.ClientID}
	for _, id := range ids {
		if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(id) {
			t.Errorf("id %q is not a lowercase UUIDv7", id)
		}
	}
	info, err := os.Stat(filepath.Join(dir, stateFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %v, %v", info, err)
	}
}

func TestLoadStateRefusesTamperedOrUnknownState(t *testing.T) {
	t.Parallel()
	for name, contents := range map[string]string{
		"unknown field": `{"format":"meshtransit-selfhost-state/v1","extra":1}`,
		"wrong format":  `{"format":"other"}`,
		"not json":      `not json`,
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, stateFile), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadState(dir); !errors.Is(err, ErrInvalidState) {
			t.Errorf("%s: LoadState() error = %v", name, err)
		}
	}
}

func TestGenerateSecretsRefusesHalfPairsAndDriftedCopies(t *testing.T) {
	t.Parallel()
	options := GenerateOptions{Now: time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)}
	dir := secretsDir(t)
	if _, err := GenerateSecrets(testConfig(t), dir, options); err != nil {
		t.Fatal(err)
	}
	// An interrupted run left a key without its certificate.
	if err := os.Remove(filepath.Join(dir, "api.crt")); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateSecrets(testConfig(t), dir, options); !errors.Is(err, ErrSecrets) {
		t.Fatalf("half a pair: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "api.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateSecrets(testConfig(t), dir, options); err != nil {
		t.Fatalf("both removed are issued again: %v", err)
	}
	// A swapped key no longer matches its certificate.
	if err := os.Rename(filepath.Join(dir, "redis.key"), filepath.Join(dir, "api.key.swap")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "api.key"), filepath.Join(dir, "redis.key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "api.key.swap"), filepath.Join(dir, "api.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateSecrets(testConfig(t), dir, options); !errors.Is(err, ErrSecrets) {
		t.Fatalf("mismatched pair: %v", err)
	}

	// The two copies of Core's client secret drifted apart.
	other := secretsDir(t)
	if _, err := GenerateSecrets(testConfig(t), other, options); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "login-client-secret"),
		[]byte(strings.Repeat("0", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateSecrets(testConfig(t), other, options); !errors.Is(err, ErrSecrets) {
		t.Fatalf("drifted copies: %v", err)
	}
	// A link in place of the first copy is never followed.
	if err := os.Remove(filepath.Join(other, "login-client-secret")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(other, "identity-core-client-secret")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hosts", filepath.Join(other, "identity-core-client-secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateSecrets(testConfig(t), other, options); !errors.Is(err, ErrSecrets) {
		t.Fatalf("linked copy: %v", err)
	}
}

func secretsDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "secrets")
}

func TestGenerateSecretsRefusesAnOpenDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil { // #nosec G302 -- the open directory under test.
		t.Fatal(err)
	}
	_, err := GenerateSecrets(testConfig(t), dir, GenerateOptions{Now: time.Now()})
	if !errors.Is(err, ErrSecrets) {
		t.Fatalf("GenerateSecrets() into a 0755 directory error = %v", err)
	}
	if _, err := GenerateSecrets(testConfig(t), "relative/dir", GenerateOptions{Now: time.Now()}); !errors.Is(err, ErrSecrets) {
		t.Fatalf("relative directory error = %v", err)
	}
}

// readFile returns a file without the trailing newline Core removes.
func readFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- a test directory.
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(contents, []byte("\n"))
}

func parseCertificate(t *testing.T, contents []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(contents)
	if block == nil {
		t.Fatal("no PEM block")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
