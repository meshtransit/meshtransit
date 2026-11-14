package selfhost

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Renewal of the server's internal TLS (docs: auto-renewal-design.md §4).
// Containers mount each file on its own, so a renewed file reaches a
// service only when it restarts. Before any file a service reads changes,
// the service is named in the restart file, and the host's timer restarts
// what it names (meshtransit-tls-renew.service) before it removes it: a run
// that fails or is killed half way still leaves every changed service
// queued. A restart too many is harmless; one too few serves a stale file.
const (
	// caRollBefore starts a CA roll while the CA has this much life left:
	// every leaf it signs then still fits inside it.
	caRollBefore = 2 * 365 * 24 * time.Hour
	// caRollStepWait separates the roll's steps, so every service has run
	// with the previous step's files before the next one changes them.
	caRollStepWait = 24 * time.Hour
	// RestartFile lists the services that must restart to load renewed
	// files. It lives in RenewDir, root's directory in the state directory:
	// root on the host reads it.
	RestartFile = "tls-restart"
	RenewDir    = "renew"
)

// restartDir is RenewDir beside secretsDir.
func restartDir(secretsDir string) string {
	return filepath.Join(filepath.Dir(secretsDir), RenewDir)
}

// PrepareRenewDir makes RenewDir, root's only (0700): renew-tls mounts it
// and the host's root reads the restart file there. A link is refused.
func PrepareRenewDir(secretsDir string) error {
	dir := restartDir(secretsDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSecrets, RenewDir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%w: %s must be a directory", ErrSecrets, RenewDir)
	}
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- a directory: root must enter it.
		return fmt.Errorf("%w: %s: %w", ErrSecrets, RenewDir, err)
	}
	return nil
}

// PendingRestart is the services the restart file names.
func PendingRestart(secretsDir string) ([]string, error) {
	return readRestart(restartDir(secretsDir))
}

// restartOrder is every service that reads a TLS file, in the order they
// restart: the datastores before their clients.
var restartOrder = []string{"postgres", "redis", "meshcore", "console", "caddy"}

// trustReaders are the services that read ca.crt.
var trustReaders = []string{"redis", "meshcore", "console", "caddy"}

// leafService is the service that serves each leaf.
var leafService = map[string]string{
	"postgres": "postgres", "redis": "redis", "api": "meshcore", "control": "meshcore",
	"login": "meshcore", "identity": "meshcore", "console": "console",
}

// CA roll steps a run can take.
const (
	CAStepTrustNext = "trust-next" // a new CA joins the bundle
	CAStepPromote   = "promote"    // the new CA signs every leaf and becomes the signing CA
	CAStepDropOld   = "drop-old"   // the old CA leaves the bundle
)

// RenewReport names what a run changed, never key material.
type RenewReport struct {
	Renewed []string `json:"renewed"`
	CAStep  string   `json:"ca_step,omitempty"`
	// Restart is every service the restart file now names: this run's and
	// any an earlier run left.
	Restart []string `json:"restart"`
	// Waiting explains a CA roll step that is due but held back.
	Waiting string `json:"waiting,omitempty"`
}

// renewal is one run over a secrets directory.
type renewal struct {
	config  Config
	dir     string
	options GenerateOptions
	report  RenewReport
}

// RenewTLS renews what is due in secretsDir: a leaf with less than a third
// of its life left (or not signed by the signing CA), and the CA roll's
// next step. It never advances the roll while a restart is pending: the
// services must load one step's files before the next step changes them.
// On an error the report still names what changed. Callers hold LockSetup.
func RenewTLS(config Config, secretsDir string, options GenerateOptions) (RenewReport, error) {
	run := &renewal{config: config, dir: secretsDir, options: options}
	err := run.renew()
	pending, readErr := PendingRestart(secretsDir)
	if err == nil {
		err = readErr
	}
	run.report.Restart = pending
	return run.report, err
}

func (run *renewal) renew() error {
	if run.options.Now.IsZero() {
		return fmt.Errorf("%w: no time", ErrSecrets)
	}
	if err := recoverTLS(run.dir, run.options.Owner); err != nil {
		return err
	}
	pending, err := PendingRestart(run.dir)
	if err != nil {
		return err
	}
	current, err := readTrust(run.dir)
	if err != nil {
		return err
	}
	if len(pending) != 0 {
		if rollDue(current, run.options.Now) {
			run.report.Waiting = "a restart is pending"
		}
	} else {
		if err := run.rollCA(current); err != nil {
			return err
		}
		if run.report.CAStep == CAStepPromote {
			return nil
		}
		if current, err = readTrust(run.dir); err != nil {
			return err
		}
	}
	return run.renewLeaves(current)
}

func leafNames() []string {
	names := make([]string, 0, len(tlsLeaves))
	for _, leaf := range tlsLeaves {
		names = append(names, leaf.name)
	}
	return names
}

// leafDue reports a leaf with less than a third of its life left.
func leafDue(certificate *x509.Certificate, now time.Time) bool {
	lifetime := certificate.NotAfter.Sub(certificate.NotBefore)
	return !now.Before(certificate.NotAfter.Add(-lifetime / 3))
}

// renewLeaves issues again, with the signing CA, every leaf that is due,
// missing, or signed by another CA.
func (run *renewal) renewLeaves(current trust) error {
	for _, leaf := range tlsLeaves {
		exists, err := pairPresent(run.dir, leaf.name)
		if err != nil {
			return err
		}
		if exists {
			certificate, _, err := readPair(filepath.Join(run.dir, leaf.name+".crt"),
				filepath.Join(run.dir, leaf.name+".key"))
			if err != nil {
				return err
			}
			if !leafDue(certificate, run.options.Now) && certificate.CheckSignatureFrom(current.signing) == nil {
				continue
			}
		}
		if err := run.replaceLeaf(leaf, current.signing, current.key); err != nil {
			return err
		}
	}
	return nil
}

// replaceLeaf queues the leaf's service, then issues the leaf (for the
// names it has, or the configuration's when it has none) and puts it in
// place in an order a crash can always finish or undo (recoverTLS): the
// new certificate and key are written beside the pair, then the key is
// renamed in, then the certificate.
func (run *renewal) replaceLeaf(leaf tlsLeaf, ca *x509.Certificate, caKey *ecdsa.PrivateKey) error {
	if err := queueRestart(run.dir, leafService[leaf.name]); err != nil {
		return err
	}
	if err := run.options.inject("leaf:" + leaf.name); err != nil {
		return err
	}
	certificate, key, err := issueLeaf(ca, caKey, leafHostNames(run.dir, leaf, run.config), run.options.Now)
	if err != nil {
		return err
	}
	defer clear(key)
	if err := replaceSecretFile(run.dir, leaf.name+".crt.next", certificate, 0o640, run.options.Owner); err != nil {
		return err
	}
	if err := replaceSecretFile(run.dir, leaf.name+".key.next", key, 0o600, run.options.Owner); err != nil {
		return err
	}
	if err := renameSecret(run.dir, leaf.name+".key.next", leaf.name+".key"); err != nil {
		return err
	}
	if err := renameSecret(run.dir, leaf.name+".crt.next", leaf.name+".crt"); err != nil {
		return err
	}
	run.report.Renewed = append(run.report.Renewed, leaf.name)
	return nil
}

// leafHostNames are the names a renewed leaf keeps: the ones it has, so a
// configuration edited but not applied yet never reaches a running
// service. A leaf that is missing or unreadable takes the configuration's.
func leafHostNames(dir string, leaf tlsLeaf, config Config) []string {
	certificates, err := readCertificates(filepath.Join(dir, leaf.name+".crt"))
	if err != nil || len(certificates[0].DNSNames) == 0 {
		return leaf.names(config)
	}
	return slices.Clone(certificates[0].DNSNames)
}

func renameSecret(dir, from, to string) error {
	if err := os.Rename(filepath.Join(dir, from), filepath.Join(dir, to)); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSecrets, to, err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("%w: sync after %s: %w", ErrSecrets, to, err)
	}
	return nil
}

// recoverTLS finishes or undoes what a crashed run left. A leaf's new
// certificate whose key is already in place is renamed in; any other
// staged leaf file is removed (the pair in place still matches). A CA whose
// key is already the signing key finishes its promotion; a new CA without
// both files (the first step stopped before its bundle) is removed. What
// it changes in place queues the services that read it.
func recoverTLS(dir string, owner *Owner) error {
	for _, leaf := range tlsLeaves {
		if err := recoverLeaf(dir, leaf.name); err != nil {
			return err
		}
	}
	keyStaged, err := present(dir, caNextKeyFile)
	if err != nil {
		return err
	}
	certificateStaged, err := present(dir, caNextCertificateFile)
	if err != nil {
		return err
	}
	switch {
	case keyStaged && certificateStaged:
		return nil // between the roll's first and second steps
	case certificateStaged:
		// The promotion renamed the key in and stopped before the bundle.
		next, err := readCertificates(filepath.Join(dir, caNextCertificateFile))
		if err != nil {
			return err
		}
		key, err := readPrivateKey(filepath.Join(dir, caKeyFile))
		if err != nil {
			return err
		}
		if !key.PublicKey.Equal(next[0].PublicKey) {
			return removeIfPresent(dir, caNextCertificateFile)
		}
		if err := queueRestart(dir, restartOrder...); err != nil {
			return err
		}
		return finishPromotion(dir, owner)
	case keyStaged:
		return removeIfPresent(dir, caNextKeyFile)
	}
	return nil
}

func recoverLeaf(dir, name string) error {
	staged, err := present(dir, name+".crt.next")
	if err != nil {
		return err
	}
	if staged {
		certificates, err := readCertificates(filepath.Join(dir, name+".crt.next"))
		if err != nil {
			return err
		}
		key, err := readPrivateKey(filepath.Join(dir, name+".key"))
		if err == nil && key.PublicKey.Equal(certificates[0].PublicKey) {
			if err := queueRestart(dir, leafService[name]); err != nil {
				return err
			}
			return renameSecret(dir, name+".crt.next", name+".crt")
		}
	}
	if err := removeIfPresent(dir, name+".crt.next"); err != nil {
		return err
	}
	return removeIfPresent(dir, name+".key.next")
}

// rollDue reports a CA roll step that would run were no restart pending
// (for the report only).
func rollDue(current trust, now time.Time) bool {
	return len(current.bundle) > 1 || current.signing.NotAfter.Sub(now) < caRollBefore
}

// rollCA takes the CA roll's next step when it is due:
//
//  1. trust-next: a new CA is made and joins the bundle; every service
//     that reads ca.crt restarts and trusts both.
//  2. promote (a day later): the new CA signs every leaf and becomes the
//     signing CA; ca.crt still holds the old one; everything restarts.
//  3. drop-old (a day later, every leaf signed by the new CA): the old CA
//     leaves the bundle; the readers restart.
func (run *renewal) rollCA(current trust) error {
	staged, err := present(run.dir, caNextKeyFile)
	if err != nil {
		return err
	}
	now := run.options.Now
	switch {
	case staged:
		next, nextKey, err := readNextCA(run.dir)
		if err != nil {
			return err
		}
		if !current.contains(next) {
			// The first step stopped before it wrote the bundle.
			return run.step(CAStepTrustNext, trustReaders, func() error {
				return writeBundle(run.dir, append(slices.Clone(current.bundle), next), run.options.Owner)
			})
		}
		if next.NotBefore.Add(time.Hour + caRollStepWait).After(now) {
			run.report.Waiting = "the new CA is trusted since less than a day"
			return nil
		}
		return run.step(CAStepPromote, restartOrder, func() error { return run.promote(next, nextKey) })
	case len(current.bundle) > 1:
		waiting, err := oldCAInUse(run.dir, current, now)
		if err != nil || waiting != "" {
			run.report.Waiting = waiting
			return err
		}
		return run.step(CAStepDropOld, trustReaders, func() error {
			return writeBundle(run.dir, []*x509.Certificate{current.signing}, run.options.Owner)
		})
	case current.signing.NotAfter.Sub(now) < caRollBefore:
		return run.step(CAStepTrustNext, trustReaders, func() error { return run.trustNewCA(current) })
	}
	return nil
}

// step queues the services a roll step changes files for, then takes it.
func (run *renewal) step(name string, services []string, take func() error) error {
	if err := queueRestart(run.dir, services...); err != nil {
		return err
	}
	run.report.CAStep = name
	return take()
}

func readNextCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certificates, err := readCertificates(filepath.Join(dir, caNextCertificateFile))
	if err != nil {
		return nil, nil, err
	}
	key, err := readPrivateKey(filepath.Join(dir, caNextKeyFile))
	if err != nil {
		return nil, nil, err
	}
	if len(certificates) != 1 || !certificates[0].IsCA || !key.PublicKey.Equal(certificates[0].PublicKey) {
		return nil, nil, fmt.Errorf("%w: ca-next.key and ca-next.crt are not one CA", ErrSecrets)
	}
	return certificates[0], key, nil
}

// trustNewCA is the roll's first step: the key, then the certificate, then
// the bundle that trusts it (recoverTLS undoes a run that stopped earlier).
func (run *renewal) trustNewCA(current trust) error {
	certificate, keyPEM, err := newCA(run.options.Now)
	if err != nil {
		return err
	}
	defer clear(keyPEM)
	if err := replaceSecretFile(run.dir, caNextKeyFile, keyPEM, 0o600, run.options.Owner); err != nil {
		return err
	}
	if err := replaceSecretFile(run.dir, caNextCertificateFile, encodeCertificates([]*x509.Certificate{certificate}),
		0o640, run.options.Owner); err != nil {
		return err
	}
	return writeBundle(run.dir, append(slices.Clone(current.bundle), certificate), run.options.Owner)
}

// promote is the roll's second step: every leaf is issued by the new CA
// (both CAs are trusted, so either leaf works meanwhile), then the new key
// becomes ca.key and the bundle lists the new CA first.
func (run *renewal) promote(next *x509.Certificate, nextKey *ecdsa.PrivateKey) error {
	for _, leaf := range tlsLeaves {
		if err := run.replaceLeaf(leaf, next, nextKey); err != nil {
			return err
		}
	}
	if err := renameSecret(run.dir, caNextKeyFile, caKeyFile); err != nil {
		return err
	}
	if err := run.options.inject("promote:key"); err != nil {
		return err
	}
	return finishPromotion(run.dir, run.options.Owner)
}

// finishPromotion orders the bundle with the new signing CA first, keeps
// the old CA after it, and removes ca-next.crt.
func finishPromotion(dir string, owner *Owner) error {
	current, err := readTrust(dir)
	if err != nil {
		return err
	}
	bundle := []*x509.Certificate{current.signing}
	for _, certificate := range current.bundle {
		if !certificate.Equal(current.signing) {
			bundle = append(bundle, certificate)
		}
	}
	if err := writeBundle(dir, bundle, owner); err != nil {
		return err
	}
	return removeIfPresent(dir, caNextCertificateFile)
}

// oldCAInUse returns why the roll's last step must wait, or "" when it may
// run: every leaf is signed by the signing CA, and the newest of them is a
// day old. A missing or broken leaf waits for renewLeaves to issue it.
func oldCAInUse(dir string, current trust, now time.Time) (string, error) {
	for _, leaf := range tlsLeaves {
		exists, err := pairPresent(dir, leaf.name)
		if err != nil || !exists {
			return "a leaf is missing", err
		}
		certificate, _, err := readPair(filepath.Join(dir, leaf.name+".crt"), filepath.Join(dir, leaf.name+".key"))
		if err != nil {
			return "", err
		}
		if certificate.CheckSignatureFrom(current.signing) != nil {
			return "a leaf is still signed by the old CA", nil
		}
		if certificate.NotBefore.Add(time.Hour + caRollStepWait).After(now) {
			return "the leaves of the new CA are less than a day old", nil
		}
	}
	return "", nil
}

func writeBundle(dir string, bundle []*x509.Certificate, owner *Owner) error {
	return replaceSecretFile(dir, caCertificateFile, encodeCertificates(bundle), 0o640, owner)
}

// newCA makes a CA certificate and its key (PKCS#8 PEM).
func newCA(now time.Time) (*x509.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: CA key: %w", ErrSecrets, err)
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber(), Subject: pkix.Name{CommonName: "MeshTransit self-host CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: CA certificate: %w", ErrSecrets, err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: CA certificate: %w", ErrSecrets, err)
	}
	keyPEM, err := privateKeyPEM(key)
	if err != nil {
		return nil, nil, err
	}
	return certificate, keyPEM, nil
}

// readRestart reads the restart file in dir: service names, one line, each
// one of restartOrder.
func readRestart(dir string) ([]string, error) {
	exists, err := present(dir, RestartFile)
	if err != nil || !exists {
		return nil, err
	}
	contents, err := readRegularFile(filepath.Join(dir, RestartFile), 4096)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", ErrSecrets, RestartFile, err)
	}
	services := strings.Fields(string(contents))
	for _, service := range services {
		if !slices.Contains(restartOrder, service) {
			return nil, fmt.Errorf("%w: %s names an unknown service", ErrSecrets, RestartFile)
		}
	}
	return services, nil
}

// queueRestart adds services to the restart file beside secretsDir (root's,
// read by the host), keeping restart order and any name already there.
func queueRestart(secretsDir string, services ...string) error {
	dir := restartDir(secretsDir)
	pending, err := readRestart(dir)
	if err != nil {
		return err
	}
	all := make([]string, 0, len(restartOrder))
	for _, service := range restartOrder {
		if slices.Contains(pending, service) || slices.Contains(services, service) {
			all = append(all, service)
		}
	}
	if slices.Equal(all, pending) {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSecrets, RenewDir, err)
	}
	return replaceSecretFile(dir, RestartFile, []byte(strings.Join(all, " ")), 0o600, nil)
}
