package kubecert

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
)

// storeFile is the certificate's file in Options.StoreDir.
const storeFile = "certificate.json"

// storeVersion is the file's form.
const storeVersion = 1

// stored is the certificate as its file holds it: the key, the chain and
// what its schedule needs, its times on the wall clock, so a restarted
// container takes it back without asking Core (K1b design §3, Q52).
type stored struct {
	Version         int       `json:"version"`
	Key             []byte    `json:"key"` // PKCS #8
	Certificate     []byte    `json:"certificate"`
	Chain           [][]byte  `json:"chain"`
	Root            []byte    `json:"root"`
	Issuer          []byte    `json:"issuer"`
	RenewAt         time.Time `json:"renew_at"`
	NetworkRevision uint64    `json:"network_revision"`
	IssuedAt        time.Time `json:"issued_at"`
}

// save writes the certificate to the store, replacing the file whole; a
// failure costs only a new certificate after a restart, so it is logged.
func (manager *Manager) save(ctx context.Context, cert Certificate) {
	dir := manager.options.StoreDir
	if dir == "" {
		return
	}
	if err := writeStored(dir, cert); err != nil {
		manager.options.Logger.WarnContext(ctx, "kubernetes gateway certificate not saved", "error_code",
			"kubernetes_certificate_save_failed", "error", err)
		// An older one left there would come back after a restart, a serial
		// Core replaced (review b7a M2): none is better.
		manager.forget()
	}
}

func writeStored(dir string, cert Certificate) error {
	key, err := x509.MarshalPKCS8PrivateKey(cert.Key)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(stored{
		Version: storeVersion, Key: key, Certificate: cert.DER, Chain: cert.Chain, Root: cert.Root[:],
		Issuer: cert.Issuer[:], RenewAt: cert.RenewAt.Round(0), NetworkRevision: cert.NetworkRevision,
		IssuedAt: cert.IssuedAt.Round(0),
	})
	clear(key)
	if err != nil {
		return err
	}
	defer clear(payload)
	file, err := os.CreateTemp(dir, ".certificate-*")
	if err != nil {
		return err
	}
	written := false
	defer func() {
		if !written {
			_ = os.Remove(file.Name())
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), filepath.Join(dir, storeFile)); err != nil {
		return err
	}
	written = true
	return nil
}

// forget removes the store's certificate, once the manager no longer
// holds it.
func (manager *Manager) forget() {
	if manager.options.StoreDir == "" {
		return
	}
	if err := os.Remove(filepath.Join(manager.options.StoreDir, storeFile)); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		manager.options.Logger.Warn("kubernetes gateway certificate file not removed", "error", err)
	}
}

// restore takes back the certificate a previous container saved, when it
// still checks as an issued one would: the key is the leaf's, the issuer
// named signs it, it serves TLS (§10 M6). Its time is not judged here: the
// clock may still be this host's, not Core's; Current and validCurrent judge
// it with Core's once there (review b7a M3). The map is checked once it
// comes (restoredMap). A file that does not check is removed and the
// gateway asks Core again. It runs once, before anything was issued.
func (manager *Manager) restore(ctx context.Context) {
	dir := manager.options.StoreDir
	if dir == "" || manager.mapSeen || manager.current != nil {
		return
	}
	removeLeftovers(dir)
	cert, err := readStored(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return
	case err != nil:
		manager.countKey(outcomeKey{"restore_refused", ""})
		manager.options.Logger.WarnContext(ctx, "kubernetes gateway certificate not restored", "error_code",
			"kubernetes_certificate_restore_refused", "error", err)
		manager.forget()
		return
	}
	manager.countKey(outcomeKey{"restored", ""})
	manager.mu.Lock()
	manager.current = &cert
	manager.mu.Unlock()
	manager.restored = true
	// Its schedule is dueAt's, from the stored issue time, once step runs.
	manager.options.Logger.InfoContext(ctx, "kubernetes gateway certificate restored",
		"not_after", cert.NotAfter.UTC())
}

// removeLeftovers removes temporary files a write cut short left, keys
// among them (review b7a L1).
func removeLeftovers(dir string) {
	matches, _ := filepath.Glob(filepath.Join(dir, ".certificate-*"))
	for _, match := range matches {
		_ = os.Remove(match)
	}
}

// maximumStored bounds the file read (review b7a L3).
const maximumStored = 64 << 10

func readStored(dir string) (Certificate, error) {
	// A regular file, not a link, and the one opened is that file: checked
	// through the descriptor, portably (re-review b7a N3, H1).
	path := filepath.Join(dir, storeFile)
	named, err := os.Lstat(path)
	if err != nil {
		return Certificate{}, err
	}
	file, err := os.Open(path) //nolint:gosec // the gateway's own store
	if err != nil {
		return Certificate{}, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return Certificate{}, err
	}
	if !named.Mode().IsRegular() || !os.SameFile(named, info) || info.Size() > maximumStored {
		return Certificate{}, errors.New("kubecert: the stored certificate is not a small regular file")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximumStored+1))
	if err != nil {
		return Certificate{}, err
	}
	defer clear(payload)
	var held stored
	if err := json.Unmarshal(payload, &held); err != nil {
		return Certificate{}, fmt.Errorf("kubecert: reading the stored certificate: %w", err)
	}
	defer clear(held.Key)
	if held.Version != storeVersion {
		return Certificate{}, fmt.Errorf("kubecert: a stored certificate of form %d", held.Version)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(held.Key)
	if err != nil {
		return Certificate{}, fmt.Errorf("kubecert: the stored key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return Certificate{}, errors.New("kubecert: the stored key is not ECDSA")
	}
	leaf, err := x509.ParseCertificate(held.Certificate)
	if err != nil {
		return Certificate{}, fmt.Errorf("kubecert: the stored certificate: %w", err)
	}
	// The same checks as an issued certificate, without a map yet, at a
	// time its validity holds: the time is judged later (M3).
	cert, err := verify(controlplane.KubeCertResult{
		Certificate: held.Certificate, Chain: held.Chain, RootFingerprint: held.Root,
		IssuerFingerprint: held.Issuer, RenewAt: held.RenewAt, NetworkRevision: held.NetworkRevision,
	}, key, nil, leaf.NotBefore)
	if err != nil {
		return Certificate{}, err
	}
	// Its schedule runs from when it was issued, which lies within its
	// validity (review b7a L3).
	if held.IssuedAt.Before(leaf.NotBefore.Add(-skew)) || !held.IssuedAt.Before(leaf.NotAfter) {
		return Certificate{}, errors.New("kubecert: the stored issue time is outside the certificate's validity")
	}
	cert.IssuedAt = held.IssuedAt
	return cert, nil
}

// restoredMap checks a restored certificate against the first map that can
// say: one whose CAs the map no longer names is kept, as an issued one is
// (Q68), and renewed soon with its own proof rather than dropped, which
// would send the gateway to its used pod token (review b7a M1). It reports
// whether to renew soon. A map that cannot say (none, or older than the
// certificate, as after a restore of Core's database) leaves it to the next.
func (manager *Manager) restoredMap(ca *networkmap.KubernetesCA) bool {
	if !manager.restored || ca == nil {
		return false
	}
	manager.mu.Lock()
	current := manager.current
	manager.mu.Unlock()
	if current == nil {
		manager.restored = false
		return false
	}
	if ca.MapRevision < current.NetworkRevision {
		return false
	}
	manager.restored = false
	// As earlyRenewal judges: only a map naming both CAs plans a renewal
	// (re-review b7a N2).
	if _, differs, _ := earlyRenewal(*current, ca, manager.options.Now()); !differs {
		return false
	}
	manager.countKey(outcomeKey{"restored_renew", "map"})
	manager.options.Logger.Info("restored kubernetes gateway certificate is not of the map's CAs; renewing soon")
	return true
}
