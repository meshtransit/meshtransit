package selfhost

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// internalDomain names the listeners only the server's own proxy reaches.
const internalDomain = "meshtransit.internal"

type tlsLeaf struct {
	name  string
	names func(Config) []string
}

func fixedNames(names ...string) func(Config) []string {
	return func(Config) []string { return names }
}

// tlsLeaves are the TLS listeners on the server's private network, all
// issued by the self-host CA. The identity broker's certificate names only
// the issuer's host (configuration.md "Identity broker").
var tlsLeaves = []tlsLeaf{
	{name: "postgres", names: fixedNames("postgres." + internalDomain)},
	{name: "redis", names: fixedNames("redis." + internalDomain)},
	{name: "api", names: fixedNames("api." + internalDomain)},
	{name: "control", names: fixedNames("control." + internalDomain)},
	{name: "login", names: fixedNames("login." + internalDomain)},
	{name: "identity", names: func(config Config) []string { return []string{config.IdentityHost()} }},
}

const (
	caLifetime   = 10 * 365 * 24 * time.Hour
	leafLifetime = 2 * 365 * 24 * time.Hour
)

// generateTLS makes the CA and every leaf dir lacks. A leaf of an existing
// CA is issued by that CA; a missing CA with existing leaves is refused, so
// the leaves are never left signed by a key setup no longer has. A key and
// its certificate are one pair: half a pair (an interrupted run) is refused,
// and an existing pair must match. Callers hold LockSetup.
func generateTLS(config Config, dir string, options GenerateOptions, record func(string, bool)) error {
	caCertificate, caKey, created, err := loadOrCreateCA(dir, options)
	if err != nil {
		return err
	}
	record("ca.crt", created)
	record("ca.key", created)
	for _, leaf := range tlsLeaves {
		present, err := pairPresent(dir, leaf.name)
		if err != nil {
			return err
		}
		if present {
			if err := verifyLeaf(dir, leaf.name, caCertificate); err != nil {
				return err
			}
			record(leaf.name+".crt", false)
			record(leaf.name+".key", false)
			continue
		}
		certificate, key, err := issueLeaf(caCertificate, caKey, leaf.names(config), options.Now)
		if err != nil {
			return err
		}
		keyCreated, err := writeIfAbsent(dir, leaf.name+".key", key, 0o600, options.Owner)
		clear(key)
		if err != nil {
			return err
		}
		certificateCreated, err := writeIfAbsent(dir, leaf.name+".crt", certificate, 0o644, options.Owner)
		if err != nil {
			return err
		}
		if !keyCreated || !certificateCreated {
			return fmt.Errorf("%w: %s appeared while setup wrote it", ErrSecrets, leaf.name)
		}
		record(leaf.name+".key", true)
		record(leaf.name+".crt", true)
	}
	return nil
}

func loadOrCreateCA(dir string, options GenerateOptions) (*x509.Certificate, *ecdsa.PrivateKey, bool, error) {
	certificatePath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	_, certificateErr := os.Lstat(certificatePath)
	_, keyErr := os.Lstat(keyPath)
	switch {
	case certificateErr == nil && keyErr == nil:
		certificate, key, err := readCA(certificatePath, keyPath)
		return certificate, key, false, err
	case !errors.Is(certificateErr, fs.ErrNotExist) || !errors.Is(keyErr, fs.ErrNotExist):
		return nil, nil, false, fmt.Errorf("%w: ca.crt and ca.key must both exist or both be absent", ErrSecrets)
	}
	for _, leaf := range tlsLeaves {
		if _, err := os.Lstat(filepath.Join(dir, leaf.name+".crt")); err == nil {
			return nil, nil, false, fmt.Errorf("%w: certificates exist without their CA", ErrSecrets)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: CA key: %w", ErrSecrets, err)
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber(), Subject: pkix.Name{CommonName: "MeshTransit self-host CA"},
		NotBefore: options.Now.Add(-time.Hour), NotAfter: options.Now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: CA certificate: %w", ErrSecrets, err)
	}
	keyPEM, err := privateKeyPEM(key)
	if err != nil {
		return nil, nil, false, err
	}
	defer clear(keyPEM)
	keyCreated, err := writeIfAbsent(dir, "ca.key", keyPEM, 0o600, options.Owner)
	if err != nil {
		return nil, nil, false, err
	}
	certificateCreated, err := writeIfAbsent(dir, "ca.crt",
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644, options.Owner)
	if err != nil {
		return nil, nil, false, err
	}
	if !keyCreated || !certificateCreated {
		return nil, nil, false, fmt.Errorf("%w: the CA appeared while setup wrote it", ErrSecrets)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: CA certificate: %w", ErrSecrets, err)
	}
	return certificate, key, true, nil
}

func readCA(certificatePath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certificate, key, err := readPair(certificatePath, keyPath)
	if err != nil {
		return nil, nil, err
	}
	if !certificate.IsCA {
		return nil, nil, fmt.Errorf("%w: ca.crt is not a CA", ErrSecrets)
	}
	return certificate, key, nil
}

// readPair reads a certificate and its key (never through a link) and
// checks that they belong together.
func readPair(certificatePath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	name := filepath.Base(certificatePath)
	certificatePEM, err := readRegularFile(certificatePath, 64*1024)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read %s: %w", ErrSecrets, name, err)
	}
	keyPEM, err := readRegularFile(keyPath, 64*1024)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read %s: %w", ErrSecrets, filepath.Base(keyPath), err)
	}
	defer clear(keyPEM)
	certificateBlock, _ := pem.Decode(certificatePEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certificateBlock == nil || keyBlock == nil {
		return nil, nil, fmt.Errorf("%w: %s is not PEM", ErrSecrets, name)
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s does not parse", ErrSecrets, name)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || !key.PublicKey.Equal(certificate.PublicKey) {
		return nil, nil, fmt.Errorf("%w: the key of %s does not match it", ErrSecrets, name)
	}
	return certificate, key, nil
}

// pairPresent reports whether name's key and certificate both exist, and
// refuses half a pair.
func pairPresent(dir, name string) (bool, error) {
	_, keyErr := os.Lstat(filepath.Join(dir, name+".key"))
	_, certificateErr := os.Lstat(filepath.Join(dir, name+".crt"))
	switch {
	case keyErr == nil && certificateErr == nil:
		return true, nil
	case errors.Is(keyErr, fs.ErrNotExist) && errors.Is(certificateErr, fs.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("%w: %s.key and %s.crt must both exist or both be absent; remove both to issue them again",
			ErrSecrets, name, name)
	}
}

// verifyLeaf checks an existing leaf: its key matches it and the current CA
// signed it (a replaced CA leaves no leaf of the old one in use).
func verifyLeaf(dir, name string, ca *x509.Certificate) error {
	certificate, _, err := readPair(filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key"))
	if err != nil {
		return err
	}
	if err := certificate.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("%w: %s.crt is not signed by ca.crt; remove %s.key and %s.crt to issue them again",
			ErrSecrets, name, name, name)
	}
	return nil
}

func issueLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, names []string, now time.Time) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: leaf key: %w", ErrSecrets, err)
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber(), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(leafLifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: leaf certificate: %w", ErrSecrets, err)
	}
	keyPEM, err := privateKeyPEM(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM, nil
}

func privateKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: encode key: %w", ErrSecrets, err)
	}
	defer clear(der)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func serialNumber() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		// crypto/rand does not fail on supported platforms (Go 1.24+).
		panic(err)
	}
	return serial
}
