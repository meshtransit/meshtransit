package selfhost

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// The CA files. ca.crt is the trust bundle every service reads: the
// signing CA, and during a CA roll (renew.go) the other CA too. ca.key is
// the signing CA's key. ca-next.key and ca-next.crt hold a new CA between
// the roll's first and second steps.
const (
	caCertificateFile     = "ca.crt"
	caKeyFile             = "ca.key"
	caNextCertificateFile = "ca-next.crt"
	caNextKeyFile         = "ca-next.key"
	maxPEMFile            = 64 * 1024
)

// trust is the CA state: the CA that signs (its certificate is in the
// bundle, matching ca.key) and every CA the bundle trusts.
type trust struct {
	signing *x509.Certificate
	key     *ecdsa.PrivateKey
	bundle  []*x509.Certificate
}

// readTrust reads ca.crt and ca.key. The signing CA is the bundle's
// certificate that matches the key, wherever it stands: a roll interrupted
// between writing the key and the bundle still has one.
func readTrust(dir string) (trust, error) {
	bundle, err := readCertificates(filepath.Join(dir, caCertificateFile))
	if err != nil {
		return trust{}, err
	}
	key, err := readPrivateKey(filepath.Join(dir, caKeyFile))
	if err != nil {
		return trust{}, err
	}
	for _, certificate := range bundle {
		if !certificate.IsCA {
			return trust{}, fmt.Errorf("%w: ca.crt holds a certificate that is not a CA", ErrSecrets)
		}
	}
	for _, certificate := range bundle {
		if key.PublicKey.Equal(certificate.PublicKey) {
			return trust{signing: certificate, key: key, bundle: bundle}, nil
		}
	}
	return trust{}, fmt.Errorf("%w: ca.key matches no certificate in ca.crt", ErrSecrets)
}

// trusts reports whether a CA of the bundle signed certificate.
func (current trust) trusts(certificate *x509.Certificate) bool {
	for _, ca := range current.bundle {
		if certificate.CheckSignatureFrom(ca) == nil {
			return true
		}
	}
	return false
}

// contains reports whether the bundle holds ca.
func (current trust) contains(ca *x509.Certificate) bool {
	for _, certificate := range current.bundle {
		if certificate.Equal(ca) {
			return true
		}
	}
	return false
}

// readCertificates reads every certificate of a PEM file; a file without
// one, or with another kind of block, is refused.
func readCertificates(path string) ([]*x509.Certificate, error) {
	name := filepath.Base(path)
	contents, err := readRegularFile(path, maxPEMFile)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", ErrSecrets, name, err)
	}
	var certificates []*x509.Certificate
	for rest := contents; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: %s holds a %s block", ErrSecrets, name, block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %s does not parse", ErrSecrets, name)
		}
		certificates = append(certificates, certificate)
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("%w: %s is not PEM", ErrSecrets, name)
	}
	return certificates, nil
}

func readPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	name := filepath.Base(path)
	contents, err := readRegularFile(path, maxPEMFile)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", ErrSecrets, name, err)
	}
	defer clear(contents)
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, fmt.Errorf("%w: %s is not PEM", ErrSecrets, name)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	clear(block.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok {
		return nil, fmt.Errorf("%w: %s is not an ECDSA key", ErrSecrets, name)
	}
	return key, nil
}

func encodeCertificates(certificates []*x509.Certificate) []byte {
	var contents []byte
	for _, certificate := range certificates {
		contents = append(contents, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
	}
	return contents
}

// replaceSecretFile writes name atomically (a temporary file renamed over it):
// a reader sees the old or the new contents, never a mix. A link at name
// is replaced, never followed.
func replaceSecretFile(dir, name string, contents []byte, mode fs.FileMode, owner *Owner) error {
	temporary, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSecrets, name, err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := writeAndSync(temporary, contents, mode, owner); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSecrets, name, err)
	}
	if err := os.Rename(temporaryName, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSecrets, name, err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("%w: sync after %s: %w", ErrSecrets, name, err)
	}
	return nil
}

// removeIfPresent removes name; an absent file is not an error.
func removeIfPresent(dir, name string) error {
	if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: remove %s: %w", ErrSecrets, name, err)
	}
	return nil
}

// present reports whether name exists (a link counts: it is never followed,
// and readers refuse it).
func present(dir, name string) (bool, error) {
	_, err := os.Lstat(filepath.Join(dir, name))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("%w: %s: %w", ErrSecrets, name, err)
	}
}
