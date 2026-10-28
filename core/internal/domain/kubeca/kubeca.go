// Package kubeca issues the TLS certificates of Kubernetes gateway replicas
// under one name-constrained CA per cluster (K1a4, ADR-053): ECDSA P-256
// certificates, and the AES-256-GCM envelope that keeps a CA's private key
// at rest.
package kubeca

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"time"
)

var (
	// ErrInvalid reports a CA, request or envelope this package cannot
	// stand behind.
	ErrInvalid = errors.New("kubeca: invalid")
	// ErrMisconfigured reports a custody whose key is missing, disabled or
	// not usable by this Core: an operator must act.
	ErrMisconfigured = errors.New("kubeca: custody misconfigured")
	// ErrUnavailable reports a custody that could not answer now (a KMS
	// call failed): try again later.
	ErrUnavailable = errors.New("kubeca: custody unavailable")
)

// Bounds of a CA's and a replica certificate's life (K1a4 §14.1, §15.9).
const (
	MinimumCALifetime          = 365 * 24 * time.Hour
	MaximumCALifetime          = 5 * 365 * 24 * time.Hour
	MinimumCertificateLifetime = time.Hour
	MaximumCertificateLifetime = 72 * time.Hour
	// MaximumCSRSize bounds a replica's CSR.
	MaximumCSRSize = 4 << 10
	// backdate lets a certificate hold on a peer whose clock is a few
	// minutes behind.
	backdate             = 5 * time.Minute
	maximumSubjectLength = 64
	maximumDNSName       = 253
	maximumDNSLabel      = 63
)

// CAParams describes a cluster's CA: the one DNS name it may sign for, its
// subject, and when it begins and for how long it lasts.
type CAParams struct {
	ClusterDNSName string
	Subject        string
	NotBefore      time.Time
	Lifetime       time.Duration
}

// CA is a cluster's CA with its private key. Certificate is read-only.
type CA struct {
	certificate *x509.Certificate
	privateKey  *ecdsa.PrivateKey
	fingerprint [sha256.Size]byte
}

// NewCA generates a CA that may sign only for params.ClusterDNSName and
// no IP address, with no CA below it.
func NewCA(params CAParams) (CA, error) {
	if !ValidDNSName(params.ClusterDNSName) || params.Subject == "" || len(params.Subject) > maximumSubjectLength ||
		params.NotBefore.IsZero() || params.Lifetime < MinimumCALifetime || params.Lifetime > MaximumCALifetime {
		return CA{}, ErrInvalid
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return CA{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return CA{}, err
	}
	template := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: params.Subject},
		NotBefore:                   params.NotBefore.Add(-backdate).UTC(),
		NotAfter:                    params.NotBefore.Add(params.Lifetime).UTC(),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{params.ClusterDNSName},
		ExcludedIPRanges: []*net.IPNet{
			{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return CA{}, err
	}
	return newCA(der, key)
}

// ParseCA rebuilds a CA from its certificate and its PKCS #8 private key,
// which must belong together. The certificate must be one NewCA could have
// made: self-signed, constrained to one valid DNS name and no IP, with no CA
// below it; a rewritten certificate row cannot widen what the key signs.
func ParseCA(certificateDER, privateKeyDER []byte) (CA, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(privateKeyDER)
	if err != nil {
		return CA{}, ErrInvalid
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return CA{}, ErrInvalid
	}
	return newCA(certificateDER, key)
}

func newCA(certificateDER []byte, key *ecdsa.PrivateKey) (CA, error) {
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil || !constrainedCA(certificate) || key.Curve != elliptic.P256() ||
		!key.PublicKey.Equal(certificate.PublicKey) || certificate.CheckSignatureFrom(certificate) != nil {
		return CA{}, ErrInvalid
	}
	return CA{certificate: certificate, privateKey: key, fingerprint: sha256.Sum256(certificate.Raw)}, nil
}

// constrainedCA reports a certificate with every constraint NewCA sets.
func constrainedCA(certificate *x509.Certificate) bool {
	return certificate.IsCA && certificate.BasicConstraintsValid && certificate.MaxPathLen == 0 &&
		certificate.MaxPathLenZero && certificate.KeyUsage == x509.KeyUsageCertSign|x509.KeyUsageCRLSign &&
		certificate.PermittedDNSDomainsCritical && len(certificate.PermittedDNSDomains) == 1 &&
		ValidDNSName(certificate.PermittedDNSDomains[0]) && len(certificate.PermittedIPRanges) == 0 &&
		len(certificate.ExcludedIPRanges) == 2 && excludesEveryAddress(certificate.ExcludedIPRanges) &&
		len(certificate.ExcludedDNSDomains) == 0 && len(certificate.PermittedEmailAddresses) == 0 &&
		len(certificate.PermittedURIDomains) == 0
}

func excludesEveryAddress(ranges []*net.IPNet) bool {
	v4, v6 := false, false
	for _, excluded := range ranges {
		ones, bits := excluded.Mask.Size()
		v4 = v4 || ones == 0 && bits == 32
		v6 = v6 || ones == 0 && bits == 128
	}
	return v4 && v6
}

// Certificate returns the CA's certificate; callers must not change it.
func (ca CA) Certificate() *x509.Certificate { return ca.certificate }

// Fingerprint returns the SHA-256 of the CA certificate's DER.
func (ca CA) Fingerprint() [sha256.Size]byte { return ca.fingerprint }

// MarshalPrivateKey returns the CA's private key as PKCS #8, to be sealed.
func (ca CA) MarshalPrivateKey() ([]byte, error) {
	if ca.privateKey == nil {
		return nil, ErrInvalid
	}
	return x509.MarshalPKCS8PrivateKey(ca.privateKey)
}

// ReplicaRequest asks for a replica's certificate: a CSR, whose public key
// alone is used, for the cluster's name, at Now, for Lifetime.
type ReplicaRequest struct {
	CSR            []byte
	ClusterDNSName string
	Now            time.Time
	Lifetime       time.Duration
}

// Issued is a signed replica certificate.
type Issued struct {
	Certificate     []byte
	Serial          *big.Int
	PublicKeySHA256 [sha256.Size]byte
	NotBefore       time.Time
	NotAfter        time.Time
}

// SignReplica signs a replica's certificate: a P-256 key whose CSR proves
// possession, for exactly the CA's cluster name, server authentication only,
// a random 126-bit serial, ending no later than the CA (K1a4-I2, I3). A CA
// with less than the minimum lifetime left signs nothing.
func (ca CA) SignReplica(request ReplicaRequest) (Issued, error) {
	certificate := ca.certificate
	if certificate == nil || ca.privateKey == nil || request.Now.IsZero() || len(request.CSR) > MaximumCSRSize ||
		request.Lifetime < MinimumCertificateLifetime || request.Lifetime > MaximumCertificateLifetime ||
		request.ClusterDNSName != certificate.PermittedDNSDomains[0] || request.Now.Before(certificate.NotBefore) ||
		certificate.NotAfter.Sub(request.Now) < MinimumCertificateLifetime {
		return Issued{}, ErrInvalid
	}
	csr, err := x509.ParseCertificateRequest(request.CSR)
	if err != nil || csr.CheckSignature() != nil || csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return Issued{}, ErrInvalid
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return Issued{}, ErrInvalid
	}
	spki, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return Issued{}, ErrInvalid
	}
	serial, err := randomSerial()
	if err != nil {
		return Issued{}, err
	}
	notBefore := request.Now.Add(-backdate).UTC()
	notAfter := request.Now.Add(request.Lifetime).UTC()
	if notAfter.After(certificate.NotAfter) {
		notAfter = certificate.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		DNSNames:              []string{request.ClusterDNSName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, certificate, key, ca.privateKey)
	if err != nil {
		return Issued{}, err
	}
	return Issued{Certificate: der, Serial: serial, PublicKeySHA256: sha256.Sum256(spki),
		NotBefore: notBefore, NotAfter: notAfter}, nil
}

// randomSerial is a positive serial of 126 random bits below a set top bit
// (127 bits), so every serial has the same length.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 126)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	return serial.Or(serial, limit), nil
}

// ValidDNSName reports a lowercase DNS name without a trailing dot: labels
// of letters, digits and inner hyphens, at most 253 bytes.
func ValidDNSName(name string) bool {
	if name == "" || len(name) > maximumDNSName {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > maximumDNSLabel || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range len(label) {
			character := label[index]
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

// DataKey is a 256-bit key that seals CA private keys (one per Network).
// It never formats or logs its bytes.
type DataKey [32]byte

// IsZero reports an all-zero key, never a usable one.
func (key DataKey) IsZero() bool { return key == DataKey{} }

// String redacts the key.
func (DataKey) String() string { return "[REDACTED]" }

// GoString redacts the key.
func (DataKey) GoString() string { return "kubeca.DataKey([REDACTED])" }

// Format redacts the key under every verb.
func (DataKey) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte("[REDACTED]")) }

// LogValue redacts the key in structured logs.
func (DataKey) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

const (
	aadDomain = "meshtransit kube ca v1"
	nonceSize = 12
)

// CAKeyAAD is the associated data that binds a sealed CA private key to its
// deployment, cluster, CA and certificate: each part length-prefixed, so no
// two different tuples encode alike, and the key opens only beside its own
// certificate.
func CAKeyAAD(deployment, cluster, ca string, fingerprint [sha256.Size]byte) string {
	return encodeAAD(aadDomain, deployment, cluster, ca, string(fingerprint[:]))
}

// encodeAAD joins a domain and parts, each part prefixed by its 32-bit
// length.
func encodeAAD(domain string, parts ...string) string {
	var builder strings.Builder
	builder.WriteString(domain)
	for _, part := range parts {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(part))) //nolint:gosec // G115: a string's length fits 32 bits here
		builder.Write(length[:])
		builder.WriteString(part)
	}
	return builder.String()
}

// SealCA seals ca's private key under dataKey for its deployment, cluster
// and CA ID, bound to the certificate it belongs to.
func SealCA(dataKey DataKey, ca CA, deployment, cluster, caID string) ([]byte, error) {
	key, err := ca.MarshalPrivateKey()
	if err != nil {
		return nil, err
	}
	return Seal(dataKey, CAKeyAAD(deployment, cluster, caID, ca.Fingerprint()), key)
}

// OpenCA opens a sealed CA private key beside its stored certificate and
// rebuilds the CA. The fingerprint comes from certificateDER itself, never
// from a stored column, so a rewritten certificate does not open the key.
func OpenCA(dataKey DataKey, certificateDER, sealed []byte, deployment, cluster, caID string) (CA, error) {
	key, err := Open(dataKey, CAKeyAAD(deployment, cluster, caID, sha256.Sum256(certificateDER)), sealed)
	if err != nil {
		return CA{}, err
	}
	return ParseCA(certificateDER, key)
}

// DataKeyAAD is the associated data that binds a wrapped data key to its
// Network.
func DataKeyAAD(network string) string { return encodeAAD("meshtransit kube data key v1", network) }

// Seal encrypts plaintext with AES-256-GCM under key, bound to aad: a
// random 96-bit nonce followed by the ciphertext and tag.
func Seal(key DataKey, aad string, plaintext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize, nonceSize+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, []byte(aad)), nil
}

// Open decrypts what Seal made with the same key and aad.
func Open(key DataKey, aad string, sealed []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < nonceSize+aead.Overhead() {
		return nil, ErrInvalid
	}
	plaintext, err := aead.Open(nil, sealed[:nonceSize], sealed[nonceSize:], []byte(aad))
	if err != nil {
		return nil, ErrInvalid
	}
	return plaintext, nil
}

func newAEAD(key DataKey) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// WrappedKey is a data key as a custody wrapped it: which custody (file or
// kms), which of its keys, and the ciphertext.
type WrappedKey struct {
	Custody    string
	KeyID      string
	Ciphertext []byte
}

// Custody keeps the key that wraps data keys (K1a4 §15.2): a key in a file
// or a key in a KMS. Only the worker holds one. Each data key belongs to
// one Network (its public ID), bound into the wrapping, so a wrapped key
// moved to another Network does not open.
type Custody interface {
	// NewDataKey returns a fresh data key for network and its wrapped form.
	NewDataKey(ctx context.Context, network string) (DataKey, WrappedKey, error)
	// OpenDataKey unwraps network's data key, with the custody's current key
	// or one it still keeps for opening.
	OpenDataKey(ctx context.Context, network string, wrapped WrappedKey) (DataKey, error)
}
