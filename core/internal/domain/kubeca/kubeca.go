// Package kubeca issues the TLS certificates of Kubernetes gateway replicas
// under two name-constrained tiers per cluster (K1a4 §17.2, ADR-053): a
// long-lived root that clients trust and that signs only intermediates, and
// short-lived intermediates that sign replicas. ECDSA P-256 certificates,
// and the AES-256-GCM envelope that keeps a CA's private key at rest.
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

// Bounds of each tier's life and of a replica certificate (K1a4 §17.2,
// Q27).
const (
	MinimumRootLifetime         = 5 * 365 * 24 * time.Hour
	MaximumRootLifetime         = 15 * 365 * 24 * time.Hour
	DefaultRootLifetime         = 10 * 365 * 24 * time.Hour
	MinimumIntermediateLifetime = 7 * 24 * time.Hour
	MaximumIntermediateLifetime = 90 * 24 * time.Hour
	DefaultIntermediateLifetime = 30 * 24 * time.Hour
	// ReplicaLifetime is the life of every replica certificate in v1.
	ReplicaLifetime = 24 * time.Hour
	// MinimumSigningLife is the life an intermediate must have left to sign.
	MinimumSigningLife = time.Hour
	// MaximumCSRSize bounds a replica's CSR.
	MaximumCSRSize = 4 << 10
	// caBackdate and replicaBackdate let a certificate hold on a peer whose
	// clock is behind (§17.3).
	caBackdate           = 24 * time.Hour
	replicaBackdate      = time.Hour
	maximumSubjectLength = 64
	maximumDNSName       = 253
	maximumDNSLabel      = 63
)

// Kind is a CA's tier.
type Kind uint8

const (
	// KindRoot is a cluster's self-signed root: clients trust it, and it signs
	// only intermediates.
	KindRoot Kind = iota + 1
	// KindIntermediate is signed by the root and signs replica certificates.
	KindIntermediate
)

// String names the tier as stored.
func (kind Kind) String() string {
	switch kind {
	case KindRoot:
		return "root"
	case KindIntermediate:
		return "intermediate"
	}
	return ""
}

// ParseKind reads a stored tier name.
func ParseKind(value string) (Kind, bool) {
	switch value {
	case "root":
		return KindRoot, true
	case "intermediate":
		return KindIntermediate, true
	}
	return 0, false
}

// RootParams describes a cluster's root: the one DNS name it and every CA
// below it may sign for, its subject, and when it begins and how long it
// lasts.
type RootParams struct {
	ClusterDNSName string
	Subject        string
	NotBefore      time.Time
	Lifetime       time.Duration
}

// IntermediateParams describes an intermediate: its subject, and when it
// begins and how long it lasts. Its name constraint is its root's.
type IntermediateParams struct {
	Subject   string
	NotBefore time.Time
	Lifetime  time.Duration
}

// CA is a cluster's root or intermediate with its private key.
// Certificates are read-only.
type CA struct {
	kind        Kind
	certificate *x509.Certificate
	root        *x509.Certificate
	privateKey  *ecdsa.PrivateKey
	fingerprint [sha256.Size]byte
}

// NewRoot generates a cluster's root: it may sign only for
// params.ClusterDNSName and no IP address, with at most one CA below it.
func NewRoot(params RootParams) (CA, error) {
	if !ValidDNSName(params.ClusterDNSName) || !validSubject(params.Subject) || params.NotBefore.IsZero() ||
		params.Lifetime < MinimumRootLifetime || params.Lifetime > MaximumRootLifetime {
		return CA{}, ErrInvalid
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return CA{}, err
	}
	template, err := caTemplate(params.Subject, params.ClusterDNSName, params.NotBefore.Add(-caBackdate),
		params.NotBefore.Add(params.Lifetime), 1)
	if err != nil {
		return CA{}, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return CA{}, err
	}
	return newRoot(der, key)
}

// NewIntermediate generates an intermediate under this root, with the
// root's name constraint and no CA below it, ending no later than the root.
func (ca CA) NewIntermediate(params IntermediateParams) (CA, error) {
	root := ca.certificate
	if ca.kind != KindRoot || root == nil || ca.privateKey == nil || !validSubject(params.Subject) ||
		params.NotBefore.IsZero() || params.Lifetime < MinimumIntermediateLifetime ||
		params.Lifetime > MaximumIntermediateLifetime || !params.NotBefore.Before(root.NotAfter) {
		return CA{}, ErrInvalid
	}
	notBefore := params.NotBefore.Add(-caBackdate)
	if notBefore.Before(root.NotBefore) {
		notBefore = root.NotBefore
	}
	notAfter := params.NotBefore.Add(params.Lifetime)
	if notAfter.After(root.NotAfter) {
		notAfter = root.NotAfter
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return CA{}, err
	}
	template, err := caTemplate(params.Subject, root.PermittedDNSDomains[0], notBefore, notAfter, 0)
	if err != nil {
		return CA{}, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, ca.privateKey)
	if err != nil {
		return CA{}, err
	}
	return newIntermediate(der, key, root)
}

func validSubject(subject string) bool {
	return subject != "" && len(subject) <= maximumSubjectLength
}

func caTemplate(subject, name string, notBefore, notAfter time.Time, pathLength int) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: subject},
		NotBefore:                   notBefore.UTC(),
		NotAfter:                    notAfter.UTC(),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLen:                  pathLength,
		MaxPathLenZero:              pathLength == 0,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{name},
		ExcludedIPRanges: []*net.IPNet{
			{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		},
	}, nil
}

// ParseRoot rebuilds a root from its certificate and its PKCS #8 private
// key, which must belong together. The certificate must be one NewRoot
// could have made: self-signed, constrained to one valid DNS name and no
// IP, with at most one CA below it; a rewritten certificate row cannot
// widen what the key signs.
func ParseRoot(certificateDER, privateKeyDER []byte) (CA, error) {
	key, err := parsePrivateKey(privateKeyDER)
	if err != nil {
		return CA{}, err
	}
	return newRoot(certificateDER, key)
}

// ParseIntermediate rebuilds an intermediate under root, as ParseRoot does
// a root: it must be signed by root, under root's name constraint, with no
// CA below it.
func ParseIntermediate(certificateDER, privateKeyDER []byte, root *x509.Certificate) (CA, error) {
	key, err := parsePrivateKey(privateKeyDER)
	if err != nil {
		return CA{}, err
	}
	return newIntermediate(certificateDER, key, root)
}

func parsePrivateKey(privateKeyDER []byte) (*ecdsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(privateKeyDER)
	if err != nil {
		return nil, ErrInvalid
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, ErrInvalid
	}
	return key, nil
}

func newRoot(certificateDER []byte, key *ecdsa.PrivateKey) (CA, error) {
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil || !constrainedCA(certificate, 1) || !key.PublicKey.Equal(certificate.PublicKey) ||
		certificate.CheckSignatureFrom(certificate) != nil {
		return CA{}, ErrInvalid
	}
	return CA{
		kind: KindRoot, certificate: certificate, root: certificate, privateKey: key,
		fingerprint: sha256.Sum256(certificate.Raw),
	}, nil
}

func newIntermediate(certificateDER []byte, key *ecdsa.PrivateKey, root *x509.Certificate) (CA, error) {
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil || root == nil || !constrainedCA(root, 1) || root.CheckSignatureFrom(root) != nil ||
		!constrainedCA(certificate, 0) ||
		certificate.PermittedDNSDomains[0] != root.PermittedDNSDomains[0] ||
		!key.PublicKey.Equal(certificate.PublicKey) || certificate.CheckSignatureFrom(root) != nil ||
		certificate.NotBefore.Before(root.NotBefore) || certificate.NotAfter.After(root.NotAfter) {
		return CA{}, ErrInvalid
	}
	return CA{
		kind: KindIntermediate, certificate: certificate, root: root, privateKey: key,
		fingerprint: sha256.Sum256(certificate.Raw),
	}, nil
}

// constrainedCA reports a CA certificate with every constraint NewRoot or
// NewIntermediate sets, at the given path length.
func constrainedCA(certificate *x509.Certificate, pathLength int) bool {
	return certificate.IsCA && certificate.BasicConstraintsValid && certificate.MaxPathLen == pathLength &&
		certificate.MaxPathLenZero == (pathLength == 0) &&
		certificate.KeyUsage == x509.KeyUsageCertSign|x509.KeyUsageCRLSign &&
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

// Kind returns the CA's tier.
func (ca CA) Kind() Kind { return ca.kind }

// Certificate returns the CA's certificate; callers must not change it.
func (ca CA) Certificate() *x509.Certificate { return ca.certificate }

// Root returns the cluster's root certificate: the CA's own for a root,
// its issuer's for an intermediate. Callers must not change it.
func (ca CA) Root() *x509.Certificate { return ca.root }

// ClusterDNSName returns the one name the CA may sign for.
func (ca CA) ClusterDNSName() string {
	if ca.certificate == nil {
		return ""
	}
	return ca.certificate.PermittedDNSDomains[0]
}

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
// alone is used, for the cluster's name, at Now.
type ReplicaRequest struct {
	CSR            []byte
	ClusterDNSName string
	Now            time.Time
}

// Issued is a signed replica certificate and the chain a gateway serves:
// the certificate, then its intermediate.
type Issued struct {
	Certificate     []byte
	Chain           [][]byte
	Serial          *big.Int
	PublicKeySHA256 [sha256.Size]byte
	NotBefore       time.Time
	NotAfter        time.Time
}

// SignReplica signs a replica's certificate with an intermediate: a P-256
// key whose CSR proves possession, for exactly the cluster's name, server
// authentication only, a random 126-bit serial, for ReplicaLifetime, within
// the intermediate's life (K1a4-I2, I3). An intermediate with less than an
// hour left, or a root, signs nothing.
func (ca CA) SignReplica(request ReplicaRequest) (Issued, error) {
	certificate := ca.certificate
	if ca.kind != KindIntermediate || certificate == nil || ca.privateKey == nil || request.Now.IsZero() ||
		len(request.CSR) > MaximumCSRSize || request.ClusterDNSName != certificate.PermittedDNSDomains[0] ||
		request.Now.Before(certificate.NotBefore) || certificate.NotAfter.Sub(request.Now) < MinimumSigningLife {
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
	notBefore := request.Now.Add(-replicaBackdate).UTC()
	if notBefore.Before(certificate.NotBefore) {
		notBefore = certificate.NotBefore
	}
	notAfter := request.Now.Add(ReplicaLifetime).UTC()
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
	return Issued{
		Certificate: der, Chain: [][]byte{der, certificate.Raw}, Serial: serial,
		PublicKeySHA256: sha256.Sum256(spki), NotBefore: notBefore, NotAfter: notAfter,
	}, nil
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

// OpenRoot opens a sealed root private key beside its stored certificate
// and rebuilds the root. The fingerprint comes from certificateDER itself,
// never from a stored column, so a rewritten certificate does not open the
// key.
func OpenRoot(dataKey DataKey, certificateDER, sealed []byte, deployment, cluster, caID string) (CA, error) {
	key, err := Open(dataKey, CAKeyAAD(deployment, cluster, caID, sha256.Sum256(certificateDER)), sealed)
	if err != nil {
		return CA{}, err
	}
	return ParseRoot(certificateDER, key)
}

// OpenIntermediate opens a sealed intermediate private key, as OpenRoot
// does, under its root.
func OpenIntermediate(dataKey DataKey, certificateDER, sealed []byte, deployment, cluster, caID string,
	root *x509.Certificate,
) (CA, error) {
	key, err := Open(dataKey, CAKeyAAD(deployment, cluster, caID, sha256.Sum256(certificateDER)), sealed)
	if err != nil {
		return CA{}, err
	}
	return ParseIntermediate(certificateDER, key, root)
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
	// WrapDataKey wraps network's existing data key under the custody's
	// current key, to replace an older wrapping (§17.1 C1).
	WrapDataKey(ctx context.Context, network string, dataKey DataKey) (WrappedKey, error)
	// OpenDataKey unwraps network's data key, with the custody's current key
	// or one it still keeps for opening.
	OpenDataKey(ctx context.Context, network string, wrapped WrappedKey) (DataKey, error)
}
