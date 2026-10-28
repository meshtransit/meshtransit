package kubeca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

const clusterName = "kinda-k1.kube.000000000101.000000000201.mesh.internal"

var testNow = time.Date(2026, time.October, 28, 12, 0, 0, 0, time.UTC)

func testCA(t *testing.T) CA {
	t.Helper()
	ca, err := NewCA(CAParams{ClusterDNSName: clusterName, Subject: "MeshTransit kinda-k1 000000000201",
		NotBefore: testNow, Lifetime: 2 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func csrFor(t *testing.T, key any, names ...string) []byte {
	t.Helper()
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "evil.example"}, DNSNames: names,
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// A cluster's CA is a constrained root: it may sign only for the cluster's
// name, never an IP, and nothing below it may sign (ADR-053, K1a4-I3).
func TestNewCAIsConstrainedToTheClusterName(t *testing.T) {
	t.Parallel()
	ca := testCA(t)
	cert := ca.Certificate()
	if !cert.IsCA || cert.MaxPathLen != 0 || !cert.MaxPathLenZero || cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Fatalf("CA basics: isCA %v pathlen %d/%v usage %v", cert.IsCA, cert.MaxPathLen, cert.MaxPathLenZero, cert.KeyUsage)
	}
	if !cert.PermittedDNSDomainsCritical || !slices.Equal(cert.PermittedDNSDomains, []string{clusterName}) ||
		len(cert.ExcludedIPRanges) != 2 || len(cert.PermittedIPRanges) != 0 {
		t.Fatalf("name constraints: %v %v %v", cert.PermittedDNSDomains, cert.ExcludedIPRanges, cert.PermittedIPRanges)
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA || cert.PublicKey.(*ecdsa.PublicKey).Curve != elliptic.P256() {
		t.Fatalf("CA key %v", cert.PublicKeyAlgorithm)
	}
	if !cert.NotAfter.Equal(testNow.Add(2*365*24*time.Hour)) || cert.NotBefore.After(testNow) {
		t.Fatalf("CA validity %v – %v", cert.NotBefore, cert.NotAfter)
	}
	if sum := sha256.Sum256(cert.Raw); ca.Fingerprint() != sum {
		t.Fatal("fingerprint is not the SHA-256 of the DER")
	}
	for name, params := range map[string]CAParams{
		"short":    {ClusterDNSName: clusterName, Subject: "x", NotBefore: testNow, Lifetime: 200 * 24 * time.Hour},
		"long":     {ClusterDNSName: clusterName, Subject: "x", NotBefore: testNow, Lifetime: 6 * 365 * 24 * time.Hour},
		"no name":  {Subject: "x", NotBefore: testNow, Lifetime: 2 * 365 * 24 * time.Hour},
		"bad name": {ClusterDNSName: "Not A Name", Subject: "x", NotBefore: testNow, Lifetime: 2 * 365 * 24 * time.Hour},
	} {
		if _, err := NewCA(params); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A replica's certificate carries only what Core sets: the cluster's name,
// server authentication, a random serial and a bounded life; of the CSR
// only the public key counts (K1a4-I2, I3).
func TestSignReplicaTakesOnlyThePublicKey(t *testing.T) {
	t.Parallel()
	ca := testCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issued, err := ca.SignReplica(ReplicaRequest{CSR: csrFor(t, key, "evil.example", clusterName),
		ClusterDNSName: clusterName, Now: testNow, Lifetime: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(issued.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cert.DNSNames, []string{clusterName}) || len(cert.IPAddresses) != 0 ||
		cert.Subject.CommonName != "" || cert.IsCA ||
		!slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) ||
		cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("leaf fields: names %v ips %v cn %q usage %v/%v", cert.DNSNames, cert.IPAddresses,
			cert.Subject.CommonName, cert.KeyUsage, cert.ExtKeyUsage)
	}
	if !cert.NotBefore.Equal(testNow.Add(-5*time.Minute)) || !cert.NotAfter.Equal(testNow.Add(24*time.Hour)) ||
		!issued.NotAfter.Equal(cert.NotAfter) {
		t.Fatalf("leaf validity %v – %v", cert.NotBefore, cert.NotAfter)
	}
	if issued.Serial.BitLen() < 120 || issued.Serial.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("serial %v", issued.Serial)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if issued.PublicKeySHA256 != sha256.Sum256(spki) {
		t.Fatal("public key hash")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: clusterName, CurrentTime: testNow,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	again, err := ca.SignReplica(ReplicaRequest{CSR: csrFor(t, key), ClusterDNSName: clusterName, Now: testNow,
		Lifetime: 24 * time.Hour})
	if err != nil || again.Serial.Cmp(issued.Serial) == 0 {
		t.Fatalf("second serial: %v", err)
	}
}

// Near the CA's end a replica's certificate ends with it.
func TestSignReplicaEndsWithTheCA(t *testing.T) {
	t.Parallel()
	ca := testCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	late := ca.Certificate().NotAfter.Add(-time.Hour)
	issued, err := ca.SignReplica(ReplicaRequest{CSR: csrFor(t, key), ClusterDNSName: clusterName, Now: late,
		Lifetime: 24 * time.Hour})
	if err != nil || !issued.NotAfter.Equal(ca.Certificate().NotAfter) {
		t.Fatalf("clamped to %v, %v", issued.NotAfter, err)
	}
	if _, err := ca.SignReplica(ReplicaRequest{CSR: csrFor(t, key), ClusterDNSName: clusterName,
		Now: ca.Certificate().NotAfter, Lifetime: 24 * time.Hour}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an expired CA signed: %v", err)
	}
}

// Only a P-256 key with a valid proof of possession is signed, for this
// CA's cluster, for at most 72 hours.
func TestSignReplicaRefusesWhatItCannotStandBehind(t *testing.T) {
	t.Parallel()
	ca := testCA(t)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	forged := csrFor(t, p256)
	forged[len(forged)-3] ^= 0xff
	for name, request := range map[string]ReplicaRequest{
		"P-384":         {CSR: csrFor(t, p384), ClusterDNSName: clusterName, Now: testNow, Lifetime: time.Hour},
		"RSA":           {CSR: csrFor(t, rsaKey), ClusterDNSName: clusterName, Now: testNow, Lifetime: time.Hour},
		"Ed25519":       {CSR: csrFor(t, edKey), ClusterDNSName: clusterName, Now: testNow, Lifetime: time.Hour},
		"bad signature": {CSR: forged, ClusterDNSName: clusterName, Now: testNow, Lifetime: time.Hour},
		"garbage":       {CSR: []byte("not a csr"), ClusterDNSName: clusterName, Now: testNow, Lifetime: time.Hour},
		"other cluster": {CSR: csrFor(t, p256), ClusterDNSName: "other.kube.000000000101.000000000201.mesh.internal",
			Now: testNow, Lifetime: time.Hour},
		"too long": {CSR: csrFor(t, p256), ClusterDNSName: clusterName, Now: testNow, Lifetime: 73 * time.Hour},
		"too short": {CSR: csrFor(t, p256), ClusterDNSName: clusterName, Now: testNow,
			Lifetime: 30 * time.Minute},
	} {
		if _, err := ca.SignReplica(request); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The name constraint is real: a certificate for another name, even signed
// by the CA's key, does not verify under it.
func TestCANameConstraintHolds(t *testing.T) {
	t.Parallel()
	ca := testCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(7), DNSNames: []string{"bank.example"},
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate(), &key.PublicKey, ca.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "bank.example", CurrentTime: testNow}); err == nil {
		t.Fatal("a certificate outside the cluster's name verified")
	}
}

// A CA comes back from its certificate and private key only when the two
// belong together.
func TestParseCAChecksTheKeyMatches(t *testing.T) {
	t.Parallel()
	ca := testCA(t)
	key, err := ca.MarshalPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCA(ca.Certificate().Raw, key)
	if err != nil || parsed.Fingerprint() != ca.Fingerprint() {
		t.Fatalf("ParseCA() = %v", err)
	}
	other := testCA(t)
	otherKey, _ := other.MarshalPrivateKey()
	if _, err := ParseCA(ca.Certificate().Raw, otherKey); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a mismatched key was taken: %v", err)
	}
}

// The envelope opens only with its key and its exact associated data.
func TestEnvelopeBindsItsContext(t *testing.T) {
	t.Parallel()
	var dataKey DataKey
	if _, err := rand.Read(dataKey[:]); err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256([]byte("certificate"))
	aad := CAKeyAAD("dep", "cluster", "ca", fingerprint)
	sealed, err := Seal(dataKey, aad, []byte("private key"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(dataKey, aad, sealed)
	if err != nil || !bytes.Equal(opened, []byte("private key")) {
		t.Fatalf("Open() = %q, %v", opened, err)
	}
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1
	var otherKey DataKey
	for name, open := range map[string]func() ([]byte, error){
		"other context": func() ([]byte, error) {
			return Open(dataKey, CAKeyAAD("dep", "cluster", "ca2", fingerprint), sealed)
		},
		"other certificate": func() ([]byte, error) {
			return Open(dataKey, CAKeyAAD("dep", "cluster", "ca", sha256.Sum256([]byte("other"))), sealed)
		},
		"tampered":  func() ([]byte, error) { return Open(dataKey, aad, tampered) },
		"other key": func() ([]byte, error) { return Open(otherKey, aad, sealed) },
		"short":     func() ([]byte, error) { return Open(dataKey, aad, sealed[:8]) },
	} {
		if _, err := open(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if CAKeyAAD("a", "bc", "d", fingerprint) == CAKeyAAD("ab", "c", "d", fingerprint) ||
		DataKeyAAD("a") == DataKeyAAD("b") {
		t.Fatal("associated data is ambiguous")
	}
	if formatted := fmt.Sprintf("%v %+v %#v %s %x", dataKey, dataKey, dataKey, dataKey, dataKey); strings.Contains(
		formatted, fmt.Sprintf("%x", dataKey[:4])) || !strings.Contains(formatted, "REDACTED") {
		t.Fatalf("a data key formats as %q", formatted)
	}
}

// A CA starts five minutes back, so a peer slightly behind accepts it, and
// signs nothing before it starts or with less than an hour left.
func TestCAValidityBounds(t *testing.T) {
	t.Parallel()
	ca := testCA(t)
	if !ca.Certificate().NotBefore.Equal(testNow.Add(-5 * time.Minute)) {
		t.Fatalf("CA NotBefore %v", ca.Certificate().NotBefore)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, now := range map[string]time.Time{
		"before the CA":      testNow.Add(-10 * time.Minute),
		"under an hour left": ca.Certificate().NotAfter.Add(-30 * time.Minute),
	} {
		if _, err := ca.SignReplica(ReplicaRequest{CSR: csrFor(t, key), ClusterDNSName: clusterName, Now: now,
			Lifetime: 24 * time.Hour}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A certificate row rewritten to widen what the key signs, or not signed by
// that key, does not come back as a CA (review a1a M1).
func TestParseCARefusesARewrittenCertificate(t *testing.T) {
	t.Parallel()
	ca := testCA(t)
	keyDER, _ := ca.MarshalPrivateKey()
	widen := func(change func(*x509.Certificate)) []byte {
		template := *ca.Certificate()
		change(&template)
		der, err := x509.CreateCertificate(rand.Reader, &template, &template, ca.privateKey.Public(), ca.privateKey)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	foreignTemplate, foreignParent := *ca.Certificate(), *ca.Certificate()
	foreignParent.PublicKey = stranger.Public()
	foreign, err := x509.CreateCertificate(rand.Reader, &foreignTemplate, &foreignParent, ca.privateKey.Public(), stranger)
	if err != nil {
		t.Fatal(err)
	}
	// A valid self-signed CA for another name is still a CA: the fingerprint
	// in the AAD keeps it from standing in for this cluster's (CAKeyAAD).
	for name, der := range map[string][]byte{
		"no IP exclusion":       widen(func(c *x509.Certificate) { c.ExcludedIPRanges = nil }),
		"path length":           widen(func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 3, false }),
		"not critical":          widen(func(c *x509.Certificate) { c.PermittedDNSDomainsCritical = false }),
		"signed by another key": foreign,
	} {
		if _, err := ParseCA(der, keyDER); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Only a CSR signed with ECDSA and SHA-256 is taken, as a P-256 key signs
// it (no SHA-1 or other digest).
func TestSignReplicaTakesOnlySHA256Requests(t *testing.T) {
	t.Parallel()
	ca := testCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA384}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.SignReplica(ReplicaRequest{CSR: csr, ClusterDNSName: clusterName, Now: testNow,
		Lifetime: 24 * time.Hour}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a non-SHA-256 CSR: %v", err)
	}
}

// A sealed CA opens only beside the certificate it was sealed with.
func TestSealedCAOpensOnlyWithItsCertificate(t *testing.T) {
	t.Parallel()
	ca, other := testCA(t), testCA(t)
	var dataKey DataKey
	if _, err := rand.Read(dataKey[:]); err != nil {
		t.Fatal(err)
	}
	sealed, err := SealCA(dataKey, ca, "dep", "cluster", "ca")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenCA(dataKey, ca.Certificate().Raw, sealed, "dep", "cluster", "ca")
	if err != nil || opened.Fingerprint() != ca.Fingerprint() {
		t.Fatalf("OpenCA() = %v", err)
	}
	if _, err := OpenCA(dataKey, other.Certificate().Raw, sealed, "dep", "cluster", "ca"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("another certificate opened the key: %v", err)
	}
}
