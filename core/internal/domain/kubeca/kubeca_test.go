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

func testRoot(t *testing.T) CA {
	t.Helper()
	root, err := NewRoot(RootParams{
		ClusterDNSName: clusterName, Subject: "MeshTransit kinda-k1 root 1",
		NotBefore: testNow, Lifetime: DefaultRootLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// testCA is an intermediate of a fresh root: the CA that signs replicas.
func testCA(t *testing.T) CA {
	t.Helper()
	ca, err := testRoot(t).NewIntermediate(IntermediateParams{
		Subject:   "MeshTransit kinda-k1 1",
		NotBefore: testNow, Lifetime: DefaultIntermediateLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func pools(ca CA) (roots, intermediates *x509.CertPool) {
	roots, intermediates = x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(ca.Root())
	intermediates.AddCert(ca.Certificate())
	return roots, intermediates
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

// checkConstrained checks what both tiers carry: the cluster's name only,
// never an IP, a P-256 key, and the fingerprint of the DER (ADR-053,
// K1a4-I3).
func checkConstrained(t *testing.T, ca CA) {
	t.Helper()
	cert := ca.Certificate()
	if !cert.IsCA || cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign ||
		!cert.PermittedDNSDomainsCritical || !slices.Equal(cert.PermittedDNSDomains, []string{clusterName}) ||
		len(cert.ExcludedIPRanges) != 2 || len(cert.PermittedIPRanges) != 0 || ca.ClusterDNSName() != clusterName {
		t.Fatalf("constraints: %v %v %v", cert.PermittedDNSDomains, cert.ExcludedIPRanges, cert.PermittedIPRanges)
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA || cert.PublicKey.(*ecdsa.PublicKey).Curve != elliptic.P256() {
		t.Fatalf("CA key %v", cert.PublicKeyAlgorithm)
	}
	if sum := sha256.Sum256(cert.Raw); ca.Fingerprint() != sum {
		t.Fatal("fingerprint is not the SHA-256 of the DER")
	}
}

// A cluster's root lives ten years and may have one CA below it; it starts
// a day back, so a client whose clock is behind still trusts it (§17.2,
// §17.3).
func TestNewRootIsConstrainedToTheClusterName(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	checkConstrained(t, root)
	cert := root.Certificate()
	if root.Kind() != KindRoot || cert.MaxPathLen != 1 || cert.MaxPathLenZero ||
		cert.CheckSignatureFrom(cert) != nil || root.Root() != cert {
		t.Fatalf("root: kind %v pathlen %d/%v", root.Kind(), cert.MaxPathLen, cert.MaxPathLenZero)
	}
	if !cert.NotBefore.Equal(testNow.Add(-24*time.Hour)) || !cert.NotAfter.Equal(testNow.Add(DefaultRootLifetime)) {
		t.Fatalf("root validity %v – %v", cert.NotBefore, cert.NotAfter)
	}
	year := 365 * 24 * time.Hour
	for name, params := range map[string]RootParams{
		"short":      {ClusterDNSName: clusterName, Subject: "x", NotBefore: testNow, Lifetime: 4 * year},
		"long":       {ClusterDNSName: clusterName, Subject: "x", NotBefore: testNow, Lifetime: 16 * year},
		"no name":    {Subject: "x", NotBefore: testNow, Lifetime: DefaultRootLifetime},
		"bad name":   {ClusterDNSName: "Not A Name", Subject: "x", NotBefore: testNow, Lifetime: DefaultRootLifetime},
		"no subject": {ClusterDNSName: clusterName, NotBefore: testNow, Lifetime: DefaultRootLifetime},
	} {
		if _, err := NewRoot(params); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// An intermediate is signed by its root, carries the same name constraint,
// may have no CA below it, and ends no later than its root.
func TestNewIntermediateIsSignedByItsRoot(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	ca, err := root.NewIntermediate(IntermediateParams{
		Subject: "MeshTransit kinda-k1 1", NotBefore: testNow,
		Lifetime: DefaultIntermediateLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkConstrained(t, ca)
	cert := ca.Certificate()
	if ca.Kind() != KindIntermediate || cert.MaxPathLen != 0 || !cert.MaxPathLenZero ||
		cert.CheckSignatureFrom(root.Certificate()) != nil || ca.Root() != root.Certificate() {
		t.Fatalf("intermediate: kind %v pathlen %d/%v", ca.Kind(), cert.MaxPathLen, cert.MaxPathLenZero)
	}
	if !cert.NotBefore.Equal(testNow.Add(-24*time.Hour)) ||
		!cert.NotAfter.Equal(testNow.Add(DefaultIntermediateLifetime)) {
		t.Fatalf("intermediate validity %v – %v", cert.NotBefore, cert.NotAfter)
	}
	// It starts no earlier than its root, and ends with it.
	late, err := root.NewIntermediate(IntermediateParams{
		Subject: "late", Lifetime: DefaultIntermediateLifetime,
		NotBefore: root.Certificate().NotAfter.Add(-10 * 24 * time.Hour),
	})
	if err != nil || !late.Certificate().NotAfter.Equal(root.Certificate().NotAfter) {
		t.Fatalf("clamped intermediate %v, %v", late.Certificate().NotAfter, err)
	}
	early, err := root.NewIntermediate(IntermediateParams{
		Subject: "early", NotBefore: testNow.Add(-time.Hour),
		Lifetime: DefaultIntermediateLifetime,
	})
	if err != nil || early.Certificate().NotBefore.Before(root.Certificate().NotBefore) {
		t.Fatalf("intermediate starts before its root: %v, %v", early.Certificate().NotBefore, err)
	}
	for name, create := range map[string]func() (CA, error){
		"short": func() (CA, error) {
			return root.NewIntermediate(IntermediateParams{Subject: "x", NotBefore: testNow, Lifetime: 6 * 24 * time.Hour})
		},
		"long": func() (CA, error) {
			return root.NewIntermediate(IntermediateParams{Subject: "x", NotBefore: testNow, Lifetime: 91 * 24 * time.Hour})
		},
		"under an intermediate": func() (CA, error) {
			return ca.NewIntermediate(IntermediateParams{
				Subject: "x", NotBefore: testNow,
				Lifetime: DefaultIntermediateLifetime,
			})
		},
		"after the root": func() (CA, error) {
			return root.NewIntermediate(IntermediateParams{
				Subject: "x", NotBefore: root.Certificate().NotAfter,
				Lifetime: DefaultIntermediateLifetime,
			})
		},
	} {
		if _, err := create(); !errors.Is(err, ErrInvalid) {
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
	issued, err := ca.SignReplica(ReplicaRequest{
		CSR:            csrFor(t, key, "evil.example", clusterName),
		ClusterDNSName: clusterName, Now: testNow,
	})
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
	if !cert.NotBefore.Equal(testNow.Add(-time.Hour)) || !cert.NotAfter.Equal(testNow.Add(ReplicaLifetime)) ||
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
	// A client that trusts only the root verifies the chain the gateway sends.
	roots, intermediates := pools(ca)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, DNSName: clusterName,
		CurrentTime: testNow, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(issued.Chain) != 2 || !bytes.Equal(issued.Chain[0], issued.Certificate) ||
		!bytes.Equal(issued.Chain[1], ca.Certificate().Raw) {
		t.Fatalf("chain of %d certificates", len(issued.Chain))
	}
	again, err := ca.SignReplica(ReplicaRequest{CSR: csrFor(t, key), ClusterDNSName: clusterName, Now: testNow})
	if err != nil || again.Serial.Cmp(issued.Serial) == 0 {
		t.Fatalf("second serial: %v", err)
	}
}

// Near the intermediate's end a replica's certificate ends with it; a root
// signs no replica.
func TestSignReplicaEndsWithTheCA(t *testing.T) {
	t.Parallel()
	ca := testCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	late := ca.Certificate().NotAfter.Add(-2 * time.Hour)
	issued, err := ca.SignReplica(ReplicaRequest{CSR: csrFor(t, key), ClusterDNSName: clusterName, Now: late})
	if err != nil || !issued.NotAfter.Equal(ca.Certificate().NotAfter) {
		t.Fatalf("clamped to %v, %v", issued.NotAfter, err)
	}
	if _, err := ca.SignReplica(ReplicaRequest{
		CSR: csrFor(t, key), ClusterDNSName: clusterName,
		Now: ca.Certificate().NotAfter,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an expired CA signed: %v", err)
	}
	if _, err := testRoot(t).SignReplica(ReplicaRequest{
		CSR: csrFor(t, key), ClusterDNSName: clusterName,
		Now: testNow,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a root signed a replica: %v", err)
	}
}

// Only a P-256 key with a valid proof of possession is signed, for this
// CA's cluster.
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
		"P-384":         {CSR: csrFor(t, p384), ClusterDNSName: clusterName, Now: testNow},
		"RSA":           {CSR: csrFor(t, rsaKey), ClusterDNSName: clusterName, Now: testNow},
		"Ed25519":       {CSR: csrFor(t, edKey), ClusterDNSName: clusterName, Now: testNow},
		"bad signature": {CSR: forged, ClusterDNSName: clusterName, Now: testNow},
		"garbage":       {CSR: []byte("not a csr"), ClusterDNSName: clusterName, Now: testNow},
		"other cluster": {
			CSR: csrFor(t, p256), ClusterDNSName: "other.kube.000000000101.000000000201.mesh.internal",
			Now: testNow,
		},
		"huge": {
			CSR: append(csrFor(t, p256), make([]byte, MaximumCSRSize)...), ClusterDNSName: clusterName,
			Now: testNow,
		},
	} {
		if _, err := ca.SignReplica(request); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The name constraint is real: a certificate for another name, even signed
// by the intermediate's key, does not verify under the root.
func TestCANameConstraintHolds(t *testing.T) {
	t.Parallel()
	ca := testCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7), DNSNames: []string{"bank.example"},
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate(), &key.PublicKey, ca.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	roots, intermediates := pools(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, DNSName: "bank.example",
		CurrentTime: testNow,
	}); err == nil {
		t.Fatal("a certificate outside the cluster's name verified")
	}
}

// A CA comes back from its certificate and private key only when the two
// belong together, and an intermediate only under its own root.
func TestParseCAChecksTheKeyMatches(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	rootKey, err := root.MarshalPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	parsedRoot, err := ParseRoot(root.Certificate().Raw, rootKey)
	if err != nil || parsedRoot.Fingerprint() != root.Fingerprint() || parsedRoot.Kind() != KindRoot {
		t.Fatalf("ParseRoot() = %v", err)
	}
	ca, err := root.NewIntermediate(IntermediateParams{
		Subject: "x", NotBefore: testNow,
		Lifetime: DefaultIntermediateLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ca.MarshalPrivateKey()
	parsed, err := ParseIntermediate(ca.Certificate().Raw, key, root.Certificate())
	if err != nil || parsed.Fingerprint() != ca.Fingerprint() || parsed.Kind() != KindIntermediate {
		t.Fatalf("ParseIntermediate() = %v", err)
	}
	other := testCA(t)
	otherKey, _ := other.MarshalPrivateKey()
	for name, parse := range map[string]func() (CA, error){
		"mismatched key":       func() (CA, error) { return ParseIntermediate(ca.Certificate().Raw, otherKey, root.Certificate()) },
		"another root":         func() (CA, error) { return ParseIntermediate(ca.Certificate().Raw, key, other.Root()) },
		"root as intermediate": func() (CA, error) { return ParseIntermediate(root.Certificate().Raw, rootKey, root.Certificate()) },
		"intermediate as root": func() (CA, error) { return ParseRoot(ca.Certificate().Raw, key) },
		"root without key":     func() (CA, error) { return ParseRoot(root.Certificate().Raw, otherKey) },
	} {
		if _, err := parse(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
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

// An intermediate signs nothing before it starts or with less than an hour
// left; a replica's certificate starts an hour back, never before its CA.
func TestCAValidityBounds(t *testing.T) {
	t.Parallel()
	ca := testCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	start := ca.Certificate().NotBefore.Add(10 * time.Minute)
	issued, err := ca.SignReplica(ReplicaRequest{CSR: csrFor(t, key), ClusterDNSName: clusterName, Now: start})
	if err != nil || !issued.NotBefore.Equal(ca.Certificate().NotBefore) {
		t.Fatalf("a certificate starting before its CA: %v, %v", issued.NotBefore, err)
	}
	for name, now := range map[string]time.Time{
		"before the CA":      ca.Certificate().NotBefore.Add(-time.Minute),
		"under an hour left": ca.Certificate().NotAfter.Add(-30 * time.Minute),
	} {
		if _, err := ca.SignReplica(ReplicaRequest{
			CSR: csrFor(t, key), ClusterDNSName: clusterName,
			Now: now,
		}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A certificate row rewritten to widen what the key signs, or not signed by
// that key, does not come back as a CA (review a1a M1).
func TestParseCARefusesARewrittenCertificate(t *testing.T) {
	t.Parallel()
	ca := testRoot(t)
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
		"no path limit":         widen(func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = -1, false }),
		"not critical":          widen(func(c *x509.Certificate) { c.PermittedDNSDomainsCritical = false }),
		"signed by another key": foreign,
	} {
		if _, err := ParseRoot(der, keyDER); !errors.Is(err, ErrInvalid) {
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
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.SignReplica(ReplicaRequest{
		CSR: csr, ClusterDNSName: clusterName,
		Now: testNow,
	}); !errors.Is(err, ErrInvalid) {
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
	opened, err := OpenIntermediate(dataKey, ca.Certificate().Raw, sealed, "dep", "cluster", "ca", ca.Root())
	if err != nil || opened.Fingerprint() != ca.Fingerprint() {
		t.Fatalf("OpenIntermediate() = %v", err)
	}
	if _, err := OpenIntermediate(dataKey, other.Certificate().Raw, sealed, "dep", "cluster", "ca",
		other.Root()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("another certificate opened the key: %v", err)
	}
	root := testRoot(t)
	sealedRoot, err := SealCA(dataKey, root, "dep", "cluster", "root")
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := OpenRoot(dataKey, root.Certificate().Raw, sealedRoot, "dep", "cluster", "root"); err != nil ||
		opened.Kind() != KindRoot {
		t.Fatalf("OpenRoot() = %v", err)
	}
}
