package kubecert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
)

var testNow = time.Date(2026, time.October, 29, 3, 0, 0, 0, time.UTC)

// testCA is a root and an intermediate that issue replica certificates as
// Core does.
type testCA struct {
	root, intermediate           *x509.Certificate
	rootKey, intermediateKey     *ecdsa.PrivateKey
	rootDER, intermediateDER     []byte
	rootPrint, intermediatePrint [32]byte
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	ca := testCA{}
	var err error
	if ca.rootKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if ca.intermediateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(24 * 365 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	if ca.rootDER, err = x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &ca.rootKey.PublicKey,
		ca.rootKey); err != nil {
		t.Fatal(err)
	}
	ca.root, _ = x509.ParseCertificate(ca.rootDER)
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "intermediate"},
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(30 * 24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	if ca.intermediateDER, err = x509.CreateCertificate(rand.Reader, intermediateTemplate, ca.root,
		&ca.intermediateKey.PublicKey, ca.rootKey); err != nil {
		t.Fatal(err)
	}
	ca.intermediate, _ = x509.ParseCertificate(ca.intermediateDER)
	ca.rootPrint, ca.intermediatePrint = fingerprint(ca.rootDER), fingerprint(ca.intermediateDER)
	return ca
}

// issue signs a replica certificate for key at now, as Core's answer.
func (ca testCA) issue(t *testing.T, key *ecdsa.PrivateKey, now time.Time, serverAuth bool,
	revision uint64,
) controlplane.KubeCertResult {
	t.Helper()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	template := &x509.Certificate{
		SerialNumber: serial.Add(serial, big.NewInt(1)),
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), DNSNames: []string{"kinda-k1.kube.x.y.mesh.internal"},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if serverAuth {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.intermediate, &key.PublicKey, ca.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	return controlplane.KubeCertResult{
		Outcome: controlplane.KubeCertIssued, Certificate: der,
		Chain: [][]byte{ca.intermediateDER}, RootFingerprint: ca.rootPrint[:], IssuerFingerprint: ca.intermediatePrint[:],
		NotAfter: template.NotAfter, RenewAt: now.Add(8 * time.Hour), NetworkRevision: revision,
	}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestRenewalTime(t *testing.T) {
	t.Parallel()
	cert := Certificate{NotAfter: testNow.Add(24 * time.Hour), RenewAt: testNow.Add(8 * time.Hour), IssuedAt: testNow}
	if got := renewalTime(cert, false); !got.Equal(cert.RenewAt) {
		t.Fatalf("a fresh certificate renews at %v", got)
	}
	// Taken with under 12 hours left: a quarter of what it had (§10 M1),
	// never sooner than 15 minutes after unless the root changed.
	short := Certificate{NotAfter: testNow.Add(4 * time.Hour), RenewAt: testNow.Add(-time.Hour), IssuedAt: testNow}
	if got := renewalTime(short, false); !got.Equal(testNow.Add(time.Hour)) {
		t.Fatalf("4 h left renews at %v", got)
	}
	shorter := Certificate{NotAfter: testNow.Add(40 * time.Minute), RenewAt: testNow, IssuedAt: testNow}
	if got := renewalTime(shorter, false); !got.Equal(testNow.Add(minimumReissue)) {
		t.Fatalf("40 min left renews at %v, want after the reissue floor", got)
	}
	if got := renewalTime(shorter, true); !got.Equal(testNow.Add(10 * time.Minute)) {
		t.Fatalf("a new root renews at %v", got)
	}
	// Core's renew_at never past half the life (a4b1 review M4).
	late := Certificate{NotAfter: testNow.Add(24 * time.Hour), RenewAt: testNow.Add(30 * time.Hour), IssuedAt: testNow}
	if got := renewalTime(late, false); !got.Equal(testNow.Add(12 * time.Hour)) {
		t.Fatalf("a renew_at past the end renews at %v", got)
	}
	gone := Certificate{NotAfter: testNow.Add(time.Second), RenewAt: testNow, IssuedAt: testNow}
	if got := renewalTime(gone, true); !got.Equal(testNow.Add(renewFloor)) {
		t.Fatalf("an almost expired certificate renews at %v", got)
	}
}

func TestBackoff(t *testing.T) {
	t.Parallel()
	for attempt := 1; attempt < 20; attempt++ {
		if wait := backoff(attempt, 24*time.Hour); wait < time.Second || wait > backoffCeiling {
			t.Fatalf("backoff(%d) = %v", attempt, wait)
		}
		// With 10 minutes left the ceiling is its 30-second floor; with an
		// hour, a twentieth of it.
		if wait := backoff(attempt, 10*time.Minute); wait > backoffMinimum {
			t.Fatalf("backoff(%d, 10m) = %v", attempt, wait)
		}
		if wait := backoff(attempt, time.Hour); wait > 3*time.Minute {
			t.Fatalf("backoff(%d, 1h) = %v", attempt, wait)
		}
		if wait := failureBackoff(attempt); wait < 30*time.Second || wait > failureCeiling {
			t.Fatalf("failureBackoff(%d) = %v", attempt, wait)
		}
	}
}

func TestActionFor(t *testing.T) {
	t.Parallel()
	refused := func(reason string) controlplane.KubeCertResult {
		return controlplane.KubeCertResult{Outcome: controlplane.KubeCertRefused, Reason: reason}
	}
	for reason, want := range map[string]Action{
		"proof": ActionToken, "renewal_unknown": ActionToken, "renewal_expired": ActionToken,
		"token": ActionWaitToken, "token_expired": ActionWaitToken, "token_used": ActionWaitToken,
		"trust_missing": ActionWaitToken, "no_ca": ActionWaitMap, "misnamed": ActionWaitMap,
		"contested": ActionNew, "superseded": ActionNew, "attempts": ActionNew, "csr": ActionNewKey,
		"conflict": ActionNewKey, "invalid": ActionNewKey, "revoked": ActionStop, "cluster": ActionStop,
		"not_gateway": ActionStop, "not_proven": ActionStop, "something new": ActionNew,
	} {
		if got := actionFor(refused(reason)); got != want {
			t.Errorf("%s: %v, want %v", reason, got, want)
		}
	}
	if actionFor(controlplane.KubeCertResult{Reason: "proof"}) != ActionRetry {
		t.Fatal("a retry was not retried")
	}
}

func TestEarlyRenewal(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	cert := Certificate{
		Root: ca.rootPrint, Issuer: ca.intermediatePrint, NotAfter: testNow.Add(20 * time.Hour),
		NetworkRevision: 7,
	}
	other := [32]byte{9}
	named := func(root, signing []byte, revision uint64) *networkmap.KubernetesCA {
		return &networkmap.KubernetesCA{Root: root, Signing: signing, MapRevision: revision}
	}
	for name, test := range map[string]struct {
		ca     *networkmap.KubernetesCA
		renews bool
		root   bool
	}{
		"absent":           {},
		"no CA yet":        {ca: named(nil, nil, 9)},
		"root only":        {ca: named(other[:], nil, 9)},
		"the same":         {ca: named(ca.rootPrint[:], ca.intermediatePrint[:], 9)},
		"an older map":     {ca: named(other[:], other[:], 6)},
		"a new root":       {ca: named(other[:], other[:], 7), renews: true, root: true},
		"a new signing CA": {ca: named(ca.rootPrint[:], other[:], 8), renews: true},
	} {
		spread, renews, root := earlyRenewal(cert, test.ca, testNow)
		if renews != test.renews || root != test.root || renews && (spread <= 0 || spread > time.Hour) {
			t.Errorf("%s: %v, %v, %v", name, spread, renews, root)
		}
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	key := newKey(t)
	good := ca.issue(t, key, testNow, true, 5)
	cert, err := verify(good, key, nil, testNow)
	if err != nil || cert.Root != ca.rootPrint || cert.Issuer != ca.intermediatePrint || cert.NetworkRevision != 5 ||
		cert.Serial == [16]byte{} {
		t.Fatalf("verify() = %+v, %v", cert, err)
	}
	// A map at or past its revision that names its issuer takes it; one
	// that names another signing CA does not (a4b1 review M2).
	same := &networkmap.KubernetesCA{Root: ca.rootPrint[:], Signing: ca.intermediatePrint[:], MapRevision: 6}
	if _, err := verify(good, key, same, testNow); err != nil {
		t.Fatalf("a later map naming the issuer refused the certificate: %v", err)
	}
	newer := &networkmap.KubernetesCA{Root: ca.rootPrint[:], Signing: make([]byte, 32), MapRevision: 6}
	if _, err := verify(good, key, newer, testNow); err == nil {
		t.Fatal("a certificate of an older intermediate was taken")
	}
	otherRoot := &networkmap.KubernetesCA{Root: make([]byte, 32), Signing: ca.intermediatePrint[:], MapRevision: 6}
	if _, err := verify(good, key, otherRoot, testNow); err == nil {
		t.Fatal("a certificate under a root the map does not name was taken")
	}
	older := &networkmap.KubernetesCA{Root: ca.rootPrint[:], Signing: make([]byte, 32), MapRevision: 4}
	if _, err := verify(good, key, older, testNow); err != nil {
		t.Fatalf("an older map refused the certificate: %v", err)
	}
	other := newTestCA(t)
	for name, test := range map[string]struct {
		result controlplane.KubeCertResult
		key    *ecdsa.PrivateKey
		ca     *networkmap.KubernetesCA
		now    time.Time
	}{
		"another key":    {result: good, key: newKey(t), now: testNow},
		"another issuer": {result: withIssuer(good, other), key: key, now: testNow},
		"no serverAuth":  {result: ca.issue(t, key, testNow, false, 5), key: key, now: testNow},
		"expired":        {result: good, key: key, now: testNow.Add(24 * time.Hour)},
		"not yet valid":  {result: ca.issue(t, key, testNow.Add(3*time.Hour), true, 5), key: key, now: testNow},
		"the map names another": {
			result: good, key: key, now: testNow,
			ca: &networkmap.KubernetesCA{Root: ca.rootPrint[:], Signing: make([]byte, 32), MapRevision: 5},
		},
		"no chain": {result: controlplane.KubeCertResult{
			Certificate: good.Certificate, RootFingerprint: ca.rootPrint[:],
			IssuerFingerprint: ca.intermediatePrint[:],
		}, key: key, now: testNow},
	} {
		if _, err := verify(test.result, test.key, test.ca, test.now); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

// withIssuer names another CA's intermediate as the issuer.
func withIssuer(result controlplane.KubeCertResult, other testCA) controlplane.KubeCertResult {
	result.Chain = [][]byte{other.intermediateDER}
	result.IssuerFingerprint = other.intermediatePrint[:]
	return result
}
