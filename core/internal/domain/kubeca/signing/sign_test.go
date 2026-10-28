package signing

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	testWorkspaceCode = "000000000101"
	testNetworkCode   = "000000000202"
	testSuffix        = "mesh.internal"
	testClusterName   = "prod"
	testDNSName       = "prod.kube." + testWorkspaceCode + "." + testNetworkCode + "." + testSuffix
)

// stubCustody hands out one data key and counts how often it was opened.
type stubCustody struct {
	dataKey kubeca.DataKey
	opened  *int
	fail    error
}

func (custody stubCustody) NewDataKey(context.Context, string) (kubeca.DataKey, kubeca.WrappedKey, error) {
	return custody.dataKey, kubeca.WrappedKey{Custody: "file", KeyID: "k1", Ciphertext: []byte("wrapped")}, nil
}

func (custody stubCustody) WrapDataKey(context.Context, string, kubeca.DataKey) (kubeca.WrappedKey, error) {
	return kubeca.WrappedKey{Custody: "file", KeyID: "k1", Ciphertext: []byte("wrapped")}, nil
}

func (custody stubCustody) OpenDataKey(context.Context, string, kubeca.WrappedKey) (kubeca.DataKey, error) {
	if custody.opened != nil {
		*custody.opened++
	}
	if custody.fail != nil {
		return kubeca.DataKey{}, custody.fail
	}
	return custody.dataKey, nil
}

type signFixture struct {
	now          time.Time
	installation deployment.ID
	root         kubeca.CA
	custody      stubCustody
	opened       *int
	leaf         *ecdsa.PrivateKey
	claim        Claim
}

func newSignFixture(t *testing.T) signFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	installation, err := deployment.ParseID(mustID(t).String())
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, err := workspace.ParseID(mustID(t).String())
	if err != nil {
		t.Fatal(err)
	}
	networkID, err := network.ParseID(mustID(t).String())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	root, err := kubeca.NewRoot(kubeca.RootParams{
		ClusterDNSName: testDNSName, Subject: "root", NotBefore: now.Add(-48 * time.Hour),
		Lifetime: kubeca.DefaultRootLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := root.NewIntermediate(kubeca.IntermediateParams{
		Subject: "intermediate", NotBefore: now.Add(-time.Hour), Lifetime: kubeca.DefaultIntermediateLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	var dataKey kubeca.DataKey
	if _, err := rand.Read(dataKey[:]); err != nil {
		t.Fatal(err)
	}
	cluster, caID := mustID(t), mustID(t)
	sealed, err := kubeca.SealCA(dataKey, intermediate, installation.String(), cluster.String(), caID.String())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, digest := newCSR(t, leaf)
	opened := 0
	return signFixture{
		now: now, installation: installation, root: root, opened: &opened, leaf: leaf,
		custody: stubCustody{dataKey: dataKey, opened: &opened},
		claim: Claim{
			ID: mustID(t), ClaimToken: ClaimToken{7}, RequestID: [16]byte{1, 2, 3}, Scope: scope, DeviceID: mustID(t),
			ClusterID: cluster, ClusterName: testClusterName, WorkspaceCode: testWorkspaceCode,
			NetworkCode: testNetworkCode, CSR: csr, PublicKeySHA256: digest, Proof: ProofToken, Token: "token",
			Trust: &Trust{
				Version: 1, Issuer: "https://issuer.example.test", JWKS: []byte(`{"keys":[]}`),
				Namespace: "meshtransit", ServiceAccount: "gateway", PodName: "gateway-0",
			},
			Intermediate: &Intermediate{
				ID: caID, Version: 1, Certificate: intermediate.Certificate().Raw, SealedKey: sealed,
				ClusterDNSName: testDNSName, NotAfter: intermediate.Certificate().NotAfter, RootID: mustID(t),
				RootCertificate: root.Certificate().Raw,
				DataKey: kubeca.StoredDataKey{
					ID: mustID(t), Version: 1, Active: true,
					Wrapped: kubeca.WrappedKey{Custody: "file", KeyID: "k1", Ciphertext: []byte("wrapped")},
				},
			},
		},
	}
}

func newCSR(t *testing.T, key *ecdsa.PrivateKey) ([]byte, [sha256.Size]byte) {
	t.Helper()
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return csr, sha256.Sum256(spki)
}

func mustID(t *testing.T) publicid.ID {
	t.Helper()
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (fixture signFixture) signer(t *testing.T, renewalValid bool) *signer {
	t.Helper()
	suffix, err := dnsname.ParseSuffix(testSuffix)
	if err != nil {
		t.Fatal(err)
	}
	return newSigner(fixture.installation, suffix,
		func(raw string, trust Trust, now time.Time) (TokenUse, error) {
			if raw != "token" {
				return TokenUse{}, errors.New("refused")
			}
			return TokenUse{JTI: "jti-1", ExpiresAt: now.Add(10 * time.Minute), PodName: trust.PodName}, nil
		},
		func(publicKey []byte, handshakeHash [32]byte, requestID, serial [16]byte, csr, proof []byte) bool {
			return renewalValid && len(publicKey) > 0 && handshakeHash == [32]byte{9} && serial == [16]byte{5} &&
				requestID == fixture.claim.RequestID && bytes.Equal(csr, fixture.claim.CSR) && bytes.Equal(proof, []byte("sig"))
		})
}

// verified is the fixture's claim once a worker checked its token (§14
// R-M1): the claims replace the token.
func (fixture signFixture) verified(t *testing.T) Claim {
	t.Helper()
	claim := fixture.claim
	verified, reason := fixture.signer(t, true).checkToken(claim, fixture.now)
	if reason != "" {
		t.Fatalf("checkToken() refused %s", reason)
	}
	claim.Verified, claim.Token = &verified, ""
	return claim
}

func TestCheckToken(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		change func(*Claim)
		want   Reason
	}{
		"a valid token":       {change: func(*Claim) {}},
		"no trust":            {change: func(claim *Claim) { claim.Trust = nil }, want: ReasonTrustMissing},
		"an incomplete trust": {change: func(claim *Claim) { claim.Trust.PodName = "" }, want: ReasonTrustMissing},
		"a refused token":     {change: func(claim *Claim) { claim.Token = "forged" }, want: ReasonToken},
		"another pod's token": {change: func(claim *Claim) { claim.Trust.PodName = "gateway-1" }},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newSignFixture(t)
			claim := fixture.claim
			trust := *claim.Trust
			claim.Trust = &trust
			test.change(&claim)
			verified, reason := fixture.signer(t, true).checkToken(claim, fixture.now)
			if reason != test.want || (reason == "") != verified.Valid() {
				t.Fatalf("checkToken() = %+v, %q; want %q", verified, reason, test.want)
			}
			if reason == "" && (verified.Use.JTI != "jti-1" || verified.TrustVersion != 1 ||
				verified.Use.PodName != claim.Trust.PodName) {
				t.Fatalf("checkToken() = %+v", verified)
			}
		})
	}
}

func TestSignIssuesForTheClusterName(t *testing.T) {
	t.Parallel()
	fixture := newSignFixture(t)
	decided, err := fixture.signer(t, true).sign(t.Context(), fixture.custody, fixture.verified(t), fixture.now)
	if err != nil || decided.refuse != "" {
		t.Fatalf("sign() = %+v, %v", decided, err)
	}
	issue := decided.issue
	certificate, err := x509.ParseCertificate(issue.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(fixture.claim.Intermediate.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(fixture.root.Certificate())
	intermediates.AddCert(intermediate)
	if _, err := certificate.Verify(x509.VerifyOptions{
		DNSName: testDNSName, Roots: roots, Intermediates: intermediates, CurrentTime: fixture.now,
	}); err != nil {
		t.Fatalf("the certificate does not verify: %v", err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&fixture.leaf.PublicKey)
	if !bytes.Equal(issue.PublicKey, spki) || len(issue.Serial) != serialBytes || issue.Serial[0]&0x40 == 0 ||
		issue.Request != fixture.claim.ID || issue.ClaimToken != fixture.claim.ClaimToken ||
		issue.CA != fixture.claim.Intermediate.ID || issue.CAVersion != 1 || !issue.ID.IsValid() ||
		issue.Token == nil || issue.Token.JTI != "jti-1" || issue.Token.PodName != "gateway-0" ||
		issue.TrustVersion != 1 {
		t.Fatalf("issue = %+v", issue)
	}
	// Renew a third into the life, give or take a twenty-fourth (§14 R-H1):
	// a 24-hour certificate 7 to 9 hours after it is issued.
	life := issue.NotAfter.Sub(fixture.now)
	if earliest, latest := fixture.now.Add(life/3-life/24), fixture.now.Add(life/3+life/24); issue.RenewAt.Before(earliest) ||
		issue.RenewAt.After(latest) {
		t.Fatalf("renew at %v, want between %v and %v", issue.RenewAt, earliest, latest)
	}
}

func TestSignRenewsWithTheCurrentKey(t *testing.T) {
	t.Parallel()
	fixture := newSignFixture(t)
	claim := fixture.claim
	claim.Proof, claim.Token, claim.Trust = ProofRenewal, "", nil
	claim.HandshakeHash, claim.RenewalProof = [32]byte{9}, []byte("sig")
	claim.RenewalPublicKey, claim.RenewalNotAfter = []byte("spki"), fixture.now.Add(time.Hour)
	claim.RenewalSerial = [16]byte{5}
	decided, err := fixture.signer(t, true).sign(t.Context(), fixture.custody, claim, fixture.now)
	if err != nil || decided.refuse != "" || decided.issue.Token != nil {
		t.Fatalf("sign(renewal) = %+v, %v", decided, err)
	}
}

func TestSignRefuses(t *testing.T) {
	t.Parallel()
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	renewal := func(claim *Claim) {
		claim.Proof, claim.Token, claim.Trust = ProofRenewal, "", nil
		claim.HandshakeHash, claim.RenewalProof = [32]byte{9}, []byte("sig")
		claim.RenewalPublicKey = []byte("spki")
	}
	for name, test := range map[string]struct {
		change       func(*Claim, time.Time)
		renewalValid bool
		want         Reason
	}{
		"no intermediate": {change: func(claim *Claim, _ time.Time) { claim.Intermediate = nil }, want: ReasonNoCA},
		"an intermediate near its end": {
			change: func(claim *Claim, now time.Time) { claim.Intermediate.NotAfter = now.Add(30 * time.Minute) },
			want:   ReasonNoCA,
		},
		"another cluster's name": {
			change: func(claim *Claim, _ time.Time) { claim.ClusterName = "staging" }, want: ReasonMisnamed,
		},
		"no tenant codes": {change: func(claim *Claim, _ time.Time) { claim.NetworkCode = "" }, want: ReasonMisnamed},
		"no trust":        {change: func(claim *Claim, _ time.Time) { claim.Trust = nil }, want: ReasonTrustMissing},
		"a trust that moved on": {
			change: func(claim *Claim, _ time.Time) { claim.Trust.Version = 2 }, want: ReasonTrustMissing,
		},
		"a token no worker checked": {
			change: func(claim *Claim, _ time.Time) { claim.Verified, claim.Token = nil, "token" }, want: ReasonToken,
		},
		"a token that expired since it was checked": {
			change: func(claim *Claim, now time.Time) {
				verified := *claim.Verified
				verified.Use.ExpiresAt = now
				claim.Verified = &verified
			},
			want: ReasonTokenExpired,
		},
		"an expired renewed certificate": {
			change: func(claim *Claim, now time.Time) { renewal(claim); claim.RenewalNotAfter = now },
			want:   ReasonRenewalExpired,
		},
		"a wrong renewal signature": {
			change: func(claim *Claim, now time.Time) { renewal(claim); claim.RenewalNotAfter = now.Add(time.Hour) },
			want:   ReasonProof,
		},
		"no proof": {change: func(claim *Claim, _ time.Time) { claim.Proof = ProofUnknown }, want: ReasonProof},
		"a CSR for another key": {
			change: func(claim *Claim, _ time.Time) { _, claim.PublicKeySHA256 = newCSR(t, otherKey) },
			want:   ReasonCSR,
		},
		"a malformed CSR": {change: func(claim *Claim, _ time.Time) { claim.CSR = []byte("csr") }, want: ReasonCSR},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newSignFixture(t)
			claim := fixture.verified(t)
			intermediate, trust := *claim.Intermediate, *claim.Trust
			claim.Intermediate, claim.Trust = &intermediate, &trust
			test.change(&claim, fixture.now)
			decided, err := fixture.signer(t, test.renewalValid).sign(t.Context(), fixture.custody, claim, fixture.now)
			if err != nil || decided.refuse != test.want {
				t.Fatalf("sign() = %+v, %v; want refused %s", decided.refuse, err, test.want)
			}
		})
	}
}

func TestSignOpensAnIntermediateOnce(t *testing.T) {
	t.Parallel()
	fixture := newSignFixture(t)
	signer := fixture.signer(t, true)
	for range 2 {
		if decided, err := signer.sign(t.Context(), fixture.custody, fixture.verified(t), fixture.now); err != nil ||
			decided.refuse != "" {
			t.Fatalf("sign() = %+v, %v", decided, err)
		}
	}
	if *fixture.opened != 1 {
		t.Fatalf("opened %d times, want once", *fixture.opened)
	}
	// Past five minutes, or once the CA changed, it is opened again.
	if _, err := signer.sign(t.Context(), fixture.custody, fixture.verified(t), fixture.now.Add(cacheLifetime)); err != nil {
		t.Fatal(err)
	}
	signer.drop(fixture.claim.Intermediate.ID)
	if _, err := signer.sign(t.Context(), fixture.custody, fixture.verified(t), fixture.now); err != nil {
		t.Fatal(err)
	}
	if *fixture.opened != 3 {
		t.Fatalf("opened %d times, want 3", *fixture.opened)
	}
}

func TestSignReportsCustodyTrouble(t *testing.T) {
	t.Parallel()
	fixture := newSignFixture(t)
	fixture.custody.fail = kubeca.ErrUnavailable
	if _, err := fixture.signer(t, true).sign(t.Context(), fixture.custody, fixture.verified(t), fixture.now); !errors.Is(err,
		kubeca.ErrUnavailable) {
		t.Fatalf("sign() error = %v", err)
	}
	// A sealed key under another cluster does not open.
	fixture = newSignFixture(t)
	claim := fixture.verified(t)
	claim.ClusterID = mustID(t)
	if _, err := fixture.signer(t, true).sign(t.Context(), fixture.custody, claim, fixture.now); err == nil {
		t.Fatal("an intermediate sealed for another cluster opened")
	}
}
