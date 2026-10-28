package mtcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/kubeca/certqueue"
	"meshtransit.net/core/internal/domain/node"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// fakeKubeCertificates answers certificate requests, optionally only once
// released.
type fakeKubeCertificates struct {
	mu          sync.Mutex
	requests    []certqueue.Request
	result      certqueue.Result
	release     chan struct{}
	unavailable bool
}

func (certificates *fakeKubeCertificates) Request(ctx context.Context, request certqueue.Request) certqueue.Result {
	certificates.mu.Lock()
	certificates.requests = append(certificates.requests, request)
	release, result := certificates.release, certificates.result
	certificates.mu.Unlock()
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return certqueue.Result{}
		}
	}
	return result
}

func (certificates *fakeKubeCertificates) Available(context.Context) (certqueue.Result, bool) {
	certificates.mu.Lock()
	defer certificates.mu.Unlock()
	if certificates.unavailable {
		return certqueue.Result{
			Outcome: certqueue.OutcomeRetry, Reason: certqueue.ReasonUnavailable,
			RetryAfter: time.Minute,
		}, false
	}
	return certqueue.Result{}, true
}

func (certificates *fakeKubeCertificates) calls() []certqueue.Request {
	certificates.mu.Lock()
	defer certificates.mu.Unlock()
	return slices.Clone(certificates.requests)
}

func testCSR(t *testing.T, curve elliptic.Curve) ([]byte, [32]byte) {
	t.Helper()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return csr, sha256.Sum256(spki)
}

// kubeCertFixture is a gateway session that negotiated gateway.cert1 and
// whose stream holds its presence.
func kubeCertFixture(t *testing.T, certificates *fakeKubeCertificates) *conversationFixture {
	t.Helper()
	f := gatewayFixture(t, &fakeMachineKeyRotations{})
	f.session.capabilities = append(f.session.capabilities, CapabilityKubeCert)
	f.talk.application.options.KubeCertificates = certificates
	f.run()
	f.expectStream(node.Key(f.session.Hello().GetNodeKey()))
	return f
}

func (f *conversationFixture) askKubeCert(request *mtcpv1.KubeCertRequest) *mtcpv1.KubeCertResult {
	f.t.Helper()
	if err := f.talk.Receive(f.t.Context(), sharedmtcp.MessageKubeCertRequest, request); err != nil {
		f.t.Fatalf("Receive() = %v, want the session kept", err)
	}
	return f.expectPast(sharedmtcp.MessageKubeCertResult).(*mtcpv1.KubeCertResult)
}

func TestKubeCertIssued(t *testing.T) {
	t.Parallel()
	notAfter := time.Now().Add(24 * time.Hour).Truncate(time.Millisecond)
	certificates := &fakeKubeCertificates{result: certqueue.Result{
		Outcome: certqueue.OutcomeIssued,
		Issued: certqueue.Stored{
			Certificate: []byte("leaf"), Chain: [][]byte{[]byte("intermediate")},
			RootFingerprint: make([]byte, 32), IssuerFingerprint: make([]byte, 32), NotAfter: notAfter,
			RenewAt: notAfter.Add(-16 * time.Hour), NetworkRevision: 9,
		},
	}}
	f := kubeCertFixture(t, certificates)
	csr, digest := testCSR(t, elliptic.P256())
	requestID := repeat(7, 16)
	got := f.askKubeCert(&mtcpv1.KubeCertRequest{
		RequestId: requestID, Csr: csr,
		ServiceAccountToken: f.podToken,
	})
	if got.GetOutcome() != mtcpv1.KubeCertResult_ISSUED || string(got.GetRequestId()) != string(requestID) ||
		string(got.GetCertificate()) != "leaf" || len(got.GetChain()) != 1 || got.GetNetworkRevision() != 9 ||
		got.GetNotAfterMs() != notAfter.UnixMilli() || got.GetReason() != "" {
		t.Fatalf("result %v", got)
	}
	calls := certificates.calls()
	machine := node.MachineKey(f.session.Machine()).Fingerprint()
	proven := node.Key(f.session.Hello().GetNodeKey()).Bytes()
	if len(calls) != 1 || calls[0].Token != f.podToken || calls[0].Renewal() || calls[0].PublicKeySHA256 != digest ||
		calls[0].MachineFingerprint != machine || calls[0].NodeKey != proven || !calls[0].ID.IsValid() ||
		calls[0].RequestID != [16]byte(requestID) {
		t.Fatalf("queued %+v", calls)
	}
}

func TestKubeCertRenewalCarriesTheSession(t *testing.T) {
	t.Parallel()
	certificates := &fakeKubeCertificates{result: certqueue.Result{
		Outcome: certqueue.OutcomeRefused,
		Reason:  "proof",
	}}
	f := kubeCertFixture(t, certificates)
	csr, _ := testCSR(t, elliptic.P256())
	got := f.askKubeCert(&mtcpv1.KubeCertRequest{
		RequestId: repeat(1, 16), Csr: csr,
		RenewalSerial: repeat(2, 16), RenewalProof: []byte("signature"),
	})
	if got.GetOutcome() != mtcpv1.KubeCertResult_REFUSED || got.GetReason() != "proof" {
		t.Fatalf("result %v", got)
	}
	calls := certificates.calls()
	if len(calls) != 1 || !calls[0].Renewal() || calls[0].HandshakeHash != f.session.HandshakeHash() ||
		calls[0].RenewalSerial != [16]byte(repeat(2, 16)) || string(calls[0].RenewalProof) != "signature" {
		t.Fatalf("queued %+v", calls)
	}
}

// A request of the wrong form is refused before anything is queued (§3
// step 2, 3).
func TestKubeCertRefusesMalformedRequests(t *testing.T) {
	t.Parallel()
	csr, _ := testCSR(t, elliptic.P256())
	p384, _ := testCSR(t, elliptic.P384())
	for name, request := range map[string]func(token string) *mtcpv1.KubeCertRequest{
		"no CSR": func(token string) *mtcpv1.KubeCertRequest { return &mtcpv1.KubeCertRequest{ServiceAccountToken: token} },
		"garbage CSR": func(token string) *mtcpv1.KubeCertRequest {
			return &mtcpv1.KubeCertRequest{Csr: []byte("csr"), ServiceAccountToken: token}
		},
		"a P-384 key": func(token string) *mtcpv1.KubeCertRequest {
			return &mtcpv1.KubeCertRequest{Csr: p384, ServiceAccountToken: token}
		},
		"no proof": func(string) *mtcpv1.KubeCertRequest { return &mtcpv1.KubeCertRequest{Csr: csr} },
		"both proofs": func(token string) *mtcpv1.KubeCertRequest {
			return &mtcpv1.KubeCertRequest{
				Csr: csr, ServiceAccountToken: token, RenewalSerial: repeat(2, 16),
				RenewalProof: []byte("signature"),
			}
		},
		"a short serial": func(string) *mtcpv1.KubeCertRequest {
			return &mtcpv1.KubeCertRequest{Csr: csr, RenewalSerial: repeat(2, 8), RenewalProof: []byte("signature")}
		},
		"a renewal proof too short": func(string) *mtcpv1.KubeCertRequest {
			return &mtcpv1.KubeCertRequest{Csr: csr, RenewalSerial: repeat(2, 16), RenewalProof: repeat(3, 7)}
		},
		"a renewal proof too long": func(string) *mtcpv1.KubeCertRequest {
			return &mtcpv1.KubeCertRequest{Csr: csr, RenewalSerial: repeat(2, 16), RenewalProof: repeat(3, 73)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			certificates := &fakeKubeCertificates{}
			f := kubeCertFixture(t, certificates)
			asked := request(f.podToken)
			asked.RequestId = repeat(4, 16)
			got := f.askKubeCert(asked)
			want := certqueue.ReasonInvalid
			if len(asked.GetCsr()) == 0 || name == "garbage CSR" || name == "a P-384 key" {
				want = certqueue.ReasonCSR
			}
			if got.GetOutcome() != mtcpv1.KubeCertResult_REFUSED || got.GetReason() != want {
				t.Fatalf("result %v", got)
			}
			if len(certificates.calls()) != 0 {
				t.Fatal("a malformed request was queued")
			}
		})
	}
}

// One request waits per session; the session goes on meanwhile.
func TestKubeCertOneRequestWaits(t *testing.T) {
	t.Parallel()
	certificates := &fakeKubeCertificates{
		release: make(chan struct{}),
		result: certqueue.Result{
			Outcome: certqueue.OutcomeRetry, Reason: certqueue.ReasonTimeout,
			RetryAfter: 2 * time.Second,
		},
	}
	f := kubeCertFixture(t, certificates)
	csr, _ := testCSR(t, elliptic.P256())
	request := &mtcpv1.KubeCertRequest{RequestId: repeat(5, 16), Csr: csr, ServiceAccountToken: f.podToken}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageKubeCertRequest, request); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(certificates.calls()) == 1 })
	second := f.askKubeCert(request)
	if second.GetOutcome() != mtcpv1.KubeCertResult_RETRY || second.GetReason() != certqueue.ReasonBusy ||
		second.GetRetryAfterMs() < kubeCertBusyRetry.Milliseconds()/2 ||
		second.GetRetryAfterMs() >= kubeCertBusyRetry.Milliseconds()*3/2 {
		t.Fatalf("second request %v", second)
	}
	close(certificates.release)
	first := f.expectPast(sharedmtcp.MessageKubeCertResult).(*mtcpv1.KubeCertResult)
	if first.GetOutcome() != mtcpv1.KubeCertResult_RETRY || first.GetReason() != certqueue.ReasonTimeout ||
		first.GetRetryAfterMs() != 2000 {
		t.Fatalf("first request %v", first)
	}
	// The slot is free again.
	waitFor(t, func() bool { return !f.talk.kubeCertPending.Load() })
}

// A gateway whose stream does not hold its presence gets no certificate.
func TestKubeCertNeedsThePresence(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		presence *fakeGatewayPresence
		outcome  mtcpv1.KubeCertResult_Outcome
		reason   string
	}{
		"held by another stream": {
			presence: &fakeGatewayPresence{state: mapsession.GatewayRotationNotHeld},
			outcome:  mtcpv1.KubeCertResult_REFUSED, reason: certqueue.ReasonContested,
		},
		"contested": {
			presence: &fakeGatewayPresence{state: mapsession.GatewayRotationContested},
			outcome:  mtcpv1.KubeCertResult_REFUSED, reason: certqueue.ReasonContested,
		},
		"redis failed": {
			presence: &fakeGatewayPresence{err: errors.New("redis: down")},
			outcome:  mtcpv1.KubeCertResult_RETRY, reason: certqueue.ReasonPresence,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			certificates := &fakeKubeCertificates{}
			f := gatewayFixture(t, &fakeMachineKeyRotations{})
			f.session.capabilities = append(f.session.capabilities, CapabilityKubeCert)
			f.talk.application.options.KubeCertificates = certificates
			f.talk.application.options.GatewayPresence = test.presence
			f.run()
			f.expectStream(node.Key(f.session.Hello().GetNodeKey()))
			csr, _ := testCSR(t, elliptic.P256())
			got := f.askKubeCert(&mtcpv1.KubeCertRequest{
				RequestId: repeat(6, 16), Csr: csr,
				ServiceAccountToken: f.podToken,
			})
			if got.GetOutcome() != test.outcome || got.GetReason() != test.reason || got.GetRetryAfterMs() == 0 {
				t.Fatalf("result %v", got)
			}
			if test.reason == certqueue.ReasonContested && (got.GetRetryAfterMs() < time.Minute.Milliseconds() ||
				got.GetRetryAfterMs() >= 90*time.Second.Milliseconds()) {
				t.Fatalf("contested retry after %d ms", got.GetRetryAfterMs())
			}
			if len(certificates.calls()) != 0 {
				t.Fatal("queued without the presence")
			}
		})
	}
}

func TestKubeCertRefusedOutsideTheCapability(t *testing.T) {
	t.Parallel()
	csr, _ := testCSR(t, elliptic.P256())
	// Without gateway.cert1: an Error, the session kept.
	f := gatewayFixture(t, &fakeMachineKeyRotations{})
	f.talk.application.options.KubeCertificates = &fakeKubeCertificates{}
	f.run()
	f.expectStream(node.Key(f.session.Hello().GetNodeKey()))
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageKubeCertRequest,
		&mtcpv1.KubeCertRequest{RequestId: repeat(1, 16), Csr: csr}); err != nil {
		t.Fatal(err)
	}
	if got := f.expectPast(sharedmtcp.MessageError).(*mtcpv1.Error); got.GetCode() != mtcpv1.Error_UNSUPPORTED ||
		got.GetFatal() {
		t.Fatalf("error %v", got)
	}
	// No request ID: nothing to answer about.
	g := kubeCertFixture(t, &fakeKubeCertificates{})
	if err := g.talk.Receive(t.Context(), sharedmtcp.MessageKubeCertRequest,
		&mtcpv1.KubeCertRequest{RequestId: repeat(1, 8), Csr: csr}); err != nil {
		t.Fatal(err)
	}
	if got := g.expectPast(sharedmtcp.MessageError).(*mtcpv1.Error); got.GetCode() != mtcpv1.Error_INVALID ||
		got.GetFatal() {
		t.Fatalf("error %v", got)
	}
	// An ordinary Device is no gateway.
	h := newConversationFixture(t, sharedmtcp.MessagePing)
	h.session.capabilities = append(h.session.capabilities, CapabilityKubeCert)
	h.talk.application.options.KubeCertificates = &fakeKubeCertificates{}
	h.run()
	got := h.askKubeCert(&mtcpv1.KubeCertRequest{RequestId: repeat(1, 16), Csr: csr})
	if got.GetOutcome() != mtcpv1.KubeCertResult_REFUSED || got.GetReason() != certqueue.ReasonNotGateway {
		t.Fatalf("result %v", got)
	}
}

func TestKubeCertResultCapsTheChain(t *testing.T) {
	t.Parallel()
	chain := make([][]byte, sharedmtcp.KubeCertChainMaximum+2)
	encoded := encodeKubeCertResult(repeat(1, 16), certqueue.Result{
		Outcome: certqueue.OutcomeIssued,
		Reason:  "ignored", Issued: certqueue.Stored{Chain: chain},
	})
	if len(encoded.GetChain()) != sharedmtcp.KubeCertChainMaximum || encoded.GetReason() != "" {
		t.Fatalf("encoded %v", encoded)
	}
	if retry := encodeKubeCertResult(nil, certqueue.Result{}); retry.GetOutcome() != mtcpv1.KubeCertResult_RETRY ||
		retry.GetReason() != certqueue.ReasonInternal {
		t.Fatalf("a zero result encoded %v", retry)
	}
}

// No worker signs: answered at once, without checking the presence.
func TestKubeCertUnavailableFirst(t *testing.T) {
	t.Parallel()
	certificates := &fakeKubeCertificates{unavailable: true}
	f := kubeCertFixture(t, certificates)
	presence := &fakeGatewayPresence{state: mapsession.GatewayRotationHeld}
	f.talk.application.options.GatewayPresence = presence
	csr, _ := testCSR(t, elliptic.P256())
	got := f.askKubeCert(&mtcpv1.KubeCertRequest{RequestId: repeat(8, 16), Csr: csr, ServiceAccountToken: f.podToken})
	if got.GetOutcome() != mtcpv1.KubeCertResult_RETRY || got.GetReason() != certqueue.ReasonUnavailable ||
		len(presence.checked()) != 0 || len(certificates.calls()) != 0 {
		t.Fatalf("result %v, presence checks %d", got, len(presence.checked()))
	}
}

// Run ends while a request waits: the wait is cancelled and joined before
// Run returns, and a request after that is refused, never started (review
// a3b Go H1).
func TestKubeCertWorkEndsWithRun(t *testing.T) {
	t.Parallel()
	certificates := &fakeKubeCertificates{release: make(chan struct{})}
	f := gatewayFixture(t, &fakeMachineKeyRotations{})
	f.session.capabilities = append(f.session.capabilities, CapabilityKubeCert)
	f.talk.application.options.KubeCertificates = certificates
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- f.talk.Run(ctx) }()
	f.expectStream(node.Key(f.session.Hello().GetNodeKey()))
	csr, _ := testCSR(t, elliptic.P256())
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageKubeCertRequest,
		&mtcpv1.KubeCertRequest{RequestId: repeat(9, 16), Csr: csr, ServiceAccountToken: f.podToken}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(certificates.calls()) == 1 })
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return while a request waited")
	}
	if f.talk.kubeCertPending.Load() {
		t.Fatal("the request's work was not joined")
	}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageKubeCertRequest,
		&mtcpv1.KubeCertRequest{RequestId: repeat(10, 16), Csr: csr, ServiceAccountToken: f.podToken}); err != nil {
		t.Fatal(err)
	}
	got := f.expectPast(sharedmtcp.MessageKubeCertResult).(*mtcpv1.KubeCertResult)
	if got.GetOutcome() != mtcpv1.KubeCertResult_RETRY || got.GetReason() != certqueue.ReasonInternal ||
		len(certificates.calls()) != 1 {
		t.Fatalf("a request after Run ended: %v", got)
	}
}
