package mtcpclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"slices"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// A gateway's certificate calls go on the session of its map stream once
// the map arrived: a token request is answered by Core's result for its
// request ID; a renewal is signed over that session's handshake; a session
// that ends answers the call waiting on it (mtcp-v1 §6.9). The map names
// the cluster's CAs with the map's revision (§7.10).
func TestGatewayStreamAsksForCertificates(t *testing.T) {
	t.Parallel()
	root, signing := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	renewal := make(chan [32]byte, 1)
	third := make(chan struct{}, 1)
	disco, _ := key.NewDiscoPrivate()
	discoKey := disco.Public()
	renewalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	core := provingCore(t, nil, func(s *coreSession) {
		if _, first, err := s.receive(5 * time.Second); err != nil {
			return
		} else if _, ok := first.(*mtcpv1.Ping); !ok {
			return
		}
		public := s.control.Public()
		_ = s.send(sharedmtcp.MessageKeyUpdate, &mtcpv1.KeyUpdate{
			Nonce:       []byte("n1"),
			ControlKeys: []*mtcpv1.KeyUpdate_ControlKey{{Key: public[:], NotAfterMs: time.Now().Add(time.Hour).UnixMilli()}},
		})
		snapshot := snapshotMessage(10)
		snapshot.Self.DiscoKey = discoKey[:]
		snapshot.Self.KubernetesCa = &mtcpv1.KubernetesCA{RootFingerprint: root, SigningFingerprint: signing}
		snapshot.NetworkRevisions = []*mtcpv1.NetworkRevision{{NetworkId: "n", Revision: 42}}
		_ = s.send(sharedmtcp.MessageMapSnapshot, snapshot)
		next := func() *mtcpv1.KubeCertRequest {
			for {
				_, message, err := s.receive(5 * time.Second)
				if err != nil {
					return nil
				}
				if request, ok := message.(*mtcpv1.KubeCertRequest); ok {
					return request
				}
			}
		}
		token := next()
		if token == nil || token.GetServiceAccountToken() != "pod-token" || len(token.GetRenewalProof()) != 0 {
			return
		}
		// A result for another request is not this call's answer.
		_ = s.send(sharedmtcp.MessageKubeCertResult, &mtcpv1.KubeCertResult{
			RequestId: bytes.Repeat([]byte{9}, 16),
			Outcome:   mtcpv1.KubeCertResult_REFUSED, Reason: "csr",
		})
		_ = s.send(sharedmtcp.MessageKubeCertResult, &mtcpv1.KubeCertResult{
			RequestId: token.GetRequestId(), Outcome: mtcpv1.KubeCertResult_ISSUED, Certificate: []byte("leaf"),
			Chain: [][]byte{[]byte("intermediate")}, RootFingerprint: root, IssuerFingerprint: signing,
			NotAfterMs: time.Now().Add(24 * time.Hour).UnixMilli(), RenewAtMs: time.Now().Add(8 * time.Hour).UnixMilli(),
			NetworkRevision: 42,
		})
		renewed := next()
		if renewed == nil || renewed.GetServiceAccountToken() != "" || len(renewed.GetRenewalSerial()) != 16 {
			return
		}
		// The proof binds this session's handshake.
		spki, _ := x509.MarshalPKIXPublicKey(&renewalKey.PublicKey)
		if sharedmtcp.VerifyKubeCertRenewal(spki, s.hash, [16]byte(renewed.GetRequestId()),
			[16]byte(renewed.GetRenewalSerial()), renewed.GetCsr(), renewed.GetRenewalProof()) {
			renewal <- s.hash
		}
		_ = s.send(sharedmtcp.MessageKubeCertResult, &mtcpv1.KubeCertResult{
			RequestId: renewed.GetRequestId(),
			Outcome:   mtcpv1.KubeCertResult_Outcome(99), Reason: "something new", RetryAfterMs: 1500,
		})
		// The third call waits until the session ends.
		if next() != nil {
			third <- struct{}{}
		}
		_, _, _ = s.receive(5 * time.Second)
	})
	core.set(func(fake *fakeCore) { fake.extra = append(fake.extra, kubeCertCapability) })
	trust := gatewayTrust(t, core)
	calls := make(chan controlplane.KubeCertCall)
	options := controlplane.NetmapOptions{
		Hostname: "meshgw-0", PinnedFingerprint: trust.Fingerprint,
		PeerProbePublicKey: "discokey:" + bytesHexOf(discoKey[:]), KubeCerts: calls,
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	mapped := make(chan networkmap.Snapshot, 4)
	done := make(chan error, 1)
	go func() {
		done <- core.gatewayClient().StreamNetmap(ctx, core.origin(), trust.Material, options,
			func(_ context.Context, snapshot networkmap.Snapshot) error {
				mapped <- snapshot
				return nil
			})
	}()
	select {
	case snapshot := <-mapped:
		if ca := snapshot.KubernetesCA; ca == nil || !bytes.Equal(ca.Root, root) || !bytes.Equal(ca.Signing, signing) ||
			ca.MapRevision != 42 {
			t.Fatalf("KubernetesCA = %+v", snapshot.KubernetesCA)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no map")
	}
	call := func(request controlplane.KubeCertRequest) controlplane.KubeCertReply {
		t.Helper()
		reply := make(chan controlplane.KubeCertReply, 1)
		select {
		case calls <- controlplane.KubeCertCall{Request: request, Reply: reply}:
		case <-time.After(5 * time.Second):
			t.Fatal("the stream took no call")
		}
		select {
		case answer := <-reply:
			return answer
		case <-time.After(10 * time.Second):
			t.Fatal("no answer")
		}
		return controlplane.KubeCertReply{}
	}
	issued := call(controlplane.KubeCertRequest{RequestID: [16]byte{1}, CSR: testCertCSR(t), Token: "pod-token"})
	if issued.Err != nil || issued.Result.Outcome != controlplane.KubeCertIssued ||
		string(issued.Result.Certificate) != "leaf" || issued.Result.NetworkRevision != 42 {
		t.Fatalf("issued = %+v", issued)
	}
	retried := call(controlplane.KubeCertRequest{
		RequestID: [16]byte{2}, CSR: testCertCSR(t), RenewalSerial: [16]byte{3}, RenewalKey: renewalKey,
	})
	if retried.Err != nil || retried.Result.Outcome != controlplane.KubeCertRetry ||
		retried.Result.RetryAfter != 1500*time.Millisecond {
		t.Fatalf("renewal = %+v", retried)
	}
	select {
	case <-renewal:
	case <-time.After(5 * time.Second):
		t.Fatal("the renewal was not signed over the session's handshake")
	}
	// The session ends while a call waits.
	reply := make(chan controlplane.KubeCertReply, 1)
	calls <- controlplane.KubeCertCall{Request: controlplane.KubeCertRequest{
		RequestID: [16]byte{4},
		CSR:       testCertCSR(t), Token: "pod-token",
	}, Reply: reply}
	select {
	case <-third:
	case <-time.After(5 * time.Second):
		t.Fatal("the third call was not sent")
	}
	cancel()
	select {
	case answer := <-reply:
		if !errors.Is(answer.Err, controlplane.ErrKubeCertSessionLost) {
			t.Fatalf("answer = %+v", answer)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting call was never answered")
	}
	<-done
	// The gateway declared gateway.cert1.
	if !slices.ContainsFunc(core.hello, func(hello *mtcpv1.ClientHello) bool {
		return slices.Contains(hello.GetCapabilities(), kubeCertCapability)
	}) {
		t.Fatal("gateway.cert1 not declared")
	}
}

// Without gateway.cert1 offered, a call is answered at once.
func TestGatewayCertificateCallWithoutTheCapability(t *testing.T) {
	t.Parallel()
	run := &sessionRun{stream: &netmapStream{client: NewGateway()}, s: &session{reply: &mtcpv1.ServerHello{}}}
	reply := make(chan controlplane.KubeCertReply, 1)
	if err := run.sendKubeCert(controlplane.KubeCertCall{
		Request: controlplane.KubeCertRequest{Token: "t"},
		Reply:   reply,
	}); err != nil {
		t.Fatal(err)
	}
	if answer := <-reply; !errors.Is(answer.Err, controlplane.ErrKubeCertUnsupported) || run.kubeCert != nil {
		t.Fatalf("answer = %+v", answer)
	}
	// meshd never takes calls, and no gateway takes them before a map.
	if (&sessionRun{stream: &netmapStream{client: New()}, mapped: true}).kubeCertCalls() != nil {
		t.Fatal("meshd takes certificate calls")
	}
	if (&sessionRun{stream: &netmapStream{client: NewGateway()}}).kubeCertCalls() != nil {
		t.Fatal("a gateway takes calls before its map")
	}
}

func TestDecodeKubeCertResult(t *testing.T) {
	t.Parallel()
	full := func() *mtcpv1.KubeCertResult {
		return &mtcpv1.KubeCertResult{
			Outcome: mtcpv1.KubeCertResult_ISSUED, Certificate: []byte("leaf"),
			Chain: [][]byte{[]byte("i")}, RootFingerprint: make([]byte, 32), IssuerFingerprint: make([]byte, 32),
			NotAfterMs: 2, RenewAtMs: 1,
		}
	}
	if got := decodeKubeCertResult(full()); got.Outcome != controlplane.KubeCertIssued {
		t.Fatalf("a full issue = %+v", got)
	}
	for name, change := range map[string]func(*mtcpv1.KubeCertResult){
		"no certificate": func(result *mtcpv1.KubeCertResult) { result.Certificate = nil },
		"no chain":       func(result *mtcpv1.KubeCertResult) { result.Chain = nil },
		"long chain":     func(result *mtcpv1.KubeCertResult) { result.Chain = make([][]byte, 5) },
		"short root":     func(result *mtcpv1.KubeCertResult) { result.RootFingerprint = []byte{1} },
		"no expiry":      func(result *mtcpv1.KubeCertResult) { result.NotAfterMs = 0 },
	} {
		result := full()
		change(result)
		if got := decodeKubeCertResult(result); got.Outcome != controlplane.KubeCertRetry || got.Reason != "internal" {
			t.Errorf("%s: %+v", name, got)
		}
	}
	if got := decodeKubeCertResult(&mtcpv1.KubeCertResult{RetryAfterMs: -5}); got.Outcome != controlplane.KubeCertRetry ||
		got.RetryAfter != 0 || got.Reason != "internal" {
		t.Fatalf("an empty result = %+v", got)
	}
}

func testCertCSR(t *testing.T) []byte {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// A call that timed out takes Core's late answer to its request on the
// next call, without sending again; a stale call, a busy session and a
// reply channel without room never send nor block (a4a review H1, M1, M3).
func TestGatewayCertificateCallEdges(t *testing.T) {
	t.Parallel()
	run := &sessionRun{
		stream: &netmapStream{client: NewGateway()},
		s:      &session{reply: &mtcpv1.ServerHello{Capabilities: []string{kubeCertCapability}}},
	}
	reply := make(chan controlplane.KubeCertReply, 1)
	run.kubeCert = &kubeCertInFlight{requestID: [16]byte{1}, reply: reply, timer: time.NewTimer(time.Hour)}
	run.timeOutKubeCert()
	if answer := <-reply; !errors.Is(answer.Err, controlplane.ErrKubeCertTimeout) || run.kubeCert != nil {
		t.Fatalf("timeout answer = %+v", answer)
	}
	request := append([]byte{1}, make([]byte, 15)...)
	// Another request's answer and a retry are not kept; the final one is.
	run.kubeCertResult(&mtcpv1.KubeCertResult{RequestId: []byte{1}, Outcome: mtcpv1.KubeCertResult_REFUSED})
	run.kubeCertResult(&mtcpv1.KubeCertResult{RequestId: request, Outcome: mtcpv1.KubeCertResult_RETRY, Reason: "busy"})
	run.kubeCertResult(&mtcpv1.KubeCertResult{
		RequestId: request, Outcome: mtcpv1.KubeCertResult_REFUSED, Reason: "token_used",
	})
	// The session has no connection: a send would panic, so none happens.
	if err := run.sendKubeCert(controlplane.KubeCertCall{
		Request: controlplane.KubeCertRequest{RequestID: [16]byte{1}}, Reply: reply,
	}); err != nil {
		t.Fatal(err)
	}
	if answer := <-reply; answer.Err != nil || answer.Result.Reason != "token_used" || run.kubeCertLate != nil {
		t.Fatalf("late answer = %+v", answer)
	}
	stale := controlplane.KubeCertCall{
		Request: controlplane.KubeCertRequest{RequestID: [16]byte{2}}, Reply: reply,
		Deadline: time.Now().Add(-time.Second),
	}
	if err := run.sendKubeCert(stale); err != nil {
		t.Fatal(err)
	}
	if answer := <-reply; !errors.Is(answer.Err, controlplane.ErrKubeCertTimeout) {
		t.Fatalf("stale answer = %+v", answer)
	}
	run.kubeCert = &kubeCertInFlight{requestID: [16]byte{3}, timer: time.NewTimer(time.Hour)}
	if err := run.sendKubeCert(controlplane.KubeCertCall{Reply: reply}); err != nil {
		t.Fatal(err)
	}
	if answer := <-reply; !errors.Is(answer.Err, controlplane.ErrKubeCertBusy) {
		t.Fatalf("busy answer = %+v", answer)
	}
	// Unbuffered, nil, or full: nothing blocks.
	if err := run.sendKubeCert(controlplane.KubeCertCall{Reply: make(chan controlplane.KubeCertReply)}); err != nil {
		t.Fatal(err)
	}
	full := make(chan controlplane.KubeCertReply, 1)
	full <- controlplane.KubeCertReply{}
	run.kubeCert = &kubeCertInFlight{requestID: [16]byte{4}, reply: full, timer: time.NewTimer(time.Hour)}
	run.endKubeCert(controlplane.ErrKubeCertSessionLost)
	if decoded := decodeKubeCertResult(&mtcpv1.KubeCertResult{RetryAfterMs: 1 << 62}); decoded.RetryAfter != time.Hour {
		t.Fatalf("retry after = %v", decoded.RetryAfter)
	}
}

// A malformed kubernetes_ca drops the CAs only, never the map; a gateway
// without certificate calls neither takes them nor declares gateway.cert1.
func TestGatewayMapStateKubernetesCA(t *testing.T) {
	t.Parallel()
	state := newMapState(false)
	state.takesKubernetesCA = true
	message := snapshotMessage(1)
	message.Self.KubernetesCa = &mtcpv1.KubernetesCA{SigningFingerprint: make([]byte, 32)}
	if err := state.applySnapshot(message); err != nil {
		t.Fatal(err)
	}
	snapshot, err := state.build(snapshotInput{revision: 1, now: time.Now()})
	if err != nil || snapshot.KubernetesCA != nil {
		t.Fatalf("build() = %+v, %v", snapshot.KubernetesCA, err)
	}
	if slices.Contains(streamCapabilities(controlplane.NetmapOptions{}, true), kubeCertCapability) {
		t.Fatal("a gateway without certificate calls declared gateway.cert1")
	}
}
