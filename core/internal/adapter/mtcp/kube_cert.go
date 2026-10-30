package mtcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/kubeca/certqueue"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/kubejoin"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// CapabilityKubeCert is gateway.cert1: a Kubernetes gateway asks Core for
// its replica certificate (mtcp-v1 §6.9).
const CapabilityKubeCert = "gateway.cert1"

// CapabilityKubeProfiles is gateway.kube.v2: a gateway takes its peers'
// access narrowed by access profiles, and its cluster's scope table
// (mtcp-v1 §7.12, K2). Offered only with gateway.kube.v1.
const CapabilityKubeProfiles = "gateway.kube.v2"

// CapabilityKubeAudit is gateway.audit1: a Kubernetes gateway has Core
// record type A operations before forwarding them (mtcp-v1 §6.10).
const CapabilityKubeAudit = "gateway.audit1"

const (
	// kubeCertBusyRetry is the wait, jittered, after a request sent while
	// another one of the session waits.
	kubeCertBusyRetry = time.Second
	// kubeCertPresenceRetry is the wait, jittered, after the presence could
	// not be checked.
	kubeCertPresenceRetry = 2 * time.Second
	// kubeCertContestedRetry and kubeCertContestedSpread: a refusal because
	// another stream holds the gateway's presence waits 60 to 90 s (§3 step
	// 5, review a3b Go L1).
	kubeCertContestedRetry  = time.Minute
	kubeCertContestedSpread = 30 * time.Second
)

// KubeCertificates queues a gateway's certificate request and waits for
// its result (certqueue.Service). Available answers, without I/O most of
// the time, whether a worker signs at all.
type KubeCertificates interface {
	Available(ctx context.Context) (certqueue.Result, bool)
	Request(ctx context.Context, request certqueue.Request) certqueue.Result
}

// kubeCert answers KubeCertRequest (mtcp-v1 §6.9, a3 §3, §14). Every
// answer about one request is a KubeCertResult (R-M4); an Error only for a
// request that cannot be answered (no request ID, or the capability not
// negotiated). The wait runs on its own goroutine, one per session, so the
// session goes on serving its map meanwhile.
func (conversation *conversation) kubeCert(ctx context.Context, request *mtcpv1.KubeCertRequest) error {
	application := conversation.application
	certificates := application.options.KubeCertificates
	if certificates == nil || !conversation.session.Supports(CapabilityKubeCert) {
		application.options.Metrics.kubeCertUnanswered("unsupported")
		return conversation.sendError(mtcpv1.Error_UNSUPPORTED, "gateway certificates are not available", 0)
	}
	requestID := request.GetRequestId()
	if len(requestID) != sharedmtcp.KubeCertRequestIDSize {
		application.options.Metrics.kubeCertUnanswered("invalid")
		return conversation.sendError(mtcpv1.Error_INVALID, "a certificate request needs a 16-byte request ID", 0)
	}
	// Every answer is counted (review a3b Go M7).
	answer := func(result certqueue.Result) error {
		application.options.Metrics.kubeCertAnswered(result, 0)
		return conversation.sendKubeCertResult(requestID, result)
	}
	if wait, ok := conversation.identity.spend(application.now(), 1); !ok {
		application.options.Metrics.limited(limitIdentity)
		return answer(certqueue.Result{Outcome: certqueue.OutcomeRetry, Reason: certqueue.ReasonLimited,
			RetryAfter: wait})
	}
	if !conversation.isGateway() {
		return answer(certqueue.Result{Outcome: certqueue.OutcomeRefused, Reason: certqueue.ReasonNotGateway})
	}
	conversation.mu.Lock()
	proven := conversation.provenNodeKey
	conversation.mu.Unlock()
	if !proven.IsValid() {
		return answer(certqueue.Result{Outcome: certqueue.OutcomeRefused, Reason: certqueue.ReasonNotProven})
	}
	queued, reason := kubeCertRequest(request, node.MachineKey(conversation.session.Machine()), proven,
		conversation.session.HandshakeHash())
	if reason != "" {
		return answer(certqueue.Result{Outcome: certqueue.OutcomeRefused, Reason: reason})
	}
	if !conversation.kubeCertPending.CompareAndSwap(false, true) {
		return answer(certqueue.Result{Outcome: certqueue.OutcomeRetry, Reason: certqueue.ReasonBusy,
			RetryAfter: certqueue.Jittered(kubeCertBusyRetry)})
	}
	workCtx, started := conversation.startKubeCert(ctx)
	if !started {
		conversation.kubeCertPending.Store(false)
		return answer(certqueue.Result{Outcome: certqueue.OutcomeRetry, Reason: certqueue.ReasonInternal,
			RetryAfter: certqueue.Jittered(kubeCertPresenceRetry)})
	}
	go func() {
		defer conversation.kubeCertWork.Done()
		defer conversation.kubeCertPending.Store(false)
		started := application.now()
		result := conversation.requestKubeCert(workCtx, certificates, queued)
		if workCtx.Err() != nil {
			return // the conversation ended; the queue abandoned the request
		}
		application.options.Metrics.kubeCertAnswered(result, application.now().Sub(started))
		_ = conversation.sendKubeCertResult(requestID, result)
	}()
	return nil
}

// startKubeCert registers one certificate request's work, under a context
// the conversation cancels when Run ends; false once it ended.
func (conversation *conversation) startKubeCert(ctx context.Context) (context.Context, bool) {
	conversation.kubeCertMu.Lock()
	defer conversation.kubeCertMu.Unlock()
	if conversation.kubeCertClosed {
		return nil, false
	}
	if conversation.kubeCertCtx == nil {
		conversation.kubeCertCtx, conversation.kubeCertCancel = context.WithCancel(ctx)
	}
	conversation.kubeCertWork.Add(1)
	return conversation.kubeCertCtx, true
}

// closeKubeCerts ends the conversation's certificate work: no new request
// starts, the waiting one is cancelled (its request abandoned), and Run
// returns only once it finished.
func (conversation *conversation) closeKubeCerts() {
	conversation.kubeCertMu.Lock()
	conversation.kubeCertClosed = true
	if conversation.kubeCertCancel != nil {
		conversation.kubeCertCancel()
	}
	conversation.kubeCertMu.Unlock()
	conversation.kubeCertWork.Wait()
}

// requestKubeCert checks the gateway's presence, then queues and waits.
func (conversation *conversation) requestKubeCert(ctx context.Context, certificates KubeCertificates,
	queued certqueue.Request,
) certqueue.Result {
	// No worker signs: answered from the cached state, before the presence
	// costs a Redis round trip (review a3b Go L4).
	if result, available := certificates.Available(ctx); !available {
		return result
	}
	if result, held := conversation.kubeCertPresence(ctx); !held {
		return result
	}
	id, err := publicid.New()
	if err != nil {
		return certqueue.Result{Outcome: certqueue.OutcomeRetry, Reason: certqueue.ReasonInternal,
			RetryAfter: 5 * time.Second}
	}
	queued.ID = id
	return certificates.Request(ctx, queued)
}

// kubeCertPresence reports whether the session's stream holds the
// gateway's presence (§3 step 5): unknown is a retry; held by another
// stream, or contested, is refused for at least a minute (review M3).
func (conversation *conversation) kubeCertPresence(ctx context.Context) (certqueue.Result, bool) {
	application := conversation.application
	unknown := certqueue.Result{Outcome: certqueue.OutcomeRetry, Reason: certqueue.ReasonPresence,
		RetryAfter: certqueue.Jittered(kubeCertPresenceRetry)}
	contested := certqueue.Result{Outcome: certqueue.OutcomeRefused, Reason: certqueue.ReasonContested,
		RetryAfter: kubeCertContestedRetry - kubeCertContestedSpread/2 + certqueue.Jittered(kubeCertContestedSpread)}
	claim, claimed := conversation.awaitClaim(ctx)
	store := application.options.GatewayPresence
	if !claimed || store == nil {
		return unknown, false
	}
	checkCtx, cancel := context.WithTimeout(ctx, application.gatewayCheckTimeout)
	defer cancel()
	state, err := store.CheckGatewayRotation(checkCtx, claim.lease)
	switch {
	case err != nil:
		return unknown, false
	case state != mapsession.GatewayRotationHeld:
		return contested, false
	case conversation.session.ctx.Err() != nil || !conversation.session.server.holds(conversation.session):
		return contested, false
	}
	return certqueue.Result{}, true
}

// kubeCertRequest checks a request's form (§3 step 2, 3): a P-256 CSR
// whose signature holds (else "csr": a new key is needed), and exactly one
// of a pod token and a renewal proof, each within its size (else
// "invalid": the request itself is wrong, review a3b Go L3). The worker
// checks the proofs themselves.
func kubeCertRequest(request *mtcpv1.KubeCertRequest, machine node.MachineKey, nodeKey node.Key,
	handshakeHash [32]byte,
) (certqueue.Request, string) {
	csr := request.GetCsr()
	if len(csr) == 0 || len(csr) > sharedmtcp.KubeCertCSRMaximum {
		return certqueue.Request{}, certqueue.ReasonCSR
	}
	parsed, err := x509.ParseCertificateRequest(csr)
	if err != nil || parsed.CheckSignature() != nil || parsed.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return certqueue.Request{}, certqueue.ReasonCSR
	}
	key, isECDSA := parsed.PublicKey.(*ecdsa.PublicKey)
	if !isECDSA || key.Curve != elliptic.P256() {
		return certqueue.Request{}, certqueue.ReasonCSR
	}
	token, serial, proof := request.GetServiceAccountToken(), request.GetRenewalSerial(), request.GetRenewalProof()
	withToken := token != "" && len(serial) == 0 && len(proof) == 0 && len(token) <= kubejoin.MaxTokenSize
	withRenewal := token == "" && len(serial) == sharedmtcp.KubeCertSerialSize &&
		len(proof) >= sharedmtcp.KubeCertRenewalProofMinimum && len(proof) <= sharedmtcp.KubeCertRenewalProofMaximum
	if !withToken && !withRenewal {
		return certqueue.Request{}, certqueue.ReasonInvalid
	}
	queued := certqueue.Request{
		MachineFingerprint: machine.Fingerprint(), NodeKey: nodeKey.Bytes(),
		RequestID: [16]byte(request.GetRequestId()), CSR: csr,
		PublicKeySHA256: sha256.Sum256(parsed.RawSubjectPublicKeyInfo), Token: token,
	}
	if withRenewal {
		queued.HandshakeHash, queued.RenewalSerial, queued.RenewalProof = handshakeHash, [16]byte(serial), proof
	}
	return queued, ""
}

// sendKubeCertResult sends one request's answer.
func (conversation *conversation) sendKubeCertResult(requestID []byte, result certqueue.Result) error {
	return conversation.session.Send(sharedmtcp.MessageKubeCertResult, encodeKubeCertResult(requestID, result))
}

func encodeKubeCertResult(requestID []byte, result certqueue.Result) *mtcpv1.KubeCertResult {
	encoded := &mtcpv1.KubeCertResult{RequestId: requestID, Reason: result.Reason}
	if result.RetryAfter > 0 {
		encoded.RetryAfterMs = result.RetryAfter.Milliseconds()
	}
	switch result.Outcome {
	case certqueue.OutcomeIssued:
		issued := result.Issued
		chain := issued.Chain
		if len(chain) > sharedmtcp.KubeCertChainMaximum {
			chain = chain[:sharedmtcp.KubeCertChainMaximum]
		}
		encoded.Outcome, encoded.Reason = mtcpv1.KubeCertResult_ISSUED, ""
		encoded.Certificate, encoded.Chain = issued.Certificate, chain
		encoded.RootFingerprint, encoded.IssuerFingerprint = issued.RootFingerprint, issued.IssuerFingerprint
		encoded.NotAfterMs, encoded.RenewAtMs = issued.NotAfter.UnixMilli(), issued.RenewAt.UnixMilli()
		encoded.NetworkRevision = issued.NetworkRevision
	case certqueue.OutcomeRefused:
		encoded.Outcome = mtcpv1.KubeCertResult_REFUSED
	default:
		encoded.Outcome = mtcpv1.KubeCertResult_RETRY
		if encoded.Reason == "" {
			encoded.Reason = certqueue.ReasonInternal
		}
	}
	return encoded
}
