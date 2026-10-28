package mtcpclient

import (
	"bytes"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// kubeCertCapability is gateway.cert1: the gateway asks for its replica
// certificate on the session of its map stream (mtcp-v1 §6.9).
const kubeCertCapability = "gateway.cert1"

// kubeCertWait bounds the wait for one answer: longer than Core's worst
// case (its 5 s queue wait, the presence claim and its reads, a4 review M2).
const kubeCertWait = 20 * time.Second

// maximumKubeCertRetry caps the wait Core may ask for (a4a review L4).
const maximumKubeCertRetry = time.Hour

// kubeCertInFlight is the call a session sent and waits on.
type kubeCertInFlight struct {
	requestID [16]byte
	reply     chan<- controlplane.KubeCertReply
	timer     *time.Timer
}

// kubeCertLate is Core's answer to a request whose call timed out: the next
// call for that request takes it without sending again (a4a review M1).
type kubeCertLate struct {
	requestID [16]byte
	timedOut  bool
	result    *controlplane.KubeCertResult
}

// replyKubeCert hands a call its answer without ever waiting: a reply
// channel without room loses the answer, never the session (a4a review
// H1).
func replyKubeCert(reply chan<- controlplane.KubeCertReply, answer controlplane.KubeCertReply) {
	if reply == nil {
		return
	}
	select {
	case reply <- answer:
	default:
	}
}

// kubeCertCalls is the stream's call channel once the session holds a map:
// Core serves a gateway's request only while its stream holds the presence
// (a4 review L3). nil otherwise, which blocks in a select.
func (run *sessionRun) kubeCertCalls() <-chan controlplane.KubeCertCall {
	if !run.mapped || run.stream.client.gateway == nil {
		return nil
	}
	return run.stream.options.KubeCerts
}

// kubeCertTimeout is the in-flight call's timer channel, or nil.
func (run *sessionRun) kubeCertTimeout() <-chan time.Time {
	if run.kubeCert == nil {
		return nil
	}
	return run.kubeCert.timer.C
}

// sendKubeCert sends one call on the session. A call it cannot send, or a
// late answer already holds, is answered at once; a send that fails ends
// the session.
func (run *sessionRun) sendKubeCert(call controlplane.KubeCertCall) error {
	answer := func(err error) {
		replyKubeCert(call.Reply, controlplane.KubeCertReply{Err: err})
	}
	request := call.Request
	switch {
	case call.Reply == nil || cap(call.Reply) == 0:
		return nil // nobody could take the answer
	case !call.Deadline.IsZero() && !time.Now().Before(call.Deadline):
		answer(controlplane.ErrKubeCertTimeout) // stale: never sent (a4a review M3)
		return nil
	case run.kubeCert != nil:
		answer(controlplane.ErrKubeCertBusy)
		return nil
	case !run.supports(kubeCertCapability):
		// Decided from the negotiated capability, never from an Error
		// (an Error names no request, a4 review M3).
		answer(controlplane.ErrKubeCertUnsupported)
		return nil
	}
	if late := run.kubeCertLate; late != nil && late.requestID == request.RequestID && late.result != nil {
		run.kubeCertLate = nil
		replyKubeCert(call.Reply, controlplane.KubeCertReply{Result: *late.result})
		return nil
	}
	message := &mtcpv1.KubeCertRequest{RequestId: bytes.Clone(request.RequestID[:]), Csr: request.CSR}
	if request.Renewal() {
		// The proof binds this session's handshake (§6.9).
		proof, err := sharedmtcp.SignKubeCertRenewal(request.RenewalKey, run.s.noise.HandshakeHash(),
			request.RequestID, request.RenewalSerial, request.CSR)
		if err != nil {
			answer(err)
			return nil
		}
		message.RenewalSerial, message.RenewalProof = bytes.Clone(request.RenewalSerial[:]), proof
	} else {
		message.ServiceAccountToken = request.Token
	}
	wait := run.kubeCertWait
	if wait <= 0 {
		wait = kubeCertWait
	}
	if late := run.kubeCertLate; late != nil && late.requestID != request.RequestID {
		// Sending the same request again keeps listening for the timed-out
		// send's answer (a4a review L).
		run.kubeCertLate = nil
	}
	run.kubeCert = &kubeCertInFlight{requestID: request.RequestID, reply: call.Reply, timer: time.NewTimer(wait)}
	if err := run.send(sharedmtcp.MessageKubeCertRequest, message); err != nil {
		run.endKubeCert(controlplane.ErrKubeCertSessionLost)
		return err
	}
	return nil
}

// kubeCertResult answers the in-flight call with Core's result for its
// request. A final answer (issued, refused) to a request whose call timed
// out is kept for the next call of that request; any other is dropped.
func (run *sessionRun) kubeCertResult(result *mtcpv1.KubeCertResult) {
	inFlight := run.kubeCert
	if inFlight == nil || !bytes.Equal(result.GetRequestId(), inFlight.requestID[:]) {
		late := run.kubeCertLate
		decoded := decodeKubeCertResult(result)
		if late != nil && late.timedOut && bytes.Equal(result.GetRequestId(), late.requestID[:]) &&
			decoded.Outcome != controlplane.KubeCertRetry {
			late.result = &decoded
		}
		return
	}
	inFlight.timer.Stop()
	run.kubeCert = nil
	replyKubeCert(inFlight.reply, controlplane.KubeCertReply{Result: decodeKubeCertResult(result)})
}

// timeOutKubeCert answers the in-flight call with ErrKubeCertTimeout and
// keeps listening for its request's answer.
func (run *sessionRun) timeOutKubeCert() {
	if inFlight := run.kubeCert; inFlight != nil {
		run.kubeCertLate = &kubeCertLate{requestID: inFlight.requestID, timedOut: true}
	}
	run.endKubeCert(controlplane.ErrKubeCertTimeout)
}

// endKubeCert answers the in-flight call, if any, with err.
func (run *sessionRun) endKubeCert(err error) {
	inFlight := run.kubeCert
	if inFlight == nil {
		return
	}
	inFlight.timer.Stop()
	run.kubeCert = nil
	replyKubeCert(inFlight.reply, controlplane.KubeCertReply{Err: err})
}

// decodeKubeCertResult maps Core's answer; an outcome this build does not
// know, or an issued answer without its parts, is a retry (§6.9).
func decodeKubeCertResult(result *mtcpv1.KubeCertResult) controlplane.KubeCertResult {
	decoded := controlplane.KubeCertResult{
		Reason: result.GetReason(),
		RetryAfter: min(time.Duration(min(max(result.GetRetryAfterMs(), 0), maximumKubeCertRetry.Milliseconds()))*
			time.Millisecond, maximumKubeCertRetry),
	}
	switch result.GetOutcome() {
	case mtcpv1.KubeCertResult_REFUSED:
		decoded.Outcome = controlplane.KubeCertRefused
	case mtcpv1.KubeCertResult_ISSUED:
		chain := result.GetChain()
		if len(result.GetCertificate()) == 0 || len(chain) == 0 || len(chain) > sharedmtcp.KubeCertChainMaximum ||
			len(result.GetRootFingerprint()) != 32 || len(result.GetIssuerFingerprint()) != 32 ||
			result.GetNotAfterMs() <= 0 || result.GetRenewAtMs() <= 0 {
			decoded.Reason = "internal"
			return decoded
		}
		decoded.Outcome, decoded.Reason = controlplane.KubeCertIssued, ""
		decoded.Certificate = bytes.Clone(result.GetCertificate())
		decoded.Chain = make([][]byte, len(chain))
		for index, intermediate := range chain {
			decoded.Chain[index] = bytes.Clone(intermediate)
		}
		decoded.RootFingerprint = bytes.Clone(result.GetRootFingerprint())
		decoded.IssuerFingerprint = bytes.Clone(result.GetIssuerFingerprint())
		decoded.NotAfter = time.UnixMilli(result.GetNotAfterMs())
		decoded.RenewAt = time.UnixMilli(result.GetRenewAtMs())
		decoded.NetworkRevision = result.GetNetworkRevision()
	default:
		decoded.Outcome = controlplane.KubeCertRetry
		if decoded.Reason == "" {
			decoded.Reason = "internal"
		}
	}
	return decoded
}
