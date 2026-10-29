package mtcpclient

import (
	"bytes"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// kubeAuditCapability is gateway.audit1: the gateway has Core record type A
// operations before forwarding them (mtcp-v1 §6.10).
const kubeAuditCapability = "gateway.audit1"

const (
	// kubeAuditInFlight is how many batches Core lets wait for an ack.
	kubeAuditInFlight = 4
	// kubeAuditWait bounds a call without a deadline.
	kubeAuditWait = 10 * time.Second
	// maximumKubeAuditRetry caps the wait Core may ask for.
	maximumKubeAuditRetry = time.Hour
	// maximumKubeAuditIntents is the most intents one batch carries.
	maximumKubeAuditIntents = 128
	// kubeAuditLateFor and maximumKubeAuditLate bound the batches kept after
	// their deadline, so an ack that still comes reports its records as
	// not forwarded (review b2 M1).
	kubeAuditLateFor     = 2 * time.Minute
	maximumKubeAuditLate = 16
)

// kubeAuditLateBatch is a batch whose call timed out.
type kubeAuditLateBatch struct {
	intents [][16]byte
	until   time.Time
}

// kubeAuditClasses maps the gateway's classes to the wire's.
var kubeAuditClasses = map[string]mtcpv1.KubeAuditIntent_Class{
	"write": mtcpv1.KubeAuditIntent_WRITE, "exec": mtcpv1.KubeAuditIntent_EXEC,
	"proxy": mtcpv1.KubeAuditIntent_PROXY, "secret_read": mtcpv1.KubeAuditIntent_SECRET_READ,
	"privileged": mtcpv1.KubeAuditIntent_PRIVILEGED, "unparsed": mtcpv1.KubeAuditIntent_UNPARSED,
}

// kubeAuditInFlightCall is a batch the session sent and waits on.
type kubeAuditInFlightCall struct {
	intents  [][16]byte
	reply    chan<- controlplane.KubeAuditReply
	deadline time.Time
}

// replyKubeAudit hands a call its answer without ever waiting.
func replyKubeAudit(reply chan<- controlplane.KubeAuditReply, answer controlplane.KubeAuditReply) {
	if reply == nil {
		return
	}
	select {
	case reply <- answer:
	default:
	}
}

// kubeAuditCalls is the stream's batch channel once the session holds a
// map: Core records a gateway's operations only while its stream holds the
// presence and its map is current. nil otherwise, which blocks in a select.
func (run *sessionRun) kubeAuditCalls() <-chan controlplane.KubeAuditCall {
	if !run.mapped || run.stream.client.gateway == nil {
		return nil
	}
	return run.stream.options.KubeAudits
}

// kubeAuditReports is the stream's report channel once the session holds a
// map; nil otherwise.
func (run *sessionRun) kubeAuditReports() <-chan controlplane.KubeAuditReport {
	if !run.mapped || run.stream.client.gateway == nil {
		return nil
	}
	return run.stream.options.KubeAuditReports
}

// kubeAuditTimeout is the timer of the earliest deadline in flight, or nil.
func (run *sessionRun) kubeAuditTimeout() <-chan time.Time {
	if len(run.kubeAudits) == 0 || run.kubeAuditTimer == nil {
		return nil
	}
	return run.kubeAuditTimer.C
}

// sendKubeAudit sends one batch on the session. A call it cannot send is
// answered at once; a send that fails ends the session.
func (run *sessionRun) sendKubeAudit(call controlplane.KubeAuditCall) error {
	answer := func(err error) { replyKubeAudit(call.Reply, controlplane.KubeAuditReply{Err: err}) }
	// A batch past its deadline frees its place first: the recorder's timer
	// and the stream's fire together (review b2 M3).
	run.timeOutKubeAudits()
	batch, now := call.Batch, time.Now()
	deadline := call.Deadline
	if deadline.IsZero() {
		deadline = now.Add(kubeAuditWait)
	}
	_, duplicate := run.kubeAudits[batch.ID]
	switch {
	case call.Reply == nil || cap(call.Reply) == 0:
		return nil // nobody could take the answer
	case !now.Before(deadline):
		answer(controlplane.ErrKubeAuditTimeout) // stale: never sent
		return nil
	case !run.supports(kubeAuditCapability):
		answer(controlplane.ErrKubeAuditUnsupported)
		return nil
	case duplicate || len(run.kubeAudits) >= kubeAuditInFlight:
		answer(controlplane.ErrKubeAuditBusy)
		return nil
	}
	message, ok := encodeKubeAuditBatch(batch)
	if !ok {
		// Never sent: a message over its limit would end the session (review
		// b2 H1).
		answer(controlplane.ErrKubeAuditBatch)
		return nil
	}
	intents := make([][16]byte, len(batch.Intents))
	for index, intent := range batch.Intents {
		intents[index] = intent.ID
	}
	if run.kubeAudits == nil {
		run.kubeAudits = make(map[[16]byte]*kubeAuditInFlightCall, kubeAuditInFlight)
	}
	run.kubeAudits[batch.ID] = &kubeAuditInFlightCall{intents: intents, reply: call.Reply, deadline: deadline}
	run.armKubeAuditTimer(now)
	if err := run.send(sharedmtcp.MessageKubeAuditIntents, message); err != nil {
		run.endKubeAudits(controlplane.ErrKubeAuditSessionLost)
		return err
	}
	return nil
}

// encodeKubeAuditBatch is a batch's message; false for one the stream
// must not send (no intents, too many, an unknown class).
func encodeKubeAuditBatch(batch controlplane.KubeAuditBatch) (*mtcpv1.KubeAuditIntents, bool) {
	if len(batch.Intents) == 0 || len(batch.Intents) > maximumKubeAuditIntents {
		return nil, false
	}
	message := &mtcpv1.KubeAuditIntents{BatchId: bytes.Clone(batch.ID[:]),
		Intents: make([]*mtcpv1.KubeAuditIntent, len(batch.Intents))}
	for index, intent := range batch.Intents {
		class, known := kubeAuditClasses[intent.Class]
		if !known {
			return nil, false
		}
		message.Intents[index] = &mtcpv1.KubeAuditIntent{
			IntentId: bytes.Clone(intent.ID[:]), PeerDeviceId: intent.Peer, Groups: slices.Clone(intent.Groups),
			Class: class,
			Verb:  intent.Verb, ApiGroup: intent.APIGroup, Resource: intent.Resource, Subresource: intent.Subresource,
			Namespace: intent.Namespace, Name: intent.Name, Impersonated: intent.Impersonated,
			TokenId: bytes.Clone(intent.TokenID), ObservedMs: intent.ObservedAt.UnixMilli(),
		}
	}
	if proto.Size(message) > sharedmtcp.MessageKubeAuditIntents.Limit() {
		return nil, false
	}
	return message, true
}

// kubeAuditAck answers the call of the batch the ack names. An ack that
// does not answer each intent of the batch, in order, answers the call
// ErrKubeAuditAck; one for no batch in flight (it timed out) is dropped.
func (run *sessionRun) kubeAuditAck(ack *mtcpv1.KubeAuditAck) error {
	if len(ack.GetBatchId()) != len([16]byte{}) {
		return nil
	}
	id := [16]byte(ack.GetBatchId())
	call, found := run.kubeAudits[id]
	if !found {
		return run.kubeAuditLateAck(id, ack)
	}
	delete(run.kubeAudits, id)
	run.armKubeAuditTimer(time.Now())
	results, ok := decodeKubeAuditResults(call.intents, ack.GetResults())
	if !ok {
		replyKubeAudit(call.reply, controlplane.KubeAuditReply{Err: controlplane.ErrKubeAuditAck})
		return nil
	}
	replyKubeAudit(call.reply, controlplane.KubeAuditReply{Results: results})
	return nil
}

// decodeKubeAuditResults reads a result per intent, in order: the same
// intent IDs, a 16-byte audit_id exactly when recorded.
func decodeKubeAuditResults(intents [][16]byte, encoded []*mtcpv1.KubeAuditResult) (
	[]controlplane.KubeAuditResult, bool,
) {
	if len(encoded) != len(intents) {
		return nil, false
	}
	results := make([]controlplane.KubeAuditResult, len(encoded))
	for index, result := range encoded {
		if !bytes.Equal(result.GetIntentId(), intents[index][:]) {
			return nil, false
		}
		decoded := controlplane.KubeAuditResult{IntentID: intents[index], Refused: result.GetRefused()}
		switch {
		case decoded.Refused == "" && len(result.GetAuditId()) == len(decoded.AuditID):
			decoded.AuditID = [16]byte(result.GetAuditId())
		case decoded.Refused == "", len(result.GetAuditId()) != 0:
			return nil, false
		}
		if retry := result.GetRetryAfterMs(); retry > 0 {
			// Capped before the multiplication, which would overflow.
			decoded.RetryAfter = time.Duration(min(retry, maximumKubeAuditRetry.Milliseconds())) * time.Millisecond
		}
		results[index] = decoded
	}
	return results, true
}

// timeOutKubeAudits answers the calls past their deadline, and keeps them
// a while: an ack that still comes is reported as not forwarded.
func (run *sessionRun) timeOutKubeAudits() {
	now := time.Now()
	for id, call := range run.kubeAudits {
		if !now.Before(call.deadline) {
			delete(run.kubeAudits, id)
			run.keepLateKubeAudit(id, call.intents, now)
			replyKubeAudit(call.reply, controlplane.KubeAuditReply{Err: controlplane.ErrKubeAuditTimeout})
		}
	}
	run.armKubeAuditTimer(now)
}

// keepLateKubeAudit keeps a timed-out batch, dropping expired ones and, past
// the bound, the oldest.
func (run *sessionRun) keepLateKubeAudit(id [16]byte, intents [][16]byte, now time.Time) {
	if run.kubeAuditLate == nil {
		run.kubeAuditLate = make(map[[16]byte]kubeAuditLateBatch)
	}
	var oldest [16]byte
	var oldestUntil time.Time
	for kept, batch := range run.kubeAuditLate {
		if !now.Before(batch.until) {
			delete(run.kubeAuditLate, kept)
			continue
		}
		if oldestUntil.IsZero() || batch.until.Before(oldestUntil) {
			oldest, oldestUntil = kept, batch.until
		}
	}
	if len(run.kubeAuditLate) >= maximumKubeAuditLate {
		delete(run.kubeAuditLate, oldest)
	}
	run.kubeAuditLate[id] = kubeAuditLateBatch{intents: intents, until: now.Add(kubeAuditLateFor)}
}

// kubeAuditLateAck reports the intents a late ack recorded as never
// forwarded (status 0): their callers had given up (review b2 M1).
func (run *sessionRun) kubeAuditLateAck(id [16]byte, ack *mtcpv1.KubeAuditAck) error {
	batch, found := run.kubeAuditLate[id]
	if !found {
		return nil
	}
	delete(run.kubeAuditLate, id)
	results, ok := decodeKubeAuditResults(batch.intents, ack.GetResults())
	if !ok {
		return nil
	}
	var report controlplane.KubeAuditReport
	for _, result := range results {
		if result.Recorded() {
			report.Outcomes = append(report.Outcomes, controlplane.KubeAuditOutcome{AuditID: result.AuditID})
		}
	}
	return run.sendKubeAuditReport(report)
}

// armKubeAuditTimer sets the timer to the earliest deadline in flight.
func (run *sessionRun) armKubeAuditTimer(now time.Time) {
	if len(run.kubeAudits) == 0 {
		if run.kubeAuditTimer != nil {
			run.kubeAuditTimer.Stop()
		}
		return
	}
	var earliest time.Time
	for _, call := range run.kubeAudits {
		if earliest.IsZero() || call.deadline.Before(earliest) {
			earliest = call.deadline
		}
	}
	wait := max(earliest.Sub(now), 0)
	if run.kubeAuditTimer == nil {
		run.kubeAuditTimer = time.NewTimer(wait)
		return
	}
	run.kubeAuditTimer.Reset(wait)
}

// endKubeAudits answers every call in flight with err.
func (run *sessionRun) endKubeAudits(err error) {
	for id, call := range run.kubeAudits {
		delete(run.kubeAudits, id)
		replyKubeAudit(call.reply, controlplane.KubeAuditReply{Err: err})
	}
	if run.kubeAuditTimer != nil {
		run.kubeAuditTimer.Stop()
	}
}

// sendKubeAuditReport sends a report Core takes; one it does not, or out
// of bounds, is dropped. A send that fails ends the session.
func (run *sessionRun) sendKubeAuditReport(report controlplane.KubeAuditReport) error {
	if !run.supports(kubeAuditCapability) || len(report.Outcomes)+len(report.Denials) == 0 ||
		len(report.Outcomes) > 1024 || len(report.Denials) > 256 {
		return nil
	}
	message := &mtcpv1.KubeAuditOutcomes{}
	for _, outcome := range report.Outcomes {
		if outcome.Status < 0 || outcome.Status > 999 || outcome.Duration < 0 {
			continue
		}
		message.Outcomes = append(message.Outcomes, &mtcpv1.KubeAuditOutcome{AuditId: bytes.Clone(outcome.AuditID[:]),
			Status: uint32(outcome.Status), DurationMs: uint32(min(outcome.Duration.Milliseconds(), 999_999_999))})
	}
	for _, denials := range report.Denials {
		if denials.Count < 1 {
			continue
		}
		message.Denials = append(message.Denials, &mtcpv1.KubeAuditDenials{PeerDeviceId: denials.Peer,
			Reason: denials.Reason, Count: uint32(min(denials.Count, 999_999_999)),
			FirstMs: denials.First.UnixMilli(), LastMs: denials.Last.UnixMilli()})
	}
	if len(message.GetOutcomes())+len(message.GetDenials()) == 0 {
		return nil
	}
	return run.send(sharedmtcp.MessageKubeAuditOutcomes, message)
}
