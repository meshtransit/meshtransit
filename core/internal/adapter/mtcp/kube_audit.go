package mtcp

import (
	"context"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/kubeaudit"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

const (
	// kubeAuditInFlight is how many batches of a session may wait for
	// their ack; another is limited (K1b0 §3.3).
	kubeAuditInFlight = 4
	// kubeAuditStaleAfter is how long after Core last read a gateway's map
	// authority as standing it still records operations by it (K1b0 §3.3;
	// the gateway's own staleAfter is no shorter, K1a3 §5.2).
	kubeAuditStaleAfter = 5 * time.Minute
	// kubeAuditRetry is the wait asked of a refusal that allows another try
	// and has no wait of its own.
	kubeAuditRetry = time.Second
	// kubeAuditSkew is how far a gateway's observed time may be from Core's
	// before the row is marked clock_skew.
	kubeAuditSkew = 30 * time.Second
	// kubeAuditLimitTimeout bounds asking the limiter.
	kubeAuditLimitTimeout = 200 * time.Millisecond
	// Bounds of one outcome's and denial's fields, the schema's (000245).
	kubeAuditMaximumStatus   = 999
	kubeAuditMaximumDuration = 999_999_999 * time.Millisecond
	kubeAuditMaximumCount    = 999_999_999
	kubeAuditLatestMs        = 253402300799999
)

// KubeAuditWriter records intents in shared transactions
// (kubeaudit.Writer).
type KubeAuditWriter interface {
	Submit(rows []kubeaudit.Row) <-chan []kubeaudit.Answer
}

// KubeAuditReports queues outcomes and denials (kubeaudit.ReportWriter);
// false: dropped.
type KubeAuditReports interface {
	Submit(report kubeaudit.Reports) bool
}

// KubeAuditLimiter takes n operations from a Workspace's and a gateway's
// buckets at once, or from neither (K1b0 §6); false asks to wait.
type KubeAuditLimiter interface {
	Take(ctx context.Context, workspace, gateway string, n int) (time.Duration, bool)
}

// kubeAuditClasses maps the wire classes.
var kubeAuditClasses = map[mtcpv1.KubeAuditIntent_Class]kubeaudit.Class{
	mtcpv1.KubeAuditIntent_WRITE: kubeaudit.ClassWrite, mtcpv1.KubeAuditIntent_EXEC: kubeaudit.ClassExec,
	mtcpv1.KubeAuditIntent_PROXY: kubeaudit.ClassProxy, mtcpv1.KubeAuditIntent_SECRET_READ: kubeaudit.ClassSecretRead,
	mtcpv1.KubeAuditIntent_PRIVILEGED: kubeaudit.ClassPrivileged, mtcpv1.KubeAuditIntent_UNPARSED: kubeaudit.ClassUnparsed,
}

// kubeAuditIntents answers KubeAuditIntents (mtcp-v1 §6.10, K1b0 §3):
// always one KubeAuditAck with a result per intent, never an Error once the
// capability was negotiated. Intents in form, of peers the map sent grants
// for, are limited and written on a goroutine of their own, which sends
// the ack, so the session goes on serving its map meanwhile.
func (conversation *conversation) kubeAuditIntents(ctx context.Context, message *mtcpv1.KubeAuditIntents) error {
	application := conversation.application
	writer := application.options.KubeAudit
	if writer == nil || !conversation.session.Supports(CapabilityKubeAudit) {
		return conversation.sendError(mtcpv1.Error_UNSUPPORTED, "operation records are not available", 0)
	}
	started := application.now()
	batch, intents := message.GetBatchId(), message.GetIntents()
	refuseAll := func(outcome kubeaudit.Outcome) error {
		answers := make([]kubeaudit.Answer, min(len(intents), kubeaudit.MaximumIntents))
		for index := range answers {
			answers[index] = kubeAuditRefusal(outcome)
		}
		application.options.Metrics.kubeAuditAnswered(answers, -1)
		return conversation.sendKubeAuditAck(batch, intents, answers)
	}
	switch {
	case conversation.session.AuditOverBudget():
		return refuseAll(kubeaudit.OutcomeLimited)
	case len(batch) != sharedmtcp.KubeAuditBatchIDSize || len(intents) == 0 || len(intents) > kubeaudit.MaximumIntents:
		return refuseAll(kubeaudit.OutcomeInvalid)
	}
	if conversation.kubeAuditPending.Add(1) > kubeAuditInFlight {
		conversation.kubeAuditPending.Add(-1)
		return refuseAll(kubeaudit.OutcomeLimited)
	}
	gateway, snapshot, refused := conversation.kubeAuditGateway(started)
	if refused != "" {
		conversation.kubeAuditPending.Add(-1)
		return refuseAll(refused)
	}
	answers := make([]kubeaudit.Answer, len(intents))
	rows, indexes := kubeAuditRows(started, gateway, snapshot, intents, answers)
	if len(rows) == 0 {
		conversation.kubeAuditPending.Add(-1)
		application.options.Metrics.kubeAuditAnswered(answers, -1)
		return conversation.sendKubeAuditAck(batch, intents, answers)
	}
	workCtx, working := conversation.startKubeAudit(ctx)
	if !working {
		conversation.kubeAuditPending.Add(-1)
		return nil // the conversation ended
	}
	go func() {
		defer conversation.kubeAuditWork.Done()
		defer conversation.kubeAuditPending.Add(-1)
		if !conversation.kubeAuditTake(workCtx, gateway, snapshot, len(rows), indexes, answers) {
			application.options.Metrics.kubeAuditAnswered(answers, -1)
			_ = conversation.sendKubeAuditAck(batch, intents, answers)
			return
		}
		var got []kubeaudit.Answer
		select {
		case got = <-writer.Submit(rows):
		case <-workCtx.Done():
			return // the session ended; the gateway sends them again
		}
		for position, index := range indexes {
			answers[index] = got[position]
		}
		application.options.Metrics.kubeAuditAnswered(answers, application.now().Sub(started))
		_ = conversation.sendKubeAuditAck(batch, intents, answers)
	}()
	return nil
}

// startKubeAudit registers one batch's work under a context the
// conversation cancels when Run ends; false once it ended.
func (conversation *conversation) startKubeAudit(ctx context.Context) (context.Context, bool) {
	conversation.kubeAuditMu.Lock()
	defer conversation.kubeAuditMu.Unlock()
	if conversation.kubeAuditClosed {
		return nil, false
	}
	if conversation.kubeAuditCtx == nil {
		conversation.kubeAuditCtx, conversation.kubeAuditCancel = context.WithCancel(ctx)
	}
	conversation.kubeAuditWork.Add(1)
	return conversation.kubeAuditCtx, true
}

// closeKubeAudits ends the conversation's batches: no new one starts, the
// waiting ones stop waiting (their rows are still written), and Run returns
// only once they finished.
func (conversation *conversation) closeKubeAudits() {
	conversation.kubeAuditMu.Lock()
	conversation.kubeAuditClosed = true
	if conversation.kubeAuditCancel != nil {
		conversation.kubeAuditCancel()
	}
	conversation.kubeAuditMu.Unlock()
	conversation.kubeAuditWork.Wait()
}

// kubeAuditRefusal is a refusal with the wait its outcome allows.
func kubeAuditRefusal(outcome kubeaudit.Outcome) kubeaudit.Answer {
	answer := kubeaudit.Answer{Outcome: outcome}
	switch outcome {
	case kubeaudit.OutcomeLimited, kubeaudit.OutcomeOverloaded, kubeaudit.OutcomeUnavailable, kubeaudit.OutcomeStale:
		answer.RetryAfter = kubeAuditRetry
	}
	return answer
}

// kubeAuditGateway returns the gateway the session serves and the map
// Core sent it. Unavailable: not a gateway that proved its node key and
// holds its presence on this stream (a rolling update); stale: no map with
// Kubernetes access whose authority Core read as standing within
// kubeAuditStaleAfter (K1b0 §3.1, §3.3).
func (conversation *conversation) kubeAuditGateway(now time.Time) (kubeaudit.Gateway, mapsession.Snapshot,
	kubeaudit.Outcome,
) {
	if !conversation.isGateway() {
		return kubeaudit.Gateway{}, mapsession.Snapshot{}, kubeaudit.OutcomeUnavailable
	}
	conversation.mu.Lock()
	proven, serving := conversation.provenNodeKey, conversation.nodeKey
	claimed, lease := conversation.claimed, conversation.claim
	conversation.mu.Unlock()
	held := false
	if claimed != nil {
		select {
		case <-claimed:
			held = lease.IsValid()
		default:
		}
	}
	if !proven.IsValid() || proven != serving || !held || conversation.session.ctx.Err() != nil ||
		!conversation.session.server.holds(conversation.session) {
		return kubeaudit.Gateway{}, mapsession.Snapshot{}, kubeaudit.OutcomeUnavailable
	}
	snapshot, stood, sent := conversation.sink.kubeAuditMap()
	if !sent || now.Sub(stood) > kubeAuditStaleAfter {
		return kubeaudit.Gateway{}, mapsession.Snapshot{}, kubeaudit.OutcomeStale
	}
	return kubeaudit.Gateway{
		MachineFingerprint: node.MachineKey(conversation.session.Machine()).Fingerprint(), NodeKey: proven.Bytes(),
		Workspace: snapshot.Scope().WorkspaceID().String(),
	}, snapshot, ""
}

// kubeAuditRows checks each intent (K1b0 §3.3) and returns the rows to
// write with the indexes of their intents; answers gets each refusal.
func kubeAuditRows(now time.Time, gateway kubeaudit.Gateway, snapshot mapsession.Snapshot,
	intents []*mtcpv1.KubeAuditIntent, answers []kubeaudit.Answer,
) ([]kubeaudit.Row, []int) {
	rows := make([]kubeaudit.Row, 0, len(intents))
	indexes := make([]int, 0, len(intents))
	seen := make(map[[16]byte]bool, len(intents))
	for index, encoded := range intents {
		intent, decoded := decodeKubeAuditIntent(encoded)
		// An ID sent twice in a batch keeps its first intent only.
		duplicate := decoded && seen[intent.ID]
		if decoded {
			seen[intent.ID] = true
		}
		if !decoded || duplicate || !intent.Valid(now) {
			answers[index] = kubeAuditRefusal(kubeaudit.OutcomeInvalid)
			continue
		}
		access, check := snapshot.KubernetesOperation(node.ID(intent.Peer), intent.Groups)
		switch check {
		case mapsession.KubernetesOperationNoPeer:
			answers[index] = kubeAuditRefusal(kubeaudit.OutcomeDevice)
			continue
		case mapsession.KubernetesOperationNotGranted:
			answers[index] = kubeAuditRefusal(kubeaudit.OutcomeNotGranted)
			continue
		}
		skew := intent.ObservedAt.Sub(now)
		rows = append(rows, kubeaudit.Row{Gateway: gateway, Intent: intent,
			Owner:           kubeaudit.Owner{Kind: access.OwnerKind.String(), Ref: access.OwnerRef},
			NetworkRevision: snapshot.NetworkRevision(), ClockSkew: skew > kubeAuditSkew || skew < -kubeAuditSkew})
		indexes = append(indexes, index)
	}
	return rows, indexes
}

// decodeKubeAuditIntent reads an intent's wire form; Valid checks the rest.
func decodeKubeAuditIntent(encoded *mtcpv1.KubeAuditIntent) (kubeaudit.Intent, bool) {
	class, known := kubeAuditClasses[encoded.GetClass()]
	peer, err := publicid.Parse(encoded.GetPeerDeviceId())
	if !known || err != nil || len(encoded.GetIntentId()) != sharedmtcp.KubeAuditIntentIDSize {
		return kubeaudit.Intent{}, false
	}
	return kubeaudit.Intent{
		ID: [16]byte(encoded.GetIntentId()), Peer: peer, Groups: encoded.GetGroups(), Class: class,
		Verb: encoded.GetVerb(), APIGroup: encoded.GetApiGroup(), Resource: encoded.GetResource(),
		Subresource: encoded.GetSubresource(), Namespace: encoded.GetNamespace(), Name: encoded.GetName(),
		Impersonated: encoded.GetImpersonated(), TokenID: encoded.GetTokenId(),
		ObservedAt: time.UnixMilli(encoded.GetObservedMs()),
	}, true
}

// kubeAuditTake takes n operations from the limits; false limits the
// rows' intents. It runs off the session's run loop: the shared limits ask
// Redis (review b0b3 L6).
func (conversation *conversation) kubeAuditTake(ctx context.Context, gateway kubeaudit.Gateway,
	snapshot mapsession.Snapshot, n int, indexes []int, answers []kubeaudit.Answer,
) bool {
	limits := conversation.application.options.KubeAuditLimits
	if limits == nil {
		return true
	}
	takeCtx, cancel := context.WithTimeout(ctx, kubeAuditLimitTimeout)
	defer cancel()
	wait, taken := limits.Take(takeCtx, gateway.Workspace, snapshot.NodeID().String(), n)
	if taken {
		return true
	}
	for _, index := range indexes {
		answers[index] = kubeaudit.Answer{Outcome: kubeaudit.OutcomeLimited, RetryAfter: max(wait, kubeAuditRetry)}
	}
	return false
}

// sendKubeAuditAck answers the intents in order, at most MaximumIntents:
// an ack stays within its size whatever a gateway sent (review b0b3 M2).
func (conversation *conversation) sendKubeAuditAck(batch []byte, intents []*mtcpv1.KubeAuditIntent,
	answers []kubeaudit.Answer,
) error {
	answers = answers[:min(len(answers), kubeaudit.MaximumIntents)]
	if len(batch) > sharedmtcp.KubeAuditBatchIDSize {
		batch = nil
	}
	ack := &mtcpv1.KubeAuditAck{BatchId: batch, Results: make([]*mtcpv1.KubeAuditResult, len(answers))}
	for index, answer := range answers {
		result := &mtcpv1.KubeAuditResult{}
		if id := intents[index].GetIntentId(); len(id) <= sharedmtcp.KubeAuditIntentIDSize {
			result.IntentId = id
		}
		if answer.Outcome.Recorded() {
			id := answer.AuditID
			result.AuditId = id[:]
		} else {
			result.Refused = string(answer.Outcome)
			if answer.RetryAfter > 0 {
				result.RetryAfterMs = answer.RetryAfter.Milliseconds()
			}
		}
		ack.Results[index] = result
	}
	return conversation.session.Send(sharedmtcp.MessageKubeAuditAck, ack)
}

// kubeAuditOutcomes queues a gateway's finished operations and denials
// (K1b0 §2 step 5); nothing answers them. Those out of form, over the
// session's budget or of a session that is no gateway are dropped and
// counted.
func (conversation *conversation) kubeAuditOutcomes(message *mtcpv1.KubeAuditOutcomes) error {
	application := conversation.application
	reports := application.options.KubeAuditReports
	if reports == nil || !conversation.session.Supports(CapabilityKubeAudit) {
		return conversation.sendError(mtcpv1.Error_UNSUPPORTED, "operation records are not available", 0)
	}
	metrics := application.options.Metrics
	total := len(message.GetOutcomes()) + len(message.GetDenials())
	conversation.mu.Lock()
	proven := conversation.provenNodeKey
	conversation.mu.Unlock()
	if conversation.session.AuditOverBudget() || !conversation.isGateway() || !proven.IsValid() ||
		len(message.GetOutcomes()) > kubeaudit.MaximumReportOutcomes ||
		len(message.GetDenials()) > kubeaudit.MaximumReportDenials {
		metrics.kubeAuditReported("dropped", total)
		return nil
	}
	report := kubeaudit.Reports{Gateway: kubeaudit.Gateway{
		MachineFingerprint: node.MachineKey(conversation.session.Machine()).Fingerprint(), NodeKey: proven.Bytes(),
	}}
	for _, outcome := range message.GetOutcomes() {
		if finished, valid := decodeKubeAuditOutcome(outcome); valid {
			report.Finished = append(report.Finished, finished)
		}
	}
	for _, encoded := range message.GetDenials() {
		if denials, valid := decodeKubeAuditDenials(encoded); valid {
			report.Denials = append(report.Denials, denials)
		}
	}
	kept := len(report.Finished) + len(report.Denials)
	if kept > 0 && !reports.Submit(report) {
		metrics.kubeAuditReported("dropped", total)
		return nil
	}
	metrics.kubeAuditReported("outcome", len(report.Finished))
	metrics.kubeAuditReported("denial", len(report.Denials))
	metrics.kubeAuditReported("dropped", total-kept)
	return nil
}

func decodeKubeAuditOutcome(encoded *mtcpv1.KubeAuditOutcome) (kubeaudit.Finished, bool) {
	duration := time.Duration(encoded.GetDurationMs()) * time.Millisecond
	if len(encoded.GetAuditId()) != len(publicid.ID{}) || encoded.GetStatus() > kubeAuditMaximumStatus ||
		duration > kubeAuditMaximumDuration {
		return kubeaudit.Finished{}, false
	}
	id := publicid.ID(encoded.GetAuditId())
	if !id.IsValid() {
		return kubeaudit.Finished{}, false
	}
	return kubeaudit.Finished{AuditID: id, Status: int(encoded.GetStatus()), Duration: duration}, true
}

func decodeKubeAuditDenials(encoded *mtcpv1.KubeAuditDenials) (kubeaudit.Denials, bool) {
	reason := kubeaudit.DenialReason(encoded.GetReason())
	switch reason {
	case kubeaudit.DenialUnauthenticated, kubeaudit.DenialForbidden, kubeaudit.DenialNotGranted,
		kubeaudit.DenialStale, kubeaudit.DenialLimited, kubeaudit.DenialOther:
	default:
		return kubeaudit.Denials{}, false
	}
	first, last := encoded.GetFirstMs(), encoded.GetLastMs()
	if encoded.GetCount() < 1 || encoded.GetCount() > kubeAuditMaximumCount || first < 0 || first > last ||
		last > kubeAuditLatestMs {
		return kubeaudit.Denials{}, false
	}
	denials := kubeaudit.Denials{Reason: reason, Count: int(encoded.GetCount()), First: time.UnixMilli(first),
		Last: time.UnixMilli(last)}
	if peer := encoded.GetPeerDeviceId(); peer != "" {
		id, err := publicid.Parse(peer)
		if err != nil {
			return kubeaudit.Denials{}, false
		}
		denials.Peer = id
	}
	return denials, true
}
