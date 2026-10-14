package pathdiscovery

import "sync/atomic"

// ProbeTelemetrySnapshot contains process-local aggregate path-discovery
// counters. It intentionally carries no peer, endpoint, key, or packet data.
type ProbeTelemetrySnapshot struct {
	MapActivations               uint64
	ActivationPreserved          uint64
	ActivationRetired            uint64
	AuthorityPeerChanges         uint64
	AuthorityNodeKeyChanges      uint64
	AuthorityDiscoveryKeyChanges uint64
	AuthorityEndpointChanges     uint64
	SocketChanges                uint64
	PendingInvalidated           uint64
	RoundsStarted                uint64
	RoundsCompleted              uint64
	ProbeAttempts                uint64
	ProbesStarted                uint64
	ProbesSent                   uint64
	ProbeStartFailures           uint64
	ProbeSendFailures            uint64
	DatagramDrops                uint64
	AuthenticatedPings           uint64
	PingRateLimited              uint64
	ProbesThrottled              uint64
	PongsSent                    uint64
	PongSendFailures             uint64
	AuthenticatedPongs           uint64
	ProbeCompletions             uint64
	CompletionRejections         uint64
	ObservationsQueued           uint64
	ObservationDrops             uint64
	ObservationsAccepted         uint64
	ObservationRejected          uint64
	DirectExpirations            uint64
	CallMeMaybeSent              uint64
	CallMeMaybeAccepted          uint64
	PeerReflexiveLearned         uint64
}

// ProbeTelemetry owns process-local counters shared across control sessions.
// All methods are safe for concurrent use and deliberately avoid labels.
type ProbeTelemetry struct {
	mapActivations               atomic.Uint64
	activationPreserved          atomic.Uint64
	activationRetired            atomic.Uint64
	authorityPeerChanges         atomic.Uint64
	authorityNodeKeyChanges      atomic.Uint64
	authorityDiscoveryKeyChanges atomic.Uint64
	authorityEndpointChanges     atomic.Uint64
	socketChanges                atomic.Uint64
	pendingInvalidated           atomic.Uint64
	roundsStarted                atomic.Uint64
	roundsCompleted              atomic.Uint64
	probeAttempts                atomic.Uint64
	probesStarted                atomic.Uint64
	probesSent                   atomic.Uint64
	probeStartFailures           atomic.Uint64
	probeSendFailures            atomic.Uint64
	datagramDrops                atomic.Uint64
	authenticatedPings           atomic.Uint64
	pingRateLimited              atomic.Uint64
	probesThrottled              atomic.Uint64
	pongsSent                    atomic.Uint64
	pongSendFailures             atomic.Uint64
	authenticatedPongs           atomic.Uint64
	probeCompletions             atomic.Uint64
	completionRejections         atomic.Uint64
	observationsQueued           atomic.Uint64
	observationDrops             atomic.Uint64
	observationsAccepted         atomic.Uint64
	observationRejected          atomic.Uint64
	directExpirations            atomic.Uint64
	callMeMaybeSent              atomic.Uint64
	callMeMaybeAccepted          atomic.Uint64
	peerReflexiveLearned         atomic.Uint64
}

// NewProbeTelemetry creates zeroed aggregate telemetry.
func NewProbeTelemetry() *ProbeTelemetry { return &ProbeTelemetry{} }

func (t *ProbeTelemetry) RecordMapActivation() { addProbeCounter(&t.mapActivations, 1) }
func (t *ProbeTelemetry) RecordActivationPreserved(count uint64) {
	addProbeCounter(&t.activationPreserved, count)
}

func (t *ProbeTelemetry) RecordActivationRetired(count uint64) {
	addProbeCounter(&t.activationRetired, count)
}

func (t *ProbeTelemetry) RecordAuthorityPeerSetChange(count uint64) {
	addProbeCounter(&t.authorityPeerChanges, count)
}

func (t *ProbeTelemetry) RecordAuthorityNodeKeyChange(count uint64) {
	addProbeCounter(&t.authorityNodeKeyChanges, count)
}

func (t *ProbeTelemetry) RecordAuthorityDiscoveryKeyChange(count uint64) {
	addProbeCounter(&t.authorityDiscoveryKeyChanges, count)
}

func (t *ProbeTelemetry) RecordAuthorityEndpointChange(count uint64) {
	addProbeCounter(&t.authorityEndpointChanges, count)
}
func (t *ProbeTelemetry) RecordSocketChange() { addProbeCounter(&t.socketChanges, 1) }
func (t *ProbeTelemetry) RecordPendingInvalidated(count uint64) {
	addProbeCounter(&t.pendingInvalidated, count)
}
func (t *ProbeTelemetry) RecordRoundStarted()      { addProbeCounter(&t.roundsStarted, 1) }
func (t *ProbeTelemetry) RecordRoundCompleted()    { addProbeCounter(&t.roundsCompleted, 1) }
func (t *ProbeTelemetry) RecordProbeAttempt()      { addProbeCounter(&t.probeAttempts, 1) }
func (t *ProbeTelemetry) RecordProbeStarted()      { addProbeCounter(&t.probesStarted, 1) }
func (t *ProbeTelemetry) RecordProbeSent()         { addProbeCounter(&t.probesSent, 1) }
func (t *ProbeTelemetry) RecordProbeStartFailure() { addProbeCounter(&t.probeStartFailures, 1) }
func (t *ProbeTelemetry) RecordProbeSendFailure()  { addProbeCounter(&t.probeSendFailures, 1) }
func (t *ProbeTelemetry) RecordDatagramDrop()      { addProbeCounter(&t.datagramDrops, 1) }
func (t *ProbeTelemetry) RecordAuthenticatedPing() { addProbeCounter(&t.authenticatedPings, 1) }
func (t *ProbeTelemetry) RecordPingRateLimited()   { addProbeCounter(&t.pingRateLimited, 1) }

// RecordProbeThrottled counts a probe the per-peer probe budget refused.
func (t *ProbeTelemetry) RecordProbeThrottled()    { addProbeCounter(&t.probesThrottled, 1) }
func (t *ProbeTelemetry) RecordPongSent()          { addProbeCounter(&t.pongsSent, 1) }
func (t *ProbeTelemetry) RecordPongSendFailure()   { addProbeCounter(&t.pongSendFailures, 1) }
func (t *ProbeTelemetry) RecordAuthenticatedPong() { addProbeCounter(&t.authenticatedPongs, 1) }
func (t *ProbeTelemetry) RecordProbeCompletion()   { addProbeCounter(&t.probeCompletions, 1) }
func (t *ProbeTelemetry) RecordCompletionRejection() {
	addProbeCounter(&t.completionRejections, 1)
}

func (t *ProbeTelemetry) RecordObservationQueued() {
	addProbeCounter(&t.observationsQueued, 1)
}

func (t *ProbeTelemetry) RecordObservationDropped() {
	addProbeCounter(&t.observationDrops, 1)
}

func (t *ProbeTelemetry) RecordObservationAccepted() {
	addProbeCounter(&t.observationsAccepted, 1)
}

func (t *ProbeTelemetry) RecordObservationRejected() {
	addProbeCounter(&t.observationRejected, 1)
}

func (t *ProbeTelemetry) RecordDirectExpiry(count uint64) {
	addProbeCounter(&t.directExpirations, count)
}

// RecordCallMeMaybeSent counts CALL_ME_MAYBE messages sent through a relay.
func (t *ProbeTelemetry) RecordCallMeMaybeSent() { addProbeCounter(&t.callMeMaybeSent, 1) }

// RecordCallMeMaybeAccepted counts authenticated CALL_ME_MAYBE messages.
func (t *ProbeTelemetry) RecordCallMeMaybeAccepted() { addProbeCounter(&t.callMeMaybeAccepted, 1) }

// RecordPeerReflexiveLearned counts peer-reflexive candidates learned.
func (t *ProbeTelemetry) RecordPeerReflexiveLearned() { addProbeCounter(&t.peerReflexiveLearned, 1) }

// Snapshot returns a coherent-enough monotonic view for operator diagnostics.
// Individual counters may advance while the snapshot is being read.
func (t *ProbeTelemetry) Snapshot() ProbeTelemetrySnapshot {
	if t == nil {
		return ProbeTelemetrySnapshot{}
	}

	return ProbeTelemetrySnapshot{
		MapActivations:               t.mapActivations.Load(),
		ActivationPreserved:          t.activationPreserved.Load(),
		ActivationRetired:            t.activationRetired.Load(),
		AuthorityPeerChanges:         t.authorityPeerChanges.Load(),
		AuthorityNodeKeyChanges:      t.authorityNodeKeyChanges.Load(),
		AuthorityDiscoveryKeyChanges: t.authorityDiscoveryKeyChanges.Load(),
		AuthorityEndpointChanges:     t.authorityEndpointChanges.Load(),
		SocketChanges:                t.socketChanges.Load(),
		PendingInvalidated:           t.pendingInvalidated.Load(),
		RoundsStarted:                t.roundsStarted.Load(),
		RoundsCompleted:              t.roundsCompleted.Load(),
		ProbeAttempts:                t.probeAttempts.Load(),
		ProbesStarted:                t.probesStarted.Load(),
		ProbesSent:                   t.probesSent.Load(),
		ProbeStartFailures:           t.probeStartFailures.Load(),
		ProbeSendFailures:            t.probeSendFailures.Load(),
		DatagramDrops:                t.datagramDrops.Load(),
		AuthenticatedPings:           t.authenticatedPings.Load(),
		PingRateLimited:              t.pingRateLimited.Load(),
		ProbesThrottled:              t.probesThrottled.Load(),
		PongsSent:                    t.pongsSent.Load(),
		PongSendFailures:             t.pongSendFailures.Load(),
		AuthenticatedPongs:           t.authenticatedPongs.Load(),
		ProbeCompletions:             t.probeCompletions.Load(),
		CompletionRejections:         t.completionRejections.Load(),
		ObservationsQueued:           t.observationsQueued.Load(),
		ObservationDrops:             t.observationDrops.Load(),
		ObservationsAccepted:         t.observationsAccepted.Load(),
		ObservationRejected:          t.observationRejected.Load(),
		DirectExpirations:            t.directExpirations.Load(),
		CallMeMaybeSent:              t.callMeMaybeSent.Load(),
		CallMeMaybeAccepted:          t.callMeMaybeAccepted.Load(),
		PeerReflexiveLearned:         t.peerReflexiveLearned.Load(),
	}
}

func addProbeCounter(counter *atomic.Uint64, count uint64) {
	if count == 0 {
		return
	}
	counter.Add(count)
}
