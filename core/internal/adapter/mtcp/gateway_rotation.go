package mtcp

import (
	"context"
	"errors"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

const (
	// gatewayClaimWait bounds how long a Kubernetes gateway's rotation
	// waits for its stream to claim the presence: a rotation sent right
	// after the Ping arrives before the stream's first snapshot.
	gatewayClaimWait = 5 * time.Second
	// gatewayCheckTimeout bounds asking Redis whether the gateway may
	// rotate: the session's messages wait meanwhile.
	gatewayCheckTimeout = 500 * time.Millisecond
	// gatewayReleaseTimeout bounds releasing the presence a rotation kept.
	gatewayReleaseTimeout = 2 * time.Second
)

// gatewayStreamSink is the sink of a Kubernetes gateway's map stream: it
// hears which presence lease the stream holds (K1a1 plan §16.12).
type gatewayStreamSink struct {
	*mapSink
	conversation *conversation
	// generation is the conversation's generation when the stream started.
	generation uint64
}

var _ mapsession.GatewayPresenceSink = (*gatewayStreamSink)(nil)

// PresenceClaimed records lease as the current stream's, unless a newer
// stream started meanwhile.
func (sink *gatewayStreamSink) PresenceClaimed(scope network.Scope, lease node.PresenceLease) {
	conversation := sink.conversation
	conversation.mu.Lock()
	defer conversation.mu.Unlock()
	if conversation.generation != sink.generation || conversation.claim.IsValid() {
		return
	}
	select {
	case <-conversation.claimed:
		return // the stream already ended
	default:
	}
	conversation.claim, conversation.claimScope = lease, scope
	close(conversation.claimed)
}

// KeepsPresence reports whether the session stopped the stream to rotate
// the gateway's machine key.
func (sink *gatewayStreamSink) KeepsPresence() bool {
	sink.conversation.mu.Lock()
	defer sink.conversation.mu.Unlock()
	return sink.conversation.keepPresence
}

// GatewayKeysFought marks the machine key contested here and reports the
// fight: live holders of the keys took the presence from each other.
func (sink *gatewayStreamSink) GatewayKeysFought() {
	session := sink.conversation.session
	session.server.contest(session.machine)
	session.server.keyReports.report(node.MachineKey(session.machine).Fingerprint(), kubecluster.KeyEventSessionFight)
}

// HandsOffPresence reports whether Core moves the session to another
// replica: a rebalance or a shutdown.
func (sink *gatewayStreamSink) HandsOffPresence() bool {
	cause := context.Cause(sink.conversation.session.ctx)
	return errors.Is(cause, errShed) || errors.Is(cause, errShuttingDown)
}

// gatewayMayRotate reports whether a Kubernetes gateway's session may
// rotate a key now: its stream holds the gateway's presence and the session
// still is this replica's session of its machine key. Any other session may.
//
// K1.1 design §7.4: every gateway rotation that gets here carries a pod
// token Core verified, which a copy of the gateway's Secret cannot have; so
// a contest (K1a1 plan §16.12) no longer refuses it, and the real pod
// rotates the copy's keys away. A contest is counted.
func (conversation *conversation) gatewayMayRotate(ctx context.Context) (gatewayClaim, bool) {
	if !conversation.isGateway() {
		return gatewayClaim{}, true
	}
	application := conversation.application
	metrics := application.options.Metrics
	claim, claimed := conversation.awaitClaim(ctx)
	if !claimed {
		metrics.limited(limitGatewayPresencePending)
		return gatewayClaim{}, false
	}
	contested := conversation.session.RotationWait() > 0
	store := application.options.GatewayPresence
	if store == nil {
		metrics.limited(limitGatewayPresenceUnknown)
		return gatewayClaim{}, false
	}
	checkCtx, cancel := context.WithTimeout(ctx, application.gatewayCheckTimeout)
	defer cancel()
	state, err := store.CheckGatewayRotation(checkCtx, claim.lease)
	switch {
	case err != nil:
		metrics.limited(limitGatewayPresenceUnknown)
		return gatewayClaim{}, false
	case state == mapsession.GatewayRotationContested:
		contested = true
	case state != mapsession.GatewayRotationHeld:
		metrics.limited(limitGatewayPresenceElsewhere)
		return gatewayClaim{}, false
	}
	if conversation.session.ctx.Err() != nil || !conversation.session.server.holds(conversation.session) {
		metrics.limited(limitGatewayPresenceElsewhere)
		return gatewayClaim{}, false
	}
	if contested {
		metrics.limited(limitGatewayContestOverridden)
	}
	return claim, true
}

// gatewayClaim is the presence lease a gateway's stream holds.
type gatewayClaim struct {
	scope network.Scope
	lease node.PresenceLease
}

// keepGatewayPresence keeps claim's lease while the stream stops for a
// machine key rotation: a stream claiming the presence meanwhile takes it.
func (conversation *conversation) keepGatewayPresence(claim gatewayClaim) {
	if !claim.lease.IsValid() {
		return
	}
	conversation.mu.Lock()
	conversation.keepPresence = true
	conversation.mu.Unlock()
}

// releaseGatewayPresence ends the lease kept for a rotation, by holder,
// once the rotation is decided and before the stream resumes.
func (conversation *conversation) releaseGatewayPresence(ctx context.Context, claim gatewayClaim) {
	if !claim.lease.IsValid() {
		return
	}
	if store := conversation.application.options.GatewayPresence; store != nil {
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gatewayReleaseTimeout)
		// Best effort: the lease still expires on its own if this fails.
		_, _ = store.ReleaseGatewayPresence(releaseCtx, claim.scope, claim.lease)
		cancel()
	}
	conversation.mu.Lock()
	conversation.keepPresence = false
	conversation.mu.Unlock()
}

// endClaim ends the claim of the stream that just ended, and wakes a
// rotation waiting for a claim the stream never made.
func (conversation *conversation) endClaim() {
	conversation.mu.Lock()
	defer conversation.mu.Unlock()
	conversation.claim = node.PresenceLease{}
	select {
	case <-conversation.claimed:
	default:
		close(conversation.claimed)
	}
}

// refuseGatewayRotation refuses a rotation for good: the node drops its
// staged key and goes on, keeping the session.
func (conversation *conversation) refuseGatewayRotation() error {
	return conversation.sendError(mtcpv1.Error_NOT_PERMITTED, "the gateway may not rotate its keys now", 0)
}

// awaitClaim waits, at most gatewayClaimWait, for the current stream to
// claim the gateway's presence, and returns the lease it holds.
func (conversation *conversation) awaitClaim(ctx context.Context) (gatewayClaim, bool) {
	conversation.mu.Lock()
	claimed := conversation.claimed
	conversation.mu.Unlock()
	timer := time.NewTimer(conversation.application.gatewayClaimWait)
	defer timer.Stop()
	select {
	case <-claimed:
	case <-ctx.Done():
		return gatewayClaim{}, false
	case <-timer.C:
		return gatewayClaim{}, false
	}
	conversation.mu.Lock()
	defer conversation.mu.Unlock()
	claim := gatewayClaim{scope: conversation.claimScope, lease: conversation.claim}
	return claim, claim.lease.IsValid() && conversation.claimed == claimed
}

// gatewayPresenceLost answers a gateway stream that lost its presence to
// another holder, or found one still ending here, with SESSION_REPLACED:
// the gateway reconnects at once, without backing off (K1a1 plan §16.12).
func (conversation *conversation) gatewayPresenceLost(err error) bool {
	if !conversation.isGateway() ||
		!errors.Is(err, mapsession.ErrPresenceTaken) && !errors.Is(err, mapsession.ErrPresenceConflict) {
		return false
	}
	_ = conversation.session.Send(sharedmtcp.MessageError, &mtcpv1.Error{Code: mtcpv1.Error_SESSION_REPLACED,
		Message: "another session holds this gateway's presence", Fatal: true})
	return true
}

// holds reports whether session is this replica's session of its machine
// key.
func (server *Server) holds(session *Session) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.byMachine[session.machine] == session
}
