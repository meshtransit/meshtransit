package mapsession

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

// GatewayContestWindow is how long after a live holder of a Kubernetes
// gateway's keys lost its presence to another that no session rotates
// them (K1a1 plan §16.12). It outlasts the loser's return: learning it at
// a renewal (PresenceTTL/3, at most 100 s), a churn window (60 s) and two
// reconnect attempts.
const GatewayContestWindow = 10 * time.Minute

// GatewayClaim is what acquiring a Kubernetes gateway's presence did.
type GatewayClaim struct {
	// Claimed: the stream holds the presence.
	Claimed bool
	// Fight: this take was the one that made the keys fought over: live
	// holders of them took the presence from each other too often.
	Fight bool
}

// GatewayRotationState is what Redis says about a gateway stream rotating
// its keys (K1a1 plan §16.12).
type GatewayRotationState int

const (
	// GatewayRotationHeld means the stream still holds the presence and the
	// keys are not contested.
	GatewayRotationHeld GatewayRotationState = iota + 1
	// GatewayRotationContested means the stream holds the presence, but a
	// live holder of the keys lost it to another within the contest window.
	GatewayRotationContested
	// GatewayRotationNotHeld means another stream holds the presence, or none.
	GatewayRotationNotHeld
)

func (state GatewayRotationState) String() string {
	switch state {
	case GatewayRotationHeld:
		return "held"
	case GatewayRotationContested:
		return "contested"
	case GatewayRotationNotHeld:
		return "not_held"
	default:
		return "unknown"
	}
}

// GatewayPresenceStore keeps the presence of Kubernetes gateways' streams:
// a lease names its holder, one Serve, and a take of a live holder's lease
// marks the gateway's machine key contested for window, on every replica.
type GatewayPresenceStore interface {
	AcquireGatewayPresence(ctx context.Context, scope network.Scope, lease node.PresenceLease,
		window time.Duration) (GatewayClaim, error)
	RenewGatewayPresence(ctx context.Context, lease node.PresenceLease) (bool, error)
	// ReleaseGatewayPresence ends the lease if lease's holder still has it.
	ReleaseGatewayPresence(ctx context.Context, scope network.Scope, lease node.PresenceLease) (bool, error)
	// HandOffGatewayPresence keeps the lease but marks it handed off by
	// Core (Shutdown, Shed): the next take of it is not counted as a fight.
	HandOffGatewayPresence(ctx context.Context, lease node.PresenceLease) (bool, error)
	CheckGatewayRotation(ctx context.Context, lease node.PresenceLease) (GatewayRotationState, error)
}

// GatewayPresenceSink is the StreamSink of a Kubernetes gateway's stream.
type GatewayPresenceSink interface {
	// PresenceClaimed tells the session its current stream holds lease,
	// before the stream's first snapshot.
	PresenceClaimed(network.Scope, node.PresenceLease)
	// GatewayKeysFought tells the session this claim made the gateway's
	// keys fought over.
	GatewayKeysFought()
	// HandsOffPresence reports whether Core is moving the session to
	// another replica (Shutdown, Shed): the lease is then kept, marked
	// handed off, instead of released.
	HandsOffPresence() bool
	// KeepsPresence reports whether the session stopped the stream to
	// rotate the gateway's machine key: the lease is then left alone, and
	// the session ends it once the rotation is decided.
	KeepsPresence() bool
}

// gatewayStream is what a Kubernetes gateway's stream holds its presence
// with.
type gatewayStream struct {
	store GatewayPresenceStore
	sink  GatewayPresenceSink
}

// gatewayPresence returns, for a Kubernetes gateway's machine, its store,
// sink and machine key fingerprint; nil for any other machine.
func (service *StreamService) gatewayPresence(machine control.AuthenticatedMachine,
	sink StreamSink) (*gatewayStream, [32]byte, error) {
	fingerprint, gateway := machine.KubernetesGateway()
	if !gateway {
		return nil, [32]byte{}, nil
	}
	store, storeOK := service.presence.(GatewayPresenceStore)
	gatewaySink, sinkOK := sink.(GatewayPresenceSink)
	if !storeOK || !sinkOK {
		return nil, [32]byte{}, ErrInvalidStreamService
	}
	return &gatewayStream{store: store, sink: gatewaySink}, fingerprint, nil
}

// gatewayLease names a fresh holder for one stream's lease.
func gatewayLease(lease node.PresenceLease, machine [32]byte) (node.PresenceLease, error) {
	holder, err := node.NewPresenceHolder()
	if err != nil {
		return node.PresenceLease{}, errors.Join(ErrStreamUnavailable, err)
	}
	lease, err = lease.WithGateway(holder, machine)
	if err != nil {
		return node.PresenceLease{}, errors.Join(ErrInvalidStreamService, err)
	}
	return lease, nil
}

func (service *StreamService) acquireGatewayPresence(ctx context.Context, scope network.Scope,
	lease node.PresenceLease, gateway *gatewayStream) (bool, error) {
	operationCtx, cancel := context.WithTimeout(ctx, service.options.CoordinationTimeout)
	defer cancel()
	claim, err := gateway.store.AcquireGatewayPresence(operationCtx, scope, lease, GatewayContestWindow)
	if err != nil || !claim.Claimed {
		return false, err
	}
	gateway.sink.PresenceClaimed(scope, lease)
	if claim.Fight {
		gateway.sink.GatewayKeysFought()
	}
	return true, nil
}

// endGatewayPresence ends a gateway stream's lease, still held or not:
// released, handed off when Core moves the session, or left to the session
// rotating the gateway's machine key. Only this holder's
// lease is touched, so it never ends another stream's.
func (service *StreamService) endGatewayPresence(ctx context.Context, scope network.Scope,
	lease node.PresenceLease, sink GatewayPresenceSink) {
	store, ok := service.presence.(GatewayPresenceStore)
	if !ok {
		return
	}
	if sink.KeepsPresence() {
		return
	}
	operationCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), service.options.CoordinationTimeout)
	defer cancel()
	// Best effort: the lease still expires on its own if this fails.
	if sink.HandsOffPresence() {
		_, _ = store.HandOffGatewayPresence(operationCtx, lease)
		return
	}
	_, _ = store.ReleaseGatewayPresence(operationCtx, scope, lease)
}
