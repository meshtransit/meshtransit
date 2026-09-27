package mapsession

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

var (
	// ErrInvalidStreamService reports incomplete dependencies or unsafe bounds.
	ErrInvalidStreamService = errors.New("map session: invalid stream service")
	// ErrStreamUnavailable classifies a stream that cannot continue safely.
	ErrStreamUnavailable = errors.New("map session: stream unavailable")
	// ErrPresenceConflict reports a generation-fenced lease owned elsewhere.
	ErrPresenceConflict = errors.New("map session: presence lease conflict")
	// ErrPresenceLost reports a lease that could not be renewed by its owner.
	ErrPresenceLost = errors.New("map session: presence lease lost")
	// ErrStreamDiscontinuity reports regressed or incompatible authority evidence.
	ErrStreamDiscontinuity = errors.New("map session: authority discontinuity")
	// ErrAuthorizationExpired reports that the stream reached its initial authority deadline.
	ErrAuthorizationExpired = errors.New("map session: authorization expired")
	// ErrStreamWrite reports a failed snapshot, delta, withdrawal, or keepalive delivery.
	ErrStreamWrite = errors.New("map session: stream write failed")
)

// SnapshotOpener authorizes and loads one immutable map snapshot.
type SnapshotOpener interface {
	Open(context.Context, control.AuthenticatedMachine, Request) (Snapshot, error)
}

// PresenceStore owns only ephemeral, generation-fenced stream observations.
type PresenceStore interface {
	ClaimPresence(context.Context, network.Scope, node.PresenceLease) (bool, error)
	ReleasePresence(context.Context, network.Scope, node.PresenceLease) (bool, error)
}

// StreamSink serially delivers product snapshots, terminal authority
// withdrawal, and transport keepalives. The caller owns the sink for the
// duration of one Serve call.
type StreamSink interface {
	SendSnapshot(context.Context, Snapshot) error
	SendAuthorityDelta(context.Context, AuthorityDelta) error
	SendConnectivityDelta(context.Context, ConnectivityDelta) error
	SendAuthorityWithdrawal(context.Context, Snapshot) error
	SendKeepAlive(context.Context) error
}

// RevisionWatcher provides a bounded local wakeup channel for one Network.
// The release function is caller-owned and must be idempotent.
type RevisionWatcher interface {
	WatchNetwork(network.ID) (<-chan network.RevisionAdvanced, func(), error)
}

// ConnectivityWatcher provides bounded wakeups for non-authoritative endpoint
// and presence changes. The release function must be idempotent.
type ConnectivityWatcher interface {
	WatchNetwork(network.ID) (<-chan ConnectivityChanged, func(), error)
}

// StreamOptions bounds one caller-owned map stream lifecycle.
type StreamOptions struct {
	ReplicaID           publicid.ID
	SnapshotTimeout     time.Duration
	PresenceTTL         time.Duration
	CoordinationTimeout time.Duration
	KeepAliveInterval   time.Duration
	ReconcileInterval   time.Duration
}

// StreamService runs generation-fenced map streams synchronously. It owns no
// goroutines or authority cache; its mutex protects only local live ownership
// and is never held across PostgreSQL, Redis, or sink I/O.
type StreamService struct {
	snapshots    SnapshotOpener
	presence     PresenceStore
	revisions    RevisionWatcher
	connectivity ConnectivityWatcher
	options      StreamOptions

	activeMu sync.Mutex
	active   map[node.ID]struct{}
}

// NewStreamService validates and constructs a stateless stream service.
func NewStreamService(
	snapshots SnapshotOpener,
	presence PresenceStore,
	revisions RevisionWatcher,
	connectivity ConnectivityWatcher,
	options StreamOptions,
) (*StreamService, error) {
	if isNilDependency(snapshots) || isNilDependency(presence) ||
		isNilDependency(revisions) || isNilDependency(connectivity) ||
		!validStreamOptions(options) {
		return nil, ErrInvalidStreamService
	}
	return &StreamService{
		snapshots:    snapshots,
		presence:     presence,
		revisions:    revisions,
		connectivity: connectivity,
		options:      options,
		active:       make(map[node.ID]struct{}),
	}, nil
}

// Serve authorizes an initial snapshot, owns and renews its Redis presence
// lease, periodically reconciles PostgreSQL, and releases exact ownership on
// exit. Redis failure terminates the stream without changing durable authority.
func (service *StreamService) Serve(
	ctx context.Context,
	machine control.AuthenticatedMachine,
	request Request,
	sink StreamSink,
) (resultErr error) {
	if ctx == nil || service == nil || isNilDependency(service.snapshots) ||
		isNilDependency(service.presence) || isNilDependency(service.revisions) ||
		isNilDependency(service.connectivity) ||
		!validStreamOptions(service.options) || !machine.IsValid() || !request.IsValid() ||
		isNilDependency(sink) {
		return ErrInvalidStreamService
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	snapshot, err := service.openSnapshot(ctx, machine, request)
	if err != nil {
		return errors.Join(ErrStreamUnavailable, err)
	}
	if !snapshot.KeyExpiry().After(time.Now()) {
		return ErrAuthorizationExpired
	}
	if !service.admit(snapshot.NodeID()) {
		return ErrPresenceConflict
	}
	defer service.release(snapshot.NodeID())
	updates, stopWatching, err := service.revisions.WatchNetwork(snapshot.Scope().NetworkID())
	if err != nil {
		return errors.Join(ErrStreamUnavailable, err)
	}
	if updates == nil || stopWatching == nil {
		if stopWatching != nil {
			stopWatching()
		}
		return ErrStreamUnavailable
	}
	defer stopWatching()
	connectivityUpdates, stopConnectivity, err := service.connectivity.WatchNetwork(
		snapshot.Scope().NetworkID(),
	)
	if err != nil {
		return errors.Join(ErrStreamUnavailable, err)
	}
	if connectivityUpdates == nil || stopConnectivity == nil {
		if stopConnectivity != nil {
			stopConnectivity()
		}
		return ErrStreamUnavailable
	}
	defer stopConnectivity()
	lease, err := node.NewPresenceLease(
		snapshot.NodeID(),
		snapshot.SessionGeneration(),
		service.options.ReplicaID.String(),
		service.options.PresenceTTL,
	)
	if err != nil {
		return errors.Join(ErrInvalidStreamService, err)
	}
	claimed, err := service.claimPresence(ctx, snapshot.Scope(), lease)
	if err != nil {
		return errors.Join(ErrStreamUnavailable, err)
	}
	if !claimed {
		return ErrPresenceConflict
	}
	defer func() {
		resultErr = errors.Join(
			resultErr,
			service.releasePresence(ctx, snapshot.Scope(), lease),
		)
	}()

	if err := sink.SendSnapshot(ctx, snapshot); err != nil {
		return errors.Join(ErrStreamWrite, err)
	}
	return service.run(
		ctx,
		machine,
		request,
		sink,
		lease,
		snapshot,
		updates,
		connectivityUpdates,
	)
}

func (service *StreamService) admit(nodeID node.ID) bool {
	service.activeMu.Lock()
	defer service.activeMu.Unlock()
	if _, exists := service.active[nodeID]; exists {
		return false
	}
	service.active[nodeID] = struct{}{}
	return true
}

func (service *StreamService) release(nodeID node.ID) {
	service.activeMu.Lock()
	delete(service.active, nodeID)
	service.activeMu.Unlock()
}

func (service *StreamService) run(
	ctx context.Context,
	machine control.AuthenticatedMachine,
	request Request,
	sink StreamSink,
	lease node.PresenceLease,
	initial Snapshot,
	updates <-chan network.RevisionAdvanced,
	connectivityUpdates <-chan ConnectivityChanged,
) error {
	renewal := time.NewTicker(service.options.PresenceTTL / 3)
	defer renewal.Stop()
	keepAlive := time.NewTicker(service.options.KeepAliveInterval)
	defer keepAlive.Stop()
	reconcile := time.NewTicker(service.options.ReconcileInterval)
	defer reconcile.Stop()
	authorityExpiry := time.NewTimer(time.Until(initial.KeyExpiry()))
	defer authorityExpiry.Stop()

	current := initial
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-authorityExpiry.C:
			return withdrawAuthority(ctx, sink, current, ErrAuthorizationExpired)
		case <-renewal.C:
			claimed, err := service.claimPresence(ctx, current.Scope(), lease)
			if err != nil {
				return errors.Join(ErrPresenceLost, err)
			}
			if !claimed {
				return ErrPresenceLost
			}
		case <-keepAlive.C:
			if err := sink.SendKeepAlive(ctx); err != nil {
				return errors.Join(ErrStreamWrite, err)
			}
		case revision, open := <-updates:
			if !open {
				return ErrStreamUnavailable
			}
			if !revision.IsValid() || revision.NetworkID() != current.Scope().NetworkID() {
				return ErrStreamDiscontinuity
			}
			if revision.Number() <= current.NetworkRevision() {
				continue
			}
			next, err := service.refresh(ctx, machine, request, sink, current)
			if err != nil {
				return err
			}
			current = next
		case change, open := <-connectivityUpdates:
			if !open {
				return ErrStreamUnavailable
			}
			if !change.IsValid() || change.NetworkID() != current.Scope().NetworkID() {
				return ErrStreamDiscontinuity
			}
			if !streamTracksConnectivity(current, change) {
				continue
			}
			next, err := service.refresh(ctx, machine, request, sink, current)
			if err != nil {
				return err
			}
			current = next
		case <-reconcile.C:
			next, err := service.refresh(ctx, machine, request, sink, current)
			if err != nil {
				return err
			}
			current = next
		}
	}
}

func (service *StreamService) refresh(
	ctx context.Context,
	machine control.AuthenticatedMachine,
	request Request,
	sink StreamSink,
	current Snapshot,
) (Snapshot, error) {
	next, err := service.openSnapshot(ctx, machine, request)
	if err != nil {
		cause := errors.Join(ErrStreamUnavailable, err)
		if errors.Is(err, ErrUnauthorized) {
			return Snapshot{}, withdrawAuthority(ctx, sink, current, cause)
		}
		return Snapshot{}, cause
	}
	if !streamCanAdvance(current, next) {
		return Snapshot{}, withdrawAuthority(ctx, sink, current, ErrStreamDiscontinuity)
	}
	if !streamSnapshotChanged(current, next) {
		return current, nil
	}
	if relayDirectoryChanged(current, next) {
		if err := sink.SendSnapshot(ctx, next); err != nil {
			return Snapshot{}, errors.Join(ErrStreamWrite, err)
		}
		return next, nil
	}
	if current.NetworkRevision() == next.NetworkRevision() {
		delta, deltaErr := NewConnectivityDelta(current, next)
		if deltaErr != nil {
			cause := errors.Join(ErrStreamDiscontinuity, deltaErr)
			return Snapshot{}, withdrawAuthority(ctx, sink, current, cause)
		}
		if err := sink.SendConnectivityDelta(ctx, delta); err != nil {
			return Snapshot{}, errors.Join(ErrStreamWrite, err)
		}
		return next, nil
	}
	if next.NetworkRevision() == current.NetworkRevision()+1 {
		delta, deltaErr := NewAuthorityDelta(current, next)
		if deltaErr == nil {
			if err := sink.SendAuthorityDelta(ctx, delta); err != nil {
				return Snapshot{}, errors.Join(ErrStreamWrite, err)
			}
			return next, nil
		}
	}
	if err := sink.SendSnapshot(ctx, next); err != nil {
		return Snapshot{}, errors.Join(ErrStreamWrite, err)
	}
	return next, nil
}

func withdrawAuthority(
	ctx context.Context,
	sink StreamSink,
	current Snapshot,
	cause error,
) error {
	if err := sink.SendAuthorityWithdrawal(ctx, current); err != nil {
		return errors.Join(cause, ErrStreamWrite, err)
	}
	return cause
}

func (service *StreamService) openSnapshot(
	ctx context.Context,
	machine control.AuthenticatedMachine,
	request Request,
) (Snapshot, error) {
	operationCtx, cancel := context.WithTimeout(ctx, service.options.SnapshotTimeout)
	defer cancel()
	return service.snapshots.Open(operationCtx, machine, request)
}

func (service *StreamService) claimPresence(
	ctx context.Context,
	scope network.Scope,
	lease node.PresenceLease,
) (bool, error) {
	operationCtx, cancel := context.WithTimeout(ctx, service.options.CoordinationTimeout)
	defer cancel()
	claimed, err := service.presence.ClaimPresence(operationCtx, scope, lease)
	if err != nil {
		return false, fmt.Errorf("claim presence: %w", err)
	}
	return claimed, nil
}

func (service *StreamService) releasePresence(
	requestCtx context.Context,
	scope network.Scope,
	lease node.PresenceLease,
) error {
	cleanupCtx, cancel := context.WithTimeout(
		context.WithoutCancel(requestCtx),
		service.options.CoordinationTimeout,
	)
	defer cancel()
	if _, err := service.presence.ReleasePresence(cleanupCtx, scope, lease); err != nil {
		return errors.Join(ErrStreamUnavailable, fmt.Errorf("release presence: %w", err))
	}
	return nil
}
