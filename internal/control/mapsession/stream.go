package mapsession

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
	AcquirePresence(context.Context, network.Scope, node.PresenceLease) (bool, error)
	RenewPresence(context.Context, node.PresenceLease) (bool, error)
}

// StreamSink serially delivers product snapshots, terminal authority
// withdrawal, and transport keepalives. The caller owns the sink for the
// duration of one Serve call.
type StreamSink interface {
	SendSnapshot(context.Context, Snapshot) error
	SendAuthorityDelta(context.Context, AuthorityDelta) error
	SendConnectivityDelta(context.Context, ConnectivityDelta) error
	SendAuthorityWithdrawal(context.Context, Snapshot) error
	// SendAuthorityPause clears every peer and rule but tells the client its
	// identity stands, so it retries until the Device is resumed.
	SendAuthorityPause(context.Context, Snapshot) error
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
// lease, and periodically reconciles PostgreSQL. On exit the lease is left to
// expire so a reconnect may take over the same generation without an offline
// gap. Redis failure terminates the stream without changing durable authority.
func (service *StreamService) Serve(
	ctx context.Context,
	machine control.AuthenticatedMachine,
	request Request,
	sink StreamSink,
) error {
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
	snapshot, watch, err := service.watchInitialSnapshot(ctx, machine, request, snapshot)
	if err != nil {
		return err
	}
	defer watch.close()
	if !snapshot.KeyExpiry().After(time.Now()) {
		return ErrAuthorizationExpired
	}
	lease, err := node.NewPresenceLease(
		snapshot.NodeID(),
		snapshot.SessionGeneration(),
		service.options.ReplicaID.String(),
		service.options.PresenceTTL,
	)
	if err != nil {
		return errors.Join(ErrInvalidStreamService, err)
	}
	claimed, err := service.acquirePresence(ctx, snapshot.Scope(), lease)
	if err != nil {
		return errors.Join(ErrStreamUnavailable, err)
	}
	if !claimed {
		return ErrPresenceConflict
	}
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
		watch,
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
	watch *streamWatch,
) error {
	renewal := time.NewTicker(service.options.PresenceTTL / 3)
	defer renewal.Stop()
	keepAlive := time.NewTicker(service.options.KeepAliveInterval)
	defer keepAlive.Stop()
	reconcile := time.NewTicker(service.options.ReconcileInterval)
	defer reconcile.Stop()
	authorityExpiry := time.NewTimer(time.Until(initial.KeyExpiry()))
	defer authorityExpiry.Stop()
	expiry := initial.KeyExpiry()
	projectionExpiry := time.NewTimer(time.Hour)
	projectionExpiry.Stop()
	defer projectionExpiry.Stop()

	defer func() { watch.close() }()
	current := initial
	for {
		if !current.KeyExpiry().Equal(expiry) {
			// An owner change or extension moved the deadline; the new snapshot
			// already carries it to the client.
			expiry = current.KeyExpiry()
			if !authorityExpiry.Stop() {
				select {
				case <-authorityExpiry.C:
				default:
				}
			}
			authorityExpiry.Reset(time.Until(expiry))
		}
		scopes := append([]network.Scope{current.Scope()}, current.SharingScopes()...)
		if !slices.Equal(scopes, watch.scopes) {
			nextWatch, err := service.watchSnapshot(ctx, current)
			if err != nil {
				return withdrawAuthority(ctx, sink, current, err)
			}
			watch.close()
			watch = nextWatch
			select {
			case watch.updates <- streamWakeup{reconcile: true}:
			default:
			}
		}
		var projectionDeadline <-chan time.Time
		if deadline := current.ProjectionExpiry(); deadline.Before(current.KeyExpiry()) {
			projectionExpiry.Reset(time.Until(deadline))
			projectionDeadline = projectionExpiry.C
		} else {
			projectionExpiry.Stop()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-authorityExpiry.C:
			return withdrawAuthority(ctx, sink, current, ErrAuthorizationExpired)
		case <-projectionDeadline:
			next, err := service.refresh(ctx, machine, request, sink, current)
			if err != nil {
				return err
			}
			current = next
		case <-renewal.C:
			claimed, err := service.renewPresence(ctx, lease)
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
		case err := <-watch.failure:
			if len(current.directDeviceProjections) != 0 {
				return withdrawAuthority(ctx, sink, current, err)
			}
			return err
		case wake := <-watch.updates:
			if !wake.reconcile {
				if wake.revision.IsValid() && wake.revision.NetworkID() == current.Scope().NetworkID() && wake.revision.Number() <= current.NetworkRevision() {
					continue
				}
				if wake.connectivity.IsValid() && !streamTracksConnectivity(current, wake.connectivity) {
					continue
				}
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
	if errors.Is(err, ErrSuspended) {
		if sendErr := sink.SendAuthorityPause(ctx, current); sendErr != nil {
			return Snapshot{}, errors.Join(err, ErrStreamWrite, sendErr)
		}
		return Snapshot{}, err
	}
	if err != nil {
		cause := errors.Join(ErrStreamUnavailable, err)
		if errors.Is(err, ErrUnauthorized) || len(current.directDeviceProjections) != 0 ||
			!current.ProjectionExpiry().After(time.Now()) {
			return Snapshot{}, withdrawAuthority(ctx, sink, current, cause)
		}
		return Snapshot{}, cause
	}
	if !streamCanAdvance(current, next) {
		return Snapshot{}, withdrawAuthority(ctx, sink, current, ErrStreamDiscontinuity)
	}
	if !streamSnapshotChanged(current, next) {
		return next, nil
	}
	if relayDirectoryChanged(current, next) ||
		(current.NetworkRevision() == next.NetworkRevision() &&
			!equalDirectDeviceProjections(current.directDeviceProjections, next.directDeviceProjections)) {
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
	snapshot, err := service.snapshots.Open(operationCtx, machine, request)
	if err == nil && len(snapshot.directDeviceProjections) != 0 && !snapshot.ProjectionExpiry().After(time.Now()) {
		return Snapshot{}, ErrStreamDiscontinuity
	}
	return snapshot, err
}

func (service *StreamService) acquirePresence(
	ctx context.Context,
	scope network.Scope,
	lease node.PresenceLease,
) (bool, error) {
	operationCtx, cancel := context.WithTimeout(ctx, service.options.CoordinationTimeout)
	defer cancel()
	claimed, err := service.presence.AcquirePresence(operationCtx, scope, lease)
	if err != nil {
		return false, fmt.Errorf("acquire presence: %w", err)
	}
	return claimed, nil
}

func (service *StreamService) renewPresence(
	ctx context.Context,
	lease node.PresenceLease,
) (bool, error) {
	operationCtx, cancel := context.WithTimeout(ctx, service.options.CoordinationTimeout)
	defer cancel()
	renewed, err := service.presence.RenewPresence(operationCtx, lease)
	if err != nil {
		return false, fmt.Errorf("renew presence: %w", err)
	}
	return renewed, nil
}
