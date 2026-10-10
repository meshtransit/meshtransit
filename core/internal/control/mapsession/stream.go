package mapsession

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
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
	// SendRelayGrant delivers only the node's own entry, carrying a renewed
	// relay grant, when nothing else in the map changed.
	SendRelayGrant(context.Context, Snapshot) error
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
	// RelayAccess, when set, issues each node's Interchange grant.
	RelayAccess RelayAccess
	// FilterDigest, when set, records the digest of each delivered packet
	// filter so enforcement reports can be compared with it.
	FilterDigest FilterDigester
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
	delivery     DeliveryRecorder
	enforcement  EnforcementRecorder

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
	snapshot, _ = service.grantRelayAccess(ctx, Snapshot{}, snapshot)
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
	service.recordDelivery(ctx, snapshot, service.filterDigest(snapshot))
	err = service.run(
		ctx,
		machine,
		request,
		sink,
		lease,
		snapshot,
		watch,
	)
	if errors.Is(err, ErrSuspended) || errors.Is(err, ErrUnauthorized) ||
		errors.Is(err, ErrAuthorizationExpired) {
		// The node lost its authority: show it offline now instead of when
		// the lease expires. A reconnect races nothing, since it is refused.
		service.releasePresence(ctx, snapshot.Scope(), lease)
	}
	return err
}

// PresenceReleaser is implemented by presence stores that can end a lease
// at once.
type PresenceReleaser interface {
	ReleasePresence(context.Context, network.Scope, node.PresenceLease) (bool, error)
}

func (service *StreamService) releasePresence(ctx context.Context, scope network.Scope, lease node.PresenceLease) {
	releaser, ok := service.presence.(PresenceReleaser)
	if !ok {
		return
	}
	operationCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), service.options.CoordinationTimeout)
	defer cancel()
	// Best effort: the lease still expires on its own if this fails.
	_, _ = releaser.ReleasePresence(operationCtx, scope, lease)
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
	relayRenewal := time.NewTimer(time.Hour)
	relayRenewal.Stop()
	defer relayRenewal.Stop()

	defer func() { watch.close() }()
	current := initial
	delivered := initial.NetworkRevision()
	deliveredFilter := service.filterDigest(initial)
	lastTouch := time.Now()
	// advance adopts a refreshed snapshot and records it when the client now
	// holds a newer Network revision, or a different packet filter, than it
	// was last known to have. Only a revision or projection change can change
	// the filter, so the digest is not recomputed for connectivity changes.
	advance := func(next Snapshot) {
		previous := current
		current = next
		revisionChanged := current.NetworkRevision() != delivered
		if !revisionChanged &&
			equalDirectDeviceProjections(previous.directDeviceProjections, current.directDeviceProjections) {
			return
		}
		filter := service.filterDigest(current)
		if !revisionChanged && filter == deliveredFilter {
			return
		}
		delivered, deliveredFilter = current.NetworkRevision(), filter
		service.recordDelivery(ctx, current, filter)
	}
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
		var relayRenewalDue <-chan time.Time
		// A renewal that failed leaves RenewAt in the past; it is retried by
		// the reconcile ticker instead of a hot loop.
		if grant := current.RelayGrant(); grant.IsValid() && grant.RenewAt().After(time.Now()) {
			relayRenewal.Reset(time.Until(grant.RenewAt()))
			relayRenewalDue = relayRenewal.C
		} else {
			relayRenewal.Stop()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-relayRenewalDue:
			next, err := service.refresh(ctx, machine, request, sink, current)
			if err != nil {
				return err
			}
			advance(next)
		case <-authorityExpiry.C:
			return withdrawAuthority(ctx, sink, current, ErrAuthorizationExpired)
		case <-projectionDeadline:
			next, err := service.refresh(ctx, machine, request, sink, current)
			if err != nil {
				return err
			}
			advance(next)
		case <-renewal.C:
			claimed, err := service.renewPresence(ctx, lease)
			if err != nil {
				return errors.Join(ErrPresenceLost, err)
			}
			if !claimed {
				return ErrPresenceLost
			}
			if now := time.Now(); now.Sub(lastTouch) >= DeliveryTouchInterval {
				lastTouch = now
				service.touchDelivery(ctx, current, now)
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
			advance(next)
		case <-reconcile.C:
			next, err := service.refresh(ctx, machine, request, sink, current)
			if err != nil {
				return err
			}
			advance(next)
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
	next, grantChanged := service.grantRelayAccess(ctx, current, next)
	selfSent, err := service.deliver(ctx, sink, current, next)
	if err != nil {
		return Snapshot{}, err
	}
	if grantChanged && !selfSent {
		if err := sink.SendRelayGrant(ctx, next); err != nil {
			return Snapshot{}, errors.Join(ErrStreamWrite, err)
		}
	}
	return next, nil
}

// deliver sends whatever moves the client from current to next and reports
// whether that included the node's own entry (and so its relay grant).
func (service *StreamService) deliver(
	ctx context.Context,
	sink StreamSink,
	current, next Snapshot,
) (bool, error) {
	if !streamSnapshotChanged(current, next) {
		return false, nil
	}
	if relayDirectoryChanged(current, next) ||
		(current.NetworkRevision() == next.NetworkRevision() &&
			!equalDirectDeviceProjections(current.directDeviceProjections, next.directDeviceProjections)) {
		if err := sink.SendSnapshot(ctx, next); err != nil {
			return false, errors.Join(ErrStreamWrite, err)
		}
		return true, nil
	}
	if current.NetworkRevision() == next.NetworkRevision() {
		delta, deltaErr := NewConnectivityDelta(current, next)
		if deltaErr != nil {
			cause := errors.Join(ErrStreamDiscontinuity, deltaErr)
			return false, withdrawAuthority(ctx, sink, current, cause)
		}
		if err := sink.SendConnectivityDelta(ctx, delta); err != nil {
			return false, errors.Join(ErrStreamWrite, err)
		}
		return delta.SelfChanged(), nil
	}
	if next.NetworkRevision() == current.NetworkRevision()+1 {
		delta, deltaErr := NewAuthorityDelta(current, next)
		if deltaErr == nil {
			if err := sink.SendAuthorityDelta(ctx, delta); err != nil {
				return false, errors.Join(ErrStreamWrite, err)
			}
			return delta.SelfChanged(), nil
		}
	}
	if err := sink.SendSnapshot(ctx, next); err != nil {
		return false, errors.Join(ErrStreamWrite, err)
	}
	return true, nil
}

// grantRelayAccess carries current's relay grant over to next while it still
// covers next, and otherwise issues a new one. Without a disco key or when
// issuing fails, the previous grant stays (it expires on its own) and the
// next refresh tries again; relay access never ends a map stream.
func (service *StreamService) grantRelayAccess(ctx context.Context, current, next Snapshot) (Snapshot, bool) {
	access := service.options.RelayAccess
	if isNilDependency(access) {
		return next, false
	}
	now := time.Now()
	previous := current.RelayGrant()
	request, ok := next.RelayGrantRequest()
	mapCurrent := true
	if freshness, tracked := access.(RelayMapFreshness); tracked && previous.IsValid() && ok {
		mapCurrent = freshness.RelayMapCurrent(request.Network, previous.mapKey)
	}
	if !ok || (mapCurrent && relayGrantCurrent(previous, request, now)) {
		if previous.IsValid() && now.Before(previous.request.NotAfter) {
			return next.WithRelayGrant(previous), false
		}
		return next, false
	}
	operationCtx, cancel := context.WithTimeout(ctx, service.options.SnapshotTimeout)
	defer cancel()
	grant, err := access.GrantRelayAccess(operationCtx, request)
	if err != nil || !grant.IsValid() {
		return next.WithRelayGrant(previous), false
	}
	return next.WithRelayGrant(grant), true
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
