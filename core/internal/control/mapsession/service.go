package mapsession

import (
	"context"
	"errors"
	"fmt"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

var (
	// ErrInvalidService reports a missing dependency or unsafe option.
	ErrInvalidService = errors.New("map session: invalid service")
	// ErrUnauthorized reports that the bound identity has no active Node authority.
	ErrUnauthorized = errors.New("map session: unauthorized")
	// ErrSuspended reports that the bound identity's Device is suspended: it
	// has no authority now but keeps its identity and may be resumed.
	ErrSuspended = errors.New("map session: device suspended")
	// ErrOpen classifies a map session that could not be opened safely.
	ErrOpen = errors.New("map session: open failed")
	// ErrEndpointObservationRejected reports a stale transient endpoint update.
	ErrEndpointObservationRejected = errors.New("map session: endpoint observation rejected")
)

// SnapshotStore loads one immutable snapshot for an authenticated Node identity.
type SnapshotStore interface {
	Load(context.Context, control.AuthenticatedNode) (Snapshot, error)
}

// DeviceAliasVersionObserver records only a transport-bound compatibility claim.
// Implementations derive current scope and key/session epochs from PostgreSQL.
type DeviceAliasVersionObserver interface {
	ObserveDeviceAliasVersion(context.Context, control.AuthenticatedNode, uint8) error
}

// EndpointObserver records only generation-fenced transient connectivity.
type EndpointObserver interface {
	ObserveEndpoints(context.Context, network.Scope, node.EndpointObservation) (bool, error)
}

// ConnectivityStore loads only exact-generation transient state for keys that
// this service already authorized through PostgreSQL and packet policy.
type ConnectivityStore interface {
	LoadConnectivity(context.Context, []ConnectivityKey) ([]Connectivity, error)
}

// Service authorizes an authenticated Node and opens its map snapshot. It owns
// no goroutines and retains no request or snapshot state.
type Service struct {
	store        SnapshotStore
	endpoints    EndpointObserver
	connectivity ConnectivityStore
	hub          *ConnectivityHub // nil: every snapshot reads its peers itself
	options      ServiceOptions
}

// WithConnectivityHub returns a copy whose snapshots read connectivity
// through the replica's shared tables.
func (service *Service) WithConnectivityHub(hub *ConnectivityHub) (*Service, error) {
	if service == nil || hub == nil {
		return nil, ErrInvalidService
	}
	copied := *service
	copied.hub = hub
	return &copied, nil
}

// NewService constructs a map-session application service.
func NewService(
	store SnapshotStore,
	endpoints EndpointObserver,
	connectivity ConnectivityStore,
	options ServiceOptions,
) (*Service, error) {
	if isNilDependency(store) || isNilDependency(endpoints) ||
		isNilDependency(connectivity) || !options.isValid() {
		return nil, ErrInvalidService
	}
	return &Service{
		store:        store,
		endpoints:    endpoints,
		connectivity: connectivity,
		options:      options,
	}, nil
}

// Open binds the request Node key to the transport-authenticated machine and
// returns only snapshot evidence that matches that exact identity.
func (service *Service) Open(
	ctx context.Context,
	machine control.AuthenticatedMachine,
	request Request,
) (Snapshot, error) {
	return service.open(ctx, machine, request, true)
}

// Reopen is Open for a stream that already opened this session: it re-reads
// authority but does not write the client's compatibility claim again,
// which Open recorded for the session's generation (a new generation ends
// the stream).
func (service *Service) Reopen(
	ctx context.Context,
	machine control.AuthenticatedMachine,
	request Request,
) (Snapshot, error) {
	return service.open(ctx, machine, request, false)
}

// SnapshotDeriver refreshes a running stream's snapshot from shared Network
// state alone. found is false when the Device must be read instead.
type SnapshotDeriver interface {
	Derive(ctx context.Context, current Snapshot, minRevision int64) (Snapshot, bool, error)
}

// Refresh implements SnapshotRefresher: it derives the stream's next
// snapshot from shared Network state when the store can, and otherwise
// re-reads authority like Reopen. A derived snapshot belongs to the same
// authenticated Device, session and keys as current.
func (service *Service) Refresh(
	ctx context.Context,
	machine control.AuthenticatedMachine,
	request Request,
	current Snapshot,
	minRevision int64,
) (Snapshot, error) {
	deriver, ok := service.store.(SnapshotDeriver)
	if !ok || ctx == nil || !current.IsValid() || !request.IsValid() {
		return service.Reopen(ctx, machine, request)
	}
	identity, err := machine.BindNodeKey(request.NodeKey())
	if err != nil {
		return Snapshot{}, errors.Join(ErrUnauthorized, err)
	}
	if current.NodeKey() != identity.NodeKey() || current.MachineKey().Fingerprint() != identity.MachineFingerprint() {
		return Snapshot{}, ErrOpen
	}
	derived, found, err := deriver.Derive(ctx, current, minRevision)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: derive snapshot: %w", ErrOpen, err)
	}
	if !found {
		return service.Reopen(ctx, machine, request)
	}
	if !derived.IsValid() || derived.NodeKey() != identity.NodeKey() ||
		derived.MachineKey().Fingerprint() != identity.MachineFingerprint() {
		return Snapshot{}, ErrOpen
	}
	return service.loadConnectivity(ctx, derived)
}

func (service *Service) open(
	ctx context.Context,
	machine control.AuthenticatedMachine,
	request Request,
	recordCompatibility bool,
) (Snapshot, error) {
	if ctx == nil || service == nil || isNilDependency(service.store) ||
		isNilDependency(service.endpoints) || isNilDependency(service.connectivity) ||
		!service.options.isValid() || !request.IsValid() {
		return Snapshot{}, ErrInvalidService
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, errors.Join(ErrOpen, err)
	}
	identity, err := machine.BindNodeKey(request.NodeKey())
	if err != nil {
		return Snapshot{}, errors.Join(ErrUnauthorized, err)
	}
	if observer, ok := service.store.(DeviceAliasVersionObserver); ok {
		if recordCompatibility {
			if err := observer.ObserveDeviceAliasVersion(ctx, identity, request.DeviceAliasVersion()); err != nil {
				return Snapshot{}, fmt.Errorf("%w: record client compatibility: %w", ErrOpen, err)
			}
		}
	} else if request.DeviceAliasVersion() != 0 {
		return Snapshot{}, ErrOpen
	}
	snapshot, err := service.store.Load(ctx, identity)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: load authoritative snapshot: %w", ErrOpen, err)
	}
	if !snapshot.IsValid() || snapshot.NodeKey() != identity.NodeKey() ||
		snapshot.MachineKey().Fingerprint() != identity.MachineFingerprint() {
		return Snapshot{}, ErrOpen
	}
	if request.DeviceAliasVersion() == 0 {
		for _, projection := range snapshot.directDeviceProjections {
			if projection.aliases.IsValid() {
				return Snapshot{}, ErrOpen
			}
		}
	}
	if err := service.observeEndpoints(ctx, snapshot, request); err != nil {
		return Snapshot{}, err
	}
	return service.loadConnectivity(ctx, snapshot)
}

func (service *Service) observeEndpoints(
	ctx context.Context,
	snapshot Snapshot,
	request Request,
) error {
	set, present := request.EndpointSet()
	if !present {
		return nil
	}
	observation, err := node.NewEndpointObservation(
		snapshot.NodeID(),
		snapshot.SessionGeneration(),
		set,
		service.options.EndpointTTL,
	)
	if err != nil {
		return errors.Join(ErrOpen, err)
	}
	if preferredRelay, preferredRelayPresent := request.PreferredRelay(); preferredRelayPresent {
		if preferredRelay > 0 && !usableRelayPreference(snapshot, preferredRelay) {
			return ErrOpen
		}
		observation, err = observation.WithPreferredRelay(preferredRelay)
		if err != nil {
			return errors.Join(ErrOpen, err)
		}
	}
	operationCtx, cancel := context.WithTimeout(ctx, service.options.EndpointTimeout)
	defer cancel()
	accepted, err := service.endpoints.ObserveEndpoints(
		operationCtx,
		snapshot.Scope(),
		observation,
	)
	if err != nil {
		return fmt.Errorf("%w: observe transient endpoints: %w", ErrOpen, err)
	}
	if !accepted {
		return errors.Join(ErrOpen, ErrEndpointObservationRejected)
	}
	return nil
}

func usableRelayPreference(snapshot Snapshot, regionID int) bool {
	region, found := snapshot.RelayDirectory().Region(regionID)
	if !found {
		return false
	}
	for _, relayNode := range region.Nodes() {
		if !relayNode.IsSTUNOnly() {
			return true
		}
	}
	return false
}

// ReloadConnectivity implements ConnectivityReloader: the same
// authoritative snapshot with its peers' connectivity read again.
func (service *Service) ReloadConnectivity(ctx context.Context, snapshot Snapshot) (Snapshot, error) {
	if ctx == nil || service == nil || isNilDependency(service.connectivity) || !snapshot.IsValid() {
		return Snapshot{}, ErrInvalidService
	}
	return service.loadConnectivity(ctx, snapshot)
}

func (service *Service) loadConnectivity(ctx context.Context, snapshot Snapshot) (Snapshot, error) {
	if service.hub == nil || len(snapshot.directDeviceProjections) != 0 {
		// A private read is bounded by the store: limit before reading, in
		// stable order (presence is unknown until read).
		snapshot = snapshot.withPeerLimit(service.options.peerLimit())
	}
	peers := snapshot.AuthorizedPeers()
	keys := make([]ConnectivityKey, 0, len(peers)+1)
	self, err := NewConnectivityKey(snapshot.NodeID(), snapshot.SessionGeneration())
	if err != nil {
		return Snapshot{}, errors.Join(ErrOpen, err)
	}
	keys = append(keys, self)
	for _, peer := range peers {
		key, keyErr := NewConnectivityKey(peer.NodeID(), peer.SessionGeneration())
		if keyErr != nil {
			return Snapshot{}, errors.Join(ErrOpen, keyErr)
		}
		keys = append(keys, key)
	}
	operationCtx, cancel := context.WithTimeout(ctx, service.options.EndpointTimeout)
	defer cancel()
	if service.hub != nil && len(snapshot.directDeviceProjections) == 0 {
		version, err := service.hub.view(operationCtx, snapshot.Scope().NetworkID(), keys)
		if err != nil {
			return Snapshot{}, fmt.Errorf("%w: load transient connectivity: %w", ErrOpen, err)
		}
		shared, err := snapshot.withSharedConnectivity(version)
		if err != nil {
			return Snapshot{}, errors.Join(ErrOpen, err)
		}
		return shared.withPeerLimit(service.options.peerLimit()), nil
	}
	values, err := service.connectivity.LoadConnectivity(operationCtx, keys)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: load transient connectivity: %w", ErrOpen, err)
	}
	if len(values) != len(keys) {
		return Snapshot{}, ErrOpen
	}
	for index := range keys {
		if !values[index].IsValid() || values[index].Key() != keys[index] {
			return Snapshot{}, ErrOpen
		}
		preferredRelay, preferredRelayPresent := values[index].PreferredRelay()
		if preferredRelayPresent && preferredRelay > 0 &&
			!usableRelayPreference(snapshot, preferredRelay) {
			values[index].preferredRelay = 0
			values[index].preferredRelayPresent = false
		}
	}
	enriched, err := snapshot.WithConnectivity(values)
	if err != nil {
		return Snapshot{}, errors.Join(ErrOpen, err)
	}
	return enriched.withPeerLimit(service.options.peerLimit()), nil
}

// ObserveSessionEndpoints records a node's transient connectivity for the
// map session of snapshot, which the caller already holds (MTCP sessions
// report endpoints on their live stream instead of a separate request).
func (service *Service) ObserveSessionEndpoints(ctx context.Context, snapshot Snapshot, set node.EndpointSet,
	preferredRelay int, hasPreferredRelay bool) error {
	if ctx == nil || service == nil || !snapshot.IsValid() || !set.IsValid() {
		return ErrInvalidRequest
	}
	request, err := NewRequest(snapshot.NodeKey())
	if err == nil {
		request, err = request.WithEndpointSet(set)
	}
	if err == nil && hasPreferredRelay {
		request, err = request.WithPreferredRelay(preferredRelay)
	}
	if err != nil {
		return err
	}
	return service.observeEndpoints(ctx, snapshot, request)
}
