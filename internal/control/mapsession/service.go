package mapsession

import (
	"context"
	"errors"
	"fmt"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
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
	options      ServiceOptions
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
		if err := observer.ObserveDeviceAliasVersion(ctx, identity, request.DeviceAliasVersion()); err != nil {
			return Snapshot{}, fmt.Errorf("%w: record client compatibility: %w", ErrOpen, err)
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

func (service *Service) loadConnectivity(ctx context.Context, snapshot Snapshot) (Snapshot, error) {
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
	return enriched, nil
}
