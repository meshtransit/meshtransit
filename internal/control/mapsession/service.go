package mapsession

import (
	"context"
	"errors"
	"fmt"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/node"
)

var (
	// ErrInvalidService reports a missing dependency or unsafe option.
	ErrInvalidService = errors.New("map session: invalid service")
	// ErrUnauthorized reports that the bound identity has no active Node authority.
	ErrUnauthorized = errors.New("map session: unauthorized")
	// ErrOpen classifies a map session that could not be opened safely.
	ErrOpen = errors.New("map session: open failed")
	// ErrEndpointObservationRejected reports a stale transient endpoint update.
	ErrEndpointObservationRejected = errors.New("map session: endpoint observation rejected")
)

// SnapshotStore loads one immutable snapshot for an authenticated Node identity.
type SnapshotStore interface {
	Load(context.Context, control.AuthenticatedNode) (Snapshot, error)
}

// EndpointObserver records only generation-fenced transient connectivity.
type EndpointObserver interface {
	ObserveEndpoints(context.Context, node.EndpointObservation) (bool, error)
}

// Service authorizes an authenticated Node and opens its map snapshot. It owns
// no goroutines and retains no request or snapshot state.
type Service struct {
	store     SnapshotStore
	endpoints EndpointObserver
	options   ServiceOptions
}

// NewService constructs a map-session application service.
func NewService(
	store SnapshotStore,
	endpoints EndpointObserver,
	options ServiceOptions,
) (*Service, error) {
	if isNilDependency(store) || isNilDependency(endpoints) || !options.isValid() {
		return nil, ErrInvalidService
	}
	return &Service{store: store, endpoints: endpoints, options: options}, nil
}

// Open binds the request Node key to the transport-authenticated machine and
// returns only snapshot evidence that matches that exact identity.
func (service *Service) Open(
	ctx context.Context,
	machine control.AuthenticatedMachine,
	request Request,
) (Snapshot, error) {
	if ctx == nil || service == nil || isNilDependency(service.store) ||
		isNilDependency(service.endpoints) || !service.options.isValid() || !request.IsValid() {
		return Snapshot{}, ErrInvalidService
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, errors.Join(ErrOpen, err)
	}
	identity, err := machine.BindNodeKey(request.NodeKey())
	if err != nil {
		return Snapshot{}, errors.Join(ErrUnauthorized, err)
	}
	snapshot, err := service.store.Load(ctx, identity)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: load authoritative snapshot: %w", ErrOpen, err)
	}
	if !snapshot.IsValid() || snapshot.NodeKey() != identity.NodeKey() ||
		snapshot.MachineKey().Fingerprint() != identity.MachineFingerprint() {
		return Snapshot{}, ErrOpen
	}
	if err := service.observeEndpoints(ctx, snapshot, request); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
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
	operationCtx, cancel := context.WithTimeout(ctx, service.options.EndpointTimeout)
	defer cancel()
	accepted, err := service.endpoints.ObserveEndpoints(operationCtx, observation)
	if err != nil {
		return fmt.Errorf("%w: observe transient endpoints: %w", ErrOpen, err)
	}
	if !accepted {
		return errors.Join(ErrOpen, ErrEndpointObservationRejected)
	}
	return nil
}
