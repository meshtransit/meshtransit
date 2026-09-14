package mapsession

import (
	"context"
	"errors"
	"fmt"

	"github.com/meshtransit/meshtransit/internal/control"
)

var (
	// ErrInvalidService reports a missing snapshot authority dependency.
	ErrInvalidService = errors.New("map session: invalid service")
	// ErrUnauthorized reports that the bound identity has no active Node authority.
	ErrUnauthorized = errors.New("map session: unauthorized")
	// ErrOpen classifies a map session that could not be opened safely.
	ErrOpen = errors.New("map session: open failed")
)

// SnapshotStore loads one immutable snapshot for an authenticated Node identity.
type SnapshotStore interface {
	Load(context.Context, control.AuthenticatedNode) (Snapshot, error)
}

// Service authorizes an authenticated Node and opens its map snapshot. It owns
// no goroutines and retains no request or snapshot state.
type Service struct {
	store SnapshotStore
}

// NewService constructs a map-session application service.
func NewService(store SnapshotStore) (*Service, error) {
	if store == nil {
		return nil, ErrInvalidService
	}
	return &Service{store: store}, nil
}

// Open binds the request Node key to the transport-authenticated machine and
// returns only snapshot evidence that matches that exact identity.
func (service *Service) Open(
	ctx context.Context,
	machine control.AuthenticatedMachine,
	request Request,
) (Snapshot, error) {
	if ctx == nil || service == nil || service.store == nil || !request.IsValid() {
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
	return snapshot, nil
}
