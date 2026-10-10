package interchange

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// Operation is what a change does to a relay.
type Operation string

// Operations a change can perform.
const (
	OperationCreate Operation = "create"
	OperationUpdate Operation = "update"
	OperationDelete Operation = "delete"
)

// Change is one validated change.
type Change struct {
	Session         accountsession.Session
	WorkspaceID     workspace.ID
	Operation       Operation
	InterchangeID   publicid.ID
	ExpectedVersion int64
	// Spec is the new spec; the previous one for a removal.
	Spec          Spec
	CorrelationID publicid.ID
}

// AdvancedNetwork is a Network whose revision a change advanced, so its
// Devices get a new relay map.
type AdvancedNetwork struct {
	NetworkID       network.ID
	NetworkRevision int64
}

// Result is the relay after a change and the Networks it advanced.
type Result struct {
	Interchange Interchange
	Deleted     bool
	Advanced    []AdvancedNetwork
}

// Listing is a Workspace's active relays and what the reader may do.
type Listing struct {
	Interchanges []Interchange
	CanManage    bool
}

// Store reads and changes relays; PostgreSQL authorizes each call.
type Store interface {
	List(ctx context.Context, session accountsession.Session, workspaceID workspace.ID) (Listing, error)
	Change(ctx context.Context, change Change) (Result, error)
}

// Clock supplies the current time.
type Clock interface{ Now() time.Time }

// IDs generates public identifiers.
type IDs interface{ New() (publicid.ID, error) }

// Service validates Private Interchange changes.
type Service struct {
	store  Store
	clock  Clock
	ids    IDs
	shared SharedRelays
}

// NewService requires a store, clock, identifier source and the shared
// relay map.
func NewService(store Store, clock Clock, ids IDs, shared SharedRelays) (*Service, error) {
	if store == nil || clock == nil || ids == nil || shared == nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, clock: clock, ids: ids, shared: shared}, nil
}

func (service *Service) admit(ctx context.Context, session accountsession.Session) error {
	if ctx == nil || service == nil || service.store == nil {
		return ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return ErrForbidden
	}
	return nil
}

// List returns the active relays of a Workspace.
func (service *Service) List(ctx context.Context, session accountsession.Session,
	workspaceID workspace.ID) (Listing, error) {
	if err := service.admit(ctx, session); err != nil {
		return Listing{}, err
	}
	if !workspaceID.IsValid() {
		return Listing{}, ErrInvalid
	}
	return service.store.List(ctx, session, workspaceID)
}

func (service *Service) checkSpec(spec Spec) error {
	if !spec.IsValid() {
		return ErrInvalid
	}
	if service.shared.Uses(spec.RegionCode, spec.RelayKey) {
		return ErrConflict
	}
	return nil
}

// Create adds a relay.
func (service *Service) Create(ctx context.Context, session accountsession.Session, workspaceID workspace.ID,
	spec Spec, correlationID publicid.ID) (Result, error) {
	if err := service.admit(ctx, session); err != nil {
		return Result{}, err
	}
	if !workspaceID.IsValid() || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	if err := service.checkSpec(spec); err != nil {
		return Result{}, err
	}
	id, err := service.ids.New()
	if err != nil {
		return Result{}, ErrUnavailable
	}
	return service.store.Change(ctx, Change{Session: session, WorkspaceID: workspaceID,
		Operation: OperationCreate, InterchangeID: id, Spec: spec, CorrelationID: correlationID})
}

// Update replaces a relay's spec at the expected version.
func (service *Service) Update(ctx context.Context, session accountsession.Session, workspaceID workspace.ID,
	id publicid.ID, expectedVersion int64, spec Spec, correlationID publicid.ID) (Result, error) {
	if err := service.admit(ctx, session); err != nil {
		return Result{}, err
	}
	if !workspaceID.IsValid() || !id.IsValid() || expectedVersion <= 0 || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	if err := service.checkSpec(spec); err != nil {
		return Result{}, err
	}
	return service.store.Change(ctx, Change{Session: session, WorkspaceID: workspaceID,
		Operation: OperationUpdate, InterchangeID: id, ExpectedVersion: expectedVersion, Spec: spec,
		CorrelationID: correlationID})
}

// Delete removes a relay at the expected version; its Networks fall back to
// the shared relays.
func (service *Service) Delete(ctx context.Context, session accountsession.Session, workspaceID workspace.ID,
	id publicid.ID, expectedVersion int64, correlationID publicid.ID) (Result, error) {
	if err := service.admit(ctx, session); err != nil {
		return Result{}, err
	}
	if !workspaceID.IsValid() || !id.IsValid() || expectedVersion <= 0 || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	return service.store.Change(ctx, Change{Session: session, WorkspaceID: workspaceID,
		Operation: OperationDelete, InterchangeID: id, ExpectedVersion: expectedVersion,
		CorrelationID: correlationID})
}

// SystemIDs generates random UUIDv7 public identifiers.
type SystemIDs struct{}

// New returns a fresh public identifier.
func (SystemIDs) New() (publicid.ID, error) { return publicid.New() }
