package guardrail

import (
	"context"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/authorization"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

// Operation is what a change does to a guardrail.
type Operation string

// Operations a change can perform.
const (
	OperationCreate Operation = "create"
	OperationUpdate Operation = "update"
	OperationDelete Operation = "delete"
)

// Change is one validated change, with the permission it needs.
type Change struct {
	Session         accountsession.Session
	WorkspaceID     workspace.ID
	Operation       Operation
	GuardrailID     publicid.ID
	ExpectedVersion int64
	// Spec is the new spec; the previous one for a deletion.
	Spec          Spec
	Previous      *Spec
	Permission    authorization.Permission
	CorrelationID publicid.ID
}

// Result is the guardrail after a change.
type Result struct {
	Guardrail Guardrail
	Deleted   bool
	UpdatedAt time.Time
}

// Listing is a Workspace's active guardrails and what the reader may do.
type Listing struct {
	Guardrails []Guardrail
	CanManage  bool
	CanWeaken  bool
}

// Store reads and changes guardrails; PostgreSQL authorizes each call.
type Store interface {
	List(ctx context.Context, session accountsession.Session, workspaceID workspace.ID) (Listing, error)
	Change(ctx context.Context, change Change) (Result, error)
}

// Clock supplies the current time.
type Clock interface{ Now() time.Time }

// IDs generates public identifiers.
type IDs interface{ New() (publicid.ID, error) }

// Service validates guardrail changes and decides the permission each needs.
type Service struct {
	store Store
	clock Clock
	ids   IDs
}

// NewService requires a store, clock and identifier source.
func NewService(store Store, clock Clock, ids IDs) (*Service, error) {
	if store == nil || clock == nil || ids == nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, clock: clock, ids: ids}, nil
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

// List returns the active guardrails of a Workspace.
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

// Create adds a guardrail; it can only narrow what is reachable.
func (service *Service) Create(ctx context.Context, session accountsession.Session, workspaceID workspace.ID,
	spec Spec, correlationID publicid.ID) (Result, error) {
	if err := service.admit(ctx, session); err != nil {
		return Result{}, err
	}
	if !workspaceID.IsValid() || !spec.IsValid() || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	id, err := service.ids.New()
	if err != nil {
		return Result{}, ErrUnavailable
	}
	return service.store.Change(ctx, Change{
		Session: session, WorkspaceID: workspaceID, Operation: OperationCreate, GuardrailID: id,
		Spec: spec, Permission: RequiredPermission(nil, &spec), CorrelationID: correlationID,
	})
}

func (service *Service) current(ctx context.Context, session accountsession.Session, workspaceID workspace.ID,
	id publicid.ID, expectedVersion int64) (Guardrail, error) {
	listing, err := service.store.List(ctx, session, workspaceID)
	if err != nil {
		return Guardrail{}, err
	}
	for _, guardrail := range listing.Guardrails {
		if guardrail.ID == id {
			if guardrail.Version != expectedVersion {
				return Guardrail{}, ErrVersionConflict
			}
			return guardrail, nil
		}
	}
	return Guardrail{}, ErrNotFound
}

// Update replaces a guardrail's spec at the expected version. Loosening it
// needs guardrail.weaken; the kind never changes.
func (service *Service) Update(ctx context.Context, session accountsession.Session, workspaceID workspace.ID,
	id publicid.ID, expectedVersion int64, spec Spec, correlationID publicid.ID) (Result, error) {
	if err := service.admit(ctx, session); err != nil {
		return Result{}, err
	}
	if !workspaceID.IsValid() || !id.IsValid() || expectedVersion <= 0 || !spec.IsValid() || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	existing, err := service.current(ctx, session, workspaceID, id, expectedVersion)
	if err != nil {
		return Result{}, err
	}
	if existing.Kind != spec.Kind {
		return Result{}, ErrInvalid
	}
	previous := existing.Spec
	return service.store.Change(ctx, Change{
		Session: session, WorkspaceID: workspaceID, Operation: OperationUpdate, GuardrailID: id,
		ExpectedVersion: expectedVersion, Spec: spec, Previous: &previous,
		Permission: RequiredPermission(&previous, &spec), CorrelationID: correlationID,
	})
}

// Delete removes a guardrail at the expected version; it needs guardrail.weaken.
func (service *Service) Delete(ctx context.Context, session accountsession.Session, workspaceID workspace.ID,
	id publicid.ID, expectedVersion int64, correlationID publicid.ID) (Result, error) {
	if err := service.admit(ctx, session); err != nil {
		return Result{}, err
	}
	if !workspaceID.IsValid() || !id.IsValid() || expectedVersion <= 0 || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	existing, err := service.current(ctx, session, workspaceID, id, expectedVersion)
	if err != nil {
		return Result{}, err
	}
	previous := existing.Spec
	return service.store.Change(ctx, Change{
		Session: session, WorkspaceID: workspaceID, Operation: OperationDelete, GuardrailID: id,
		ExpectedVersion: expectedVersion, Spec: previous, Previous: &previous,
		Permission: RequiredPermission(&previous, nil), CorrelationID: correlationID,
	})
}

// SystemIDs generates random UUIDv7 public identifiers.
type SystemIDs struct{}

// New returns a fresh public identifier.
func (SystemIDs) New() (publicid.ID, error) { return publicid.New() }
