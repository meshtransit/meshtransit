package devicegroup

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// Operation is what a definition change does.
type Operation string

// Definition operations.
const (
	OperationCreate Operation = "create"
	OperationUpdate Operation = "update"
	OperationDelete Operation = "delete"
)

// Change is one validated definition change.
type Change struct {
	Session         accountsession.Session
	Scope           network.Scope
	Operation       Operation
	GroupID         ID
	ExpectedVersion int64
	Definition      Definition
	CorrelationID   publicid.ID
	EvaluatedAt     time.Time
}

// MembershipChange adds and removes Devices; each added Device carries the
// identity its membership row gets.
type MembershipChange struct {
	Session         accountsession.Session
	Scope           network.Scope
	GroupID         ID
	ExpectedVersion int64
	Add             []node.ID
	AddMemberIDs    []publicid.ID
	Remove          []node.ID
	CorrelationID   publicid.ID
	EvaluatedAt     time.Time
}

// Store reads and changes groups; PostgreSQL authorizes each call.
type Store interface {
	List(ctx context.Context, session accountsession.Session, scope network.Scope, at time.Time) (Listing, error)
	Members(ctx context.Context, session accountsession.Session, scope network.Scope, group ID,
		after node.ID, limit int, at time.Time) (MemberPage, error)
	Change(ctx context.Context, change Change) (Result, error)
	ChangeMembers(ctx context.Context, change MembershipChange) (MembershipResult, error)
}

// Clock supplies the current time.
type Clock interface{ Now() time.Time }

// IDs generates public identifiers.
type IDs interface{ New() (publicid.ID, error) }

// Service validates group changes before PostgreSQL authorizes them.
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

func (service *Service) admit(ctx context.Context, session accountsession.Session,
	scope network.Scope) (time.Time, error) {
	if ctx == nil || service == nil || service.store == nil || !scope.IsValid() {
		return time.Time{}, ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return time.Time{}, ErrForbidden
	}
	return now, nil
}

// List returns the Network's active groups.
func (service *Service) List(ctx context.Context, session accountsession.Session,
	scope network.Scope) (Listing, error) {
	now, err := service.admit(ctx, session, scope)
	if err != nil {
		return Listing{}, err
	}
	return service.store.List(ctx, session, scope, now)
}

// Members returns one page of a group's members after the given Device.
func (service *Service) Members(ctx context.Context, session accountsession.Session, scope network.Scope,
	group ID, after node.ID, limit int) (MemberPage, error) {
	now, err := service.admit(ctx, session, scope)
	if err != nil {
		return MemberPage{}, err
	}
	if !group.IsValid() || limit < 1 || limit > MaximumMemberPage {
		return MemberPage{}, ErrInvalid
	}
	return service.store.Members(ctx, session, scope, group, after, limit, now)
}

// Create adds an empty group.
func (service *Service) Create(ctx context.Context, session accountsession.Session, scope network.Scope,
	definition Definition, correlationID publicid.ID) (Result, error) {
	now, err := service.admit(ctx, session, scope)
	if err != nil {
		return Result{}, err
	}
	if !definition.IsValid() || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	id, err := service.ids.New()
	if err != nil {
		return Result{}, ErrUnavailable
	}
	return service.store.Change(ctx, Change{
		Session: session, Scope: scope, Operation: OperationCreate, GroupID: ID(id),
		Definition: definition, CorrelationID: correlationID, EvaluatedAt: now,
	})
}

// Update renames a group or changes its description at the expected version.
func (service *Service) Update(ctx context.Context, session accountsession.Session, scope network.Scope,
	group ID, expectedVersion int64, definition Definition, correlationID publicid.ID) (Result, error) {
	now, err := service.admit(ctx, session, scope)
	if err != nil {
		return Result{}, err
	}
	if !group.IsValid() || expectedVersion <= 0 || !definition.IsValid() || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	return service.store.Change(ctx, Change{
		Session: session, Scope: scope, Operation: OperationUpdate, GroupID: group,
		ExpectedVersion: expectedVersion, Definition: definition, CorrelationID: correlationID, EvaluatedAt: now,
	})
}

// Delete removes a group no active rule selects, with its memberships.
func (service *Service) Delete(ctx context.Context, session accountsession.Session, scope network.Scope,
	group ID, expectedVersion int64, correlationID publicid.ID) (Result, error) {
	now, err := service.admit(ctx, session, scope)
	if err != nil {
		return Result{}, err
	}
	if !group.IsValid() || expectedVersion <= 0 || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	return service.store.Change(ctx, Change{
		Session: session, Scope: scope, Operation: OperationDelete, GroupID: group,
		ExpectedVersion: expectedVersion, CorrelationID: correlationID, EvaluatedAt: now,
	})
}

func uniqueValid(ids []node.ID) bool {
	seen := make(map[node.ID]struct{}, len(ids))
	for _, id := range ids {
		if !id.IsValid() {
			return false
		}
		if _, duplicate := seen[id]; duplicate {
			return false
		}
		seen[id] = struct{}{}
	}
	return true
}

// ChangeMembers adds and removes Devices at the expected version. A Device
// cannot be both added and removed in one change.
func (service *Service) ChangeMembers(ctx context.Context, session accountsession.Session, scope network.Scope,
	group ID, expectedVersion int64, add, remove []node.ID, correlationID publicid.ID) (MembershipResult, error) {
	now, err := service.admit(ctx, session, scope)
	if err != nil {
		return MembershipResult{}, err
	}
	if !group.IsValid() || expectedVersion <= 0 || !correlationID.IsValid() ||
		len(add) > MaximumMembersPerChange || len(remove) > MaximumMembersPerChange ||
		len(add)+len(remove) == 0 || !uniqueValid(add) || !uniqueValid(remove) ||
		!uniqueValid(append(append([]node.ID(nil), add...), remove...)) {
		return MembershipResult{}, ErrInvalid
	}
	memberIDs := make([]publicid.ID, len(add))
	for index := range add {
		if memberIDs[index], err = service.ids.New(); err != nil {
			return MembershipResult{}, ErrUnavailable
		}
	}
	return service.store.ChangeMembers(ctx, MembershipChange{
		Session: session, Scope: scope, GroupID: group, ExpectedVersion: expectedVersion,
		Add: add, AddMemberIDs: memberIDs, Remove: remove, CorrelationID: correlationID, EvaluatedAt: now,
	})
}

// SystemIDs generates random UUIDv7 public identifiers.
type SystemIDs struct{}

// New returns a fresh public identifier.
func (SystemIDs) New() (publicid.ID, error) { return publicid.New() }
