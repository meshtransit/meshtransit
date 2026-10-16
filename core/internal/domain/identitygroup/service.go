package identitygroup

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// Store reads and changes groups; PostgreSQL authorizes each call and
// decides it, and every time it persists, on the database clock.
type Store interface {
	List(ctx context.Context, session accountsession.Session, workspaceID workspace.ID) (Listing, error)
	Members(ctx context.Context, session accountsession.Session, workspaceID workspace.ID, group ID,
		after publicid.ID, limit int) (MemberPage, error)
	Change(ctx context.Context, change Change) (Result, error)
	ChangeMembers(ctx context.Context, change MembershipChange) (MembershipResult, error)
}

// Clock supplies this host's time for the early session gate only.
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

// admit is an early, fail-closed gate on this host's clock: it can only deny.
// PostgreSQL authorizes the call on the database clock.
func (service *Service) admit(ctx context.Context, session accountsession.Session,
	workspaceID workspace.ID) error {
	if ctx == nil || service == nil || service.store == nil || !workspaceID.IsValid() {
		return ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return ErrForbidden
	}
	return nil
}

// List returns the Workspace's active groups.
func (service *Service) List(ctx context.Context, session accountsession.Session,
	workspaceID workspace.ID) (Listing, error) {
	err := service.admit(ctx, session, workspaceID)
	if err != nil {
		return Listing{}, err
	}
	return service.store.List(ctx, session, workspaceID)
}

// Members returns one page of a group's members after the given principal.
func (service *Service) Members(ctx context.Context, session accountsession.Session, workspaceID workspace.ID,
	group ID, after publicid.ID, limit int) (MemberPage, error) {
	err := service.admit(ctx, session, workspaceID)
	if err != nil {
		return MemberPage{}, err
	}
	if !group.IsValid() || limit < 1 || limit > MaximumMemberPage {
		return MemberPage{}, ErrInvalid
	}
	return service.store.Members(ctx, session, workspaceID, group, after, limit)
}

// Create adds an empty group.
func (service *Service) Create(ctx context.Context, session accountsession.Session, workspaceID workspace.ID,
	definition Definition, correlationID publicid.ID) (Result, error) {
	err := service.admit(ctx, session, workspaceID)
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
		Session: session, WorkspaceID: workspaceID, Operation: OperationCreate, GroupID: ID(id),
		Definition: definition, CorrelationID: correlationID,
	})
}

// Update renames a group or changes its description at the expected version.
func (service *Service) Update(ctx context.Context, session accountsession.Session, workspaceID workspace.ID,
	group ID, expectedVersion int64, definition Definition, correlationID publicid.ID) (Result, error) {
	err := service.admit(ctx, session, workspaceID)
	if err != nil {
		return Result{}, err
	}
	if !group.IsValid() || expectedVersion <= 0 || !definition.IsValid() || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	return service.store.Change(ctx, Change{
		Session: session, WorkspaceID: workspaceID, Operation: OperationUpdate, GroupID: group,
		ExpectedVersion: expectedVersion, Definition: definition, CorrelationID: correlationID,
	})
}

// Delete removes a group that no active rule selects and that owns no tag.
func (service *Service) Delete(ctx context.Context, session accountsession.Session, workspaceID workspace.ID,
	group ID, expectedVersion int64, correlationID publicid.ID) (Result, error) {
	err := service.admit(ctx, session, workspaceID)
	if err != nil {
		return Result{}, err
	}
	if !group.IsValid() || expectedVersion <= 0 || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	return service.store.Change(ctx, Change{
		Session: session, WorkspaceID: workspaceID, Operation: OperationDelete, GroupID: group,
		ExpectedVersion: expectedVersion, CorrelationID: correlationID,
	})
}

func uniqueValid(ids []publicid.ID) bool {
	seen := make(map[publicid.ID]struct{}, len(ids))
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

// ChangeMembers adds and removes principals at the expected version. A
// principal cannot be both added and removed in one change.
func (service *Service) ChangeMembers(ctx context.Context, session accountsession.Session,
	workspaceID workspace.ID, group ID, expectedVersion int64, add, remove []publicid.ID,
	correlationID publicid.ID) (MembershipResult, error) {
	err := service.admit(ctx, session, workspaceID)
	if err != nil {
		return MembershipResult{}, err
	}
	if !group.IsValid() || expectedVersion <= 0 || !correlationID.IsValid() ||
		len(add) > MaximumMembersPerChange || len(remove) > MaximumMembersPerChange ||
		len(add)+len(remove) == 0 || !uniqueValid(add) || !uniqueValid(remove) ||
		!uniqueValid(append(append([]publicid.ID(nil), add...), remove...)) {
		return MembershipResult{}, ErrInvalid
	}
	memberIDs := make([]publicid.ID, len(add))
	for index := range add {
		if memberIDs[index], err = service.ids.New(); err != nil {
			return MembershipResult{}, ErrUnavailable
		}
	}
	return service.store.ChangeMembers(ctx, MembershipChange{
		Session: session, WorkspaceID: workspaceID, GroupID: group, ExpectedVersion: expectedVersion,
		Add: append([]publicid.ID(nil), add...), AddMemberIDs: memberIDs,
		Remove: append([]publicid.ID(nil), remove...), CorrelationID: correlationID,
	})
}

// SystemIDs generates random UUIDv7 public identifiers.
type SystemIDs struct{}

// New returns a fresh public identifier.
func (SystemIDs) New() (publicid.ID, error) { return publicid.New() }
