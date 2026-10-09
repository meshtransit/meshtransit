package devicetag

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// Store reads and changes tags; PostgreSQL authorizes each call.
type Store interface {
	List(ctx context.Context, session accountsession.Session, workspaceID workspace.ID, at time.Time) (Listing, error)
	Change(ctx context.Context, change Change) (Result, error)
	NetworkTags(ctx context.Context, session accountsession.Session, scope network.Scope,
		at time.Time) ([]DeviceTags, error)
	ChangeAssignments(ctx context.Context, change AssignmentChange) (AssignmentResult, error)
	NetworkOptions(ctx context.Context, session accountsession.Session, scope network.Scope,
		at time.Time) (NetworkOptions, error)
}

// Clock supplies the current time.
type Clock interface{ Now() time.Time }

// IDs generates public identifiers.
type IDs interface{ New() (publicid.ID, error) }

// Service validates tag changes before PostgreSQL authorizes them.
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

func (service *Service) now(ctx context.Context, session accountsession.Session) (time.Time, error) {
	if ctx == nil || service == nil || service.store == nil {
		return time.Time{}, ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return time.Time{}, ErrForbidden
	}
	return now, nil
}

// List returns the Workspace's tag catalog.
func (service *Service) List(ctx context.Context, session accountsession.Session,
	workspaceID workspace.ID) (Listing, error) {
	now, err := service.now(ctx, session)
	if err != nil {
		return Listing{}, err
	}
	if !workspaceID.IsValid() {
		return Listing{}, ErrInvalid
	}
	return service.store.List(ctx, session, workspaceID, now)
}

func (service *Service) ownerRows(definition Definition) ([]publicid.ID, error) {
	rows := make([]publicid.ID, len(definition.OwnerGroups)+len(definition.OwnerRoles))
	for index := range rows {
		id, err := service.ids.New()
		if err != nil {
			return nil, ErrUnavailable
		}
		rows[index] = id
	}
	return rows, nil
}

// Create adds a tag with its owners.
func (service *Service) Create(ctx context.Context, session accountsession.Session, workspaceID workspace.ID,
	definition Definition, correlationID publicid.ID) (Result, error) {
	now, err := service.now(ctx, session)
	if err != nil {
		return Result{}, err
	}
	definition = definition.Canonical()
	if !workspaceID.IsValid() || !definition.IsValid() || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	id, err := service.ids.New()
	if err != nil {
		return Result{}, ErrUnavailable
	}
	rows, err := service.ownerRows(definition)
	if err != nil {
		return Result{}, err
	}
	return service.store.Change(ctx, Change{
		Session: session, WorkspaceID: workspaceID, Operation: OperationCreate, TagID: ID(id),
		Definition: definition, OwnerRowIDs: rows, CorrelationID: correlationID, EvaluatedAt: now,
	})
}

// Update replaces a tag's name, description and owners at the expected
// version. Renaming keeps the tag's identity, so rules that select it are
// unaffected.
func (service *Service) Update(ctx context.Context, session accountsession.Session, workspaceID workspace.ID,
	tag ID, expectedVersion int64, definition Definition, correlationID publicid.ID) (Result, error) {
	now, err := service.now(ctx, session)
	if err != nil {
		return Result{}, err
	}
	definition = definition.Canonical()
	if !workspaceID.IsValid() || !tag.IsValid() || expectedVersion <= 0 || !definition.IsValid() ||
		!correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	rows, err := service.ownerRows(definition)
	if err != nil {
		return Result{}, err
	}
	return service.store.Change(ctx, Change{
		Session: session, WorkspaceID: workspaceID, Operation: OperationUpdate, TagID: tag,
		ExpectedVersion: expectedVersion, Definition: definition, OwnerRowIDs: rows,
		CorrelationID: correlationID, EvaluatedAt: now,
	})
}

// Delete removes a tag no active rule selects, with its assignments.
func (service *Service) Delete(ctx context.Context, session accountsession.Session, workspaceID workspace.ID,
	tag ID, expectedVersion int64, correlationID publicid.ID) (Result, error) {
	now, err := service.now(ctx, session)
	if err != nil {
		return Result{}, err
	}
	if !workspaceID.IsValid() || !tag.IsValid() || expectedVersion <= 0 || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	return service.store.Change(ctx, Change{
		Session: session, WorkspaceID: workspaceID, Operation: OperationDelete, TagID: tag,
		ExpectedVersion: expectedVersion, CorrelationID: correlationID, EvaluatedAt: now,
	})
}

// NetworkTags returns the tags of the Network's tagged Devices.
func (service *Service) NetworkTags(ctx context.Context, session accountsession.Session,
	scope network.Scope) ([]DeviceTags, error) {
	now, err := service.now(ctx, session)
	if err != nil {
		return nil, err
	}
	if !scope.IsValid() {
		return nil, ErrInvalid
	}
	return service.store.NetworkTags(ctx, session, scope, now)
}

// NetworkOptions returns the tags the session may apply in the Network, the
// tags its Devices carry, and the Devices of the Network the session owns.
func (service *Service) NetworkOptions(ctx context.Context, session accountsession.Session,
	scope network.Scope) (NetworkOptions, error) {
	now, err := service.now(ctx, session)
	if err != nil {
		return NetworkOptions{}, err
	}
	if !scope.IsValid() {
		return NetworkOptions{}, ErrInvalid
	}
	return service.store.NetworkOptions(ctx, session, scope, now)
}

func uniqueTags(ids []ID) bool {
	seen := make(map[ID]struct{}, len(ids))
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

// ChangeAssignments adds and removes tags of one Device. A tag cannot be both
// added and removed in one change.
func (service *Service) ChangeAssignments(ctx context.Context, session accountsession.Session,
	scope network.Scope, device node.ID, add, remove []ID, correlationID publicid.ID) (AssignmentResult, error) {
	now, err := service.now(ctx, session)
	if err != nil {
		return AssignmentResult{}, err
	}
	if !scope.IsValid() || !device.IsValid() || !correlationID.IsValid() ||
		len(add) > MaximumTagsPerChange || len(remove) > MaximumTagsPerChange || len(add)+len(remove) == 0 ||
		!uniqueTags(append(append([]ID(nil), add...), remove...)) {
		return AssignmentResult{}, ErrInvalid
	}
	assignmentIDs := make([]publicid.ID, len(add))
	for index := range add {
		if assignmentIDs[index], err = service.ids.New(); err != nil {
			return AssignmentResult{}, ErrUnavailable
		}
	}
	return service.store.ChangeAssignments(ctx, AssignmentChange{
		Session: session, Scope: scope, DeviceID: device, Add: append([]ID(nil), add...),
		AddAssignmentIDs: assignmentIDs, Remove: append([]ID(nil), remove...),
		CorrelationID: correlationID, EvaluatedAt: now,
	})
}

// SystemIDs generates random UUIDv7 public identifiers.
type SystemIDs struct{}

// New returns a fresh public identifier.
func (SystemIDs) New() (publicid.ID, error) { return publicid.New() }
