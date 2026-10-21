package exitpool

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// Operation is what a pool change does.
type Operation string

// Pool operations.
const (
	OperationCreate Operation = "create"
	OperationUpdate Operation = "update"
	OperationDelete Operation = "delete"
)

// NodeOperation is what an exit node change does.
type NodeOperation string

// Exit node operations.
const (
	NodePut    NodeOperation = "put"
	NodeDelete NodeOperation = "delete"
)

// Page bounds of the pool list.
const (
	DefaultPage = 10
	MaximumPage = 100
)

// Abilities says what the reader may do: create and change pools and their
// exit nodes (route.approve), delete pools and remove exit nodes
// (route.withdraw).
type Abilities struct {
	CanManage bool
	CanDelete bool
}

// Listing is one page of a Network's active pools in name order.
type Listing struct {
	Pools   []Pool
	HasMore bool
	Abilities
}

// Reading is one pool and what the reader may do with it.
type Reading struct {
	Pool Pool
	// Primary is the exit node Core elected; nil before the first election.
	Primary *Primary
	// Serving is a spread pool's serving set; nil for a failover pool and
	// before the first election.
	Serving *Serving
	Abilities
}

// Result is a pool after a change. Changed is false when the change asked
// for what was already stored: nothing was written.
type Result struct {
	Pool     Pool
	Previous *Pool
	Deleted  bool
	Changed  bool
}

// Change is one validated pool change.
type Change struct {
	Session         accountsession.Session
	Scope           network.Scope
	Operation       Operation
	PoolID          ID
	ExpectedVersion int64
	Definition      Definition
	PoolLimit       int
	// SpreadSalt becomes the pool's assignment salt the first time it is
	// spread.
	SpreadSalt    [SpreadSaltSize]byte
	CorrelationID publicid.ID
}

// NodeChange adds, changes or removes one exit node of a pool.
type NodeChange struct {
	Session         accountsession.Session
	Scope           network.Scope
	Operation       NodeOperation
	PoolID          ID
	ExpectedVersion int64
	Assignment      NodeAssignment
	NodeLimit       int
	NodeRowID       publicid.ID
	CorrelationID   publicid.ID
}

// Store reads and changes pools; PostgreSQL authorizes each call and decides
// it on the database clock.
type Store interface {
	List(ctx context.Context, session accountsession.Session, scope network.Scope, after ID, limit int) (Listing, error)
	Read(ctx context.Context, session accountsession.Session, scope network.Scope, pool ID) (Reading, error)
	Change(ctx context.Context, change Change) (Result, error)
	ChangeNode(ctx context.Context, change NodeChange) (Result, error)
}

// Clock supplies this host's time for the early session gate only.
type Clock interface{ Now() time.Time }

// IDs generates public identifiers.
type IDs interface{ New() (publicid.ID, error) }

// Service validates pool changes before PostgreSQL authorizes them.
type Service struct {
	store          Store
	history        PrimaryHistoryStore
	servingHistory ServingHistoryStore
	clock          Clock
	ids            IDs
	limits         Limits
	// spread allows pools to become spread (exit node design §16).
	spread bool
}

// NewService requires a store, clock, identifier source and valid limits.
func NewService(store Store, clock Clock, ids IDs, limits Limits) (*Service, error) {
	if store == nil || clock == nil || ids == nil || limits.Validate() != nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, clock: clock, ids: ids, limits: limits}, nil
}

// WithPrimaryHistory returns the service reading pools' primary changes
// from history.
func (service *Service) WithPrimaryHistory(history PrimaryHistoryStore) (*Service, error) {
	if service == nil || history == nil {
		return nil, ErrInvalid
	}
	extended := *service
	extended.history = history
	return &extended, nil
}

// admit is an early, fail-closed gate on this host's clock: it can only deny.
func (service *Service) admit(ctx context.Context, session accountsession.Session, scope network.Scope) error {
	if ctx == nil || service == nil || service.store == nil || !scope.IsValid() {
		return ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return ErrForbidden
	}
	return nil
}

// List returns one page of the Network's active pools after the given one
// (the zero ID starts at the first).
func (service *Service) List(ctx context.Context, session accountsession.Session, scope network.Scope,
	after ID, limit int) (Listing, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Listing{}, err
	}
	if limit < 1 || limit > MaximumPage || (after != ID{} && !after.IsValid()) {
		return Listing{}, ErrInvalid
	}
	return service.store.List(ctx, session, scope, after, limit)
}

// Read returns one active pool.
func (service *Service) Read(ctx context.Context, session accountsession.Session, scope network.Scope,
	pool ID) (Reading, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Reading{}, err
	}
	if !pool.IsValid() {
		return Reading{}, ErrInvalid
	}
	return service.store.Read(ctx, session, scope, pool)
}

// Create adds a pool without exit nodes.
func (service *Service) Create(ctx context.Context, session accountsession.Session, scope network.Scope,
	definition Definition, correlationID publicid.ID) (Result, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Result{}, err
	}
	if err := definition.Validate(service.limits); err != nil {
		return Result{}, err
	}
	if !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	if definition.Mode == ModeKeep {
		definition.Mode = ModeFailover
	}
	if err := service.admitMode(definition.Mode, ModeFailover); err != nil {
		return Result{}, err
	}
	id, err := service.ids.New()
	if err != nil {
		return Result{}, ErrUnavailable
	}
	salt, err := NewSpreadSalt()
	if err != nil {
		return Result{}, ErrUnavailable
	}
	return service.store.Change(ctx, Change{
		Session: session, Scope: scope, Operation: OperationCreate, PoolID: ID(id),
		Definition: definition.Canonical(), PoolLimit: service.limits.PoolsPerNetwork, SpreadSalt: salt,
		CorrelationID: correlationID,
	})
}

// Update replaces a pool's definition at the expected version.
func (service *Service) Update(ctx context.Context, session accountsession.Session, scope network.Scope,
	pool ID, expectedVersion int64, definition Definition, correlationID publicid.ID) (Result, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Result{}, err
	}
	if !pool.IsValid() || expectedVersion <= 0 || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	if err := definition.Validate(service.limits); err != nil {
		return Result{}, err
	}
	if definition.Mode == ModeSpread && !service.spread {
		// Only a pool already spread may stay spread.
		current, err := service.store.Read(ctx, session, scope, pool)
		if err != nil {
			return Result{}, err
		}
		if err := service.admitMode(definition.Mode, current.Pool.Mode); err != nil {
			return Result{}, err
		}
	}
	salt, err := NewSpreadSalt()
	if err != nil {
		return Result{}, ErrUnavailable
	}
	return service.store.Change(ctx, Change{
		Session: session, Scope: scope, Operation: OperationUpdate, PoolID: pool,
		ExpectedVersion: expectedVersion, Definition: definition.Canonical(), SpreadSalt: salt,
		CorrelationID: correlationID,
	})
}

// Delete removes a pool and its exit nodes.
func (service *Service) Delete(ctx context.Context, session accountsession.Session, scope network.Scope,
	pool ID, expectedVersion int64, correlationID publicid.ID) (Result, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Result{}, err
	}
	if !pool.IsValid() || expectedVersion <= 0 || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	return service.store.Change(ctx, Change{
		Session: session, Scope: scope, Operation: OperationDelete, PoolID: pool,
		ExpectedVersion: expectedVersion, CorrelationID: correlationID,
	})
}

// PutNode makes a Device an exit node of a pool, or changes its priority or
// state, at the pool's expected version.
func (service *Service) PutNode(ctx context.Context, session accountsession.Session, scope network.Scope,
	pool ID, expectedVersion int64, assignment NodeAssignment, correlationID publicid.ID) (Result, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Result{}, err
	}
	if err := assignment.Validate(); err != nil {
		return Result{}, err
	}
	if !pool.IsValid() || expectedVersion <= 0 || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	rowID, err := service.ids.New()
	if err != nil {
		return Result{}, ErrUnavailable
	}
	return service.store.ChangeNode(ctx, NodeChange{
		Session: session, Scope: scope, Operation: NodePut, PoolID: pool, ExpectedVersion: expectedVersion,
		Assignment: assignment, NodeLimit: service.limits.NodesPerPool, NodeRowID: rowID,
		CorrelationID: correlationID,
	})
}

// RemoveNode removes an exit node from a pool at the pool's expected
// version.
func (service *Service) RemoveNode(ctx context.Context, session accountsession.Session, scope network.Scope,
	pool ID, expectedVersion int64, device node.ID, correlationID publicid.ID) (Result, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Result{}, err
	}
	if !pool.IsValid() || expectedVersion <= 0 || !device.IsValid() || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	return service.store.ChangeNode(ctx, NodeChange{
		Session: session, Scope: scope, Operation: NodeDelete, PoolID: pool, ExpectedVersion: expectedVersion,
		Assignment: NodeAssignment{DeviceID: device}, CorrelationID: correlationID,
	})
}

// SystemIDs generates random UUIDv7 public identifiers.
type SystemIDs struct{}

// New returns a fresh public identifier.
func (SystemIDs) New() (publicid.ID, error) { return publicid.New() }
