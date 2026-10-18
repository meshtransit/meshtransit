package site

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// Operation is what a Site change does.
type Operation string

// Site operations.
const (
	OperationCreate Operation = "create"
	OperationUpdate Operation = "update"
	OperationDelete Operation = "delete"
)

// RouterOperation is what a router change does.
type RouterOperation string

// Router operations.
const (
	RouterPut    RouterOperation = "put"
	RouterDelete RouterOperation = "delete"
)

// Page bounds of the Site list.
const (
	DefaultPage = 10
	MaximumPage = 100
)

// Abilities says what the reader may do: create and change Sites and their
// routers (route.approve), delete Sites and remove routers (route.withdraw).
type Abilities struct {
	CanManage bool
	CanDelete bool
}

// Listing is one page of a Network's active Sites in name order.
type Listing struct {
	Sites   []Site
	HasMore bool
	Abilities
}

// Reading is one Site and what the reader may do with it.
type Reading struct {
	Site Site
	Abilities
}

// Result is a Site after a change. Changed is false when the change asked
// for what was already stored: nothing was written.
type Result struct {
	Site     Site
	Previous *Site
	Deleted  bool
	Changed  bool
}

// Change is one validated Site change.
type Change struct {
	Session         accountsession.Session
	Scope           network.Scope
	Operation       Operation
	SiteID          ID
	ExpectedVersion int64
	Definition      Definition
	SiteLimit       int
	CorrelationID   publicid.ID
}

// RouterChange adds, changes or removes one router of a Site.
type RouterChange struct {
	Session         accountsession.Session
	Scope           network.Scope
	Operation       RouterOperation
	SiteID          ID
	ExpectedVersion int64
	Assignment      RouterAssignment
	RouterLimit     int
	RouterRowID     publicid.ID
	CorrelationID   publicid.ID
}

// Store reads and changes Sites; PostgreSQL authorizes each call and decides
// it on the database clock.
type Store interface {
	List(ctx context.Context, session accountsession.Session, scope network.Scope, after ID, limit int) (Listing, error)
	Read(ctx context.Context, session accountsession.Session, scope network.Scope, site ID) (Reading, error)
	Change(ctx context.Context, change Change) (Result, error)
	ChangeRouter(ctx context.Context, change RouterChange) (Result, error)
}

// Clock supplies this host's time for the early session gate only.
type Clock interface{ Now() time.Time }

// IDs generates public identifiers.
type IDs interface{ New() (publicid.ID, error) }

// Config is what the deployment decides: the plan limits (until paid plans
// set them per Workspace) and the addresses no Site may cover, the ones
// clients dial: relays and the control endpoint.
type Config struct {
	Limits Limits
	Denied []netip.Prefix
}

// Service validates Site changes before PostgreSQL authorizes them.
type Service struct {
	store  Store
	clock  Clock
	ids    IDs
	config Config
}

// NewService requires a store, clock, identifier source and valid limits.
func NewService(store Store, clock Clock, ids IDs, config Config) (*Service, error) {
	if store == nil || clock == nil || ids == nil || config.Limits.Validate() != nil ||
		slices.ContainsFunc(config.Denied, func(prefix netip.Prefix) bool { return !prefix.IsValid() }) {
		return nil, ErrInvalid
	}
	config.Denied = slices.Clone(config.Denied)
	return &Service{store: store, clock: clock, ids: ids, config: config}, nil
}

// routerLimit is the plan limit, and never more than high availability
// supports yet.
func (service *Service) routerLimit() int {
	return min(service.config.Limits.RoutersPerSite, RoutersSupported)
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

// List returns one page of the Network's active Sites after the given one
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

// Read returns one active Site.
func (service *Service) Read(ctx context.Context, session accountsession.Session, scope network.Scope,
	site ID) (Reading, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Reading{}, err
	}
	if !site.IsValid() {
		return Reading{}, ErrInvalid
	}
	return service.store.Read(ctx, session, scope, site)
}

// Create adds a Site without routers.
func (service *Service) Create(ctx context.Context, session accountsession.Session, scope network.Scope,
	definition Definition, correlationID publicid.ID) (Result, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Result{}, err
	}
	if err := definition.Validate(service.config.Limits, service.config.Denied); err != nil {
		return Result{}, err
	}
	if !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	id, err := service.ids.New()
	if err != nil {
		return Result{}, ErrUnavailable
	}
	return service.store.Change(ctx, Change{
		Session: session, Scope: scope, Operation: OperationCreate, SiteID: ID(id),
		Definition: definition.Canonical(), SiteLimit: service.config.Limits.SitesPerNetwork,
		CorrelationID: correlationID,
	})
}

// Update replaces a Site's definition at the expected version.
func (service *Service) Update(ctx context.Context, session accountsession.Session, scope network.Scope,
	site ID, expectedVersion int64, definition Definition, correlationID publicid.ID) (Result, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Result{}, err
	}
	if err := definition.Validate(service.config.Limits, service.config.Denied); err != nil {
		return Result{}, err
	}
	if !site.IsValid() || expectedVersion <= 0 || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	return service.store.Change(ctx, Change{
		Session: session, Scope: scope, Operation: OperationUpdate, SiteID: site,
		ExpectedVersion: expectedVersion, Definition: definition.Canonical(), CorrelationID: correlationID,
	})
}

// Delete removes a Site and its routers.
func (service *Service) Delete(ctx context.Context, session accountsession.Session, scope network.Scope,
	site ID, expectedVersion int64, correlationID publicid.ID) (Result, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Result{}, err
	}
	if !site.IsValid() || expectedVersion <= 0 || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	return service.store.Change(ctx, Change{
		Session: session, Scope: scope, Operation: OperationDelete, SiteID: site,
		ExpectedVersion: expectedVersion, CorrelationID: correlationID,
	})
}

// PutRouter makes a Device a router of a Site, or changes its priority or
// state, at the Site's expected version.
func (service *Service) PutRouter(ctx context.Context, session accountsession.Session, scope network.Scope,
	site ID, expectedVersion int64, assignment RouterAssignment, correlationID publicid.ID) (Result, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Result{}, err
	}
	if err := assignment.Validate(); err != nil {
		return Result{}, err
	}
	if !site.IsValid() || expectedVersion <= 0 || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	rowID, err := service.ids.New()
	if err != nil {
		return Result{}, ErrUnavailable
	}
	return service.store.ChangeRouter(ctx, RouterChange{
		Session: session, Scope: scope, Operation: RouterPut, SiteID: site, ExpectedVersion: expectedVersion,
		Assignment: assignment, RouterLimit: service.routerLimit(), RouterRowID: rowID,
		CorrelationID: correlationID,
	})
}

// RemoveRouter removes a router from a Site at the Site's expected version.
func (service *Service) RemoveRouter(ctx context.Context, session accountsession.Session, scope network.Scope,
	site ID, expectedVersion int64, assignment RouterAssignment, correlationID publicid.ID) (Result, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Result{}, err
	}
	if !site.IsValid() || expectedVersion <= 0 || !assignment.DeviceID.IsValid() || !correlationID.IsValid() {
		return Result{}, ErrInvalid
	}
	return service.store.ChangeRouter(ctx, RouterChange{
		Session: session, Scope: scope, Operation: RouterDelete, SiteID: site, ExpectedVersion: expectedVersion,
		Assignment: RouterAssignment{DeviceID: assignment.DeviceID}, CorrelationID: correlationID,
	})
}

// Eligible decides whether a stored router can serve its Site: an active
// Device owned by the Workspace whose own configuration offers every prefix.
func Eligible(deviceState, ownership string, offersSite bool) bool {
	return deviceState == "active" && ownership == "workspace" && offersSite
}

// SystemIDs generates random UUIDv7 public identifiers.
type SystemIDs struct{}

// New returns a fresh public identifier.
func (SystemIDs) New() (publicid.ID, error) { return publicid.New() }
