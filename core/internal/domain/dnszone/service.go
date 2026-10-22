package dnszone

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// Operation is what a zone change does.
type Operation string

// Zone operations.
const (
	OperationCreate Operation = "create"
	OperationUpdate Operation = "update"
	OperationDelete Operation = "delete"
)

// Page bounds of the zone list.
const (
	DefaultPage = 10
	MaximumPage = 100
)

// Abilities says what the reader may do: create, change and delete zones
// (dns.manage).
type Abilities struct {
	CanManage bool
}

// Listing is one page of a Network's active zones in domain order, the root
// first, and the Network's system zones.
type Listing struct {
	Zones   []Zone
	HasMore bool
	// WorkspaceCode and NetworkCode are the display codes that name the
	// Network's system zone; the store reads them.
	WorkspaceCode identity.DisplayCode
	NetworkCode   identity.DisplayCode
	// System are the zones MeshTransit answers itself: the Network's own
	// (its Devices' names) and the shared zone (the names of shares the
	// Network receives). The service fills them.
	System SystemZones
	Abilities
}

// SystemZones are the domains of a Network's system zones.
type SystemZones struct {
	Network string
	Shared  string
}

// Reading is one zone and what the reader may do with it.
type Reading struct {
	Zone Zone
	Abilities
}

// Result is a zone after a change. Changed is false when the change asked
// for what was already stored: nothing was written. Names is how many names
// a new zone took from shorter zones, or a deleted zone deleted.
type Result struct {
	Zone     Zone
	Previous *Zone
	Changed  bool
	Names    int
}

// Change is one validated zone change. Domain, Class and ListVersion are
// set on create and must match the stored zone on update. WithNames lets a
// new zone take the names shorter zones hold under its domain, and a
// deleted zone delete the names it holds; without it either fails with
// ErrZoneHoldsNames.
type Change struct {
	Session         accountsession.Session
	Scope           network.Scope
	Operation       Operation
	ZoneID          ID
	ExpectedVersion int64
	Domain          Domain
	Class           Class
	ListVersion     string
	Definition      Definition
	Limits          Limits
	WithNames       bool
	CorrelationID   publicid.ID
}

// Store reads and changes zones and their names; PostgreSQL authorizes each
// call, checks the resolver and target Devices and the Device Groups, and
// decides it on the database clock.
type Store interface {
	List(ctx context.Context, session accountsession.Session, scope network.Scope, after ID, limit int) (Listing, error)
	Read(ctx context.Context, session accountsession.Session, scope network.Scope, zone ID) (Reading, error)
	Change(ctx context.Context, change Change) (Result, error)
	ListNames(ctx context.Context, session accountsession.Session, scope network.Scope, zone ID, after NameID,
		prefix string, limit int) (NameListing, error)
	ReadName(ctx context.Context, session accountsession.Session, scope network.Scope, zone ID,
		name NameID) (NameReading, error)
	ChangeNames(ctx context.Context, change NameChange) (NameResult, error)
}

// Clock supplies this host's time for the early session gate only.
type Clock interface{ Now() time.Time }

// IDs generates public identifiers.
type IDs interface{ New() (publicid.ID, error) }

// Options are the deployment's settings for zones.
type Options struct {
	// Enabled lets zones be created and changed; reads always work.
	Enabled bool
	// Root lets a root zone be created (DNS design D1b).
	Root bool
	// Names are what domains are checked against.
	Names Names
}

// Service validates zone changes before PostgreSQL authorizes them.
type Service struct {
	store   Store
	clock   Clock
	ids     IDs
	limits  Limits
	options Options
}

// NewService requires a store, clock, identifier source, valid limits and a
// valid mesh suffix.
func NewService(store Store, clock Clock, ids IDs, limits Limits, options Options) (*Service, error) {
	if store == nil || clock == nil || ids == nil || limits.Validate() != nil || !options.Names.Suffix.IsValid() {
		return nil, ErrInvalid
	}
	return &Service{store: store, clock: clock, ids: ids, limits: limits, options: options}, nil
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

// admitWrite also requires the deployment to have turned zones on.
func (service *Service) admitWrite(ctx context.Context, session accountsession.Session, scope network.Scope,
	correlationID publicid.ID) error {
	if err := service.admit(ctx, session, scope); err != nil {
		return err
	}
	if !correlationID.IsValid() {
		return ErrInvalid
	}
	if !service.options.Enabled {
		return ErrDisabled
	}
	return nil
}

// List returns one page of the Network's active zones after the given one
// (the zero ID starts at the first).
func (service *Service) List(ctx context.Context, session accountsession.Session, scope network.Scope,
	after ID, limit int) (Listing, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Listing{}, err
	}
	if limit < 1 || limit > MaximumPage || (after != ID{} && !after.IsValid()) {
		return Listing{}, ErrInvalid
	}
	listing, err := service.store.List(ctx, session, scope, after, limit)
	if err != nil {
		return Listing{}, err
	}
	suffix := service.options.Names.Suffix
	zone, err := dnsname.NewZone(listing.WorkspaceCode, listing.NetworkCode, suffix)
	if err != nil {
		return Listing{}, ErrInvalid
	}
	listing.System = SystemZones{Network: zone.String(), Shared: "shared." + suffix.String()}
	return listing, nil
}

// Read returns one active zone.
func (service *Service) Read(ctx context.Context, session accountsession.Session, scope network.Scope,
	zone ID) (Reading, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Reading{}, err
	}
	if !zone.IsValid() {
		return Reading{}, ErrInvalid
	}
	return service.store.Read(ctx, session, scope, zone)
}

// Create adds a zone; a definition without OtherNames forwards them (D1).
// adoptNames lets it take the names shorter zones hold under its domain.
func (service *Service) Create(ctx context.Context, session accountsession.Session, scope network.Scope,
	definition Definition, adoptNames bool, correlationID publicid.ID) (Result, error) {
	if err := service.admitWrite(ctx, session, scope, correlationID); err != nil {
		return Result{}, err
	}
	if definition.OtherNames == "" {
		definition.OtherNames = OtherForward
	}
	domain, class, err := ParseDomain(definition.Domain, service.options.Names)
	if err != nil {
		return Result{}, err
	}
	if err := service.check(domain, class, definition); err != nil {
		return Result{}, err
	}
	id, err := service.ids.New()
	if err != nil {
		return Result{}, ErrUnavailable
	}
	definition.Domain = domain.String()
	return service.store.Change(ctx, Change{
		Session: session, Scope: scope, Operation: OperationCreate, ZoneID: ID(id), Domain: domain,
		Class: class, ListVersion: PublicListVersion(), Definition: definition.Canonical(),
		Limits: service.limits, WithNames: adoptNames, CorrelationID: correlationID,
	})
}

// Update replaces a zone's kind, resolvers, Device Groups, failure mode,
// search position and confirmation at the expected version; its domain
// never changes. A definition without OtherNames keeps the zone's kind.
func (service *Service) Update(ctx context.Context, session accountsession.Session, scope network.Scope,
	zone ID, expectedVersion int64, definition Definition, correlationID publicid.ID) (Result, error) {
	if err := service.admitWrite(ctx, session, scope, correlationID); err != nil {
		return Result{}, err
	}
	if !zone.IsValid() || expectedVersion <= 0 {
		return Result{}, ErrInvalid
	}
	current, err := service.store.Read(ctx, session, scope, zone)
	if err != nil {
		return Result{}, err
	}
	stored := current.Zone
	if definition.Domain != "" && definition.Domain != stored.Domain.String() {
		return Result{}, ErrInvalid
	}
	if definition.OtherNames == "" {
		definition.OtherNames = stored.OtherNames
	}
	if err := service.check(stored.Domain, stored.Class, definition); err != nil {
		return Result{}, err
	}
	definition.Domain = stored.Domain.String()
	return service.store.Change(ctx, Change{
		Session: session, Scope: scope, Operation: OperationUpdate, ZoneID: zone,
		ExpectedVersion: expectedVersion, Domain: stored.Domain, Class: stored.Class,
		ListVersion: stored.ListVersion, Definition: definition.Canonical(), Limits: service.limits,
		CorrelationID: correlationID,
	})
}

// Delete removes a zone; withNames deletes the names it holds with it.
func (service *Service) Delete(ctx context.Context, session accountsession.Session, scope network.Scope,
	zone ID, expectedVersion int64, withNames bool, correlationID publicid.ID) (Result, error) {
	if err := service.admitWrite(ctx, session, scope, correlationID); err != nil {
		return Result{}, err
	}
	if !zone.IsValid() || expectedVersion <= 0 {
		return Result{}, ErrInvalid
	}
	return service.store.Change(ctx, Change{
		Session: session, Scope: scope, Operation: OperationDelete, ZoneID: zone,
		ExpectedVersion: expectedVersion, WithNames: withNames, CorrelationID: correlationID,
	})
}

// check validates a definition for a domain of class: the root only where
// offered, never a search domain and always forward; a public domain only
// when confirmed and never nxdomain.
func (service *Service) check(domain Domain, class Class, definition Definition) error {
	if err := definition.Validate(service.limits); err != nil {
		return err
	}
	if domain.IsRoot() && definition.OtherNames != OtherForward {
		return ErrInvalid
	}
	if class == ClassPublic && definition.OtherNames == OtherNXDomain {
		return ErrNXDomainPublic
	}
	if domain.IsRoot() && (!service.options.Root || definition.SearchPosition != nil) {
		if !service.options.Root {
			return ErrRootUnavailable
		}
		return ErrInvalid
	}
	if class == ClassPublic && !definition.PublicConfirmed {
		return ErrPublicUnconfirmed
	}
	return nil
}

// SystemIDs generates random UUIDv7 public identifiers.
type SystemIDs struct{}

// New returns a fresh public identifier.
func (SystemIDs) New() (publicid.ID, error) { return publicid.New() }
