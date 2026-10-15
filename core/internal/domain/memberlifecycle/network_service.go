package memberlifecycle

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// NetworkStore lists, adds and removes the members of one Network;
// PostgreSQL authorizes each call.
type NetworkStore interface {
	ListNetworkMembers(ctx context.Context, query NetworkMemberQuery) (NetworkMemberPage, error)
	AddNetworkMembers(ctx context.Context, addition NetworkAddition) (NetworkAdditionResult, error)
	RemoveNetworkMember(ctx context.Context, removal NetworkRemoval) (NetworkRemovalResult, error)
}

// NetworkService validates Network member changes before PostgreSQL
// authorizes them.
type NetworkService struct {
	store NetworkStore
	clock Clock
}

// NewNetworkService requires a store and a clock.
func NewNetworkService(store NetworkStore, clock Clock) (*NetworkService, error) {
	if store == nil || clock == nil {
		return nil, ErrInvalid
	}
	return &NetworkService{store: store, clock: clock}, nil
}

// NetworkRemovalRequest names a removal before the service stamps its time.
type NetworkRemovalRequest struct {
	Scope         network.Scope
	MemberID      publicid.ID
	Reason        string
	Devices       []DevicePlan
	CorrelationID publicid.ID
}

// now returns the evaluation time, refusing a session that is no longer
// active.
func (service *NetworkService) now(ctx context.Context, session accountsession.Session) (time.Time, error) {
	if ctx == nil || service == nil || service.store == nil || service.clock == nil {
		return time.Time{}, ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return time.Time{}, ErrForbidden
	}
	return now, nil
}

// List returns one page of the Network's members after a principal ID.
func (service *NetworkService) List(ctx context.Context, session accountsession.Session, scope network.Scope,
	after publicid.ID, limit int) (NetworkMemberPage, error) {
	now, err := service.now(ctx, session)
	if err != nil {
		return NetworkMemberPage{}, err
	}
	query := NetworkMemberQuery{Session: session, Scope: scope, After: after, Limit: limit, EvaluatedAt: now}
	if !query.IsValid() {
		return NetworkMemberPage{}, ErrInvalid
	}
	return service.store.ListNetworkMembers(ctx, query)
}

// Add adds Workspace members to the Network; members already in it are
// reported unchanged.
func (service *NetworkService) Add(ctx context.Context, session accountsession.Session, scope network.Scope,
	members []publicid.ID, correlationID publicid.ID) (NetworkAdditionResult, error) {
	now, err := service.now(ctx, session)
	if err != nil {
		return NetworkAdditionResult{}, err
	}
	addition := NetworkAddition{
		Session: session, Scope: scope, MemberIDs: append([]publicid.ID(nil), members...),
		CorrelationID: correlationID, EvaluatedAt: now,
	}
	if !addition.IsValid() {
		return NetworkAdditionResult{}, ErrInvalid
	}
	return service.store.AddNetworkMembers(ctx, addition)
}

// Remove removes one member from the Network, handling their Devices there
// as the plan says.
func (service *NetworkService) Remove(ctx context.Context, session accountsession.Session,
	request NetworkRemovalRequest) (NetworkRemovalResult, error) {
	now, err := service.now(ctx, session)
	if err != nil {
		return NetworkRemovalResult{}, err
	}
	removal := NetworkRemoval{
		Session: session, Scope: request.Scope, MemberID: request.MemberID, Reason: request.Reason,
		Devices: append([]DevicePlan(nil), request.Devices...), CorrelationID: request.CorrelationID,
		EvaluatedAt: now,
	}
	if !removal.IsValid() {
		return NetworkRemovalResult{}, ErrInvalid
	}
	return service.store.RemoveNetworkMember(ctx, removal)
}
