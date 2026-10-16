package memberlifecycle

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// Store applies one change or removal; PostgreSQL authorizes it on the
// database clock.
type Store interface {
	Change(ctx context.Context, change Change) (Result, error)
	Remove(ctx context.Context, removal Removal) (RemovalResult, error)
}

// Clock supplies this host's time, used only to refuse early a session that
// has already ended; PostgreSQL decides on the database clock.
type Clock interface{ Now() time.Time }

// Service validates member changes before PostgreSQL authorizes them.
type Service struct {
	store Store
	clock Clock
}

// NewService requires a store and a clock.
func NewService(store Store, clock Clock) (*Service, error) {
	if store == nil || clock == nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, clock: clock}, nil
}

// Request names one member change.
type Request struct {
	WorkspaceID   workspace.ID
	MemberID      publicid.ID
	Action        Action
	Reason        string
	CorrelationID publicid.ID
}

// Change validates and applies one member change.
func (service *Service) Change(ctx context.Context, session accountsession.Session, request Request) (Result, error) {
	if ctx == nil || service == nil || service.store == nil {
		return Result{}, ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return Result{}, ErrForbidden
	}
	change := Change{
		Session: session, WorkspaceID: request.WorkspaceID, MemberID: request.MemberID, Action: request.Action,
		Reason: request.Reason, CorrelationID: request.CorrelationID,
	}
	if !change.IsValid() {
		return Result{}, ErrInvalid
	}
	return service.store.Change(ctx, change)
}

// RemovalRequest names one member removal.
type RemovalRequest struct {
	WorkspaceID   workspace.ID
	MemberID      publicid.ID
	Reason        string
	Devices       []DevicePlan
	CorrelationID publicid.ID
}

// Remove validates and applies one member removal.
func (service *Service) Remove(ctx context.Context, session accountsession.Session, request RemovalRequest) (
	RemovalResult, error) {
	if ctx == nil || service == nil || service.store == nil {
		return RemovalResult{}, ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return RemovalResult{}, ErrForbidden
	}
	removal := Removal{
		Session: session, WorkspaceID: request.WorkspaceID, MemberID: request.MemberID, Reason: request.Reason,
		Devices: append([]DevicePlan(nil), request.Devices...), CorrelationID: request.CorrelationID,
	}
	if !removal.IsValid() {
		return RemovalResult{}, ErrInvalid
	}
	return service.store.Remove(ctx, removal)
}
