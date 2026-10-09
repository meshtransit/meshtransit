package memberlifecycle

import (
	"context"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

// Store applies one change or removal; PostgreSQL authorizes it.
type Store interface {
	Change(ctx context.Context, change Change) (Result, error)
	Remove(ctx context.Context, removal Removal) (RemovalResult, error)
}

// Clock supplies the current time.
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

// Request names a change before the service stamps its time.
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
		Reason: request.Reason, CorrelationID: request.CorrelationID, EvaluatedAt: now,
	}
	if !change.IsValid() {
		return Result{}, ErrInvalid
	}
	return service.store.Change(ctx, change)
}

// RemovalRequest names a removal before the service stamps its time.
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
		Devices: append([]DevicePlan(nil), request.Devices...), CorrelationID: request.CorrelationID, EvaluatedAt: now,
	}
	if !removal.IsValid() {
		return RemovalResult{}, ErrInvalid
	}
	return service.store.Remove(ctx, removal)
}
