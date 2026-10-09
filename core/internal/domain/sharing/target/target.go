// Package target resolves the consumer Network of a new share from its
// 12-digit display code (ADR-050 D7). PostgreSQL requires share.offer on the
// provider Network and reveals only existence: public IDs and display codes,
// never names. This package validates shapes and receipts.
package target

import (
	"context"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
)

var (
	// ErrInvalid reports a malformed request or durable result.
	ErrInvalid = errors.New("share target: invalid request or result")
	// ErrForbidden reports a Session without share.offer on the provider Network.
	ErrForbidden = errors.New("share target: permission denied")
	// ErrNotFound reports no active Network with that display code in the Deployment.
	ErrNotFound = errors.New("share target: not found")
	// ErrUnavailable reports an unavailable or uncertain read.
	ErrUnavailable = errors.New("share target: unavailable")
)

// Query asks for the Network behind NetworkCode, on behalf of a share
// offered from Provider.
type Query struct {
	Session     accountsession.Session
	Provider    network.Scope
	NetworkCode identity.DisplayCode
}

// IsValid checks shape only; authority is checked by PostgreSQL.
func (query Query) IsValid() bool {
	return query.Session.IsValid() && query.Provider.IsValid() && query.NetworkCode.IsValid()
}

// Target is an existing, active Network that a share may be offered to.
type Target struct {
	Scope         network.Scope
	WorkspaceCode identity.DisplayCode
	NetworkCode   identity.DisplayCode
}

// CrossWorkspace reports whether the target lies outside the provider Workspace.
func (target Target) CrossWorkspace(provider network.Scope) bool {
	return target.Scope.WorkspaceID() != provider.WorkspaceID()
}

// Store resolves display codes with fresh authority.
type Store interface {
	Resolve(context.Context, Query) (Target, error)
}

// Clock supplies the application admission instant.
type Clock interface{ Now() time.Time }

// Service validates requests and receipts.
type Service struct {
	store Store
	clock Clock
}

// NewService validates explicit dependencies.
func NewService(store Store, clock Clock) (*Service, error) {
	if store == nil || clock == nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, clock: clock}, nil
}

// Resolve admits an active Session and checks that the receipt names the
// requested code.
func (service *Service) Resolve(ctx context.Context, query Query) (Target, error) {
	if ctx == nil || service == nil || service.store == nil || service.clock == nil || !query.IsValid() {
		return Target{}, ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !query.Session.IsActiveAt(now) {
		return Target{}, ErrForbidden
	}
	target, err := service.store.Resolve(ctx, query)
	if err != nil {
		return Target{}, err
	}
	if !target.Scope.IsValid() || target.NetworkCode != query.NetworkCode || !target.WorkspaceCode.IsValid() {
		return Target{}, ErrInvalid
	}
	return target, nil
}
