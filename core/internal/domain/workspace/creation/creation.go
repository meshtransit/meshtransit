// Package creation owns Account-initiated Workspace creation (ADR-050 D3).
// PostgreSQL validates the Session, the verified entitlement and both quotas
// under one Deployment lock; this package validates shapes and receipts and
// never retries an uncertain commit.
package creation

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/domain/workspace/settings"
)

var (
	// ErrInvalid reports a malformed request or durable result.
	ErrInvalid = errors.New("workspace creation: invalid request or result")
	// ErrForbidden reports an inactive Session.
	ErrForbidden = errors.New("workspace creation: permission denied")
	// ErrEntitlementMissing reports a Deployment without a verified entitlement.
	ErrEntitlementMissing = errors.New("workspace creation: deployment entitlement missing")
	// ErrEntitlementExpired reports an entitlement past its grace period.
	ErrEntitlementExpired = errors.New("workspace creation: deployment entitlement expired")
	// ErrDeploymentLimit reports the active Workspace ceiling.
	ErrDeploymentLimit = errors.New("workspace creation: deployment workspace limit")
	// ErrAccountLimit reports the per-Account ownership quota.
	ErrAccountLimit = errors.New("workspace creation: account workspace limit")
	// ErrConflict reports a reused Workspace ID or a name the Account owns.
	ErrConflict = errors.New("workspace creation: conflict")
	// ErrUnavailable reports an unavailable or uncertain durable operation.
	ErrUnavailable = errors.New("workspace creation: unavailable")
)

// Command creates one Workspace owned by the Session's Account. WorkspaceID
// is client-chosen so a retried request converges on one Workspace.
type Command struct {
	Session       accountsession.Session
	WorkspaceID   workspace.ID
	DisplayName   string
	CorrelationID publicid.ID
}

// IsValid checks shape only; authority is checked by PostgreSQL.
func (command Command) IsValid() bool {
	return command.Session.IsValid() && command.WorkspaceID.IsValid() &&
		settings.ValidName(command.DisplayName) && command.CorrelationID.IsValid()
}

// Result is the durable Workspace; Replayed reports an earlier commit.
type Result struct {
	WorkspaceID workspace.ID
	DisplayName string
	DisplayCode identity.DisplayCode
	Version     int64
	CreatedAt   time.Time
	Replayed    bool
}

// IsValid checks bounded post-commit evidence.
func (result Result) IsValid() bool {
	return result.WorkspaceID.IsValid() && settings.ValidName(result.DisplayName) &&
		result.DisplayCode.IsValid() && result.Version > 0 && !result.CreatedAt.IsZero()
}

// Store commits with fresh authority and audit evidence.
type Store interface {
	Create(context.Context, Command) (Result, error)
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

// Create admits an active Session and returns the durable Workspace.
func (service *Service) Create(ctx context.Context, command Command) (Result, error) {
	if ctx == nil || service == nil || service.store == nil || service.clock == nil || !command.IsValid() {
		return Result{}, ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !command.Session.IsActiveAt(now) {
		return Result{}, ErrForbidden
	}
	result, err := service.store.Create(ctx, command)
	if err != nil {
		return Result{}, err
	}
	if !result.IsValid() || result.WorkspaceID != command.WorkspaceID || result.DisplayName != command.DisplayName {
		return Result{}, ErrInvalid
	}
	return result, nil
}
