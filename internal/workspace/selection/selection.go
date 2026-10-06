// Package selection lets an Account Session move between the Workspaces its
// Account may enter (ADR-050 step 7). PostgreSQL applies the login rules:
// an active membership in an active Workspace that routes the Session's
// provider and client. Switching increments the Session version, so requests
// bound to the previous version fail their exact-version check. This package
// validates shapes and receipts and never retries an uncertain commit.
package selection

import (
	"context"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
	"github.com/meshtransit/meshtransit/internal/workspace/settings"
)

// MaxCandidates bounds the switchable Workspace list; PostgreSQL enforces the same.
const MaxCandidates = 100

var (
	// ErrInvalid reports a malformed request or durable result.
	ErrInvalid = errors.New("workspace selection: invalid request or result")
	// ErrForbidden reports an inactive Session.
	ErrForbidden = errors.New("workspace selection: permission denied")
	// ErrNotAvailable reports a Workspace this Account may not enter.
	ErrNotAvailable = errors.New("workspace selection: workspace not available")
	// ErrSessionChanged reports a Session that changed during the switch.
	ErrSessionChanged = errors.New("workspace selection: session changed")
	// ErrUnavailable reports an unavailable or uncertain durable operation.
	ErrUnavailable = errors.New("workspace selection: unavailable")
)

// Candidate is one Workspace the Session may switch to.
type Candidate struct {
	WorkspaceID workspace.ID
	DisplayName string
	DisplayCode identity.DisplayCode
	Owner       bool
	Current     bool
}

// IsValid checks a durable candidate.
func (candidate Candidate) IsValid() bool {
	return candidate.WorkspaceID.IsValid() && settings.ValidName(candidate.DisplayName) &&
		candidate.DisplayCode.IsValid()
}

// SwitchCommand moves the Session to WorkspaceID.
type SwitchCommand struct {
	Session       accountsession.Session
	WorkspaceID   workspace.ID
	CorrelationID publicid.ID
}

// IsValid checks shape only; authority is checked by PostgreSQL.
func (command SwitchCommand) IsValid() bool {
	return command.Session.IsValid() && command.WorkspaceID.IsValid() && command.CorrelationID.IsValid()
}

// SwitchResult is the committed binding. Replayed reports that the Session
// was already in WorkspaceID and nothing changed.
type SwitchResult struct {
	WorkspaceID    workspace.ID
	SessionVersion int64
	Replayed       bool
}

// Store reads candidates and commits switches with audit evidence.
type Store interface {
	List(context.Context, accountsession.Session) ([]Candidate, error)
	Switch(context.Context, SwitchCommand) (SwitchResult, error)
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

func (service *Service) admit(session accountsession.Session) error {
	if !session.IsValid() {
		return ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return ErrForbidden
	}
	return nil
}

// List returns at most MaxCandidates Workspaces, with at most one current.
func (service *Service) List(ctx context.Context, session accountsession.Session) ([]Candidate, error) {
	if ctx == nil || service == nil || service.store == nil || service.clock == nil {
		return nil, ErrInvalid
	}
	if err := service.admit(session); err != nil {
		return nil, err
	}
	candidates, err := service.store.List(ctx, session)
	if err != nil {
		return nil, err
	}
	if len(candidates) > MaxCandidates {
		return nil, ErrInvalid
	}
	seen := make(map[workspace.ID]struct{}, len(candidates))
	current := 0
	for _, candidate := range candidates {
		if _, duplicate := seen[candidate.WorkspaceID]; duplicate || !candidate.IsValid() {
			return nil, ErrInvalid
		}
		seen[candidate.WorkspaceID] = struct{}{}
		if candidate.Current {
			current++
		}
	}
	if current > 1 {
		return nil, ErrInvalid
	}
	return candidates, nil
}

// Switch moves the Session and checks the receipt: the requested Workspace,
// and a version that advanced unless replayed.
func (service *Service) Switch(ctx context.Context, command SwitchCommand) (SwitchResult, error) {
	if ctx == nil || service == nil || service.store == nil || service.clock == nil || !command.IsValid() {
		return SwitchResult{}, ErrInvalid
	}
	if err := service.admit(command.Session); err != nil {
		return SwitchResult{}, err
	}
	result, err := service.store.Switch(ctx, command)
	if err != nil {
		return SwitchResult{}, err
	}
	version := command.Session.Version()
	if result.WorkspaceID != command.WorkspaceID ||
		(result.Replayed && result.SessionVersion != version) ||
		(!result.Replayed && result.SessionVersion != version+1) {
		return SwitchResult{}, ErrInvalid
	}
	return result, nil
}
