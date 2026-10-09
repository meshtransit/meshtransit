// Package settings owns authenticated Workspace name changes.
package settings

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

var (
	// ErrInvalid reports malformed requests or durable evidence.
	ErrInvalid = errors.New("workspace settings: invalid request or result")
	// ErrForbidden conceals missing current owner authority.
	ErrForbidden = errors.New("workspace settings: permission denied")
	// ErrConflict reports stale versions or name collisions.
	ErrConflict = errors.New("workspace settings: version or name conflict")
	// ErrUnavailable reports an unavailable or uncertain durable operation.
	ErrUnavailable = errors.New("workspace settings: unavailable")
)

// Command carries the canonical scope and a server-observed version, never a role flag.
type Command struct {
	Session         accountsession.Session
	WorkspaceID     workspace.ID
	DisplayName     string
	ExpectedVersion int64
	CorrelationID   publicid.ID
}

// IsValid binds the mutation to the exact login Workspace.
func (command Command) IsValid() bool {
	login, ok := command.Session.LoginWorkspaceID()
	return command.Session.IsValid() && ok && login == command.WorkspaceID &&
		command.WorkspaceID.IsValid() && command.CorrelationID.IsValid() &&
		command.ExpectedVersion > 0 && command.ExpectedVersion < 1<<63-1 && ValidName(command.DisplayName)
}

// Result is fresh durable evidence after a confirmed name-change commit.
type Result struct {
	WorkspaceID workspace.ID
	DisplayName string
	DisplayCode identity.DisplayCode
	Version     int64
}

// IsValid checks bounded post-commit evidence.
func (result Result) IsValid() bool {
	return result.WorkspaceID.IsValid() && ValidName(result.DisplayName) && result.DisplayCode.IsValid() && result.Version > 0
}

// ValidName rejects ambiguous, invalid or unbounded labels.
func ValidName(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Store commits one freshly authorized rename with audit and outbox evidence.
type Store interface {
	Rename(context.Context, Command) (Result, error)
}

// Clock supplies the application admission instant.
type Clock interface{ Now() time.Time }

// Service validates rename requests and durable receipts.
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

// Rename rechecks input and never retries an uncertain commit.
func (service *Service) Rename(ctx context.Context, command Command) (Result, error) {
	if ctx == nil || service == nil || service.store == nil || service.clock == nil || !command.IsValid() {
		return Result{}, ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !command.Session.IsActiveAt(now) {
		return Result{}, ErrForbidden
	}
	result, err := service.store.Rename(ctx, command)
	if err != nil {
		return Result{}, err
	}
	if !result.IsValid() || result.WorkspaceID != command.WorkspaceID || result.DisplayName != command.DisplayName || result.Version != command.ExpectedVersion+1 {
		return Result{}, ErrInvalid
	}
	return result, nil
}
