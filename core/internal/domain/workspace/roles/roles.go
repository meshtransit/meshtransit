// Package roles owns Workspace member listing and built-in role assignment
// (ADR-050 D6). Authority, the delegation ceiling and self-change rules are
// enforced by PostgreSQL on every call; this package validates shapes and
// durable receipts and never retries an uncertain commit.
package roles

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/meshtransit/meshtransit/core/internal/domain/authorization"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

var (
	// ErrInvalid reports malformed requests or durable evidence.
	ErrInvalid = errors.New("workspace roles: invalid request or result")
	// ErrForbidden conceals missing authority or a request above the
	// delegation ceiling, including changes to one's own roles.
	ErrForbidden = errors.New("workspace roles: permission denied")
	// ErrNotFound reports an unavailable member, Network or assignment.
	ErrNotFound = errors.New("workspace roles: not found")
	// ErrConflict reports a duplicate role, a reused assignment ID or a stale version.
	ErrConflict = errors.New("workspace roles: conflict")
	// ErrUnavailable reports an unavailable or uncertain durable operation.
	ErrUnavailable = errors.New("workspace roles: unavailable")
)

// maxMembers bounds one listing; larger Workspaces need pagination later.
const maxMembers = 1000

// Assignment is one active built-in role grant. A zero NetworkID means the
// role applies in every current and future Network of the Workspace.
type Assignment struct {
	ID        publicid.ID
	Role      authorization.BuiltinRole
	NetworkID network.ID
	ExpiresAt time.Time
	Version   int64
	CreatedAt time.Time
}

// IsValid checks one decoded assignment.
func (assignment Assignment) IsValid() bool {
	return assignment.ID.IsValid() && assignment.Role.IsValid() &&
		(assignment.NetworkID == network.ID{} || assignment.Role.NetworkScopeAllowed()) &&
		assignment.Version > 0 && !assignment.CreatedAt.IsZero()
}

// Member is one non-revoked Workspace membership and its active assignments.
type Member struct {
	PrincipalID         publicid.ID
	DisplayName         string
	MembershipState     string
	MembershipExpiresAt time.Time
	Owner               bool
	Assignments         []Assignment
}

// IsValid checks one decoded member.
func (member Member) IsValid() bool {
	if !member.PrincipalID.IsValid() || member.DisplayName == "" || len(member.DisplayName) > 256 ||
		!utf8.ValidString(member.DisplayName) ||
		(member.MembershipState != "active" && member.MembershipState != "suspended") {
		return false
	}
	for _, assignment := range member.Assignments {
		if !assignment.IsValid() {
			return false
		}
	}
	return true
}

// Directory is the member listing of one Workspace.
type Directory struct {
	WorkspaceID workspace.ID
	Members     []Member
	Truncated   bool
}

// ListCommand reads the members of the Session's login Workspace.
type ListCommand struct {
	Session     accountsession.Session
	WorkspaceID workspace.ID
}

// IsValid binds the read to the exact login Workspace.
func (command ListCommand) IsValid() bool {
	login, ok := command.Session.LoginWorkspaceID()
	return command.Session.IsValid() && ok && login == command.WorkspaceID && command.WorkspaceID.IsValid()
}

// AssignCommand grants one built-in role. AssignmentID is client-chosen so a
// retried request converges on one assignment.
type AssignCommand struct {
	Session       accountsession.Session
	WorkspaceID   workspace.ID
	AssignmentID  publicid.ID
	PrincipalID   publicid.ID
	Role          authorization.BuiltinRole
	NetworkID     network.ID
	ExpiresAt     time.Time
	CorrelationID publicid.ID
}

// IsValid checks shape and the role's allowed scope.
func (command AssignCommand) IsValid() bool {
	login, ok := command.Session.LoginWorkspaceID()
	return command.Session.IsValid() && ok && login == command.WorkspaceID && command.WorkspaceID.IsValid() &&
		command.AssignmentID.IsValid() && command.PrincipalID.IsValid() && command.Role.IsValid() &&
		(command.NetworkID == network.ID{} || command.NetworkID.IsValid() && command.Role.NetworkScopeAllowed()) &&
		command.CorrelationID.IsValid()
}

// AssignResult is the durable assignment; Replayed reports an earlier commit.
type AssignResult struct {
	Assignment Assignment
	Replayed   bool
}

// RevokeCommand ends one assignment at its reviewed version.
type RevokeCommand struct {
	Session         accountsession.Session
	WorkspaceID     workspace.ID
	AssignmentID    publicid.ID
	ExpectedVersion int64
	CorrelationID   publicid.ID
}

// IsValid checks shape.
func (command RevokeCommand) IsValid() bool {
	login, ok := command.Session.LoginWorkspaceID()
	return command.Session.IsValid() && ok && login == command.WorkspaceID && command.WorkspaceID.IsValid() &&
		command.AssignmentID.IsValid() && command.ExpectedVersion > 0 && command.ExpectedVersion < 1<<63-1 &&
		command.CorrelationID.IsValid()
}

// RevokeResult is the durable revocation; Replayed reports an earlier commit.
type RevokeResult struct {
	AssignmentID publicid.ID
	Version      int64
	Replayed     bool
}

// Store reads and commits with fresh authority and audit evidence.
type Store interface {
	ListMembers(context.Context, ListCommand) (Directory, error)
	Assign(context.Context, AssignCommand) (AssignResult, error)
	Revoke(context.Context, RevokeCommand) (RevokeResult, error)
}

// Clock supplies the application admission instant.
type Clock interface{ Now() time.Time }

// Service validates requests and durable receipts.
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

func (service *Service) admit(ctx context.Context, session accountsession.Session) error {
	if ctx == nil || service == nil || service.store == nil || service.clock == nil {
		return ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return ErrForbidden
	}
	return nil
}

// ListMembers returns the Workspace's members and their active assignments.
func (service *Service) ListMembers(ctx context.Context, command ListCommand) (Directory, error) {
	if !command.IsValid() {
		return Directory{}, ErrInvalid
	}
	if err := service.admit(ctx, command.Session); err != nil {
		return Directory{}, err
	}
	directory, err := service.store.ListMembers(ctx, command)
	if err != nil {
		return Directory{}, err
	}
	if directory.WorkspaceID != command.WorkspaceID || len(directory.Members) > maxMembers {
		return Directory{}, ErrInvalid
	}
	for _, member := range directory.Members {
		if !member.IsValid() {
			return Directory{}, ErrInvalid
		}
	}
	return directory, nil
}

// Assign grants one role and returns the durable assignment.
func (service *Service) Assign(ctx context.Context, command AssignCommand) (AssignResult, error) {
	if !command.IsValid() {
		return AssignResult{}, ErrInvalid
	}
	if err := service.admit(ctx, command.Session); err != nil {
		return AssignResult{}, err
	}
	if !command.ExpiresAt.IsZero() && !command.ExpiresAt.After(service.clock.Now().UTC()) {
		return AssignResult{}, ErrInvalid
	}
	result, err := service.store.Assign(ctx, command)
	if err != nil {
		return AssignResult{}, err
	}
	assignment := result.Assignment
	if !assignment.IsValid() || assignment.ID != command.AssignmentID || assignment.Role != command.Role ||
		assignment.NetworkID != command.NetworkID || !assignment.ExpiresAt.Equal(command.ExpiresAt) {
		return AssignResult{}, ErrInvalid
	}
	return result, nil
}

// Revoke ends one assignment at its reviewed version.
func (service *Service) Revoke(ctx context.Context, command RevokeCommand) (RevokeResult, error) {
	if !command.IsValid() {
		return RevokeResult{}, ErrInvalid
	}
	if err := service.admit(ctx, command.Session); err != nil {
		return RevokeResult{}, err
	}
	result, err := service.store.Revoke(ctx, command)
	if err != nil {
		return RevokeResult{}, err
	}
	if result.AssignmentID != command.AssignmentID || result.Version != command.ExpectedVersion+1 {
		return RevokeResult{}, ErrInvalid
	}
	return result, nil
}
