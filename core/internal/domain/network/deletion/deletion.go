// Package deletion owns deleting a Network (docs/network-delete-design.md).
// Phase 1 runs with the request: PostgreSQL checks the Workspace-wide
// network.delete grant and what blocks the deletion, marks the Network
// deleted and revokes its enrollment keys; a worker then revokes its
// Devices and frees its prefixes. This package validates shapes and
// results and never retries an uncertain commit.
package deletion

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

var (
	// ErrInvalid reports a malformed request or durable result.
	ErrInvalid = errors.New("network deletion: invalid request or result")
	// ErrForbidden conceals a missing Workspace-wide network.delete grant.
	ErrForbidden = errors.New("network deletion: permission denied")
	// ErrNotFound reports a Network that is unknown, or whose deletion completed.
	ErrNotFound = errors.New("network deletion: Network unavailable")
	// ErrVersionConflict reports a Network changed since the version the caller named.
	ErrVersionConflict = errors.New("network deletion: version conflict")
	// ErrUnavailable reports an unavailable or uncertain durable operation.
	ErrUnavailable = errors.New("network deletion: unavailable")
)

// MaxReasonBytes bounds the reason; PostgreSQL enforces the same.
const MaxReasonBytes = 512

// MaxNamedBlockers bounds the blockers named in one refusal.
const MaxNamedBlockers = 50

// ValidReason reports 1 to 512 bytes of UTF-8 without surrounding spaces,
// control characters, or invisible format characters (bidi overrides,
// zero-width) that could make it read differently in the Console.
func ValidReason(reason string) bool {
	return len(reason) > 0 && len(reason) <= MaxReasonBytes && utf8.ValidString(reason) &&
		strings.Trim(reason, " ") == reason &&
		!strings.ContainsFunc(reason, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}

// Command deletes one Network of the Session's login Workspace, at the
// version the caller last read.
type Command struct {
	Session         accountsession.Session
	Scope           network.Scope
	ExpectedVersion int64
	Reason          string
	CorrelationID   publicid.ID
}

// IsValid checks shape and binds the request to the login Workspace.
func (command Command) IsValid() bool {
	login, ok := command.Session.LoginWorkspaceID()
	return command.Session.IsValid() && ok && login == command.Scope.WorkspaceID() && command.Scope.IsValid() &&
		command.ExpectedVersion > 0 && ValidReason(command.Reason) && command.CorrelationID.IsValid()
}

// Progress is how far a deletion is.
type Progress struct {
	NetworkID      network.ID
	RequestedAt    time.Time
	DevicesTotal   int64
	DevicesRevoked int64
	// CompletedAt is set once every Device is revoked and the prefixes held.
	CompletedAt *time.Time
}

// IsValid checks the figures agree.
func (progress Progress) IsValid() bool {
	return progress.NetworkID.IsValid() && !progress.RequestedAt.IsZero() && progress.DevicesTotal >= 0 &&
		progress.DevicesRevoked >= 0 &&
		(progress.CompletedAt == nil || !progress.CompletedAt.Before(progress.RequestedAt))
}

// Blocker kinds: what must end before a Network can be deleted.
const (
	BlockerTrustContract     = "trust_contract"
	BlockerKubernetesCluster = "kubernetes_cluster"
	BlockerKubernetesCA      = "kubernetes_ca"
)

// Blocker names one thing to end first.
type Blocker struct {
	Kind string
	ID   publicid.ID
	// Name is the cluster's name; empty for a Trust Contract.
	Name string
}

// Blockers is what refused a deletion: totals, and the first ones by name.
type Blockers struct {
	Total              int64
	TrustContracts     int64
	KubernetesClusters int64
	KubernetesCAs      int64
	Items              []Blocker
}

// IsValid checks the totals agree and every named blocker is well formed.
func (blockers Blockers) IsValid() bool {
	if blockers.Total <= 0 || blockers.TrustContracts < 0 || blockers.KubernetesClusters < 0 ||
		blockers.KubernetesCAs < 0 ||
		blockers.Total != blockers.TrustContracts+blockers.KubernetesClusters+blockers.KubernetesCAs ||
		len(blockers.Items) == 0 || len(blockers.Items) > MaxNamedBlockers ||
		int64(len(blockers.Items)) > blockers.Total {
		return false
	}
	for _, item := range blockers.Items {
		switch item.Kind {
		case BlockerTrustContract, BlockerKubernetesCluster, BlockerKubernetesCA:
		default:
			return false
		}
		if !item.ID.IsValid() || (item.Kind == BlockerTrustContract) != (item.Name == "") {
			return false
		}
	}
	return true
}

// Outcome kinds.
const (
	// OutcomeDeleted: the Network was deleted by this request.
	OutcomeDeleted = "deleted"
	// OutcomeDeleting: a repeat while phase 2 runs; nothing changed.
	OutcomeDeleting = "deleting"
	// OutcomeBlocked: nothing changed; Blockers says what to end first.
	OutcomeBlocked = "blocked"
)

// Outcome is what one request did.
type Outcome struct {
	Kind     string
	Progress Progress
	Blockers Blockers
	// Version is the Network's version after a deletion by this request.
	Version     int64
	KeysRevoked int
}

func (outcome Outcome) matches(command Command) bool {
	switch outcome.Kind {
	case OutcomeDeleted:
		return outcome.Progress.IsValid() && outcome.Progress.NetworkID == command.Scope.NetworkID() &&
			outcome.Progress.CompletedAt == nil && outcome.Version > command.ExpectedVersion &&
			outcome.KeysRevoked >= 0
	case OutcomeDeleting:
		return outcome.Progress.IsValid() && outcome.Progress.NetworkID == command.Scope.NetworkID() &&
			outcome.Progress.CompletedAt == nil
	case OutcomeBlocked:
		return outcome.Blockers.IsValid()
	}
	return false
}

// Network states as the API reads them.
const (
	StateActive   = "active"
	StateDeleting = "deleting"
)

// View is one Network as GET reads it.
type View struct {
	NetworkID   network.ID
	DisplayName string
	DisplayCode string
	State       string
	Version     int64
	CreatedAt   time.Time
	// Deletion is set while the Network is being deleted.
	Deletion *Progress
}

func (view View) matches(scope network.Scope) bool {
	if view.NetworkID != scope.NetworkID() || view.DisplayName == "" || view.Version <= 0 || view.CreatedAt.IsZero() {
		return false
	}
	switch view.State {
	case StateActive:
		return view.Deletion == nil
	case StateDeleting:
		return view.Deletion != nil && view.Deletion.IsValid() && view.Deletion.NetworkID == view.NetworkID &&
			view.Deletion.CompletedAt == nil
	}
	return false
}

// Store commits with fresh authority and audit evidence.
type Store interface {
	Delete(context.Context, Command) (Outcome, error)
	Read(context.Context, accountsession.Session, network.Scope) (View, error)
}

// Clock supplies the application admission instant.
type Clock interface{ Now() time.Time }

// Service validates requests and results.
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

// Delete admits an active Session and returns what the request did.
func (service *Service) Delete(ctx context.Context, command Command) (Outcome, error) {
	if !command.IsValid() {
		return Outcome{}, ErrInvalid
	}
	if err := service.admit(ctx, command.Session); err != nil {
		return Outcome{}, err
	}
	outcome, err := service.store.Delete(ctx, command)
	if err != nil {
		return Outcome{}, err
	}
	if !outcome.matches(command) {
		return Outcome{}, ErrInvalid
	}
	return outcome, nil
}

// Read admits an active Session bound to the Network's Workspace.
func (service *Service) Read(ctx context.Context, session accountsession.Session, scope network.Scope) (View, error) {
	login, ok := session.LoginWorkspaceID()
	if !session.IsValid() || !ok || !scope.IsValid() || login != scope.WorkspaceID() {
		return View{}, ErrInvalid
	}
	if err := service.admit(ctx, session); err != nil {
		return View{}, err
	}
	view, err := service.store.Read(ctx, session, scope)
	if err != nil {
		return View{}, err
	}
	if !view.matches(scope) {
		return View{}, ErrInvalid
	}
	return view, nil
}
