// Package memberlifecycle suspends, resumes and removes Workspace members,
// and ends their Console sessions in a Workspace.
// Suspending a member cuts them off in the Workspace at once: their
// membership grants nothing, the Devices they own there are suspended, and
// their Console sessions in the Workspace end. Resuming restores exactly what
// the suspension took. Removing a member hands each of their Devices to the
// Workspace or another member, or revokes it, and ends their keys, groups,
// roles, sessions and membership. PostgreSQL authorizes every change and
// records it with audit evidence.
package memberlifecycle

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

var (
	// ErrInvalid reports a malformed change.
	ErrInvalid = errors.New("member lifecycle: invalid change")
	// ErrForbidden reports a change the session may not make, including a
	// member who holds a role beyond the actor's delegation ceiling.
	ErrForbidden = errors.New("member lifecycle: forbidden")
	// ErrNotFound reports an unknown member.
	ErrNotFound = errors.New("member lifecycle: member not found")
	// ErrWrongState reports a member whose state the action does not accept.
	ErrWrongState = errors.New("member lifecycle: member state does not allow this change")
	// ErrProtected reports the owner or the actor as the target.
	ErrProtected = errors.New("member lifecycle: the owner and the actor cannot be changed")
	// ErrUnavailable reports a dependency failure.
	ErrUnavailable = errors.New("member lifecycle: unavailable")
)

// MaximumReasonBytes bounds the reason recorded with a change.
const MaximumReasonBytes = 256

// Action is one member lifecycle change.
type Action string

// Actions.
const (
	ActionSuspend Action = "suspend"
	ActionResume  Action = "resume"
	// ActionRevokeSessions ends the member's Console sessions signed in to
	// the Workspace and changes nothing else.
	ActionRevokeSessions Action = "revoke-sessions"
	// ActionRemove names a removal, which travels as a Removal, never as a
	// Change.
	ActionRemove Action = "remove"
)

// Change is one validated member change.
type Change struct {
	Session       accountsession.Session
	WorkspaceID   workspace.ID
	MemberID      publicid.ID
	Action        Action
	Reason        string
	CorrelationID publicid.ID
	EvaluatedAt   time.Time
}

// Member is a membership document.
type Member struct {
	PrincipalID publicid.ID
	State       string
	ExpiresAt   *time.Time
	Version     int64
}

// ChangedDevice is one Device the change suspended or resumed.
type ChangedDevice struct {
	DeviceID  node.ID
	NetworkID network.ID
	Hostname  string
	State     string
}

// AdvancedNetwork is a Network whose maps the change rebuilt.
type AdvancedNetwork struct {
	NetworkID       network.ID
	NetworkRevision int64
	GroupRevision   int64
}

// Result is a member before and after one change, with its effects.
type Result struct {
	Before        Member
	After         Member
	Devices       []ChangedDevice
	SessionsEnded int
	Networks      []AdvancedNetwork
}

// ValidReason reports a non-empty single-line reason within bounds.
func ValidReason(reason string) bool {
	return reason != "" && strings.TrimSpace(reason) == reason && len(reason) <= MaximumReasonBytes &&
		utf8.ValidString(reason) && !strings.ContainsAny(reason, "\r\n\x00")
}

// IsValid reports a complete change with a reason.
func (change Change) IsValid() bool {
	return change.Session.IsValid() && change.WorkspaceID.IsValid() && change.MemberID.IsValid() &&
		(change.Action == ActionSuspend || change.Action == ActionResume || change.Action == ActionRevokeSessions) &&
		ValidReason(change.Reason) &&
		change.CorrelationID.IsValid() && !change.EvaluatedAt.IsZero()
}
