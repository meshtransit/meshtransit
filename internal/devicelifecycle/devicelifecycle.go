// Package devicelifecycle changes who owns a Device and whether it may
// connect: suspend and resume it, transfer it to the Workspace or to another
// member (who must then sign in on it), and rename it. PostgreSQL authorizes
// every change and records it with audit evidence.
package devicelifecycle

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

var (
	// ErrInvalid reports a malformed change.
	ErrInvalid = errors.New("device lifecycle: invalid change")
	// ErrForbidden reports a change the session may not make.
	ErrForbidden = errors.New("device lifecycle: forbidden")
	// ErrNotFound reports an unknown Device.
	ErrNotFound = errors.New("device lifecycle: Device not found")
	// ErrVersionConflict reports a stale expected version.
	ErrVersionConflict = errors.New("device lifecycle: version conflict")
	// ErrWrongState reports a Device whose state the action does not accept.
	ErrWrongState = errors.New("device lifecycle: Device state does not allow this change")
	// ErrIneligibleOwner reports a new owner who is not an active member of
	// the Workspace and Network.
	ErrIneligibleOwner = errors.New("device lifecycle: new owner is not an active member")
	// ErrHostnameTaken reports a hostname another Device of the Network has.
	ErrHostnameTaken = errors.New("device lifecycle: hostname taken")
	// ErrUnavailable reports a dependency failure.
	ErrUnavailable = errors.New("device lifecycle: unavailable")
)

// MaximumReasonBytes bounds the reason recorded with a change.
const MaximumReasonBytes = 256

// Action is one lifecycle change.
type Action string

// Actions.
const (
	ActionSuspend           Action = "suspend"
	ActionResume            Action = "resume"
	ActionTransferWorkspace Action = "transfer_workspace"
	ActionTransferMember    Action = "transfer_member"
	ActionRename            Action = "rename"
)

// Ownership is who owns a Device.
type Ownership string

// Ownership kinds.
const (
	OwnershipMember    Ownership = "member"
	OwnershipWorkspace Ownership = "workspace"
)

// SuspendedReason says why a Device is suspended.
type SuspendedReason string

// Suspension reasons.
const (
	SuspendedByAdmin     SuspendedReason = "admin"
	SuspendedForHandover SuspendedReason = "handover"
)

// Change is one validated lifecycle change.
type Change struct {
	Session  accountsession.Session
	Scope    network.Scope
	DeviceID node.ID
	Action   Action
	// ExpectedVersion is the Device version the caller saw.
	ExpectedVersion int64
	// NewOwner is the member a transfer_member change hands the Device to.
	NewOwner publicid.ID
	// Hostname is the new name of a rename.
	Hostname      node.Hostname
	Reason        string
	CorrelationID publicid.ID
	EvaluatedAt   time.Time
}

// State is a Device's lifecycle document.
type State struct {
	DeviceID        node.ID
	Hostname        string
	State           string
	Ownership       Ownership
	Owner           publicid.ID
	SuspendedReason SuspendedReason
	HandoverTo      publicid.ID
	HostnameLocked  bool
	ExpiresAt       time.Time
	Version         int64
}

// Result is a Device before and after one change.
type Result struct {
	Before          State
	After           State
	NetworkRevision int64
}

// ValidReason reports a non-empty single-line reason within bounds.
func ValidReason(reason string) bool {
	return reason != "" && strings.TrimSpace(reason) == reason && len(reason) <= MaximumReasonBytes &&
		utf8.ValidString(reason) && !strings.ContainsAny(reason, "\r\n\x00")
}

// IsValid reports a complete change; every action but rename needs a reason.
func (change Change) IsValid() bool {
	if !change.Session.IsValid() || !change.Scope.IsValid() || !change.DeviceID.IsValid() ||
		change.ExpectedVersion < 1 || !change.CorrelationID.IsValid() || change.EvaluatedAt.IsZero() {
		return false
	}
	if change.Action != ActionRename && !ValidReason(change.Reason) {
		return false
	}
	if change.Action == ActionRename && change.Reason != "" && !ValidReason(change.Reason) {
		return false
	}
	switch change.Action {
	case ActionSuspend, ActionResume, ActionTransferWorkspace:
		return change.NewOwner == (publicid.ID{}) && change.Hostname == (node.Hostname{})
	case ActionTransferMember:
		return change.NewOwner.IsValid() && change.Hostname == (node.Hostname{})
	case ActionRename:
		return change.NewOwner == (publicid.ID{}) && change.Hostname.IsValid()
	default:
		return false
	}
}
