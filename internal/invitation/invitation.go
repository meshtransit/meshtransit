// Package invitation lets administrators invite people to a Workspace by
// email. An invitation carries a 256-bit bearer token that only the invitee's
// link holds: MeshCore stores a domain-separated digest, shows the link to the
// inviter once and emails it. Resending rotates the token. PostgreSQL
// authorizes every change and records it with audit evidence.
package invitation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

var (
	// ErrInvalid reports a malformed request.
	ErrInvalid = errors.New("invitation: invalid request")
	// ErrForbidden reports a change the session may not make, including a
	// role beyond the inviter's delegation ceiling.
	ErrForbidden = errors.New("invitation: forbidden")
	// ErrNotFound reports an unknown invitation.
	ErrNotFound = errors.New("invitation: not found")
	// ErrVersionConflict reports a stale expected version.
	ErrVersionConflict = errors.New("invitation: version conflict")
	// ErrAlreadyInvited reports a pending invitation for the same address.
	ErrAlreadyInvited = errors.New("invitation: address already invited")
	// ErrTooMany reports a Workspace at its pending-invitation limit.
	ErrTooMany = errors.New("invitation: too many pending invitations")
	// ErrNotPending reports an accepted, revoked or expired invitation.
	ErrNotPending = errors.New("invitation: not pending")
	// ErrTooSoon reports a resend within a minute of the last delivery.
	ErrTooSoon = errors.New("invitation: resent too soon")
	// ErrUnavailable reports a dependency failure.
	ErrUnavailable = errors.New("invitation: unavailable")
)

// Lifetime is how long a link stays valid after it is sent.
const Lifetime = 7 * 24 * time.Hour

// MaximumEmailBytes bounds an invited address.
const MaximumEmailBytes = 254

// tokenBytes is the bearer token entropy.
const tokenBytes = 32

// tokenDomain separates invitation digests from every other digest.
const tokenDomain = "meshtransit/workspace-invitation/v1\x00"

// Action is one change to an invitation.
type Action string

// Actions. Delivery outcomes are recorded by the service after it sends.
const (
	ActionCreate         Action = "create"
	ActionResend         Action = "resend"
	ActionRevoke         Action = "revoke"
	ActionDelivered      Action = "delivered"
	ActionDeliveryFailed Action = "delivery_failed"
	ActionNotConfigured  Action = "not_configured"
)

// Person names an account.
type Person struct {
	PrincipalID publicid.ID
	DisplayName string
}

// Invitation is one invitation as an administrator sees it.
type Invitation struct {
	ID            publicid.ID
	Email         string
	Role          string
	State         string
	ExpiresAt     time.Time
	InvitedBy     Person
	DeliveryState string
	LastSentAt    *time.Time
	SendCount     int
	CreatedAt     time.Time
	Version       int64
}

// Token is a bearer token; its String is the only plaintext copy.
type Token struct{ value string }

// NewToken draws a fresh token from the system CSPRNG.
func NewToken() (Token, error) {
	material := make([]byte, tokenBytes)
	if _, err := rand.Read(material); err != nil {
		return Token{}, ErrUnavailable
	}
	return Token{value: base64.RawURLEncoding.EncodeToString(material)}, nil
}

// ParseToken accepts exactly a token's canonical encoding.
func ParseToken(text string) (Token, bool) {
	material, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil || len(material) != tokenBytes || base64.RawURLEncoding.EncodeToString(material) != text {
		return Token{}, false
	}
	return Token{value: text}, true
}

// String returns the token for the link; never log it.
func (token Token) String() string { return token.value }

// IsValid reports a drawn or parsed token.
func (token Token) IsValid() bool { return token.value != "" }

// Digest is what PostgreSQL stores and matches.
func (token Token) Digest() [32]byte { return sha256.Sum256([]byte(tokenDomain + token.value)) }

// NormalizeEmail returns the lowercase bare address, or false.
func NormalizeEmail(text string) (string, bool) {
	trimmed := strings.TrimSpace(text)
	address, err := mail.ParseAddress(trimmed)
	if err != nil || address.Name != "" || address.Address != trimmed || len(trimmed) > MaximumEmailBytes ||
		strings.ContainsAny(trimmed, " \t\r\n\"\\") {
		return "", false
	}
	at := strings.LastIndexByte(trimmed, '@')
	if at < 1 || !strings.Contains(trimmed[at+1:], ".") {
		return "", false
	}
	return strings.ToLower(trimmed), true
}

// Change is one validated change for the store.
type Change struct {
	Session         accountsession.Session
	WorkspaceID     workspace.ID
	InvitationID    publicid.ID
	Action          Action
	Email           string
	Role            string
	TokenDigest     *[32]byte
	ExpiresAt       time.Time
	ExpectedVersion int64
	CorrelationID   publicid.ID
	EvaluatedAt     time.Time
}

// ChangeResult is an invitation after one change.
type ChangeResult struct {
	Before        *Invitation
	Invitation    Invitation
	WorkspaceName string
}

// IsValid reports a complete change for its action.
func (change Change) IsValid() bool {
	if !change.Session.IsValid() || !change.WorkspaceID.IsValid() || !change.InvitationID.IsValid() ||
		!change.CorrelationID.IsValid() || change.EvaluatedAt.IsZero() {
		return false
	}
	rotating := change.Action == ActionCreate || change.Action == ActionResend
	if rotating != (change.TokenDigest != nil && !change.ExpiresAt.IsZero()) {
		return false
	}
	switch change.Action {
	case ActionCreate:
		_, ok := NormalizeEmail(change.Email)
		return ok && change.ExpectedVersion == 0
	case ActionResend, ActionRevoke, ActionDelivered, ActionDeliveryFailed, ActionNotConfigured:
		return change.Email == "" && change.Role == "" && change.ExpectedVersion > 0
	default:
		return false
	}
}
