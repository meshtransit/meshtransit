// Package enrollmentkey issues, lists and revokes enrollment keys: bearer
// secrets that each enroll exactly one Device into one Network without a
// browser, for servers, routers and automation.
//
// The person who creates a key chooses two lifetimes separately: how long
// the key itself can be used (24 hours by default) and how long the Device
// it enrolls lives, which may be never. The Device belongs to the key's
// creator. A key's expiry or revocation never affects the Device it
// enrolled. Core stores only a keyed digest of the secret, which the caller
// sees once, when the key is created. PostgreSQL authorizes every call on
// the database clock and records each creation and revocation.
package enrollmentkey

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

var (
	// ErrInvalid reports a malformed request.
	ErrInvalid = errors.New("enrollment key: invalid request")
	// ErrForbidden reports a session without the permission in the Network.
	ErrForbidden = errors.New("enrollment key: forbidden")
	// ErrNotFound reports a key unknown in the Network.
	ErrNotFound = errors.New("enrollment key: not found")
	// ErrNotActive reports a key that is already spent, expired or revoked.
	ErrNotActive = errors.New("enrollment key: not active")
	// ErrUsed reports a key that already enrolled its Device: the Device is
	// managed from then on, not the key.
	ErrUsed = errors.New("enrollment key: used")
	// ErrLimitReached reports a Network with MaximumActiveKeys usable keys.
	ErrLimitReached = errors.New("enrollment key: too many usable keys")
	// ErrUnavailable reports a dependency failure.
	ErrUnavailable = errors.New("enrollment key: unavailable")
)

const (
	// DefaultKeyLifetime is how long a key can be used when the request
	// does not say.
	DefaultKeyLifetime = 24 * time.Hour
	// MinimumKeyLifetime is the shortest validity a key may have.
	MinimumKeyLifetime = 5 * time.Minute
	// MaximumKeyLifetime is the longest validity a key may have.
	MaximumKeyLifetime = 30 * 24 * time.Hour
	// MaximumDescriptionLength bounds a key's description, in characters.
	MaximumDescriptionLength = 128
	// MaximumActiveKeys bounds the usable keys of one Network.
	MaximumActiveKeys = 100
	// MaximumListedKeys bounds one listing.
	MaximumListedKeys = 200
)

// State is a key's lifecycle as seen now.
type State string

// States.
const (
	StateActive  State = "active"
	StateUsed    State = "used"
	StateExpired State = "expired"
	StateRevoked State = "revoked"
)

func (state State) isValid() bool {
	switch state {
	case StateActive, StateUsed, StateExpired, StateRevoked:
		return true
	default:
		return false
	}
}

// Key is one enrollment key, without its secret.
type Key struct {
	id             enrollment.CredentialID
	description    string
	issuedBy       identity.PrincipalID
	createdAt      time.Time
	expiresAt      time.Time
	revokedAt      time.Time
	state          State
	deviceLifetime enrollment.DeviceLifetime
	deviceID       node.ID
	deviceName     string
}

// KeyParams rehydrates a Key from storage.
type KeyParams struct {
	ID             enrollment.CredentialID
	Description    string
	IssuedBy       identity.PrincipalID
	CreatedAt      time.Time
	ExpiresAt      time.Time
	RevokedAt      time.Time
	State          State
	DeviceLifetime enrollment.DeviceLifetime
	// DeviceID and DeviceName name the Device the key enrolled, if any.
	DeviceID   node.ID
	DeviceName string
}

// NewKey validates stored key state.
func NewKey(params KeyParams) (Key, error) {
	key := Key{
		id: params.ID, description: params.Description, issuedBy: params.IssuedBy,
		createdAt: params.CreatedAt.UTC(), expiresAt: params.ExpiresAt.UTC(), revokedAt: params.RevokedAt.UTC(),
		state: params.State, deviceLifetime: params.DeviceLifetime, deviceID: params.DeviceID,
		deviceName: params.DeviceName,
	}
	if params.RevokedAt.IsZero() {
		key.revokedAt = time.Time{}
	}
	if !key.id.IsValid() || !key.issuedBy.IsValid() || params.CreatedAt.IsZero() ||
		!key.expiresAt.After(key.createdAt) || !key.state.isValid() || !validDescription(key.description) ||
		key.deviceLifetime.Kind() == enrollment.DeviceLifetimeProfile ||
		(key.state == StateRevoked) != !key.revokedAt.IsZero() || !key.deviceMatchesState() {
		return Key{}, ErrInvalid
	}
	return key, nil
}

// deviceMatchesState: a used key names its Device, an active or expired one
// none; a revoked key may have been used before.
func (key Key) deviceMatchesState() bool {
	enrolled := key.deviceID.IsValid()
	switch key.state {
	case StateUsed:
		return enrolled
	case StateActive, StateExpired:
		return !enrolled && key.deviceName == ""
	default:
		return enrolled || key.deviceName == ""
	}
}

// ID returns the key's public ID.
func (key Key) ID() enrollment.CredentialID { return key.id }

// Description returns what the key is for, possibly empty.
func (key Key) Description() string { return key.description }

// IssuedBy returns the member who created the key and owns its Device.
func (key Key) IssuedBy() identity.PrincipalID { return key.issuedBy }

// CreatedAt returns when the key was created.
func (key Key) CreatedAt() time.Time { return key.createdAt }

// ExpiresAt returns when the key stops being usable.
func (key Key) ExpiresAt() time.Time { return key.expiresAt }

// RevokedAt returns when the key was revoked, or the zero time.
func (key Key) RevokedAt() time.Time { return key.revokedAt }

// State returns the key's lifecycle state.
func (key Key) State() State { return key.state }

// DeviceLifetime returns how long the Device it enrolls lives.
func (key Key) DeviceLifetime() enrollment.DeviceLifetime { return key.deviceLifetime }

// Device returns the Device the key enrolled and its name.
func (key Key) Device() (node.ID, string, bool) {
	return key.deviceID, key.deviceName, key.deviceID.IsValid()
}

// Issued is a new key and its one-time presentation.
type Issued struct {
	key          Key
	presentation enrollment.CredentialPresentation
}

// NewIssued pairs a stored key with the presentation of its secret.
func NewIssued(key Key, presentation enrollment.CredentialPresentation) (Issued, error) {
	if !presentation.IsValid() || presentation.CredentialID() != key.ID() || key.State() != StateActive {
		return Issued{}, ErrInvalid
	}
	return Issued{key: key, presentation: presentation}, nil
}

// Key returns the stored key.
func (issued Issued) Key() Key { return issued.key }

// Presentation returns the secret to hand to the Device, once.
func (issued Issued) Presentation() enrollment.CredentialPresentation { return issued.presentation }

// IssueRequest asks for one key.
type IssueRequest struct {
	Scope       network.Scope
	Description string
	// KeyLifetime is how long the key can be used; zero means
	// DefaultKeyLifetime.
	KeyLifetime time.Duration
	// DeviceLifetime must be fixed or never; it cannot defer to a profile.
	DeviceLifetime enrollment.DeviceLifetime
	CorrelationID  publicid.ID
}

// Issue is a validated IssueRequest with its session and secret.
type Issue struct {
	Session        accountsession.Session
	Scope          network.Scope
	Description    string
	KeyLifetime    time.Duration
	DeviceLifetime enrollment.DeviceLifetime
	CredentialID   enrollment.CredentialID
	Token          enrollment.CredentialToken
	CorrelationID  publicid.ID
}

// IsValid reports whether every field is within bounds.
func (issue Issue) IsValid() bool {
	kind := issue.DeviceLifetime.Kind()
	return issue.Scope.IsValid() && validDescription(issue.Description) &&
		issue.KeyLifetime >= MinimumKeyLifetime && issue.KeyLifetime <= MaximumKeyLifetime &&
		issue.KeyLifetime%time.Second == 0 &&
		(kind == enrollment.DeviceLifetimeFixed || kind == enrollment.DeviceLifetimeNever) &&
		issue.CredentialID.IsValid() && issue.Token.IsValid() && issue.CorrelationID.IsValid()
}

// Revocation asks to revoke one key.
type Revocation struct {
	Session       accountsession.Session
	Scope         network.Scope
	KeyID         enrollment.CredentialID
	CorrelationID publicid.ID
}

// IsValid reports whether every field is set.
func (revocation Revocation) IsValid() bool {
	return revocation.Scope.IsValid() && revocation.KeyID.IsValid() && revocation.CorrelationID.IsValid()
}

func validDescription(description string) bool {
	return utf8.ValidString(description) && utf8.RuneCountInString(description) <= MaximumDescriptionLength &&
		description == strings.TrimSpace(description) &&
		!strings.ContainsFunc(description, func(character rune) bool { return character < 0x20 || character == 0x7f })
}
