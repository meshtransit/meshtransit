package mapsession

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/displayemail"
)

// Ownership is whose a Device is, as its own map tells it (MTCP
// self.identity1, docs/device-logout-s4b-accounts-ux.md §3).
type Ownership uint8

const (
	// OwnershipMember is a person's Device.
	OwnershipMember Ownership = iota + 1
	// OwnershipWorkspace is a Device the Workspace owns (tags, servers,
	// gateways): it has no person's name.
	OwnershipWorkspace
)

// maxIdentityNameRunes bounds the Workspace's and the account's display
// names as the schema does (128 characters each).
const maxIdentityNameRunes = 128

// ErrInvalidSelfIdentity reports names a Device's own map cannot carry.
var ErrInvalidSelfIdentity = errors.New("mapsession: invalid self identity")

// SelfIdentity is what the apps show for the account a Device belongs to:
// its Workspace's name, whose it is and, for a member's Device, the owner's
// account display name. It is presentation only, and goes only into the
// Device's own map, never a peer's. The zero value carries none.
type SelfIdentity struct {
	workspaceName string
	ownership     Ownership
	ownerName     string
	known         bool
	// ownerEmail is the owner's verified email (schema 288, S4c); emailRead
	// says the store read it, so an empty email means the account has none.
	ownerEmail string
	emailRead  bool
}

// NewSelfIdentity validates the names a store read. A member's Device
// without an account name (the account is gone) carries an empty owner; a
// Workspace's Device never carries one.
func NewSelfIdentity(workspaceName string, ownership Ownership, ownerName string) (SelfIdentity, error) {
	if ownership != OwnershipMember && ownership != OwnershipWorkspace {
		return SelfIdentity{}, ErrInvalidSelfIdentity
	}
	if ownership == OwnershipWorkspace {
		ownerName = ""
	}
	if !validIdentityName(workspaceName, false) || !validIdentityName(ownerName, true) {
		return SelfIdentity{}, ErrInvalidSelfIdentity
	}
	return SelfIdentity{workspaceName: workspaceName, ownership: ownership, ownerName: ownerName, known: true}, nil
}

// ParseOwnership reads the schema's device.ownership.
func ParseOwnership(value string) (Ownership, error) {
	switch value {
	case "member":
		return OwnershipMember, nil
	case "workspace":
		return OwnershipWorkspace, nil
	default:
		return 0, ErrInvalidSelfIdentity
	}
}

// ValidWorkspaceName reports whether a Workspace display name can be carried
// on a map: the schema takes names a map cannot (padding other than spaces,
// tabs), which a shared view then leaves out rather than compare forever.
func ValidWorkspaceName(name string) bool { return validIdentityName(name, false) }

func validIdentityName(value string, mayBeEmpty bool) bool {
	if value == "" {
		return mayBeEmpty
	}
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxIdentityNameRunes ||
		strings.TrimSpace(value) != value {
		return false
	}
	return strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) }) < 0
}

// Known reports whether the identity was read: a store that cannot read it,
// or a session that did not negotiate self.identity1, carries none.
func (identity SelfIdentity) Known() bool { return identity.known }

// WorkspaceName returns the Workspace's display name.
func (identity SelfIdentity) WorkspaceName() string { return identity.workspaceName }

// Ownership returns whose the Device is.
func (identity SelfIdentity) Ownership() Ownership { return identity.ownership }

// OwnerName returns the owner's account display name; empty for a
// Workspace's Device or an account that is gone.
func (identity SelfIdentity) OwnerName() string { return identity.ownerName }

// WithWorkspaceName returns the identity with a newer Workspace name, as a
// shared Network view reads it. An identity the session does not carry
// stays absent, and an invalid name keeps the one it has.
func (identity SelfIdentity) WithWorkspaceName(name string) SelfIdentity {
	if !identity.known || !validIdentityName(name, false) {
		return identity
	}
	identity.workspaceName = name
	return identity
}

// WithOwnerEmail returns the identity with the owner's email as schema 288
// reads it. An email Devices may not show, or one on a Workspace's Device,
// reads as none: it never costs the names. An identity the session does not
// carry stays absent.
func (identity SelfIdentity) WithOwnerEmail(email string) SelfIdentity {
	if !identity.known {
		return identity
	}
	identity.emailRead = true
	identity.ownerEmail = ""
	if identity.ownership == OwnershipMember && displayemail.Valid(email) {
		identity.ownerEmail = email
	}
	return identity
}

// OwnerEmail returns the owner's verified email and whether it was read;
// read with an empty email means the account has none.
func (identity SelfIdentity) OwnerEmail() (string, bool) {
	return identity.ownerEmail, identity.emailRead
}

// Equal reports whether two identities carry the same names. SelfIdentity
// holds only comparable values; keep it so, or compare field by field.
func (identity SelfIdentity) Equal(other SelfIdentity) bool { return identity == other }

// withSelfIdentityCapability keeps the identity only for a session that
// negotiated self.identity1, which the protocol adapter never records for
// a Kubernetes gateway: no person's name reaches a cluster.
func (snapshot Snapshot) withSelfIdentityCapability(request Request) Snapshot {
	if !request.SelfIdentity() {
		snapshot.selfIdentity = SelfIdentity{}
	}
	return snapshot
}

// SelfIdentity returns the names the Device's own map carries for its
// account; the zero value when the session carries none.
func (snapshot Snapshot) SelfIdentity() SelfIdentity { return snapshot.selfIdentity }
