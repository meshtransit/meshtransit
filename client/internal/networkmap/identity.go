package networkmap

import (
	"errors"
	"strings"
	"unicode"
)

// Ownership values of an Identity (mtcp-v1 §7.13).
const (
	OwnershipMember    = "member"
	OwnershipWorkspace = "workspace"
)

// maxIdentityNameRunes bounds the Workspace's and the account's display
// names as Core does.
const maxIdentityNameRunes = 128

var errInvalidIdentity = errors.New("account names are malformed")

// Identity is the names of the account the node's Device belongs to, from
// its own entry (mtcp-v1 §7.13, self.identity1): for display only, never
// for routing, names or access.
type Identity struct {
	// Network and Workspace are their display names.
	Network   string
	Workspace string
	// Ownership is OwnershipMember (a person's Device) or OwnershipWorkspace.
	Ownership string
	// Owner is the owner's account display name; empty unless a member's
	// Device, or when the account is gone.
	Owner string
	// Email is the owner's verified email (S4c §4); EmailKnown says the map
	// carried the field, so an empty Email means the account has none.
	// CheckIdentity does not check it: a bad one never costs the names.
	Email      string
	EmailKnown bool
}

// CheckIdentity reports whether an identity can be shown: nil is none.
func CheckIdentity(identity *Identity) error {
	if identity == nil {
		return nil
	}
	if !validName(identity.Network, maxNameRunes) || !validName(identity.Workspace, maxIdentityNameRunes) {
		return errInvalidIdentity
	}
	switch identity.Ownership {
	case OwnershipMember:
		if identity.Owner != "" && !validName(identity.Owner, maxIdentityNameRunes) {
			return errInvalidIdentity
		}
	case OwnershipWorkspace:
		if identity.Owner != "" {
			return errInvalidIdentity
		}
	default:
		return errInvalidIdentity
	}
	return nil
}

// maxEmailBytes bounds an email as Core does.
const maxEmailBytes = 254

// CheckEmail reports an email a Device may show, by Core's rule (S4c §3.1):
// 3-254 printable ASCII characters without '"', '<' or '>', with exactly
// one '@', text on both sides and a dot in the domain.
func CheckEmail(email string) bool {
	if len(email) < 3 || len(email) > maxEmailBytes {
		return false
	}
	for index := range len(email) {
		character := email[index]
		if character < 0x21 || character > 0x7e || character == '"' || character == '<' || character == '>' {
			return false
		}
	}
	local, domain, found := strings.Cut(email, "@")
	return found && local != "" && domain != "" && !strings.Contains(domain, "@") && strings.Contains(domain, ".")
}

// CheckDisplayName reports whether a name a person sees (an account's,
// a Device's) can be shown as is.
func CheckDisplayName(value string) bool { return validName(value, maxNameRunes) }

// validName is validateText that also refuses bidirectional controls,
// which could make a name read as another (Trojan Source).
func validName(value string, maxRunes int) bool {
	return validateText("name", value, maxRunes) == nil &&
		strings.IndexFunc(value, func(r rune) bool { return unicode.Is(unicode.Bidi_Control, r) }) < 0
}
