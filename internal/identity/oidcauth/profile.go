package oidcauth

import (
	"log/slog"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maximumProfileNameRunes  = 128
	maximumProfileEmailBytes = 254
)

// Profile is optional display data from the provider: a name and an email the
// provider marked verified. It names a new Account and its first Workspace;
// it never identifies, links or authorizes anyone.
type Profile struct {
	name, email string
}

// NewProfile keeps each value only when it is bounded, single-line text; an
// email must also have exactly one "@" with text on both sides.
func NewProfile(name, verifiedEmail string) Profile {
	var profile Profile
	if trimmed := strings.TrimSpace(name); validProfileText(trimmed) &&
		utf8.RuneCountInString(trimmed) <= maximumProfileNameRunes {
		profile.name = trimmed
	}
	if validProfileEmail(verifiedEmail) {
		profile.email = verifiedEmail
	}
	return profile
}

// Name returns the provider display name, or "".
func (profile Profile) Name() string { return profile.name }

// Email returns the provider-verified email, or "".
func (profile Profile) Email() string { return profile.email }

// DisplayName is the name, else the verified email, else fallback.
func (profile Profile) DisplayName(fallback string) string {
	switch {
	case profile.name != "":
		return profile.name
	case profile.email != "":
		return profile.email
	default:
		return fallback
	}
}

// String redacts personal data.
func (Profile) String() string { return "[REDACTED]" }

// LogValue redacts personal data.
func (Profile) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Profile returns the optional provider display data.
func (identity ExternalIdentity) Profile() Profile { return identity.profile }

func validProfileText(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' {
			return false
		}
	}
	return true
}

func validProfileEmail(value string) bool {
	if len(value) > maximumProfileEmailBytes || !validProfileText(value) || strings.ContainsAny(value, " <>\"") {
		return false
	}
	local, domain, found := strings.Cut(value, "@")
	return found && local != "" && domain != "" && !strings.Contains(domain, "@") && strings.Contains(domain, ".")
}
