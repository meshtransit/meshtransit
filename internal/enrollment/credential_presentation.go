package enrollment

import (
	"errors"
	"log/slog"
	"strings"
)

const credentialPresentationPrefix = "mtc1"

// ErrInvalidCredentialPresentation reports an absent or non-canonical
// enrollment credential presented by a client.
var ErrInvalidCredentialPresentation = errors.New("enrollment: invalid credential presentation")

// CredentialPresentation is the versioned bearer credential presented by a
// client. Its default formatting and structured-log representation are always
// redacted; Reveal is the only API that returns its transport encoding.
type CredentialPresentation struct {
	id    CredentialID
	token CredentialToken
}

// NewCredentialPresentation validates a credential ID and bearer token.
func NewCredentialPresentation(
	id CredentialID,
	token CredentialToken,
) (CredentialPresentation, error) {
	presentation := CredentialPresentation{id: id, token: token}
	if !presentation.IsValid() {
		return CredentialPresentation{}, ErrInvalidCredentialPresentation
	}
	return presentation, nil
}

// ParseCredentialPresentation accepts only the canonical versioned transport
// encoding.
func ParseCredentialPresentation(encoded string) (CredentialPresentation, error) {
	prefix, remainder, found := strings.Cut(encoded, ".")
	if !found || prefix != credentialPresentationPrefix {
		return CredentialPresentation{}, ErrInvalidCredentialPresentation
	}
	encodedID, encodedToken, found := strings.Cut(remainder, ".")
	if !found || strings.Contains(encodedToken, ".") {
		return CredentialPresentation{}, ErrInvalidCredentialPresentation
	}
	id, err := ParseCredentialID(encodedID)
	if err != nil {
		return CredentialPresentation{}, ErrInvalidCredentialPresentation
	}
	token, err := ParseCredentialToken(encodedToken)
	if err != nil {
		return CredentialPresentation{}, ErrInvalidCredentialPresentation
	}
	return NewCredentialPresentation(id, token)
}

// CredentialID returns the public ID carried by the presentation.
func (presentation CredentialPresentation) CredentialID() CredentialID {
	return presentation.id
}

// Token returns the bearer proof carried by the presentation.
func (presentation CredentialPresentation) Token() CredentialToken {
	return presentation.token
}

// Reveal returns the canonical transport encoding for one-time disclosure.
func (presentation CredentialPresentation) Reveal() string {
	return credentialPresentationPrefix + "." + presentation.id.String() + "." +
		presentation.token.Reveal()
}

// IsValid reports whether the presentation contains a valid credential ID and token.
func (presentation CredentialPresentation) IsValid() bool {
	return presentation.id.IsValid() && presentation.token.IsValid()
}

// String prevents accidental plaintext disclosure through fmt and slog.
func (CredentialPresentation) String() string { return "[REDACTED]" }

// GoString prevents accidental plaintext disclosure through %#v formatting.
func (CredentialPresentation) GoString() string {
	return "enrollment.CredentialPresentation([REDACTED])"
}

// LogValue prevents accidental plaintext disclosure in structured logs.
func (CredentialPresentation) LogValue() slog.Value {
	return slog.StringValue("[REDACTED]")
}
