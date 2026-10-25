package enrollment

import (
	"log/slog"
	"strings"
)

const joinKeyPresentationPrefix = "mtk1"

// JoinKeyPresentation is a Kubernetes cluster join key as a replica presents
// it: mtk1.<id>.<secret>. Its prefix differs from an enrollment key's, so
// neither parser accepts the other (K1a1 plan §0.3). Like
// CredentialPresentation it is redacted everywhere except Reveal.
type JoinKeyPresentation struct {
	id    CredentialID
	token CredentialToken
}

// NewJoinKeyPresentation validates a credential ID and bearer token.
func NewJoinKeyPresentation(id CredentialID, token CredentialToken) (JoinKeyPresentation, error) {
	presentation := JoinKeyPresentation{id: id, token: token}
	if !presentation.IsValid() {
		return JoinKeyPresentation{}, ErrInvalidCredentialPresentation
	}
	return presentation, nil
}

// ParseJoinKeyPresentation accepts only the canonical mtk1 encoding.
func ParseJoinKeyPresentation(encoded string) (JoinKeyPresentation, error) {
	prefix, remainder, found := strings.Cut(encoded, ".")
	if !found || prefix != joinKeyPresentationPrefix {
		return JoinKeyPresentation{}, ErrInvalidCredentialPresentation
	}
	encodedID, encodedToken, found := strings.Cut(remainder, ".")
	if !found || strings.Contains(encodedToken, ".") {
		return JoinKeyPresentation{}, ErrInvalidCredentialPresentation
	}
	id, err := ParseCredentialID(encodedID)
	if err != nil {
		return JoinKeyPresentation{}, ErrInvalidCredentialPresentation
	}
	token, err := ParseCredentialToken(encodedToken)
	if err != nil {
		return JoinKeyPresentation{}, ErrInvalidCredentialPresentation
	}
	return NewJoinKeyPresentation(id, token)
}

// CredentialID returns the key's public ID.
func (presentation JoinKeyPresentation) CredentialID() CredentialID { return presentation.id }

// Token returns the key's secret.
func (presentation JoinKeyPresentation) Token() CredentialToken { return presentation.token }

// Reveal returns the canonical encoding for one-time disclosure.
func (presentation JoinKeyPresentation) Reveal() string {
	return joinKeyPresentationPrefix + "." + presentation.id.String() + "." + presentation.token.Reveal()
}

// IsValid reports whether the presentation holds a valid ID and secret.
func (presentation JoinKeyPresentation) IsValid() bool {
	return presentation.id.IsValid() && presentation.token.IsValid()
}

// String prevents accidental plaintext disclosure through fmt and slog.
func (JoinKeyPresentation) String() string { return "[REDACTED]" }

// GoString prevents accidental plaintext disclosure through %#v formatting.
func (JoinKeyPresentation) GoString() string { return "enrollment.JoinKeyPresentation([REDACTED])" }

// LogValue prevents accidental plaintext disclosure in structured logs.
func (JoinKeyPresentation) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
