package enrollment

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

const credentialTokenBytes = 32

// ErrInvalidCredentialToken reports absent, malformed, or unavailable token entropy.
var ErrInvalidCredentialToken = errors.New("enrollment: invalid credential token")

// CredentialToken is a 256-bit bearer secret. Its default formatting and
// structured-log representation are always redacted; Reveal is the only API
// that returns its transport encoding.
type CredentialToken struct {
	secret [credentialTokenBytes]byte
}

// GenerateCredentialToken reads a new token from the operating-system CSPRNG.
func GenerateCredentialToken() (CredentialToken, error) {
	return generateCredentialToken(rand.Reader)
}

// NewCredentialToken validates raw token bytes received from a trusted
// boundary. The input is copied.
func NewCredentialToken(secret [credentialTokenBytes]byte) (CredentialToken, error) {
	if secret == ([credentialTokenBytes]byte{}) {
		return CredentialToken{}, ErrInvalidCredentialToken
	}
	return CredentialToken{secret: secret}, nil
}

// ParseCredentialToken accepts only the canonical unpadded base64url encoding.
func ParseCredentialToken(encoded string) (CredentialToken, error) {
	if len(encoded) != base64.RawURLEncoding.EncodedLen(credentialTokenBytes) {
		return CredentialToken{}, ErrInvalidCredentialToken
	}
	var secret [credentialTokenBytes]byte
	decoded, err := base64.RawURLEncoding.Decode(secret[:], []byte(encoded))
	if err != nil || decoded != credentialTokenBytes ||
		base64.RawURLEncoding.EncodeToString(secret[:]) != encoded {
		return CredentialToken{}, ErrInvalidCredentialToken
	}
	return NewCredentialToken(secret)
}

// Reveal returns the canonical transport encoding for one-time disclosure.
func (token CredentialToken) Reveal() string {
	return base64.RawURLEncoding.EncodeToString(token.secret[:])
}

// IsValid reports whether the token contains a non-zero 256-bit secret.
func (token CredentialToken) IsValid() bool {
	return token.secret != ([credentialTokenBytes]byte{})
}

// String prevents accidental plaintext disclosure through fmt and slog.
func (CredentialToken) String() string { return "[REDACTED]" }

// GoString prevents accidental plaintext disclosure through %#v formatting.
func (CredentialToken) GoString() string { return "enrollment.CredentialToken([REDACTED])" }

// LogValue prevents accidental plaintext disclosure in structured logs.
func (CredentialToken) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func (token CredentialToken) bytes() [credentialTokenBytes]byte { return token.secret }

func generateCredentialToken(entropy io.Reader) (CredentialToken, error) {
	if entropy == nil {
		return CredentialToken{}, ErrInvalidCredentialToken
	}
	var secret [credentialTokenBytes]byte
	if _, err := io.ReadFull(entropy, secret[:]); err != nil {
		return CredentialToken{}, fmt.Errorf("generate enrollment credential token: %w", err)
	}
	return NewCredentialToken(secret)
}
