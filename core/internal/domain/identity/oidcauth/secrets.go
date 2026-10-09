package oidcauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

const transactionSecretBytes = 32

var (
	// ErrGenerateSecrets reports unavailable or incomplete CSPRNG output.
	ErrGenerateSecrets = errors.New("oidc auth: generate transaction secrets")
	// ErrInvalidState reports malformed OIDC state material.
	ErrInvalidState = errors.New("oidc auth: invalid state")
	// ErrInvalidNonce reports malformed OIDC nonce material.
	ErrInvalidNonce = errors.New("oidc auth: invalid nonce")
	// ErrInvalidVerifier reports malformed PKCE verifier material.
	ErrInvalidVerifier = errors.New("oidc auth: invalid pkce verifier")
)

// State contains exactly 256 bits of OIDC CSRF and callback replay material.
type State struct{ value [transactionSecretBytes]byte }

// ParseState accepts only the canonical 256-bit base64url representation.
func ParseState(value string) (State, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != transactionSecretBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return State{}, ErrInvalidState
	}
	var raw [transactionSecretBytes]byte
	copy(raw[:], decoded)
	clear(decoded)
	if raw == ([transactionSecretBytes]byte{}) {
		return State{}, ErrInvalidState
	}
	return State{value: raw}, nil
}

// Encoded returns the raw browser-bound value. Callers must never log it.
func (state State) Encoded() string {
	return base64.RawURLEncoding.EncodeToString(state.value[:])
}

// IsValid reports whether state contains non-zero canonical entropy.
func (state State) IsValid() bool { return state.value != ([transactionSecretBytes]byte{}) }

// String prevents accidental state disclosure.
func (State) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed state disclosure.
func (State) GoString() string { return "oidcauth.State([REDACTED])" }

// LogValue prevents accidental structured-log state disclosure.
func (State) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Nonce contains exactly 256 bits binding the ID token to one transaction.
type Nonce struct{ value [transactionSecretBytes]byte }

// ParseNonce accepts only the canonical 256-bit base64url representation.
func ParseNonce(value string) (Nonce, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != transactionSecretBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return Nonce{}, ErrInvalidNonce
	}
	var raw [transactionSecretBytes]byte
	copy(raw[:], decoded)
	clear(decoded)
	if raw == ([transactionSecretBytes]byte{}) {
		return Nonce{}, ErrInvalidNonce
	}
	return Nonce{value: raw}, nil
}

// Encoded returns the raw authorization-request value. Callers must never log it.
func (nonce Nonce) Encoded() string {
	return base64.RawURLEncoding.EncodeToString(nonce.value[:])
}

// IsValid reports whether nonce contains non-zero canonical entropy.
func (nonce Nonce) IsValid() bool { return nonce.value != ([transactionSecretBytes]byte{}) }

// String prevents accidental nonce disclosure.
func (Nonce) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed nonce disclosure.
func (Nonce) GoString() string { return "oidcauth.Nonce([REDACTED])" }

// LogValue prevents accidental structured-log nonce disclosure.
func (Nonce) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Verifier is the canonical RFC 7636 PKCE verifier for one transaction.
type Verifier struct{ value [transactionSecretBytes]byte }

// ParseVerifier accepts only the canonical 256-bit base64url representation.
func ParseVerifier(value string) (Verifier, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != transactionSecretBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return Verifier{}, ErrInvalidVerifier
	}
	var raw [transactionSecretBytes]byte
	copy(raw[:], decoded)
	clear(decoded)
	if raw == ([transactionSecretBytes]byte{}) {
		return Verifier{}, ErrInvalidVerifier
	}
	return Verifier{value: raw}, nil
}

// Encoded returns the token-endpoint proof. Callers must never log it.
func (verifier Verifier) Encoded() string {
	return base64.RawURLEncoding.EncodeToString(verifier.value[:])
}

// Challenge returns the RFC 7636 S256 authorization-request challenge.
func (verifier Verifier) Challenge() string {
	digest := sha256.Sum256([]byte(verifier.Encoded()))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// IsValid reports whether the verifier contains non-zero canonical entropy.
func (verifier Verifier) IsValid() bool {
	return verifier.value != ([transactionSecretBytes]byte{})
}

// String prevents accidental verifier disclosure.
func (Verifier) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed verifier disclosure.
func (Verifier) GoString() string { return "oidcauth.Verifier([REDACTED])" }

// LogValue prevents accidental structured-log verifier disclosure.
func (Verifier) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Secrets contains independent state, nonce, PKCE verifier, and pre-auth cookie values.
type Secrets struct {
	state         State
	nonce         Nonce
	verifier      Verifier
	preAuthCookie PreAuthCookie
}

// GenerateSecrets reads 1024 bits from the operating-system CSPRNG.
func GenerateSecrets() (Secrets, error) { return generateSecrets(rand.Reader) }

func generateSecrets(entropy io.Reader) (Secrets, error) {
	if entropy == nil {
		return Secrets{}, ErrGenerateSecrets
	}
	var material [transactionSecretBytes * 4]byte
	if _, err := io.ReadFull(entropy, material[:]); err != nil {
		clear(material[:])
		return Secrets{}, fmt.Errorf("%w: %w", ErrGenerateSecrets, err)
	}
	var stateValue, nonceValue, verifierValue, cookieValue [transactionSecretBytes]byte
	copy(stateValue[:], material[:transactionSecretBytes])
	copy(nonceValue[:], material[transactionSecretBytes:transactionSecretBytes*2])
	copy(verifierValue[:], material[transactionSecretBytes*2:transactionSecretBytes*3])
	copy(cookieValue[:], material[transactionSecretBytes*3:])
	clear(material[:])
	secrets := Secrets{
		state:         State{value: stateValue},
		nonce:         Nonce{value: nonceValue},
		verifier:      Verifier{value: verifierValue},
		preAuthCookie: PreAuthCookie{value: cookieValue},
	}
	if !secrets.IsValid() {
		return Secrets{}, ErrGenerateSecrets
	}
	return secrets, nil
}

// State returns a copy of the browser-bound state value.
func (secrets Secrets) State() State { return secrets.state }

// Nonce returns a copy of the ID-token nonce value.
func (secrets Secrets) Nonce() Nonce { return secrets.nonce }

// Verifier returns a copy of the PKCE verifier.
func (secrets Secrets) Verifier() Verifier { return secrets.verifier }

// PreAuthCookie returns the independent browser-binding handle, never URL material.
func (secrets Secrets) PreAuthCookie() PreAuthCookie { return secrets.preAuthCookie }

// IsValid reports whether every secret is present and purpose-distinct.
func (secrets Secrets) IsValid() bool {
	if !secrets.state.IsValid() || !secrets.nonce.IsValid() ||
		!secrets.verifier.IsValid() || !secrets.preAuthCookie.IsValid() {
		return false
	}
	// Evaluate all six purpose pairs without short-circuiting secret equality.
	repeated := subtle.ConstantTimeCompare(secrets.state.value[:], secrets.nonce.value[:])
	repeated |= subtle.ConstantTimeCompare(secrets.state.value[:], secrets.verifier.value[:])
	repeated |= subtle.ConstantTimeCompare(secrets.nonce.value[:], secrets.verifier.value[:])
	repeated |= subtle.ConstantTimeCompare(secrets.preAuthCookie.value[:], secrets.state.value[:])
	repeated |= subtle.ConstantTimeCompare(secrets.preAuthCookie.value[:], secrets.nonce.value[:])
	repeated |= subtle.ConstantTimeCompare(secrets.preAuthCookie.value[:], secrets.verifier.value[:])
	return repeated == 0
}

// String prevents accidental transaction-secret disclosure.
func (Secrets) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed transaction-secret disclosure.
func (Secrets) GoString() string { return "oidcauth.Secrets([REDACTED])" }

// LogValue prevents accidental structured-log transaction-secret disclosure.
func (Secrets) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
