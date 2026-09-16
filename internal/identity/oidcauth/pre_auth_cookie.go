package oidcauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
)

const preAuthCookieDigestDomain = "meshtransit/oidc-auth/pre-auth-cookie/v1\x00"

var (
	// ErrInvalidPreAuthCookie reports malformed browser-binding material without echoing it.
	ErrInvalidPreAuthCookie = errors.New("oidc auth: invalid pre-auth cookie")
	// ErrInvalidCookieDigest reports malformed durable browser-binding evidence.
	ErrInvalidCookieDigest = errors.New("oidc auth: invalid cookie digest")
)

// PreAuthCookie is an independent 256-bit opaque browser handle, not a session.
type PreAuthCookie struct{ value [transactionSecretBytes]byte }

// ParsePreAuthCookie rejects unbounded input before allocating decoded material.
func ParsePreAuthCookie(value string) (PreAuthCookie, error) {
	if len(value) != 43 {
		return PreAuthCookie{}, ErrInvalidPreAuthCookie
	}
	var material [transactionSecretBytes]byte
	written, err := base64.RawURLEncoding.Strict().Decode(material[:], []byte(value))
	if err != nil || written != transactionSecretBytes ||
		base64.RawURLEncoding.EncodeToString(material[:]) != value {
		clear(material[:])
		return PreAuthCookie{}, ErrInvalidPreAuthCookie
	}
	cookie := PreAuthCookie{value: material}
	clear(material[:])
	if !cookie.IsValid() {
		return PreAuthCookie{}, ErrInvalidPreAuthCookie
	}
	return cookie, nil
}

// Encoded explicitly releases browser material. Callers must never log it.
func (cookie PreAuthCookie) Encoded() string {
	return base64.RawURLEncoding.EncodeToString(cookie.value[:])
}

// IsValid reports whether the cookie contains non-zero entropy.
func (cookie PreAuthCookie) IsValid() bool {
	return cookie.value != ([transactionSecretBytes]byte{})
}

// String prevents accidental cookie disclosure.
func (PreAuthCookie) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed cookie disclosure.
func (PreAuthCookie) GoString() string { return "oidcauth.PreAuthCookie([REDACTED])" }

// LogValue prevents accidental structured-log cookie disclosure.
func (PreAuthCookie) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// CookieDigest distinguishes browser binding from state or nonce lookup evidence.
type CookieDigest struct{ digest Digest }

// NewCookieDigest validates the versioned evidence recovered from a browser proof.
func NewCookieDigest(algorithm string, keyID DigestKeyID, value [sha256.Size]byte) (CookieDigest, error) {
	if algorithm != DigestAlgorithmHMACSHA256V1 {
		return CookieDigest{}, ErrInvalidCookieDigest
	}
	digest, err := NewDigest(keyID, value)
	if err != nil {
		return CookieDigest{}, ErrInvalidCookieDigest
	}
	return CookieDigest{digest: digest}, nil
}

// Algorithm returns the fixed HMAC algorithm authenticated by the payload version.
func (CookieDigest) Algorithm() string { return DigestAlgorithmHMACSHA256V1 }

// KeyID returns the exact key generation needed for callback verification.
func (digest CookieDigest) KeyID() DigestKeyID { return digest.digest.KeyID() }

// Bytes returns a defensive copy for encrypted proof preparation.
func (digest CookieDigest) Bytes() [sha256.Size]byte { return digest.digest.Bytes() }

// IsValid reports whether digest evidence is canonical and non-zero.
func (digest CookieDigest) IsValid() bool { return digest.digest.IsValid() }

// String prevents accidental cookie-digest disclosure.
func (CookieDigest) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed cookie-digest disclosure.
func (CookieDigest) GoString() string { return "oidcauth.CookieDigest([REDACTED])" }

// LogValue prevents accidental structured-log cookie-digest disclosure.
func (CookieDigest) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// PreAuthCookie binds an independent handle to every exact authority dimension.
func (key DigestKey) PreAuthCookie(binding Binding, cookie PreAuthCookie) (CookieDigest, error) {
	if !key.isValid() || !binding.IsValid() || !cookie.IsValid() {
		return CookieDigest{}, ErrInvalidCookieDigest
	}
	mac := hmac.New(sha256.New, key.material[:])
	// hash.Hash writes cannot fail. The existing bounded binding encoding is
	// wrapped in an independent keyed purpose, never a state/nonce digest.
	_, _ = mac.Write([]byte(preAuthCookieDigestDomain))
	_, _ = mac.Write(verifierBindingBytes(binding))
	_, _ = mac.Write(cookie.value[:])
	var value [sha256.Size]byte
	copy(value[:], mac.Sum(nil))
	return NewCookieDigest(DigestAlgorithmHMACSHA256V1, key.ID(), value)
}

// VerifyPreAuthCookie requires exact key identity and constant-time digest equality.
// A retired/unavailable generation fails closed; callers never try a fallback key.
func (key DigestKey) VerifyPreAuthCookie(binding Binding, cookie PreAuthCookie, expected CookieDigest) bool {
	if !expected.IsValid() || expected.KeyID() != key.ID() {
		return false
	}
	actual, err := key.PreAuthCookie(binding, cookie)
	if err != nil {
		return false
	}
	actualBytes, expectedBytes := actual.Bytes(), expected.Bytes()
	return hmac.Equal(actualBytes[:], expectedBytes[:])
}
