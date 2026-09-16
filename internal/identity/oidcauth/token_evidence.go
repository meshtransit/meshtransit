package oidcauth

import (
	"log/slog"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"
)

// TokenEvidenceParams is trusted adapter output after signature/route validation.
// It has no provider bearer token, profile/email, group, role, or admission fields.
type TokenEvidenceParams struct {
	Issuer, Subject, SessionID, ACR string
	Nonce                           Nonce
	IssuedAt, ExpiresAt, AuthTime   time.Time
	AMR                             []string
}

// String redacts trusted adapter parameters, including raw subject and sid.
func (TokenEvidenceParams) String() string { return "[REDACTED]" }

// GoString redacts detailed trusted adapter parameter formatting.
func (TokenEvidenceParams) GoString() string { return "oidcauth.TokenEvidenceParams([REDACTED])" }

// LogValue redacts structured trusted adapter parameter formatting.
func (TokenEvidenceParams) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// ExternalIdentity preserves the exact case-sensitive issuer/subject namespace.
// Assurance and sid remain authentication evidence, never RBAC or membership.
type ExternalIdentity struct {
	issuer, subject, sessionID, acr string
	issuedAt, expiresAt, authTime   time.Time
	amr                             []string
}

// Issuer returns the exact validated configured issuer, without runtime normalization.
func (identity ExternalIdentity) Issuer() string { return identity.issuer }

// Subject returns the exact opaque subject; never use email as a substitute.
func (identity ExternalIdentity) Subject() string { return identity.subject }

// SessionID explicitly releases optional provider logout evidence, never a Core handle.
func (identity ExternalIdentity) SessionID() string { return identity.sessionID }

// ACR returns bounded provider assurance without granting a permission.
func (identity ExternalIdentity) ACR() string { return identity.acr }

// AMR returns a defensive copy of optional assurance method evidence.
func (identity ExternalIdentity) AMR() []string { return slices.Clone(identity.amr) }

// IssuedAt returns the validated whole-second token issue time.
func (identity ExternalIdentity) IssuedAt() time.Time { return identity.issuedAt }

// ExpiresAt returns the validated provider deadline, not a Core session lifetime.
func (identity ExternalIdentity) ExpiresAt() time.Time { return identity.expiresAt }

// AuthTime returns optional validated authentication time; zero means absent.
func (identity ExternalIdentity) AuthTime() time.Time { return identity.authTime }

// IsValid checks bounded evidence shape, not cryptographic validity or authority.
func (identity ExternalIdentity) IsValid() bool {
	validTimes := !identity.issuedAt.IsZero() && identity.issuedAt.Nanosecond() == 0 && identity.expiresAt.Nanosecond() == 0 && identity.expiresAt.After(identity.issuedAt) && identity.expiresAt.Sub(identity.issuedAt) <= 24*time.Hour
	validOptional := (identity.sessionID == "" || validOpaqueIdentity(identity.sessionID, 255)) && (identity.acr == "" || validBoundedToken(identity.acr, 128)) && len(identity.amr) <= 16
	if !validTimes || !validOptional || !validHTTPSURL(identity.issuer, true) || !validOpaqueIdentity(identity.subject, 255) {
		return false
	}
	if !identity.authTime.IsZero() && (identity.authTime.Nanosecond() != 0 || identity.authTime.After(identity.issuedAt)) {
		return false
	}
	seen := make(map[string]struct{}, len(identity.amr))
	for _, method := range identity.amr {
		if !validBoundedToken(method, 64) {
			return false
		}
		if _, exists := seen[method]; exists {
			return false
		}
		seen[method] = struct{}{}
	}
	return true
}

// String redacts sensitive external identity.
func (ExternalIdentity) String() string { return "[REDACTED]" }

// GoString redacts detailed external identity.
func (ExternalIdentity) GoString() string { return "oidcauth.ExternalIdentity([REDACTED])" }

// LogValue redacts structured external identity.
func (ExternalIdentity) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// TokenEvidence carries validated identity plus nonce only inside the trusted port.
// Shape constructors are not a signature verifier; only the provider adapter may
// create positive evidence after its complete cryptographic validation contract.
type TokenEvidence struct {
	identity ExternalIdentity
	nonce    Nonce
}

// NewTokenEvidence validates/copies adapter output; it never accepts an IdP role.
func NewTokenEvidence(params TokenEvidenceParams) (TokenEvidence, error) {
	evidence := TokenEvidence{identity: ExternalIdentity{issuer: params.Issuer, subject: params.Subject, sessionID: params.SessionID, acr: params.ACR, issuedAt: params.IssuedAt.UTC(), expiresAt: params.ExpiresAt.UTC(), authTime: params.AuthTime.UTC(), amr: slices.Clone(params.AMR)}, nonce: params.Nonce}
	if !evidence.IsValid() {
		return TokenEvidence{}, ErrExchangeRejected
	}
	return evidence, nil
}

// IsValid checks bounded identity/nonce shape without implying Core authorization.
func (evidence TokenEvidence) IsValid() bool {
	return evidence.identity.IsValid() && evidence.nonce.IsValid()
}

// Issuer returns exact validated route evidence for the Core nonce cross-check.
func (evidence TokenEvidence) Issuer() string { return evidence.identity.Issuer() }

// ExpiresAt returns the release deadline without exposing a bearer token.
func (evidence TokenEvidence) ExpiresAt() time.Time { return evidence.identity.ExpiresAt() }

// String redacts nonce and identity.
func (TokenEvidence) String() string { return "[REDACTED]" }

// GoString redacts detailed nonce and identity.
func (TokenEvidence) GoString() string { return "oidcauth.TokenEvidence([REDACTED])" }

// LogValue redacts structured nonce and identity.
func (TokenEvidence) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func validOpaqueIdentity(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
