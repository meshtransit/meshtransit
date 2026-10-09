package oidcauth

import (
	"crypto/hmac"
	"errors"
	"log/slog"
	"time"
)

// ErrInvalidPendingSnapshot reports unsupported or unbound durable browser evidence.
var ErrInvalidPendingSnapshot = errors.New("oidc auth: invalid pending snapshot")

// PendingSnapshotParams contains loaded evidence, never new secrets or ciphertext.
// Only version-one pending browser login rows are supported at this boundary.
type PendingSnapshotParams struct {
	TransactionID      TransactionID
	Route              Route
	Version            int64
	State              string
	FlowKind           string
	OperationKind      string
	StateDigest        Digest
	NonceDigest        Digest
	VerifierCiphertext Ciphertext
	SemanticHash       [32]byte
	CreatedAt          time.Time
	ExpiresAt          time.Time
}

// PendingSnapshot is immutable creation-bound evidence, not a claim or session.
// The partial Pending reuses the unchanged v1 hash encoding without its creation-
// only authorization request or mutation IDs; neither participates in that hash.
type PendingSnapshot struct {
	pending Pending
	version int64
}

// NewPendingSnapshot recomputes the complete creation hash without entropy,
// encryption, or timestamp rounding. Legacy, changed, and noncanonical rows reject.
func NewPendingSnapshot(params PendingSnapshotParams) (PendingSnapshot, error) {
	if params.Version != 1 || params.State != "pending" ||
		params.FlowKind != "browser_authorization_code" || params.OperationKind != "login" {
		return PendingSnapshot{}, ErrInvalidPendingSnapshot
	}
	ciphertext, err := NewCiphertext(params.VerifierCiphertext.KeyID(), params.VerifierCiphertext.Bytes())
	if err != nil {
		return PendingSnapshot{}, ErrInvalidPendingSnapshot
	}
	snapshot := PendingSnapshot{version: params.Version, pending: Pending{
		transactionID: params.TransactionID, route: params.Route,
		stateDigest: params.StateDigest, nonceDigest: params.NonceDigest,
		verifierCiphertext: ciphertext, semanticHash: params.SemanticHash,
		createdAt: params.CreatedAt.UTC(), expiresAt: params.ExpiresAt.UTC(),
	}}
	if !snapshot.IsValid() {
		return PendingSnapshot{}, ErrInvalidPendingSnapshot
	}
	return snapshot, nil
}

// IsValid checks supported shape, precision, lifetime, and exact full binding hash.
func (snapshot PendingSnapshot) IsValid() bool {
	pending := snapshot.pending
	if snapshot.version != 1 || !pending.transactionID.IsValid() || !pending.route.IsValid() ||
		!pending.stateDigest.IsValid() || !pending.nonceDigest.IsValid() ||
		pending.stateDigest.KeyID() != pending.nonceDigest.KeyID() ||
		!pending.verifierCiphertext.IsValid() || pending.createdAt.IsZero() ||
		pending.expiresAt.IsZero() || pending.createdAt.Nanosecond()%1000 != 0 ||
		pending.expiresAt.Nanosecond()%1000 != 0 || !pending.createdAt.Before(pending.expiresAt) ||
		pending.expiresAt.Sub(pending.createdAt) > maximumPendingLifetime ||
		pending.semanticHash == ([32]byte{}) {
		return false
	}
	state, nonce := pending.stateDigest.Bytes(), pending.nonceDigest.Bytes()
	if hmac.Equal(state[:], nonce[:]) {
		return false
	}
	// AES-GCM v1 has a 12-byte nonce and 16-byte tag. Verifier-only envelopes
	// cannot satisfy the canonical browser payload's size even before opening.
	size := len(pending.verifierCiphertext.value) - 12 - 16
	if size < browserProofFixedBytes+1 || size > browserProofFixedBytes+128 {
		return false
	}
	actual := hashPending(pending)
	return hmac.Equal(actual[:], pending.semanticHash[:])
}

// MatchesRoute rejects every configured dimension, including local route labels.
// It supplies no revocation lease; a consuming transaction must recheck authority.
func (snapshot PendingSnapshot) MatchesRoute(route Route) bool {
	if !snapshot.IsValid() || !route.IsValid() {
		return false
	}
	pending := snapshot.pending
	pending.route = route
	actual := hashPending(pending)
	return hmac.Equal(actual[:], snapshot.pending.semanticHash[:])
}

// TransactionID returns the exact immutable transaction identity.
func (snapshot PendingSnapshot) TransactionID() TransactionID {
	return snapshot.pending.TransactionID()
}

// Route returns the trusted creation-bound configuration.
func (snapshot PendingSnapshot) Route() Route { return snapshot.pending.Route() }

// Version returns the only supported pending version; zero snapshots remain invalid.
func (snapshot PendingSnapshot) Version() int64 { return snapshot.version }

// StateDigest returns purpose-separated lookup evidence, never the raw state.
func (snapshot PendingSnapshot) StateDigest() Digest { return snapshot.pending.StateDigest() }

// NonceDigest returns validation evidence without releasing a raw nonce.
func (snapshot PendingSnapshot) NonceDigest() Digest { return snapshot.pending.NonceDigest() }

// VerifierCiphertext returns a defensive copy, never decrypted exchange material.
func (snapshot PendingSnapshot) VerifierCiphertext() Ciphertext {
	return snapshot.pending.VerifierCiphertext()
}

// SemanticHash returns the unchanged creation binding hash for a later locked claim.
func (snapshot PendingSnapshot) SemanticHash() [32]byte { return snapshot.pending.SemanticHash() }

// CreatedAt returns the canonical durable timestamp.
func (snapshot PendingSnapshot) CreatedAt() time.Time { return snapshot.pending.CreatedAt() }

// ExpiresAt returns the immutable pending deadline.
func (snapshot PendingSnapshot) ExpiresAt() time.Time { return snapshot.pending.ExpiresAt() }

// String prevents accidental evidence disclosure.
func (PendingSnapshot) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed evidence disclosure.
func (PendingSnapshot) GoString() string { return "oidcauth.PendingSnapshot([REDACTED])" }

// LogValue prevents accidental structured-log evidence disclosure.
func (PendingSnapshot) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
