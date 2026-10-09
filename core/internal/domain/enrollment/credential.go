package enrollment

import (
	"errors"
	"math"
	"time"

	"meshtransit.net/core/internal/domain/identity"
)

var (
	// ErrInvalidCredential reports malformed durable credential state.
	ErrInvalidCredential = errors.New("enrollment: invalid credential")
	// ErrCredentialInactive reports a credential outside the active lifecycle.
	ErrCredentialInactive = errors.New("enrollment: credential inactive")
	// ErrCredentialNotYetValid reports a credential used before its validity window.
	ErrCredentialNotYetValid = errors.New("enrollment: credential not yet valid")
	// ErrCredentialExpired reports a credential at or after its expiry deadline.
	ErrCredentialExpired = errors.New("enrollment: credential expired")
	// ErrCredentialExhausted reports a bounded credential with no remaining uses.
	ErrCredentialExhausted = errors.New("enrollment: credential exhausted")
	// ErrRecoveryEpochMismatch reports authority issued before the active recovery epoch.
	ErrRecoveryEpochMismatch = errors.New("enrollment: recovery epoch mismatch")
)

// CredentialState identifies the durable enrollment credential lifecycle.
type CredentialState uint8

const (
	// CredentialStateUnknown is the invalid zero-value state.
	CredentialStateUnknown CredentialState = iota
	// CredentialStateActive permits use within the configured limits.
	CredentialStateActive
	// CredentialStateRevoked permanently denies future use.
	CredentialStateRevoked
)

// UseLimitKind identifies whether a credential use limit is bounded.
type UseLimitKind uint8

const (
	// UseLimitUnknown is the invalid zero-value use policy.
	UseLimitUnknown UseLimitKind = iota
	// UseLimitBounded permits a positive fixed number of registrations.
	UseLimitBounded
	// UseLimitUnlimited explicitly permits reuse until expiry or revocation.
	UseLimitUnlimited
)

// UseLimit is an explicit credential quota. Unlimited use is never inferred
// from a zero integer.
type UseLimit struct {
	kind UseLimitKind
	max  int64
}

// NewBoundedUseLimit validates a positive registration quota.
func NewBoundedUseLimit(maximum int64) (UseLimit, error) {
	if maximum <= 0 {
		return UseLimit{}, ErrInvalidCredential
	}
	return UseLimit{kind: UseLimitBounded, max: maximum}, nil
}

// NewUnlimitedUseLimit explicitly constructs a reusable credential policy.
func NewUnlimitedUseLimit() UseLimit { return UseLimit{kind: UseLimitUnlimited} }

// Kind returns the quota policy kind.
func (limit UseLimit) Kind() UseLimitKind { return limit.kind }

// Maximum returns the bounded quota and whether one exists.
func (limit UseLimit) Maximum() (int64, bool) {
	return limit.max, limit.kind == UseLimitBounded
}

func (limit UseLimit) isValid() bool {
	return (limit.kind == UseLimitBounded && limit.max > 0) ||
		(limit.kind == UseLimitUnlimited && limit.max == 0)
}

// CredentialParams contains validated persistence fields needed to rehydrate a
// credential without exposing its plaintext bearer token.
type CredentialParams struct {
	ID                  CredentialID
	ProfileID           ProfileID
	IssuerID            identity.PrincipalID
	State               CredentialState
	UseLimit            UseLimit
	UsedCount           int64
	IssuedRecoveryEpoch int64
	ValidFrom           time.Time
	ExpiresAt           time.Time
}

// Credential is immutable enrollment authority. Consume returns a new value;
// the caller must hold the durable credential lock before persisting it.
type Credential struct {
	id                  CredentialID
	profileID           ProfileID
	issuerID            identity.PrincipalID
	state               CredentialState
	useLimit            UseLimit
	usedCount           int64
	issuedRecoveryEpoch int64
	validFrom           time.Time
	expiresAt           time.Time
}

// NewCredential validates durable credential state.
func NewCredential(params CredentialParams) (Credential, error) {
	if !params.ID.IsValid() || !params.ProfileID.IsValid() || !params.IssuerID.IsValid() ||
		(params.State != CredentialStateActive && params.State != CredentialStateRevoked) ||
		!params.UseLimit.isValid() || params.UsedCount < 0 || params.IssuedRecoveryEpoch <= 0 ||
		params.ValidFrom.IsZero() || !params.ExpiresAt.After(params.ValidFrom) {
		return Credential{}, ErrInvalidCredential
	}
	if maximum, bounded := params.UseLimit.Maximum(); bounded && params.UsedCount > maximum {
		return Credential{}, ErrInvalidCredential
	}
	return Credential{
		id:                  params.ID,
		profileID:           params.ProfileID,
		issuerID:            params.IssuerID,
		state:               params.State,
		useLimit:            params.UseLimit,
		usedCount:           params.UsedCount,
		issuedRecoveryEpoch: params.IssuedRecoveryEpoch,
		validFrom:           params.ValidFrom.UTC(),
		expiresAt:           params.ExpiresAt.UTC(),
	}, nil
}

// ID returns the credential public ID.
func (credential Credential) ID() CredentialID { return credential.id }

// ProfileID returns the profile whose authority this credential carries.
func (credential Credential) ProfileID() ProfileID { return credential.profileID }

// IssuerID returns the principal that issued this credential.
func (credential Credential) IssuerID() identity.PrincipalID { return credential.issuerID }

// State returns the durable lifecycle state.
func (credential Credential) State() CredentialState { return credential.state }

// UseLimit returns the explicit credential quota policy.
func (credential Credential) UseLimit() UseLimit { return credential.useLimit }

// UsedCount returns the number of durably committed uses.
func (credential Credential) UsedCount() int64 { return credential.usedCount }

// IssuedRecoveryEpoch returns the recovery epoch bound at issuance.
func (credential Credential) IssuedRecoveryEpoch() int64 {
	return credential.issuedRecoveryEpoch
}

// ValidFrom returns the inclusive credential validity start.
func (credential Credential) ValidFrom() time.Time { return credential.validFrom }

// ExpiresAt returns the exclusive credential validity deadline.
func (credential Credential) ExpiresAt() time.Time { return credential.expiresAt }

// IsValid reports whether the credential can be safely evaluated as durable state.
func (credential Credential) IsValid() bool {
	if !credential.id.IsValid() || !credential.profileID.IsValid() || !credential.issuerID.IsValid() ||
		(credential.state != CredentialStateActive && credential.state != CredentialStateRevoked) ||
		!credential.useLimit.isValid() || credential.usedCount < 0 ||
		credential.issuedRecoveryEpoch <= 0 || credential.validFrom.IsZero() ||
		!credential.expiresAt.After(credential.validFrom) {
		return false
	}
	maximum, bounded := credential.useLimit.Maximum()
	return !bounded || credential.usedCount <= maximum
}

// Consume validates one use and returns the incremented immutable state.
func (credential Credential) Consume(now time.Time, recoveryEpoch int64) (Credential, error) {
	if !credential.IsValid() || now.IsZero() {
		return Credential{}, ErrInvalidCredential
	}
	if credential.state != CredentialStateActive {
		return Credential{}, ErrCredentialInactive
	}
	if recoveryEpoch <= 0 || recoveryEpoch != credential.issuedRecoveryEpoch {
		return Credential{}, ErrRecoveryEpochMismatch
	}
	if now.Before(credential.validFrom) {
		return Credential{}, ErrCredentialNotYetValid
	}
	if !now.Before(credential.expiresAt) {
		return Credential{}, ErrCredentialExpired
	}
	if maximum, bounded := credential.useLimit.Maximum(); bounded && credential.usedCount >= maximum {
		return Credential{}, ErrCredentialExhausted
	}
	if credential.usedCount == math.MaxInt64 {
		return Credential{}, ErrCredentialExhausted
	}

	consumed := credential
	consumed.usedCount++
	return consumed, nil
}

// Revoke returns terminal credential state. Repeated revocation is idempotent.
func (credential Credential) Revoke() (Credential, error) {
	if !credential.IsValid() {
		return Credential{}, ErrInvalidCredential
	}
	revoked := credential
	revoked.state = CredentialStateRevoked
	return revoked, nil
}
