package oidcauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"
)

const subjectDigestDomain = "meshtransit/oidc-auth/identity-subject/v1\x00"

// ErrInvalidSubjectKeyring rejects unsafe stable-identity key rotation.
var ErrInvalidSubjectKeyring = errors.New("oidc auth: invalid subject keyring")

// SubjectKey restricts resident HMAC material to stable external-subject lookup.
// It has no state/nonce/bearer API and never reads a secret or performs I/O.
type SubjectKey struct{ key DigestKey }

// NewSubjectKey validates and copies one purpose-owned 256-bit resident key.
func NewSubjectKey(id DigestKeyID, material []byte) (SubjectKey, error) {
	key, err := NewDigestKey(id, material)
	if err != nil {
		return SubjectKey{}, err
	}
	return SubjectKey{key: key}, nil
}

// ID returns the non-secret durable key version.
func (key SubjectKey) ID() DigestKeyID { return key.key.ID() }

// String redacts resident subject-key material.
func (SubjectKey) String() string { return "[REDACTED]" }

// GoString redacts detailed subject-key formatting.
func (SubjectKey) GoString() string { return "oidcauth.SubjectKey([REDACTED])" }

// LogValue redacts structured subject-key formatting.
func (SubjectKey) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// SubjectDigest is versioned stable-identity evidence, not a bearer verifier.
type SubjectDigest struct{ digest Digest }

// NewSubjectDigest validates exact durable bytes without padding or normalization.
func NewSubjectDigest(id DigestKeyID, value [sha256.Size]byte) (SubjectDigest, error) {
	digest, err := NewDigest(id, value)
	if err != nil {
		return SubjectDigest{}, err
	}
	return SubjectDigest{digest: digest}, nil
}

// Algorithm returns the fixed durable HMAC algorithm.
func (SubjectDigest) Algorithm() string { return DigestAlgorithmHMACSHA256V1 }

// KeyID returns the non-secret durable key version.
func (digest SubjectDigest) KeyID() DigestKeyID { return digest.digest.KeyID() }

// Bytes returns a copy only for the trusted persistence boundary.
func (digest SubjectDigest) Bytes() [sha256.Size]byte { return digest.digest.Bytes() }

// IsValid rejects absent or malformed digest evidence.
func (digest SubjectDigest) IsValid() bool { return digest.digest.IsValid() }

// String redacts stable subject lookup evidence.
func (SubjectDigest) String() string { return "[REDACTED]" }

// GoString redacts detailed subject lookup evidence.
func (SubjectDigest) GoString() string { return "oidcauth.SubjectDigest([REDACTED])" }

// LogValue redacts structured subject lookup evidence.
func (SubjectDigest) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// SubjectKeyring holds one active and at most one previous stable-binding key.
// Retirement requires audited binding migration, not a pending-login TTL.
type SubjectKeyring struct {
	active      SubjectKey
	previous    SubjectKey
	hasPrevious bool
}

// NewSubjectKeyring rejects aliases, reused material and unbounded key windows.
func NewSubjectKeyring(active SubjectKey, previous ...SubjectKey) (*SubjectKeyring, error) {
	if !active.key.isValid() || len(previous) > 1 {
		return nil, ErrInvalidSubjectKeyring
	}
	ring := &SubjectKeyring{active: active}
	if len(previous) == 0 {
		return ring, nil
	}
	if !previous[0].key.isValid() || previous[0].ID() == active.ID() {
		return nil, ErrInvalidSubjectKeyring
	}
	if hmac.Equal(previous[0].key.material[:], active.key.material[:]) {
		return nil, ErrInvalidSubjectKeyring
	}
	ring.previous, ring.hasPrevious = previous[0], true
	return ring, nil
}

// Digests prepares active then previous candidates from exact validated identity.
// Workspace/client/generation/epoch are authority fences, not subject identity.
// Shape validation does not replace signature validation by the exchange service.
func (ring *SubjectKeyring) Digests(route Route, identity ExternalIdentity) ([]SubjectDigest, error) {
	if !ring.isValid() || !route.IsValid() {
		return nil, ErrInvalidSubjectKeyring
	}
	if !identity.IsValid() || identity.Issuer() != route.Issuer() {
		return nil, ErrSubjectResolutionRejected
	}
	result := make([]SubjectDigest, 0, 2)
	active, err := digestSubject(ring.active, route, identity)
	if err != nil {
		return nil, err
	}
	result = append(result, active)
	if !ring.hasPrevious {
		return result, nil
	}
	previous, err := digestSubject(ring.previous, route, identity)
	if err != nil {
		return nil, err
	}
	return append(result, previous), nil
}

// String redacts the complete resident key window.
func (SubjectKeyring) String() string { return "[REDACTED]" }

// GoString redacts detailed resident key-window formatting.
func (SubjectKeyring) GoString() string { return "oidcauth.SubjectKeyring([REDACTED])" }

// LogValue redacts structured resident key-window formatting.
func (SubjectKeyring) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func (ring *SubjectKeyring) isValid() bool {
	if ring == nil || !ring.active.key.isValid() {
		return false
	}
	if !ring.hasPrevious {
		return ring.previous == (SubjectKey{})
	}
	if !ring.previous.key.isValid() || ring.previous.ID() == ring.active.ID() {
		return false
	}
	return !hmac.Equal(ring.previous.key.material[:], ring.active.key.material[:])
}

func digestSubject(key SubjectKey, route Route, identity ExternalIdentity) (SubjectDigest, error) {
	input := make([]byte, 0, len(subjectDigestDomain)+32+6+len(key.ID().String())+len(identity.Issuer())+len(identity.Subject()))
	input = append(input, subjectDigestDomain...)
	deploymentBytes, providerBytes := route.DeploymentID().Bytes(), route.ProviderID().Bytes()
	input = append(input, deploymentBytes[:]...)
	input = append(input, providerBytes[:]...)
	for _, value := range []string{key.ID().String(), identity.Issuer(), identity.Subject()} {
		length := len(value)
		if length <= 0 || length > 65535 {
			return SubjectDigest{}, ErrInvalidDigest
		}
		input = binary.BigEndian.AppendUint16(input, uint16(length))
		input = append(input, value...)
	}
	mac := hmac.New(sha256.New, key.key.material[:])
	_, _ = mac.Write(input)
	var value [sha256.Size]byte
	copy(value[:], mac.Sum(nil))
	return NewSubjectDigest(key.ID(), value)
}
