package oidcauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"log/slog"
	"strings"
)

const (
	// DigestAlgorithmHMACSHA256V1 identifies durable transaction digests.
	DigestAlgorithmHMACSHA256V1 = "hmac-sha256-v1"
	digestKeyBytes              = 32
	digestDomainState           = "meshtransit/oidc-auth/state/v1\x00"
	digestDomainNonce           = "meshtransit/oidc-auth/nonce/v1\x00"
)

var (
	// ErrInvalidDigestKey reports malformed key identity or material.
	ErrInvalidDigestKey = errors.New("oidc auth: invalid digest key")
	// ErrInvalidDigest reports malformed durable digest evidence.
	ErrInvalidDigest = errors.New("oidc auth: invalid digest")
)

// DigestKeyID identifies one versioned transaction HMAC key.
type DigestKeyID struct{ value string }

// NewDigestKeyID validates a bounded public key identifier.
func NewDigestKeyID(value string) (DigestKeyID, error) {
	if !validKeyID(value) {
		return DigestKeyID{}, ErrInvalidDigestKey
	}
	return DigestKeyID{value: value}, nil
}

// String returns the non-secret key generation.
func (id DigestKeyID) String() string { return id.value }

// IsValid reports whether the key identifier remains canonical.
func (id DigestKeyID) IsValid() bool { return validKeyID(id.value) }

// DigestKey owns one 256-bit transaction HMAC key.
type DigestKey struct {
	id       DigestKeyID
	material [digestKeyBytes]byte
}

// NewDigestKey validates and defensively copies key material.
func NewDigestKey(id DigestKeyID, material []byte) (DigestKey, error) {
	if !id.IsValid() || len(material) != digestKeyBytes {
		return DigestKey{}, ErrInvalidDigestKey
	}
	key := DigestKey{id: id}
	copy(key.material[:], material)
	if key.material == ([digestKeyBytes]byte{}) {
		return DigestKey{}, ErrInvalidDigestKey
	}
	return key, nil
}

// ID returns the public key generation.
func (key DigestKey) ID() DigestKeyID { return key.id }

// State destroys raw state using its dedicated domain.
func (key DigestKey) State(state State) (Digest, error) {
	if !key.isValid() || !state.IsValid() {
		return Digest{}, ErrInvalidDigest
	}
	digest := key.digest(digestDomainState, state.value[:])
	if !digest.IsValid() {
		return Digest{}, ErrInvalidDigest
	}
	return digest, nil
}

// Nonce destroys a raw nonce using a distinct dedicated domain.
func (key DigestKey) Nonce(nonce Nonce) (Digest, error) {
	if !key.isValid() || !nonce.IsValid() {
		return Digest{}, ErrInvalidDigest
	}
	digest := key.digest(digestDomainNonce, nonce.value[:])
	if !digest.IsValid() {
		return Digest{}, ErrInvalidDigest
	}
	return digest, nil
}

func (key DigestKey) digest(domain string, value []byte) Digest {
	mac := hmac.New(sha256.New, key.material[:])
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write(value)
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return Digest{keyID: key.id, value: result}
}

func (key DigestKey) isValid() bool {
	return key.id.IsValid() && key.material != ([digestKeyBytes]byte{})
}

// String prevents accidental resident-key disclosure.
func (DigestKey) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed resident-key disclosure.
func (DigestKey) GoString() string { return "oidcauth.DigestKey([REDACTED])" }

// LogValue prevents accidental structured-log key disclosure.
func (DigestKey) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Digest is versioned HMAC evidence safe for durable lookup.
type Digest struct {
	keyID DigestKeyID
	value [sha256.Size]byte
}

// NewDigest validates digest evidence loaded from storage.
func NewDigest(keyID DigestKeyID, value [sha256.Size]byte) (Digest, error) {
	if !keyID.IsValid() || value == ([sha256.Size]byte{}) {
		return Digest{}, ErrInvalidDigest
	}
	return Digest{keyID: keyID, value: value}, nil
}

// Algorithm returns the fixed durable digest algorithm.
func (Digest) Algorithm() string { return DigestAlgorithmHMACSHA256V1 }

// KeyID returns the public digest key generation.
func (digest Digest) KeyID() DigestKeyID { return digest.keyID }

// Bytes returns a defensive copy for persistence.
func (digest Digest) Bytes() [sha256.Size]byte { return digest.value }

// IsValid reports whether digest evidence is canonical.
func (digest Digest) IsValid() bool {
	return digest.keyID.IsValid() && digest.value != ([sha256.Size]byte{})
}

// String prevents accidental digest disclosure.
func (Digest) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed digest disclosure.
func (Digest) GoString() string { return "oidcauth.Digest([REDACTED])" }

// LogValue prevents accidental structured-log digest disclosure.
func (Digest) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func validKeyID(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value ||
		!isASCIIAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !isASCIIAlphaNumeric(character) && character != '.' && character != '_' &&
			character != ':' && character != '-' {
			return false
		}
	}
	return true
}

func isASCIIAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9'
}
