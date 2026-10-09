package enrollment

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"log/slog"
	"strings"

	"meshtransit.net/core/internal/domain/deployment"
)

const (
	// DigestAlgorithmHMACSHA256 is the durable algorithm identifier persisted
	// with every enrollment credential digest.
	DigestAlgorithmHMACSHA256 = "hmac-sha256-v1"
	credentialDigestKeyBytes  = 32
	credentialDigestBytes     = sha256.Size
	credentialFingerprintSize = 16
	digestDomain              = "meshtransit/enrollment-credential/v1\x00"
)

var (
	// ErrInvalidDigestKey reports malformed key identity or key material.
	ErrInvalidDigestKey = errors.New("enrollment: invalid credential digest key")
	// ErrInvalidCredentialDigest reports malformed durable digest state.
	ErrInvalidCredentialDigest = errors.New("enrollment: invalid credential digest")
	// ErrInvalidCredentialKeyring reports an unsafe active/previous key window.
	ErrInvalidCredentialKeyring = errors.New("enrollment: invalid credential keyring")
)

// DigestKeyID is the public version identifier for one credential digest key.
type DigestKeyID struct {
	value string
}

// NewDigestKeyID validates a bounded durable key identifier.
func NewDigestKeyID(value string) (DigestKeyID, error) {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value ||
		!asciiAlphaNumeric(value[0]) {
		return DigestKeyID{}, ErrInvalidDigestKey
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !asciiAlphaNumeric(character) && character != '.' && character != '_' &&
			character != ':' && character != '-' {
			return DigestKeyID{}, ErrInvalidDigestKey
		}
	}
	return DigestKeyID{value: value}, nil
}

// String returns the non-secret durable key identifier.
func (id DigestKeyID) String() string { return id.value }

// IsValid reports whether the key identifier is safe to persist.
func (id DigestKeyID) IsValid() bool {
	validated, err := NewDigestKeyID(id.value)
	return err == nil && validated == id
}

// DigestKey contains one local HMAC key. The constructor and accessors copy key
// material; default formatting and structured logs are redacted.
type DigestKey struct {
	id       DigestKeyID
	material [credentialDigestKeyBytes]byte
}

// NewDigestKey validates and copies exactly 256 bits of HMAC key material.
func NewDigestKey(id DigestKeyID, material []byte) (DigestKey, error) {
	if !id.IsValid() || len(material) != credentialDigestKeyBytes {
		return DigestKey{}, ErrInvalidDigestKey
	}
	key := DigestKey{id: id}
	copy(key.material[:], material)
	if key.material == ([credentialDigestKeyBytes]byte{}) {
		return DigestKey{}, ErrInvalidDigestKey
	}
	return key, nil
}

// ID returns the non-secret durable key identifier.
func (key DigestKey) ID() DigestKeyID { return key.id }

// String prevents accidental key disclosure through fmt and slog.
func (DigestKey) String() string { return "[REDACTED]" }

// GoString prevents accidental key disclosure through %#v formatting.
func (DigestKey) GoString() string { return "enrollment.DigestKey([REDACTED])" }

// LogValue prevents accidental key disclosure in structured logs.
func (DigestKey) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func (key DigestKey) isValid() bool {
	return key.id.IsValid() && key.material != ([credentialDigestKeyBytes]byte{})
}

// CredentialDigest is the versioned verifier persisted instead of a bearer
// token. Its value remains redacted because possession permits offline guesses.
type CredentialDigest struct {
	keyID DigestKeyID
	value [credentialDigestBytes]byte
}

// NewCredentialDigest validates a digest loaded from durable storage.
func NewCredentialDigest(keyID DigestKeyID, value [credentialDigestBytes]byte) (CredentialDigest, error) {
	if !keyID.IsValid() || value == ([credentialDigestBytes]byte{}) {
		return CredentialDigest{}, ErrInvalidCredentialDigest
	}
	return CredentialDigest{keyID: keyID, value: value}, nil
}

// Algorithm returns the durable versioned algorithm identifier.
func (CredentialDigest) Algorithm() string { return DigestAlgorithmHMACSHA256 }

// KeyID returns the key version used to compute this digest.
func (digest CredentialDigest) KeyID() DigestKeyID { return digest.keyID }

// Bytes returns a copy for persistence at the database boundary.
func (digest CredentialDigest) Bytes() [credentialDigestBytes]byte { return digest.value }

// Fingerprint returns a non-verifier correlation value derived from the keyed
// digest. Raw token bytes never enter this display-oriented value directly.
func (digest CredentialDigest) Fingerprint() [credentialFingerprintSize]byte {
	const domain = "meshtransit/enrollment-fingerprint/v1\x00"
	var input [len(domain) + credentialDigestBytes]byte
	copy(input[:], domain)
	copy(input[len(domain):], digest.value[:])
	full := sha256.Sum256(input[:])
	var fingerprint [credentialFingerprintSize]byte
	copy(fingerprint[:], full[:credentialFingerprintSize])
	return fingerprint
}

// IsValid reports whether the digest can be verified safely.
func (digest CredentialDigest) IsValid() bool {
	return digest.keyID.IsValid() && digest.value != ([credentialDigestBytes]byte{})
}

// String prevents accidental digest disclosure through fmt and slog.
func (CredentialDigest) String() string { return "[REDACTED]" }

// GoString prevents accidental digest disclosure through %#v formatting.
func (CredentialDigest) GoString() string { return "enrollment.CredentialDigest([REDACTED])" }

// LogValue prevents accidental digest disclosure in structured logs.
func (CredentialDigest) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// CredentialKeyring holds exactly one active key and at most one previous key.
// It is immutable after construction and safe for concurrent use.
type CredentialKeyring struct {
	active   DigestKey
	previous DigestKey
	hasPrior bool
}

// NewCredentialKeyring constructs an explicit active/previous rotation window.
func NewCredentialKeyring(active DigestKey, previous ...DigestKey) (*CredentialKeyring, error) {
	if !active.isValid() || len(previous) > 1 {
		return nil, ErrInvalidCredentialKeyring
	}
	keyring := &CredentialKeyring{active: active}
	if len(previous) == 0 {
		return keyring, nil
	}
	if !previous[0].isValid() || previous[0].id == active.id {
		return nil, ErrInvalidCredentialKeyring
	}
	keyring.previous = previous[0]
	keyring.hasPrior = true
	return keyring, nil
}

// Digest computes a verifier with the active key.
func (keyring *CredentialKeyring) Digest(
	deploymentID deployment.ID,
	recoveryEpoch int64,
	token CredentialToken,
) (CredentialDigest, error) {
	if keyring == nil || !keyring.active.isValid() || !deploymentID.IsValid() ||
		recoveryEpoch <= 0 || !token.IsValid() {
		return CredentialDigest{}, ErrInvalidCredentialKeyring
	}
	return digestCredentialToken(keyring.active, deploymentID, recoveryEpoch, token)
}

// Verify compares a presented token against a stored active or previous-key
// digest using a constant-time primitive. Unknown key versions fail closed.
func (keyring *CredentialKeyring) Verify(
	deploymentID deployment.ID,
	recoveryEpoch int64,
	token CredentialToken,
	digest CredentialDigest,
) bool {
	if keyring == nil || !deploymentID.IsValid() || recoveryEpoch <= 0 ||
		!token.IsValid() || !digest.IsValid() {
		return false
	}
	key, ok := keyring.key(digest.keyID)
	if !ok {
		return false
	}
	expected, err := digestCredentialToken(key, deploymentID, recoveryEpoch, token)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(expected.value[:], digest.value[:]) == 1
}

// String prevents accidental disclosure of resident key material.
func (CredentialKeyring) String() string { return "[REDACTED]" }

// GoString prevents accidental disclosure through %#v formatting.
func (CredentialKeyring) GoString() string { return "enrollment.CredentialKeyring([REDACTED])" }

// LogValue prevents accidental disclosure in structured logs.
func (CredentialKeyring) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func (keyring *CredentialKeyring) key(id DigestKeyID) (DigestKey, bool) {
	if keyring.active.id == id {
		return keyring.active, true
	}
	if keyring.hasPrior && keyring.previous.id == id {
		return keyring.previous, true
	}
	return DigestKey{}, false
}

func digestCredentialToken(
	key DigestKey,
	deploymentID deployment.ID,
	recoveryEpoch int64,
	token CredentialToken,
) (CredentialDigest, error) {
	if !key.isValid() || !deploymentID.IsValid() || recoveryEpoch <= 0 || !token.IsValid() {
		return CredentialDigest{}, ErrInvalidCredentialDigest
	}
	mac := hmac.New(sha256.New, key.material[:])
	_, _ = mac.Write([]byte(digestDomain))
	deploymentBytes := deploymentID.Bytes()
	_, _ = mac.Write(deploymentBytes[:])
	var epoch [8]byte
	binary.BigEndian.PutUint64(epoch[:], uint64(recoveryEpoch))
	_, _ = mac.Write(epoch[:])
	tokenBytes := token.bytes()
	_, _ = mac.Write(tokenBytes[:])
	var value [credentialDigestBytes]byte
	copy(value[:], mac.Sum(nil))
	return NewCredentialDigest(key.id, value)
}

func asciiAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9'
}
