package accountsession

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"log/slog"
	"strings"
)

const (
	// DigestAlgorithmHMACSHA256V1 identifies the durable Account Session digest.
	DigestAlgorithmHMACSHA256V1 = "hmac-sha256-v1"
	digestDomain                = "meshtransit/account-session-token/v1\x00"
	digestKeyBytes              = 32
	digestBytes                 = sha256.Size
)

var (
	// ErrInvalidDigestKey reports malformed digest key identity or material.
	ErrInvalidDigestKey = errors.New("account session: invalid digest key")
	// ErrInvalidDigest reports malformed durable Account Session digest evidence.
	ErrInvalidDigest = errors.New("account session: invalid digest")
	// ErrInvalidKeyring reports an unsafe active/previous key window.
	ErrInvalidKeyring = errors.New("account session: invalid digest keyring")
)

// DigestKeyID is the public version identifier of one Account Session HMAC key.
type DigestKeyID struct{ value string }

// NewDigestKeyID validates a bounded durable digest key identifier.
func NewDigestKeyID(value string) (DigestKeyID, error) {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value ||
		!isASCIIAlphaNumeric(value[0]) {
		return DigestKeyID{}, ErrInvalidDigestKey
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !isASCIIAlphaNumeric(character) && character != '.' && character != '_' &&
			character != ':' && character != '-' {
			return DigestKeyID{}, ErrInvalidDigestKey
		}
	}
	return DigestKeyID{value: value}, nil
}

// String returns the non-secret durable key identifier.
func (id DigestKeyID) String() string { return id.value }

// IsValid reports whether the key identifier is canonical.
func (id DigestKeyID) IsValid() bool {
	validated, err := NewDigestKeyID(id.value)
	return err == nil && validated == id
}

// DigestKey contains one local HMAC key and always formats as redacted.
type DigestKey struct {
	id       DigestKeyID
	material [digestKeyBytes]byte
}

// NewDigestKey validates and copies exactly 256 bits of HMAC key material.
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

// ID returns the public key version.
func (key DigestKey) ID() DigestKeyID { return key.id }

// String prevents accidental key disclosure.
func (DigestKey) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed key disclosure.
func (DigestKey) GoString() string { return "accountsession.DigestKey([REDACTED])" }

// LogValue prevents accidental structured-log key disclosure.
func (DigestKey) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func (key DigestKey) isValid() bool {
	return key.id.IsValid() && key.material != ([digestKeyBytes]byte{})
}

// Digest is the secret-safe versioned verifier persisted with an Account Session.
type Digest struct {
	keyID DigestKeyID
	value [digestBytes]byte
}

// NewDigest validates verifier evidence loaded from durable storage.
func NewDigest(keyID DigestKeyID, value [digestBytes]byte) (Digest, error) {
	if !keyID.IsValid() || value == ([digestBytes]byte{}) {
		return Digest{}, ErrInvalidDigest
	}
	return Digest{keyID: keyID, value: value}, nil
}

// Algorithm returns the fixed durable digest algorithm.
func (Digest) Algorithm() string { return DigestAlgorithmHMACSHA256V1 }

// KeyID returns the public digest key version.
func (digest Digest) KeyID() DigestKeyID { return digest.keyID }

// Bytes returns a defensive copy for the persistence boundary.
func (digest Digest) Bytes() [digestBytes]byte { return digest.value }

// IsValid reports whether digest evidence is safe to resolve.
func (digest Digest) IsValid() bool {
	return digest.keyID.IsValid() && digest.value != ([digestBytes]byte{})
}

// String prevents accidental verifier disclosure.
func (Digest) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed verifier disclosure.
func (Digest) GoString() string { return "accountsession.Digest([REDACTED])" }

// LogValue prevents accidental structured-log verifier disclosure.
func (Digest) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Keyring holds exactly one active key and at most one previous key.
type Keyring struct {
	active      DigestKey
	previous    DigestKey
	hasPrevious bool
}

// NewKeyring constructs an immutable bounded rotation window.
func NewKeyring(active DigestKey, previous ...DigestKey) (*Keyring, error) {
	if !active.isValid() || len(previous) > 1 {
		return nil, ErrInvalidKeyring
	}
	keyring := &Keyring{active: active}
	if len(previous) == 0 {
		return keyring, nil
	}
	if !previous[0].isValid() || previous[0].id == active.id ||
		hmac.Equal(previous[0].material[:], active.material[:]) {
		return nil, ErrInvalidKeyring
	}
	keyring.previous = previous[0]
	keyring.hasPrevious = true
	return keyring, nil
}

// IsValid checks the bounded resident verifier window without secret I/O.
func (keyring *Keyring) IsValid() bool {
	return keyring != nil && keyring.active.isValid() && (!keyring.hasPrevious ||
		(keyring.previous.isValid() && keyring.previous.id != keyring.active.id &&
			!hmac.Equal(keyring.previous.material[:], keyring.active.material[:])))
}

// ActiveDigest creates issuance evidence only under the active resident key.
func (keyring *Keyring) ActiveDigest(token Token) (Digest, error) {
	if !keyring.IsValid() {
		return Digest{}, ErrInvalidKeyring
	}
	return digestToken(keyring.active, token)
}

// Digests returns active then previous verifier candidates for one token.
func (keyring *Keyring) Digests(token Token) ([]Digest, error) {
	if keyring == nil || !keyring.active.isValid() || !token.IsValid() {
		return nil, ErrInvalidKeyring
	}
	digests := make([]Digest, 0, 2)
	active, err := digestToken(keyring.active, token)
	if err != nil {
		return nil, err
	}
	digests = append(digests, active)
	if !keyring.hasPrevious {
		return digests, nil
	}
	previous, err := digestToken(keyring.previous, token)
	if err != nil {
		return nil, err
	}
	return append(digests, previous), nil
}

// String prevents accidental resident-key disclosure.
func (Keyring) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed resident-key disclosure.
func (Keyring) GoString() string { return "accountsession.Keyring([REDACTED])" }

// LogValue prevents accidental structured-log resident-key disclosure.
func (Keyring) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func digestToken(key DigestKey, token Token) (Digest, error) {
	if !key.isValid() {
		return Digest{}, ErrInvalidDigestKey
	}
	secret, deploymentBytes, epoch, err := tokenDigestInput(token)
	if err != nil {
		return Digest{}, ErrInvalidDigest
	}
	mac := hmac.New(sha256.New, key.material[:])
	_, _ = mac.Write([]byte(digestDomain))
	_, _ = mac.Write(deploymentBytes[:])
	_, _ = mac.Write(epoch[:])
	_, _ = mac.Write(secret[:])
	var value [digestBytes]byte
	copy(value[:], mac.Sum(nil))
	return NewDigest(key.id, value)
}

func isASCIIAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9'
}
