package idempotency

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"log/slog"
)

const (
	digestKeyBytes     = 32
	minimumRawKeyBytes = 16
	maximumRawKeyBytes = 128
	digestDomain       = "meshtransit/idempotency-key/v1\x00"
)

var (
	// ErrInvalidDigestKey reports malformed HMAC key identity or material.
	ErrInvalidDigestKey = errors.New("idempotency: invalid digest key")
	// ErrInvalidRawKey reports a malformed caller-supplied idempotency key.
	ErrInvalidRawKey = errors.New("idempotency: invalid raw key")
)

// DigestKeyID is the public version identifier for one HMAC key.
type DigestKeyID struct{ value string }

// NewDigestKeyID validates a bounded durable digest key identifier.
func NewDigestKeyID(value string) (DigestKeyID, error) {
	if !validDigestKeyID(value) {
		return DigestKeyID{}, ErrInvalidDigestKey
	}
	return DigestKeyID{value: value}, nil
}

// String returns the non-secret durable key identifier.
func (id DigestKeyID) String() string { return id.value }

// IsValid reports whether the key identifier remains canonical.
func (id DigestKeyID) IsValid() bool {
	validated, err := NewDigestKeyID(id.value)
	return err == nil && validated == id
}

// Digester converts raw request keys into purpose-separated durable evidence.
type Digester struct {
	keyID    DigestKeyID
	material [digestKeyBytes]byte
}

// NewDigester validates and copies exactly 256 bits of HMAC key material.
func NewDigester(keyID DigestKeyID, material []byte) (*Digester, error) {
	if !keyID.IsValid() || len(material) != digestKeyBytes {
		return nil, ErrInvalidDigestKey
	}
	digester := &Digester{keyID: keyID}
	copy(digester.material[:], material)
	if digester.material == ([digestKeyBytes]byte{}) {
		return nil, ErrInvalidDigestKey
	}
	return digester, nil
}

// Proof validates a raw key and returns only its versioned HMAC digest.
func (digester *Digester) Proof(raw string) (Proof, error) {
	if digester == nil || !digester.keyID.IsValid() ||
		digester.material == ([digestKeyBytes]byte{}) {
		return Proof{}, ErrInvalidDigestKey
	}
	if !validRawKey(raw) {
		return Proof{}, ErrInvalidRawKey
	}
	mac := hmac.New(sha256.New, digester.material[:])
	_, _ = mac.Write([]byte(digestDomain))
	_, _ = mac.Write([]byte(raw))
	var digest [sha256.Size]byte
	copy(digest[:], mac.Sum(nil))
	return NewProof(digester.keyID.String(), digest)
}

// String prevents accidental HMAC key disclosure.
func (*Digester) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed HMAC key disclosure.
func (*Digester) GoString() string { return "idempotency.Digester([REDACTED])" }

// LogValue prevents accidental structured-log key disclosure.
func (*Digester) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func validRawKey(value string) bool {
	if len(value) < minimumRawKeyBytes || len(value) > maximumRawKeyBytes {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '.' || character == '_' || character == ':' ||
			character == '~' || character == '-' {
			continue
		}
		return false
	}
	return true
}
