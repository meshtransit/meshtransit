package key

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"

	"golang.org/x/crypto/blake2s"
)

const (
	signingPrefix = "mtsign:"
	keyIDDomain   = "meshtransit/key-id/v1"
	// KeyIDSize is the length of a signing key ID.
	KeyIDSize = 8
)

// SigningPublic is a Core Ed25519 public key that signs tickets and relay maps.
type SigningPublic [ed25519.PublicKeySize]byte

// KeyID names a signing key on the wire.
type KeyID [KeyIDSize]byte

// SigningPrivate is a Core Ed25519 signing key. It never formats itself.
type SigningPrivate struct{ private ed25519.PrivateKey }

// ParseSigningPublic parses the text form "mtsign:<hex>".
func ParseSigningPublic(text string) (SigningPublic, error) {
	var k SigningPublic
	return k, parsePublic(signingPrefix, text, k[:])
}

func (k SigningPublic) String() string { return signingPrefix + hex.EncodeToString(k[:]) }

// IsZero reports whether the key is unset.
func (k SigningPublic) IsZero() bool { return isZero(k[:]) }

// MarshalText implements encoding.TextMarshaler.
func (k SigningPublic) MarshalText() ([]byte, error) { return marshalPublic(k[:], k.String()) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *SigningPublic) UnmarshalText(b []byte) error {
	return parsePublic(signingPrefix, string(b), k[:])
}

// ID derives the key ID: the first 8 bytes of
// BLAKE2s-256("meshtransit/key-id/v1" || 0x00 || public key).
func (k SigningPublic) ID() KeyID {
	h, _ := blake2s.New256(nil) // unkeyed BLAKE2s never fails
	h.Write([]byte(keyIDDomain))
	h.Write([]byte{0})
	h.Write(k[:])
	var id KeyID
	copy(id[:], h.Sum(nil))
	return id
}

// Verify checks an Ed25519 signature over message.
func (k SigningPublic) Verify(message, signature []byte) bool {
	if k.IsZero() || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(k[:], message, signature)
}

func (id KeyID) String() string { return hex.EncodeToString(id[:]) }

// NewSigningPrivate generates a signing key from the given CSPRNG (crypto/rand.Reader in production).
func NewSigningPrivate(random io.Reader) (SigningPrivate, error) {
	_, private, err := ed25519.GenerateKey(random)
	if err != nil {
		return SigningPrivate{}, fmt.Errorf("key: generate signing key: %w", err)
	}
	return SigningPrivate{private}, nil
}

// SigningPrivateFromSeed builds a signing key from a 32-byte seed. The seed is copied.
func SigningPrivateFromSeed(seed []byte) (SigningPrivate, error) {
	if len(seed) != ed25519.SeedSize || isZero(seed) {
		return SigningPrivate{}, ErrInvalid
	}
	return SigningPrivate{ed25519.NewKeyFromSeed(seed)}, nil
}

// IsZero reports whether the key is unset.
func (k SigningPrivate) IsZero() bool { return k.private == nil }

// Public returns the matching public key.
func (k SigningPrivate) Public() SigningPublic {
	var p SigningPublic
	if k.private == nil {
		return p
	}
	if public, ok := k.private.Public().(ed25519.PublicKey); ok {
		copy(p[:], public)
	}
	return p
}

// Sign signs message. It returns nil for an unset key.
func (k SigningPrivate) Sign(message []byte) []byte {
	if k.private == nil {
		return nil
	}
	return ed25519.Sign(k.private, message)
}

// String, GoString, Format and LogValue never reveal private material.
func (SigningPrivate) String() string               { return "mtsign-private:[REDACTED]" }
func (SigningPrivate) GoString() string             { return "key.SigningPrivate([REDACTED])" }
func (SigningPrivate) LogValue() slog.Value         { return slog.StringValue("[REDACTED]") }
func (k SigningPrivate) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }
