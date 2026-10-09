// Package key defines MeshTransit's key types (docs/protocol/keys.md).
//
// Each purpose has its own Go type so a key of one kind can never be passed
// where another is expected. Public keys have a strict text form
// ("<prefix>" + 64 lowercase hex characters); private keys never format
// themselves, so they cannot leak through logs or %v.
package key

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

// Size is the length in bytes of every public and private X25519 key.
const Size = 32

var (
	// ErrInvalid reports a malformed, zero or wrongly prefixed key.
	ErrInvalid = errors.New("key: invalid key")
	// ErrLowOrder reports an X25519 exchange that produced an all-zero secret.
	ErrLowOrder = errors.New("key: low-order public key")
)

// Text prefixes of the public key types.
const (
	nodePrefix  = "mtnode:"
	discoPrefix = "mtdisco:"
	relayPrefix = "mtrelay:"
)

// NodePublic is a node's WireGuard static public key.
type NodePublic [Size]byte

// DiscoPublic authenticates disco v2 messages and MTRP sessions.
type DiscoPublic [Size]byte

// RelayPublic is an Interchange node's Noise responder static key.
type RelayPublic [Size]byte

// ParseNodePublic parses the text form "mtnode:<hex>".
func ParseNodePublic(text string) (NodePublic, error) {
	var k NodePublic
	return k, parsePublic(nodePrefix, text, k[:])
}

// ParseDiscoPublic parses the text form "mtdisco:<hex>".
func ParseDiscoPublic(text string) (DiscoPublic, error) {
	var k DiscoPublic
	return k, parsePublic(discoPrefix, text, k[:])
}

// ParseRelayPublic parses the text form "mtrelay:<hex>".
func ParseRelayPublic(text string) (RelayPublic, error) {
	var k RelayPublic
	return k, parsePublic(relayPrefix, text, k[:])
}

func (k NodePublic) String() string  { return nodePrefix + hex.EncodeToString(k[:]) }
func (k DiscoPublic) String() string { return discoPrefix + hex.EncodeToString(k[:]) }
func (k RelayPublic) String() string { return relayPrefix + hex.EncodeToString(k[:]) }

// IsZero reports whether the key is unset. The zero key is never valid.
func (k NodePublic) IsZero() bool  { return isZero(k[:]) }
func (k DiscoPublic) IsZero() bool { return isZero(k[:]) }
func (k RelayPublic) IsZero() bool { return isZero(k[:]) }

// MarshalText implements encoding.TextMarshaler.
func (k NodePublic) MarshalText() ([]byte, error) { return marshalPublic(k[:], k.String()) }

// MarshalText implements encoding.TextMarshaler.
func (k DiscoPublic) MarshalText() ([]byte, error) { return marshalPublic(k[:], k.String()) }

// MarshalText implements encoding.TextMarshaler.
func (k RelayPublic) MarshalText() ([]byte, error) { return marshalPublic(k[:], k.String()) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *NodePublic) UnmarshalText(b []byte) error { return parsePublic(nodePrefix, string(b), k[:]) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *DiscoPublic) UnmarshalText(b []byte) error {
	return parsePublic(discoPrefix, string(b), k[:])
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *RelayPublic) UnmarshalText(b []byte) error {
	return parsePublic(relayPrefix, string(b), k[:])
}

// DiscoPrivate is a node's disco private key.
type DiscoPrivate struct{ private *ecdh.PrivateKey }

// RelayPrivate is an Interchange node's static private key.
type RelayPrivate struct{ private *ecdh.PrivateKey }

// NewDiscoPrivate generates a disco key from the operating system CSPRNG.
func NewDiscoPrivate() (DiscoPrivate, error) {
	k, err := generate(rand.Reader)
	return DiscoPrivate{k}, err
}

// NewRelayPrivate generates a relay key from the operating system CSPRNG.
func NewRelayPrivate() (RelayPrivate, error) {
	k, err := generate(rand.Reader)
	return RelayPrivate{k}, err
}

// DiscoPrivateFromBytes builds a disco key from raw bytes (configuration
// files and test vectors). The slice is copied.
func DiscoPrivateFromBytes(raw []byte) (DiscoPrivate, error) {
	k, err := fromBytes(raw)
	return DiscoPrivate{k}, err
}

// RelayPrivateFromBytes builds a relay key from raw bytes. The slice is copied.
func RelayPrivateFromBytes(raw []byte) (RelayPrivate, error) {
	k, err := fromBytes(raw)
	return RelayPrivate{k}, err
}

// IsZero reports whether the key is unset.
func (k DiscoPrivate) IsZero() bool { return k.private == nil }

// IsZero reports whether the key is unset.
func (k RelayPrivate) IsZero() bool { return k.private == nil }

// Public returns the matching public key.
func (k DiscoPrivate) Public() DiscoPublic {
	var p DiscoPublic
	if k.private != nil {
		copy(p[:], k.private.PublicKey().Bytes())
	}
	return p
}

// Public returns the matching public key.
func (k RelayPrivate) Public() RelayPublic {
	var p RelayPublic
	if k.private != nil {
		copy(p[:], k.private.PublicKey().Bytes())
	}
	return p
}

// Shared performs X25519 with a peer's disco key. Low-order peer keys, which
// would give an all-zero secret, are rejected.
func (k DiscoPrivate) Shared(peer DiscoPublic) ([Size]byte, error) {
	return shared(k.private, peer[:])
}

// ECDH exposes the key for Noise implementations that take *ecdh.PrivateKey.
func (k DiscoPrivate) ECDH() *ecdh.PrivateKey { return k.private }

// ECDH exposes the key for Noise implementations that take *ecdh.PrivateKey.
func (k RelayPrivate) ECDH() *ecdh.PrivateKey { return k.private }

// String, GoString, Format and LogValue never reveal private material.
func (DiscoPrivate) String() string               { return "mtdisco-private:[REDACTED]" }
func (DiscoPrivate) GoString() string             { return "key.DiscoPrivate([REDACTED])" }
func (DiscoPrivate) LogValue() slog.Value         { return slog.StringValue("[REDACTED]") }
func (k DiscoPrivate) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }
func (RelayPrivate) String() string               { return "mtrelay-private:[REDACTED]" }
func (RelayPrivate) GoString() string             { return "key.RelayPrivate([REDACTED])" }
func (RelayPrivate) LogValue() slog.Value         { return slog.StringValue("[REDACTED]") }
func (k RelayPrivate) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }

// Equal compares two public keys in constant time.
func Equal(a, b [Size]byte) bool { return subtle.ConstantTimeCompare(a[:], b[:]) == 1 }

func generate(random io.Reader) (*ecdh.PrivateKey, error) {
	k, err := ecdh.X25519().GenerateKey(random)
	if err != nil {
		return nil, fmt.Errorf("key: generate: %w", err)
	}
	return k, nil
}

func fromBytes(raw []byte) (*ecdh.PrivateKey, error) {
	if len(raw) != Size || isZero(raw) {
		return nil, ErrInvalid
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, ErrInvalid
	}
	return k, nil
}

func shared(private *ecdh.PrivateKey, peer []byte) ([Size]byte, error) {
	var out [Size]byte
	if private == nil || isZero(peer) {
		return out, ErrInvalid
	}
	public, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return out, ErrInvalid
	}
	secret, err := private.ECDH(public)
	if err != nil { // crypto/ecdh rejects all-zero results for X25519.
		return out, ErrLowOrder
	}
	copy(out[:], secret)
	return out, nil
}

func parsePublic(prefix, text string, dst []byte) error {
	if len(text) != len(prefix)+2*Size || text[:len(prefix)] != prefix {
		return ErrInvalid
	}
	body := text[len(prefix):]
	for i := 0; i < len(body); i++ {
		c := body[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') { // lowercase hex only
			return ErrInvalid
		}
	}
	var decoded [Size]byte
	if _, err := hex.Decode(decoded[:], []byte(body)); err != nil || isZero(decoded[:]) {
		return ErrInvalid
	}
	copy(dst, decoded[:])
	return nil
}

func marshalPublic(raw []byte, text string) ([]byte, error) {
	if isZero(raw) {
		return nil, ErrInvalid
	}
	return []byte(text), nil
}

func isZero(b []byte) bool {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	return acc == 0
}
