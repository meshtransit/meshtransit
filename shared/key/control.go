package key

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"

	"golang.org/x/crypto/blake2s"
)

// Text prefixes of the MTCP key types (docs/protocol/keys.md).
const (
	machinePrefix = "mtmachine:"
	controlPrefix = "mtcontrol:"
)

// MachinePublic identifies a node installation: the MTCP Noise initiator
// static key.
type MachinePublic [Size]byte

// ControlPublic is a Core deployment's MTCP Noise responder static key,
// pinned by nodes.
type ControlPublic [Size]byte

// ParseMachinePublic parses the text form "mtmachine:<hex>".
func ParseMachinePublic(text string) (MachinePublic, error) {
	var k MachinePublic
	return k, parsePublic(machinePrefix, text, k[:])
}

// ParseControlPublic parses the text form "mtcontrol:<hex>".
func ParseControlPublic(text string) (ControlPublic, error) {
	var k ControlPublic
	return k, parsePublic(controlPrefix, text, k[:])
}

func (k MachinePublic) String() string { return machinePrefix + hex.EncodeToString(k[:]) }
func (k ControlPublic) String() string { return controlPrefix + hex.EncodeToString(k[:]) }

// IsZero reports whether the key is unset. The zero key is never valid.
func (k MachinePublic) IsZero() bool { return isZero(k[:]) }
func (k ControlPublic) IsZero() bool { return isZero(k[:]) }

// MarshalText implements encoding.TextMarshaler.
func (k MachinePublic) MarshalText() ([]byte, error) { return marshalPublic(k[:], k.String()) }

// MarshalText implements encoding.TextMarshaler.
func (k ControlPublic) MarshalText() ([]byte, error) { return marshalPublic(k[:], k.String()) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *MachinePublic) UnmarshalText(b []byte) error {
	return parsePublic(machinePrefix, string(b), k[:])
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *ControlPublic) UnmarshalText(b []byte) error {
	return parsePublic(controlPrefix, string(b), k[:])
}

// ID derives the key ID that names a control key in the MTCP upgrade: the
// first 8 bytes of BLAKE2s-256("meshtransit/key-id/v1" || 0x00 || key),
// the same derivation as signing key IDs.
func (k ControlPublic) ID() KeyID {
	h, _ := blake2s.New256(nil) // unkeyed BLAKE2s never fails
	h.Write([]byte(keyIDDomain))
	h.Write([]byte{0})
	h.Write(k[:])
	var id KeyID
	copy(id[:], h.Sum(nil))
	return id
}

// MachinePrivate is a node installation's machine private key.
type MachinePrivate struct{ private *ecdh.PrivateKey }

// ControlPrivate is a Core deployment's control private key.
type ControlPrivate struct{ private *ecdh.PrivateKey }

// NodePrivate is a node's WireGuard static private key. MTCP uses it only
// to prove possession of the node key (mtcp-v1 §6.4).
type NodePrivate struct{ private *ecdh.PrivateKey }

// NewMachinePrivate generates a machine key from the given CSPRNG
// (crypto/rand.Reader when nil).
func NewMachinePrivate(random io.Reader) (MachinePrivate, error) {
	k, err := generate(orRandom(random))
	return MachinePrivate{k}, err
}

// NewControlPrivate generates a control key from the given CSPRNG
// (crypto/rand.Reader when nil).
func NewControlPrivate(random io.Reader) (ControlPrivate, error) {
	k, err := generate(orRandom(random))
	return ControlPrivate{k}, err
}

func orRandom(random io.Reader) io.Reader {
	if random == nil {
		return rand.Reader
	}
	return random
}

// MachinePrivateFromBytes builds a machine key from raw bytes. The slice is copied.
func MachinePrivateFromBytes(raw []byte) (MachinePrivate, error) {
	k, err := fromBytes(raw)
	return MachinePrivate{k}, err
}

// ControlPrivateFromBytes builds a control key from raw bytes. The slice is copied.
func ControlPrivateFromBytes(raw []byte) (ControlPrivate, error) {
	k, err := fromBytes(raw)
	return ControlPrivate{k}, err
}

// NodePrivateFromBytes builds a node key from raw bytes. The slice is copied.
func NodePrivateFromBytes(raw []byte) (NodePrivate, error) {
	k, err := fromBytes(raw)
	return NodePrivate{k}, err
}

// IsZero reports whether the key is unset.
func (k MachinePrivate) IsZero() bool { return k.private == nil }

// IsZero reports whether the key is unset.
func (k ControlPrivate) IsZero() bool { return k.private == nil }

// IsZero reports whether the key is unset.
func (k NodePrivate) IsZero() bool { return k.private == nil }

// Public returns the matching public key.
func (k MachinePrivate) Public() MachinePublic {
	var p MachinePublic
	if k.private != nil {
		copy(p[:], k.private.PublicKey().Bytes())
	}
	return p
}

// Public returns the matching public key.
func (k ControlPrivate) Public() ControlPublic {
	var p ControlPublic
	if k.private != nil {
		copy(p[:], k.private.PublicKey().Bytes())
	}
	return p
}

// Public returns the matching public key.
func (k NodePrivate) Public() NodePublic {
	var p NodePublic
	if k.private != nil {
		copy(p[:], k.private.PublicKey().Bytes())
	}
	return p
}

// SharedWithPublic performs X25519 with any 32-byte public key: Core uses it
// to check a proof of possession of a node or disco key.
func (k ControlPrivate) SharedWithPublic(peer [Size]byte) ([Size]byte, error) {
	return shared(k.private, peer[:])
}

// SharedWithControl performs X25519 with a control key, for a proof of
// possession.
func (k NodePrivate) SharedWithControl(control ControlPublic) ([Size]byte, error) {
	return shared(k.private, control[:])
}

// SharedWithControl performs X25519 with a control key, for a proof of
// possession of the disco key.
func (k DiscoPrivate) SharedWithControl(control ControlPublic) ([Size]byte, error) {
	return shared(k.private, control[:])
}

// SharedWithControl performs X25519 with a control key, for a proof that a
// gateway holds the machine key it rotates to.
func (k MachinePrivate) SharedWithControl(control ControlPublic) ([Size]byte, error) {
	return shared(k.private, control[:])
}

// ECDH exposes the key for Noise implementations that take *ecdh.PrivateKey.
func (k MachinePrivate) ECDH() *ecdh.PrivateKey { return k.private }

// ECDH exposes the key for Noise implementations that take *ecdh.PrivateKey.
func (k ControlPrivate) ECDH() *ecdh.PrivateKey { return k.private }

// String, GoString, Format and LogValue never reveal private material.
func (MachinePrivate) String() string               { return "mtmachine-private:[REDACTED]" }
func (MachinePrivate) GoString() string             { return "key.MachinePrivate([REDACTED])" }
func (MachinePrivate) LogValue() slog.Value         { return slog.StringValue("[REDACTED]") }
func (k MachinePrivate) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }
func (ControlPrivate) String() string               { return "mtcontrol-private:[REDACTED]" }
func (ControlPrivate) GoString() string             { return "key.ControlPrivate([REDACTED])" }
func (ControlPrivate) LogValue() slog.Value         { return slog.StringValue("[REDACTED]") }
func (k ControlPrivate) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }
func (NodePrivate) String() string                  { return "mtnode-private:[REDACTED]" }
func (NodePrivate) GoString() string                { return "key.NodePrivate([REDACTED])" }
func (NodePrivate) LogValue() slog.Value            { return slog.StringValue("[REDACTED]") }
func (k NodePrivate) Format(f fmt.State, _ rune)    { _, _ = io.WriteString(f, k.String()) }
