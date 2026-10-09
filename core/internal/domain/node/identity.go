// Package node owns logical Node identity, cryptographic key epochs, and
// lifecycle invariants independently of any client wire protocol.
package node

import (
	"crypto/sha256"
	"errors"

	"meshtransit.net/core/internal/domain/publicid"
)

const (
	machineKeyFingerprintDomain = "meshtransit/machine-key/v1\x00"
	nodeKeyFingerprintDomain    = "meshtransit/node-key/v1\x00"
)

var (
	// ErrInvalidID reports an absent or malformed Node public ID.
	ErrInvalidID = errors.New("node: invalid id")
	// ErrInvalidMachineKey reports an unusable authenticated machine public key.
	ErrInvalidMachineKey = errors.New("node: invalid machine key")
	// ErrInvalidKey reports an unusable WireGuard Node public key.
	ErrInvalidKey = errors.New("node: invalid key")
	// ErrInvalidRegistrationIdentity reports an incomplete cryptographic identity.
	ErrInvalidRegistrationIdentity = errors.New("node: invalid registration identity")
)

// ID is a validated opaque UUIDv7 identifying one logical Node.
type ID publicid.ID

// NewID validates and returns a Node ID from its binary representation.
func NewID(value [16]byte) (ID, error) {
	id, err := publicid.FromBytes(value)
	if err != nil {
		return ID{}, ErrInvalidID
	}
	return ID(id), nil
}

// ParseID validates and returns a Node ID from its canonical string.
func ParseID(value string) (ID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ID{}, ErrInvalidID
	}
	return ID(id), nil
}

// String returns the lowercase canonical UUID representation.
func (id ID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the ID satisfies the Node identity contract.
func (id ID) IsValid() bool { return publicid.ID(id).IsValid() }

// MachineKey is the authenticated machine public key at the client boundary.
type MachineKey [32]byte

// NewMachineKey validates and returns a machine public key.
func NewMachineKey(value [32]byte) (MachineKey, error) {
	if value == ([32]byte{}) {
		return MachineKey{}, ErrInvalidMachineKey
	}
	return MachineKey(value), nil
}

// Bytes returns a copy of the machine public key.
func (key MachineKey) Bytes() [32]byte { return [32]byte(key) }

// IsValid reports whether the machine public key is non-zero.
func (key MachineKey) IsValid() bool { return key != MachineKey{} }

// Fingerprint returns a domain-separated digest suitable for indexed equality.
func (key MachineKey) Fingerprint() [32]byte {
	var input [len(machineKeyFingerprintDomain) + len(key)]byte
	copy(input[:], machineKeyFingerprintDomain)
	copy(input[len(machineKeyFingerprintDomain):], key[:])
	return sha256.Sum256(input[:])
}

// Key is a WireGuard Node public key for one key epoch.
type Key [32]byte

// NewKey validates and returns a Node public key.
func NewKey(value [32]byte) (Key, error) {
	if value == ([32]byte{}) {
		return Key{}, ErrInvalidKey
	}
	return Key(value), nil
}

// Bytes returns a copy of the Node public key.
func (key Key) Bytes() [32]byte { return [32]byte(key) }

// IsValid reports whether the Node public key is non-zero.
func (key Key) IsValid() bool { return key != Key{} }

// Fingerprint returns a domain-separated digest suitable for indexed equality.
func (key Key) Fingerprint() [32]byte {
	var input [len(nodeKeyFingerprintDomain) + len(key)]byte
	copy(input[:], nodeKeyFingerprintDomain)
	copy(input[len(nodeKeyFingerprintDomain):], key[:])
	return sha256.Sum256(input[:])
}

// RegistrationIdentity binds the authenticated machine key to the requested
// Node key without assigning Workspace or Network authority.
type RegistrationIdentity struct {
	machineKey MachineKey
	nodeKey    Key
}

// NewRegistrationIdentity validates a complete registration identity.
func NewRegistrationIdentity(machineKey MachineKey, nodeKey Key) (RegistrationIdentity, error) {
	if !machineKey.IsValid() || !nodeKey.IsValid() {
		return RegistrationIdentity{}, ErrInvalidRegistrationIdentity
	}
	return RegistrationIdentity{machineKey: machineKey, nodeKey: nodeKey}, nil
}

// MachineKey returns the authenticated machine public key.
func (identity RegistrationIdentity) MachineKey() MachineKey { return identity.machineKey }

// NodeKey returns the requested Node public key.
func (identity RegistrationIdentity) NodeKey() Key { return identity.nodeKey }

// IsValid reports whether both cryptographic identities are present.
func (identity RegistrationIdentity) IsValid() bool {
	return identity.machineKey.IsValid() && identity.nodeKey.IsValid()
}
