package registration

import (
	"crypto/sha256"
	"errors"
	"math/big"
)

const intentHashDomain = "meshtransit/registration-intent/v1\x00"

// ErrInvalidRequestHash reports absent or malformed durable idempotency evidence.
var ErrInvalidRequestHash = errors.New("registration: invalid request hash")

// RequestHash is a deterministic digest of the authenticated registration
// semantics. The Registration ID is deliberately excluded because it is the
// idempotency key whose payload this hash protects.
type RequestHash [sha256.Size]byte

// NewRequestHash validates a hash loaded from durable storage.
func NewRequestHash(value [sha256.Size]byte) (RequestHash, error) {
	hash := RequestHash(value)
	if !hash.IsValid() {
		return RequestHash{}, ErrInvalidRequestHash
	}
	return hash, nil
}

// RequestHash returns the canonical semantic hash for this command.
func (command Command) RequestHash() (RequestHash, error) {
	if !command.IsValid() {
		return RequestHash{}, ErrInvalidCommand
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(intentHashDomain))
	workspaceID := command.Scope.WorkspaceID().Bytes()
	_, _ = hasher.Write(workspaceID[:])
	networkID := command.Scope.NetworkID().Bytes()
	_, _ = hasher.Write(networkID[:])
	credentialID := command.CredentialID.Bytes()
	_, _ = hasher.Write(credentialID[:])
	machineKey := command.Identity.MachineKey().Bytes()
	_, _ = hasher.Write(machineKey[:])
	nodeKey := command.Identity.NodeKey().Bytes()
	_, _ = hasher.Write(nodeKey[:])
	var recoveryEpoch [8]byte
	big.NewInt(command.RecoveryEpoch).FillBytes(recoveryEpoch[:])
	_, _ = hasher.Write(recoveryEpoch[:])
	hostname := command.Hostname.String()
	_, _ = hasher.Write([]byte(hostname))

	var value [sha256.Size]byte
	copy(value[:], hasher.Sum(nil))
	return NewRequestHash(value)
}

// Bytes returns a copy for persistence at the database boundary.
func (hash RequestHash) Bytes() [sha256.Size]byte { return [sha256.Size]byte(hash) }

// IsValid reports whether the request hash is present.
func (hash RequestHash) IsValid() bool { return hash != RequestHash{} }
