package mtcp

import (
	"crypto/subtle"
	"encoding/hex"

	"golang.org/x/crypto/blake2s"

	"meshtransit.net/shared/key"
)

// Domain strings (docs/protocol/keys.md).
const (
	proofDomain       = "meshtransit/mtcp-key-proof/v1"
	sessionDomain     = "meshtransit/mtcp-node-key-session/v1"
	rotationDomain    = "meshtransit/mtcp-machine-key-rotation/v1"
	fingerprintDomain = "meshtransit/mtcp-control-fp/v1"
	fingerprintSize   = 16
)

// ProofSize is the length of a proof of possession.
const ProofSize = 32

// NodeKeyProof proves possession of a node key in this session (mtcp-v1 §6.4).
func NodeKeyProof(node key.NodePrivate, control key.ControlPublic, handshakeHash [32]byte) ([ProofSize]byte, error) {
	secret, err := node.SharedWithControl(control)
	if err != nil {
		return [ProofSize]byte{}, err
	}
	defer clear(secret[:])
	public := node.Public()
	return proof(secret, handshakeHash, public), nil
}

// DiscoKeyProof proves possession of a disco key in this session.
func DiscoKeyProof(disco key.DiscoPrivate, control key.ControlPublic,
	handshakeHash [32]byte,
) ([ProofSize]byte, error) {
	secret, err := disco.SharedWithControl(control)
	if err != nil {
		return [ProofSize]byte{}, err
	}
	defer clear(secret[:])
	public := disco.Public()
	return proof(secret, handshakeHash, public), nil
}

// VerifyKeyProof checks a node or disco key proof on Core, in constant time
// with respect to the proof.
func VerifyKeyProof(control key.ControlPrivate, handshakeHash [32]byte, public [key.Size]byte, got []byte) bool {
	secret, err := control.SharedWithPublic(public)
	if err != nil || len(got) != ProofSize {
		return false
	}
	defer clear(secret[:])
	want := proof(secret, handshakeHash, public)
	return subtle.ConstantTimeCompare(want[:], got) == 1
}

// NodeKeySessionProof proves, as a session's first record, that the node
// holds the ClientHello's node key (mtcp-v1 §6.7).
func NodeKeySessionProof(node key.NodePrivate, control key.ControlPublic,
	handshakeHash [32]byte,
) ([ProofSize]byte, error) {
	secret, err := node.SharedWithControl(control)
	if err != nil {
		return [ProofSize]byte{}, err
	}
	defer clear(secret[:])
	return domainProof(sessionDomain, secret, handshakeHash, node.Public()), nil
}

// VerifyNodeKeySessionProof checks a NodeKeyProof on Core.
func VerifyNodeKeySessionProof(control key.ControlPrivate, handshakeHash [32]byte, public [key.Size]byte,
	got []byte,
) bool {
	return verifyDomainProof(sessionDomain, control, handshakeHash, public, got)
}

// MachineKeyRotationProof proves possession of the machine key a gateway
// rotates to (mtcp-v1 §6.8).
func MachineKeyRotationProof(next key.MachinePrivate, control key.ControlPublic,
	handshakeHash [32]byte,
) ([ProofSize]byte, error) {
	secret, err := next.SharedWithControl(control)
	if err != nil {
		return [ProofSize]byte{}, err
	}
	defer clear(secret[:])
	return domainProof(rotationDomain, secret, handshakeHash, next.Public()), nil
}

// VerifyMachineKeyRotationProof checks a RotateMachineKey proof on Core.
func VerifyMachineKeyRotationProof(control key.ControlPrivate, handshakeHash [32]byte, public [key.Size]byte,
	got []byte,
) bool {
	return verifyDomainProof(rotationDomain, control, handshakeHash, public, got)
}

func verifyDomainProof(domain string, control key.ControlPrivate, handshakeHash [32]byte, public [key.Size]byte,
	got []byte,
) bool {
	secret, err := control.SharedWithPublic(public)
	if err != nil || len(got) != ProofSize {
		return false
	}
	defer clear(secret[:])
	want := domainProof(domain, secret, handshakeHash, public)
	return subtle.ConstantTimeCompare(want[:], got) == 1
}

// proof is BLAKE2s-256(key = secret, domain || 0x00 || h || K).
func proof(secret, handshakeHash, public [32]byte) [ProofSize]byte {
	return domainProof(proofDomain, secret, handshakeHash, public)
}

func domainProof(domain string, secret, handshakeHash, public [32]byte) [ProofSize]byte {
	h, _ := blake2s.New256(secret[:]) // a 32-byte key is always valid
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(handshakeHash[:])
	h.Write(public[:])
	var out [ProofSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ControlFingerprint returns the fingerprint that enrollment links carry as
// ck=: the first 16 bytes of BLAKE2s-256(domain || 0x00 || key), as 32
// lowercase hex characters (mtcp-v1 §2.1).
func ControlFingerprint(control key.ControlPublic) string {
	h, _ := blake2s.New256(nil) // unkeyed BLAKE2s never fails
	h.Write([]byte(fingerprintDomain))
	h.Write([]byte{0})
	h.Write(control[:])
	return hex.EncodeToString(h.Sum(nil)[:fingerprintSize])
}

// FingerprintMatches compares a fingerprint from a link with a control key
// in constant time.
func FingerprintMatches(control key.ControlPublic, fingerprint string) bool {
	want := ControlFingerprint(control)
	return len(fingerprint) == len(want) && subtle.ConstantTimeCompare([]byte(want), []byte(fingerprint)) == 1
}
