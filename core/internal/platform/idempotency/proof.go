// Package idempotency owns bounded, secret-safe request replay evidence.
package idempotency

import "errors"

const (
	// DigestAlgorithmHMACSHA256V1 identifies the only accepted key-digest format.
	DigestAlgorithmHMACSHA256V1 = "hmac-sha256-v1"
	maximumDigestKeyIDBytes     = 128
)

var (
	// ErrInvalidProof reports missing or malformed HMAC replay evidence.
	ErrInvalidProof = errors.New("idempotency: invalid proof")
)

// Proof contains only a versioned HMAC digest and its non-secret key ID. The
// raw caller-supplied idempotency key must be discarded at the API boundary.
type Proof struct {
	digestKeyID string
	digest      [32]byte
}

// NewProof validates secret-safe idempotency evidence.
func NewProof(digestKeyID string, digest [32]byte) (Proof, error) {
	proof := Proof{digestKeyID: digestKeyID, digest: digest}
	if !proof.IsValid() {
		return Proof{}, ErrInvalidProof
	}
	return proof, nil
}

// DigestAlgorithm returns the fixed, versioned digest contract.
func (Proof) DigestAlgorithm() string { return DigestAlgorithmHMACSHA256V1 }

// DigestKeyID returns the non-secret identifier of the HMAC key generation.
func (proof Proof) DigestKeyID() string { return proof.digestKeyID }

// Digest returns a defensive copy of the request-key HMAC.
func (proof Proof) Digest() [32]byte { return proof.digest }

// IsValid reports whether the proof is bounded and canonical.
func (proof Proof) IsValid() bool {
	if proof.digest == ([32]byte{}) || !validDigestKeyID(proof.digestKeyID) {
		return false
	}
	return true
}

func validDigestKeyID(value string) bool {
	if len(value) == 0 || len(value) > maximumDigestKeyIDBytes {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			(index > 0 && (character == '.' || character == '_' || character == ':' ||
				character == '/' || character == '-')) {
			continue
		}
		return false
	}
	return true
}
