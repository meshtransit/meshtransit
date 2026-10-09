package idempotency_test

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/platform/idempotency"
)

func TestProof(t *testing.T) {
	t.Parallel()

	digest := [32]byte{31: 1}
	proof, err := idempotency.NewProof("kms/idempotency-v1", digest)
	if err != nil {
		t.Fatalf("NewProof() error = %v", err)
	}
	if !proof.IsValid() || proof.DigestKeyID() != "kms/idempotency-v1" ||
		proof.DigestAlgorithm() != idempotency.DigestAlgorithmHMACSHA256V1 ||
		proof.Digest() != digest {
		t.Fatal("NewProof() did not preserve canonical replay evidence")
	}
}

func TestProofRejectsInvalidEvidence(t *testing.T) {
	t.Parallel()

	validDigest := [32]byte{31: 1}
	tests := []struct {
		name   string
		keyID  string
		digest [32]byte
	}{
		{name: "missing key ID", digest: validDigest},
		{name: "invalid first separator", keyID: "/key", digest: validDigest},
		{name: "whitespace", keyID: "key id", digest: validDigest},
		{name: "zero digest", keyID: "key-v1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := idempotency.NewProof(test.keyID, test.digest); !errors.Is(
				err,
				idempotency.ErrInvalidProof,
			) {
				t.Fatalf("NewProof() error = %v, want ErrInvalidProof", err)
			}
		})
	}
	if (idempotency.Proof{}).IsValid() {
		t.Fatal("zero Proof is valid")
	}
}
