package revisionworker

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

const workerIDPrefix = "revision-"

// NewWorkerID returns a non-secret, process-unique identity for lease fencing.
// It intentionally carries no hostname, address, or deployment metadata.
func NewWorkerID() (string, error) {
	return newWorkerID(rand.Reader)
}

func newWorkerID(random io.Reader) (string, error) {
	if random == nil {
		return "", ErrInvalidDispatcher
	}
	var entropy [16]byte
	if _, err := io.ReadFull(random, entropy[:]); err != nil {
		return "", fmt.Errorf("generate revision worker identity: %w", err)
	}
	return workerIDPrefix + hex.EncodeToString(entropy[:]), nil
}
