package registration

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

const maxRetryDelay = time.Minute

// ErrInvalidBackoff reports an unsafe retry delay or retry ordinal.
var ErrInvalidBackoff = errors.New("registration: invalid retry backoff")

// SystemClock reads the process wall clock without retaining mutable state.
type SystemClock struct{}

// Now returns the current UTC time.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// PublicNodeIDGenerator creates UUIDv7 Node IDs from OS entropy.
type PublicNodeIDGenerator struct{}

// NewNodeID returns a fresh application-owned Node ID.
func (PublicNodeIDGenerator) NewNodeID() (node.ID, error) {
	id, err := publicid.New()
	if err != nil {
		return node.ID{}, fmt.Errorf("generate public Node ID: %w", err)
	}
	nodeID, err := node.NewID(id.Bytes())
	if err != nil {
		return node.ID{}, fmt.Errorf("construct public Node ID: %w", err)
	}
	return nodeID, nil
}

// ExponentialBackoff provides capped exponential delay with 50-100% jitter.
// Wait owns no goroutine and stops its timer on cancellation.
type ExponentialBackoff struct {
	initial time.Duration
	maximum time.Duration
	entropy io.Reader
}

// NewExponentialBackoff validates retry delay bounds and uses OS entropy.
func NewExponentialBackoff(initial, maximum time.Duration) (*ExponentialBackoff, error) {
	return newExponentialBackoff(initial, maximum, rand.Reader)
}

func newExponentialBackoff(
	initial time.Duration,
	maximum time.Duration,
	entropy io.Reader,
) (*ExponentialBackoff, error) {
	if initial <= 0 || maximum < initial || maximum > maxRetryDelay || entropy == nil {
		return nil, ErrInvalidBackoff
	}
	return &ExponentialBackoff{initial: initial, maximum: maximum, entropy: entropy}, nil
}

// Wait blocks only the calling goroutine until the jittered delay or context cancellation.
func (backoff *ExponentialBackoff) Wait(ctx context.Context, retry int) error {
	if ctx == nil || backoff == nil || backoff.entropy == nil || retry <= 0 {
		return ErrInvalidBackoff
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	delay := backoff.initial
	for step := 1; step < retry && delay < backoff.maximum; step++ {
		if delay > backoff.maximum/2 {
			delay = backoff.maximum
			break
		}
		delay *= 2
	}
	if delay > backoff.maximum {
		delay = backoff.maximum
	}

	half := delay / 2
	window := delay - half
	offset, err := rand.Int(backoff.entropy, big.NewInt(int64(window)+1))
	if err != nil {
		return fmt.Errorf("read registration retry jitter: %w", err)
	}
	jittered := half + time.Duration(offset.Int64())
	timer := time.NewTimer(jittered)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
