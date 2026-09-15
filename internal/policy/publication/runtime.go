package publication

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"
)

const maximumRetryDelay = time.Minute

// ErrInvalidBackoff reports an unsafe retry delay or attempt ordinal.
var ErrInvalidBackoff = errors.New("policy publication: invalid retry backoff")

// SystemClock reads the process wall clock without retaining mutable state.
type SystemClock struct{}

// Now returns the current UTC time.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// ExponentialBackoff provides capped exponential delay with 50-100% jitter.
type ExponentialBackoff struct {
	initial time.Duration
	maximum time.Duration
	entropy io.Reader
}

// NewExponentialBackoff validates retry bounds and uses operating-system entropy.
func NewExponentialBackoff(initial, maximum time.Duration) (*ExponentialBackoff, error) {
	return newExponentialBackoff(initial, maximum, rand.Reader)
}

func newExponentialBackoff(
	initial time.Duration,
	maximum time.Duration,
	entropy io.Reader,
) (*ExponentialBackoff, error) {
	if initial <= 0 || maximum < initial || maximum > maximumRetryDelay || entropy == nil {
		return nil, ErrInvalidBackoff
	}
	return &ExponentialBackoff{initial: initial, maximum: maximum, entropy: entropy}, nil
}

// Wait blocks only the calling goroutine until jittered delay or cancellation.
func (backoff *ExponentialBackoff) Wait(ctx context.Context, attempt int) error {
	if ctx == nil || backoff == nil || backoff.entropy == nil || attempt <= 0 {
		return ErrInvalidBackoff
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	delay := backoff.initial
	for step := 1; step < attempt && delay < backoff.maximum; step++ {
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
		return fmt.Errorf("read policy publication retry jitter: %w", err)
	}
	timer := time.NewTimer(half + time.Duration(offset.Int64()))
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
