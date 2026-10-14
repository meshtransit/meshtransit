package controlplane

import (
	"errors"
	"time"
)

// MaxRetryAfter bounds how long a node waits because Core asked it to: a
// wrong or hostile value cannot keep a Device away for longer.
const MaxRetryAfter = 15 * time.Minute

// RetryAfterError is an error Core answered with a wait: retry_after_ms of
// an MTCP Error or Lifecycle, or the Retry-After of a 503 or 429.
type RetryAfterError struct {
	Err  error
	Wait time.Duration
}

func (err *RetryAfterError) Error() string { return err.Err.Error() }

func (err *RetryAfterError) Unwrap() error { return err.Err }

// WithRetryAfter attaches Core's wait to err; a wait of zero or less leaves
// err as it is.
func WithRetryAfter(err error, wait time.Duration) error {
	if err == nil || wait <= 0 {
		return err
	}
	return &RetryAfterError{Err: err, Wait: wait}
}

// RetryAfterOf returns the wait Core attached to err, at most MaxRetryAfter,
// or zero.
func RetryAfterOf(err error) time.Duration {
	var retry *RetryAfterError
	if !errors.As(err, &retry) {
		return 0
	}
	return min(max(retry.Wait, 0), MaxRetryAfter)
}
