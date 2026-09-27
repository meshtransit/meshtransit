// Package wakeup owns transport-agnostic recovery for transient wakeup streams.
package wakeup

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"time"
)

const (
	minimumRetryDelay = time.Millisecond
	maximumRetryDelay = time.Minute
)

// ErrInvalidRecovery reports missing dependencies or unsafe retry bounds.
var ErrInvalidRecovery = errors.New("invalid wakeup recovery")

// Subscription is one caller-owned, context-cancelable wakeup transport.
type Subscription[T any] interface {
	Receive(context.Context) (T, error)
	Close() error
}

// RecoveryOptions bound subscription setup and reconnect backoff.
type RecoveryOptions struct {
	SubscribeTimeout time.Duration
	RetryInitial     time.Duration
	RetryMaximum     time.Duration
}

// RecoveryObserver exposes bounded state transitions without transport detail.
type RecoveryObserver struct {
	SetConnected     func(bool)
	ReconnectAttempt func()
	ReconnectSuccess func()
}

// ValidRecoveryOptions reports whether retry bounds are safe and coherent.
func ValidRecoveryOptions(options RecoveryOptions) bool {
	return options.SubscribeTimeout > 0 &&
		options.RetryInitial >= minimumRetryDelay &&
		options.RetryMaximum >= options.RetryInitial &&
		options.RetryMaximum <= maximumRetryDelay
}

// RunRecovery receives wakeups until cancellation. Transport loss closes the
// failed subscription and reconnects forever with bounded jittered backoff.
// The caller-provided consumer decides whether a successfully received value
// is valid; consumer errors remain terminal instead of being hidden by retry.
func RunRecovery[T any](
	ctx context.Context,
	initial Subscription[T],
	subscribe func(context.Context) (Subscription[T], error),
	options RecoveryOptions,
	observer RecoveryObserver,
	consume func(T) error,
) error {
	if ctx == nil || isNilSubscription(initial) || subscribe == nil || consume == nil ||
		!ValidRecoveryOptions(options) || observer.SetConnected == nil ||
		observer.ReconnectAttempt == nil || observer.ReconnectSuccess == nil {
		return ErrInvalidRecovery
	}

	current := initial
	for {
		value, err := current.Receive(ctx)
		if err == nil {
			if consumeErr := consume(value); consumeErr != nil {
				observer.SetConnected(false)
				return errors.Join(consumeErr, current.Close())
			}
			continue
		}

		observer.SetConnected(false)
		closeErr := current.Close()
		if ctx.Err() != nil {
			return closeErr
		}

		next, recoveryErr := reconnect(ctx, subscribe, options, observer)
		if recoveryErr != nil {
			if ctx.Err() != nil {
				return closeErr
			}
			return errors.Join(recoveryErr, closeErr)
		}
		current = next
		observer.SetConnected(true)
	}
}

func reconnect[T any](
	ctx context.Context,
	subscribe func(context.Context) (Subscription[T], error),
	options RecoveryOptions,
	observer RecoveryObserver,
) (Subscription[T], error) {
	for attempt := 1; ; attempt = nextAttempt(attempt) {
		if err := waitRetry(ctx, attempt, options, rand.Reader); err != nil {
			return nil, err
		}
		observer.ReconnectAttempt()

		setupCtx, cancel := context.WithTimeout(ctx, options.SubscribeTimeout)
		subscription, err := subscribe(setupCtx)
		setupErr := setupCtx.Err()
		cancel()
		if err == nil && setupErr == nil && !isNilSubscription(subscription) {
			observer.ReconnectSuccess()
			return subscription, nil
		}
		if !isNilSubscription(subscription) {
			_ = subscription.Close()
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
}

func waitRetry(
	ctx context.Context,
	attempt int,
	options RecoveryOptions,
	entropy io.Reader,
) error {
	if ctx == nil || attempt <= 0 || entropy == nil || !ValidRecoveryOptions(options) {
		return ErrInvalidRecovery
	}

	delay := options.RetryInitial
	for step := 1; step < attempt && delay < options.RetryMaximum; step++ {
		if delay > options.RetryMaximum/2 {
			delay = options.RetryMaximum
			break
		}
		delay *= 2
	}
	if delay > options.RetryMaximum {
		delay = options.RetryMaximum
	}
	half := delay / 2
	window := delay - half
	offset, err := rand.Int(entropy, big.NewInt(int64(window)+1))
	if err != nil {
		return fmt.Errorf("%w: read retry entropy: %w", ErrInvalidRecovery, err)
	}

	timer := time.NewTimer(half + time.Duration(offset.Int64()))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func nextAttempt(attempt int) int {
	maximumInt := int(^uint(0) >> 1)
	if attempt == maximumInt {
		return maximumInt
	}
	return attempt + 1
}

func isNilSubscription[T any](subscription Subscription[T]) bool {
	if subscription == nil {
		return true
	}
	value := reflect.ValueOf(subscription)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
