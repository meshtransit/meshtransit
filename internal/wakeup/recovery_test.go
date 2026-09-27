package wakeup

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestRunRecoveryReconnectsAndPreservesConsumption(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := newRecoverySubscription[int]()
		second := newRecoverySubscription[int]()
		var subscribeCalls atomic.Int32
		observer, state := newRecoveryObserver()
		consumed := make(chan int, 1)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() {
			result <- RunRecovery(
				ctx,
				first,
				func(context.Context) (Subscription[int], error) {
					subscribeCalls.Add(1)
					return second, nil
				},
				testRecoveryOptions(),
				observer,
				func(value int) error {
					consumed <- value
					return nil
				},
			)
		}()

		first.fail(errors.New("transport lost"))
		time.Sleep(10 * time.Millisecond)
		synctest.Wait()
		second.send(42)
		synctest.Wait()
		if value := <-consumed; value != 42 {
			t.Fatalf("consumed value = %d, want 42", value)
		}
		connected, attempts, successes := state.snapshot()
		if !connected || attempts != 1 || successes != 1 || subscribeCalls.Load() != 1 {
			t.Fatalf(
				"recovery state = (%t,%d,%d), subscribe calls = %d",
				connected,
				attempts,
				successes,
				subscribeCalls.Load(),
			)
		}
		if first.closeCount() != 1 {
			t.Fatalf("failed subscription close calls = %d, want 1", first.closeCount())
		}

		cancel()
		synctest.Wait()
		if err := <-result; err != nil {
			t.Fatalf("RunRecovery() error = %v", err)
		}
		if second.closeCount() != 1 {
			t.Fatalf("recovered subscription close calls = %d, want 1", second.closeCount())
		}
	})
}

func TestRunRecoveryRetriesFailedAndNilSubscriptions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := newRecoverySubscription[int]()
		second := newRecoverySubscription[int]()
		var subscribeCalls atomic.Int32
		observer, state := newRecoveryObserver()
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() {
			result <- RunRecovery(
				ctx,
				first,
				func(context.Context) (Subscription[int], error) {
					switch subscribeCalls.Add(1) {
					case 1:
						return nil, errors.New("setup unavailable")
					case 2:
						var typedNil *recoverySubscription[int]
						return typedNil, nil
					default:
						return second, nil
					}
				},
				testRecoveryOptions(),
				observer,
				func(int) error { return nil },
			)
		}()

		first.fail(errors.New("transport lost"))
		time.Sleep(10 * time.Millisecond)
		synctest.Wait()
		connected, attempts, successes := state.snapshot()
		if !connected || attempts != 3 || successes != 1 || subscribeCalls.Load() != 3 {
			t.Fatalf(
				"recovery state = (%t,%d,%d), subscribe calls = %d",
				connected,
				attempts,
				successes,
				subscribeCalls.Load(),
			)
		}

		cancel()
		synctest.Wait()
		if err := <-result; err != nil {
			t.Fatalf("RunRecovery() error = %v", err)
		}
	})
}

func TestRunRecoveryBoundsReconnectSetup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := newRecoverySubscription[int]()
		second := newRecoverySubscription[int]()
		var subscribeCalls atomic.Int32
		var timedOut atomic.Bool
		observer, state := newRecoveryObserver()
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() {
			result <- RunRecovery(
				ctx,
				first,
				func(setupCtx context.Context) (Subscription[int], error) {
					if subscribeCalls.Add(1) == 1 {
						<-setupCtx.Done()
						timedOut.Store(errors.Is(setupCtx.Err(), context.DeadlineExceeded))
						return nil, setupCtx.Err()
					}
					return second, nil
				},
				testRecoveryOptions(),
				observer,
				func(int) error { return nil },
			)
		}()

		first.fail(errors.New("transport lost"))
		time.Sleep(2 * time.Second)
		synctest.Wait()
		connected, attempts, successes := state.snapshot()
		if !timedOut.Load() || !connected || attempts != 2 || successes != 1 ||
			subscribeCalls.Load() != 2 {
			t.Fatalf(
				"bounded recovery = (timeout=%t,connected=%t,attempts=%d,successes=%d,calls=%d)",
				timedOut.Load(),
				connected,
				attempts,
				successes,
				subscribeCalls.Load(),
			)
		}

		cancel()
		synctest.Wait()
		if err := <-result; err != nil {
			t.Fatalf("RunRecovery() error = %v", err)
		}
	})
}

func TestRunRecoveryKeepsConsumerErrorsTerminal(t *testing.T) {
	t.Parallel()

	subscription := newRecoverySubscription[int]()
	subscription.sendBuffered(7)
	wantErr := errors.New("invalid wakeup")
	observer, state := newRecoveryObserver()
	err := RunRecovery(
		t.Context(),
		subscription,
		func(context.Context) (Subscription[int], error) {
			t.Fatal("consumer failure attempted to reconnect")
			return nil, nil
		},
		testRecoveryOptions(),
		observer,
		func(int) error { return wantErr },
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("RunRecovery() error = %v, want consumer error", err)
	}
	connected, attempts, successes := state.snapshot()
	if connected || attempts != 0 || successes != 0 || subscription.closeCount() != 1 {
		t.Fatalf(
			"terminal state = (%t,%d,%d), close calls = %d",
			connected,
			attempts,
			successes,
			subscription.closeCount(),
		)
	}
}

func TestRunRecoveryRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	validSubscription := newRecoverySubscription[int]()
	validSubscribe := func(context.Context) (Subscription[int], error) {
		return validSubscription, nil
	}
	validObserver, _ := newRecoveryObserver()
	validConsumer := func(int) error { return nil }
	var nilContext context.Context
	var typedNil *recoverySubscription[int]
	tests := []struct {
		name      string
		ctx       context.Context
		initial   Subscription[int]
		subscribe func(context.Context) (Subscription[int], error)
		options   RecoveryOptions
		observer  RecoveryObserver
		consume   func(int) error
	}{
		{name: "nil context", initial: validSubscription, subscribe: validSubscribe, options: testRecoveryOptions(), observer: validObserver, consume: validConsumer},
		{name: "typed nil subscription", ctx: t.Context(), initial: typedNil, subscribe: validSubscribe, options: testRecoveryOptions(), observer: validObserver, consume: validConsumer},
		{name: "missing subscribe", ctx: t.Context(), initial: validSubscription, options: testRecoveryOptions(), observer: validObserver, consume: validConsumer},
		{name: "invalid retry", ctx: t.Context(), initial: validSubscription, subscribe: validSubscribe, observer: validObserver, consume: validConsumer},
		{name: "missing observer", ctx: t.Context(), initial: validSubscription, subscribe: validSubscribe, options: testRecoveryOptions(), consume: validConsumer},
		{name: "missing consumer", ctx: t.Context(), initial: validSubscription, subscribe: validSubscribe, options: testRecoveryOptions(), observer: validObserver},
	}
	tests[0].ctx = nilContext
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := RunRecovery(test.ctx, test.initial, test.subscribe, test.options, test.observer, test.consume); !errors.Is(err, ErrInvalidRecovery) {
				t.Fatalf("RunRecovery() error = %v, want ErrInvalidRecovery", err)
			}
		})
	}
}

func testRecoveryOptions() RecoveryOptions {
	return RecoveryOptions{
		SubscribeTimeout: time.Second,
		RetryInitial:     time.Millisecond,
		RetryMaximum:     4 * time.Millisecond,
	}
}

type recoveryResult[T any] struct {
	value T
	err   error
}

type recoverySubscription[T any] struct {
	results chan recoveryResult[T]
	closes  atomic.Int32
}

func newRecoverySubscription[T any]() *recoverySubscription[T] {
	return &recoverySubscription[T]{results: make(chan recoveryResult[T])}
}

func (subscription *recoverySubscription[T]) Receive(ctx context.Context) (T, error) {
	select {
	case result := <-subscription.results:
		return result.value, result.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

func (subscription *recoverySubscription[T]) Close() error {
	subscription.closes.Add(1)
	return nil
}

func (subscription *recoverySubscription[T]) send(value T) {
	subscription.results <- recoveryResult[T]{value: value}
}

func (subscription *recoverySubscription[T]) sendBuffered(value T) {
	subscription.results = make(chan recoveryResult[T], 1)
	subscription.results <- recoveryResult[T]{value: value}
}

func (subscription *recoverySubscription[T]) fail(err error) {
	subscription.results <- recoveryResult[T]{err: err}
}

func (subscription *recoverySubscription[T]) closeCount() int32 {
	return subscription.closes.Load()
}

type recoveryObserverState struct {
	mu        sync.Mutex
	connected bool
	attempts  uint64
	successes uint64
}

func newRecoveryObserver() (RecoveryObserver, *recoveryObserverState) {
	state := &recoveryObserverState{connected: true}
	return RecoveryObserver{
		SetConnected: func(connected bool) {
			state.mu.Lock()
			state.connected = connected
			state.mu.Unlock()
		},
		ReconnectAttempt: func() {
			state.mu.Lock()
			state.attempts++
			state.mu.Unlock()
		},
		ReconnectSuccess: func() {
			state.mu.Lock()
			state.successes++
			state.mu.Unlock()
		},
	}, state
}

func (state *recoveryObserverState) snapshot() (bool, uint64, uint64) {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.connected, state.attempts, state.successes
}
