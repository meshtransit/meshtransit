// Package connectivityfeed fans out best-effort transient connectivity wakeups.
package connectivityfeed

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/wakeup"
)

const (
	maximumWatchers         = 1 << 20
	minimumSubscribeTimeout = time.Millisecond
	maximumSubscribeTimeout = 30 * time.Second
)

var (
	// ErrInvalidFeed reports missing dependencies or unsafe bounds.
	ErrInvalidFeed = errors.New("connectivity feed: invalid feed")
	// ErrFeedStarted reports that a Feed may only start once.
	ErrFeedStarted = errors.New("connectivity feed: already started")
	// ErrFeedNotStarted reports shutdown before a successful start.
	ErrFeedNotStarted = errors.New("connectivity feed: not started")
	// ErrFeedUnavailable reports that the feed cannot admit a watcher.
	ErrFeedUnavailable = errors.New("connectivity feed: unavailable")
	// ErrSubscribe reports failure to establish the process-owned subscription.
	ErrSubscribe = errors.New("connectivity feed: subscribe")
	// ErrReceive reports a terminal invalid value from the process-owned subscription.
	ErrReceive = errors.New("connectivity feed: receive")
)

// Subscription is one caller-owned stream of validated connectivity hints.
type Subscription interface {
	Receive(context.Context) (mapsession.ConnectivityChanged, error)
	Close() error
}

// SubscribeFunc establishes one process-owned subscription. Its context bounds
// setup only and must not be retained by the implementation.
type SubscribeFunc func(context.Context) (Subscription, error)

// Options bounds one process-local connectivity fan-out.
type Options struct {
	MaxWatchers      int
	SubscribeTimeout time.Duration
	ReconnectInitial time.Duration
	ReconnectMaximum time.Duration
}

// Feed owns one subscription goroutine and bounded latest-wins watcher mailboxes.
// It retains no authority and wakeup loss is repaired by map reconciliation.
type Feed struct {
	options   Options
	subscribe SubscribeFunc
	telemetry *Telemetry

	mu           sync.Mutex
	starting     bool
	started      bool
	stopping     bool
	cancel       context.CancelFunc
	subscription Subscription
	startDone    chan struct{}
	done         chan error
	nextWatcher  uint64
	watcherCount int
	watchers     map[network.ID]map[uint64]chan mapsession.ConnectivityChanged
}

// New constructs a stopped connectivity feed.
func New(options Options, subscribe SubscribeFunc, telemetry *Telemetry) (*Feed, error) {
	if options.MaxWatchers <= 0 || options.MaxWatchers > maximumWatchers ||
		options.SubscribeTimeout < minimumSubscribeTimeout ||
		options.SubscribeTimeout > maximumSubscribeTimeout ||
		!wakeup.ValidRecoveryOptions(recoveryOptions(options)) ||
		subscribe == nil || telemetry == nil {
		return nil, ErrInvalidFeed
	}
	return &Feed{
		options:   options,
		subscribe: subscribe,
		telemetry: telemetry,
		watchers: make(
			map[network.ID]map[uint64]chan mapsession.ConnectivityChanged,
		),
	}, nil
}

// Start establishes the subscription synchronously, then starts one receive goroutine.
func (feed *Feed) Start(ctx context.Context) error {
	if ctx == nil || feed == nil || feed.subscribe == nil || feed.telemetry == nil {
		return ErrInvalidFeed
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	feed.mu.Lock()
	if feed.started || feed.starting || feed.stopping {
		feed.mu.Unlock()
		return ErrFeedStarted
	}
	workerCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	startDone := make(chan struct{})
	feed.starting = true
	feed.cancel = cancel
	feed.startDone = startDone
	feed.mu.Unlock()
	stopStartupPropagation := context.AfterFunc(ctx, cancel)

	setupCtx, setupCancel := context.WithTimeout(workerCtx, feed.options.SubscribeTimeout)
	subscription, err := feed.subscribe(setupCtx)
	setupErr := setupCtx.Err()
	setupCancel()
	if err != nil || setupErr != nil || isNilSubscription(subscription) {
		if err == nil {
			err = setupErr
		}
		if err == nil {
			err = ErrSubscribe
		}
		if !isNilSubscription(subscription) {
			err = errors.Join(err, subscription.Close())
		}
		stopStartupPropagation()
		return feed.finishFailedStart(workerCtx, cancel, startDone, err)
	}

	feed.mu.Lock()
	if feed.stopping || ctx.Err() != nil || workerCtx.Err() != nil {
		feed.starting = false
		feed.cancel = nil
		feed.startDone = nil
		feed.mu.Unlock()
		stopStartupPropagation()
		cancel()
		close(startDone)
		return errors.Join(context.Canceled, subscription.Close())
	}
	done := make(chan error, 1)
	feed.cancel = cancel
	feed.subscription = subscription
	feed.done = done
	feed.starting = false
	feed.started = true
	feed.startDone = nil
	feed.telemetry.setConnected(true)
	go func() {
		done <- feed.run(workerCtx, subscription)
		close(done)
	}()
	close(startDone)
	feed.mu.Unlock()
	stopStartupPropagation()
	return nil
}

func (feed *Feed) finishFailedStart(
	workerCtx context.Context,
	cancel context.CancelFunc,
	startDone chan struct{},
	cause error,
) error {
	canceled := workerCtx.Err() != nil
	cancel()
	feed.mu.Lock()
	stopping := feed.stopping
	feed.starting = false
	feed.cancel = nil
	feed.startDone = nil
	close(startDone)
	feed.mu.Unlock()
	if stopping || errors.Is(cause, context.Canceled) || canceled {
		return context.Canceled
	}
	return errors.Join(ErrSubscribe, cause)
}

// Done returns the join channel after Start succeeds.
func (feed *Feed) Done() <-chan error {
	if feed == nil {
		return nil
	}
	feed.mu.Lock()
	defer feed.mu.Unlock()
	return feed.done
}

// Shutdown cancels receive and closes the process-owned subscription.
func (feed *Feed) Shutdown(ctx context.Context) error {
	if ctx == nil || feed == nil {
		return ErrInvalidFeed
	}
	feed.mu.Lock()
	if feed.starting {
		feed.stopping = true
		cancel := feed.cancel
		startDone := feed.startDone
		feed.mu.Unlock()
		cancel()
		select {
		case <-startDone:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if !feed.started {
		feed.mu.Unlock()
		return ErrFeedNotStarted
	}
	feed.stopping = true
	cancel := feed.cancel
	subscription := feed.subscription
	feed.mu.Unlock()
	cancel()
	return subscription.Close()
}

func (feed *Feed) run(ctx context.Context, subscription Subscription) error {
	defer feed.stopWatching()
	defer feed.telemetry.setConnected(false)
	return wakeup.RunRecovery(
		ctx,
		subscription,
		func(subscribeCtx context.Context) (wakeup.Subscription[mapsession.ConnectivityChanged], error) {
			return feed.subscribe(subscribeCtx)
		},
		recoveryOptions(feed.options),
		wakeup.RecoveryObserver{
			SetConnected:     feed.telemetry.setConnected,
			ReconnectAttempt: feed.telemetry.reconnectAttempt,
			ReconnectSuccess: feed.telemetry.reconnectSuccess,
		},
		func(change mapsession.ConnectivityChanged) error {
			if !change.IsValid() {
				return errors.Join(ErrReceive, ErrInvalidFeed)
			}
			feed.dispatch(change)
			return nil
		},
	)
}

func recoveryOptions(options Options) wakeup.RecoveryOptions {
	return wakeup.RecoveryOptions{
		SubscribeTimeout: options.SubscribeTimeout,
		RetryInitial:     options.ReconnectInitial,
		RetryMaximum:     options.ReconnectMaximum,
	}
}

func isNilSubscription(subscription Subscription) bool {
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
