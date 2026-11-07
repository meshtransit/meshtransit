package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Device alias hints (docs/performance-logic-plan.md §8, L1b): control
// announces each recorded alias claim, and the Device alias workers listen
// to those claims and to Network revisions, so an idle worker can space its
// sweeps out. Hints are best effort: while a subscription is down the worker
// is told it is not listening and sweeps at its poll interval.

const (
	aliasHintMinimumBackoff = time.Second
	aliasHintMaximumBackoff = 30 * time.Second
	// aliasHintPublishTimeout bounds publishing one claim hint.
	aliasHintPublishTimeout = time.Second
	// aliasHintPublishSpacing spaces one control replica's claim hints: the
	// workers sweep no more often than this anyway.
	aliasHintPublishSpacing = 500 * time.Millisecond
	// aliasHintWarnInterval bounds the warnings about failed publishes.
	aliasHintWarnInterval = time.Minute
)

var errAliasHintsStarted = errors.New("device alias hints: already started")

// aliasHintSubscription receives one kind of hint; Receive returns nil for
// a hint, errMalformedAliasHint for a message to skip, and any other error
// when the subscription failed.
type aliasHintSubscription interface {
	Receive(context.Context) error
	Close() error
}

var errMalformedAliasHint = errors.New("device alias hints: malformed hint")

// aliasHintSource opens one subscription; name labels it in logs.
type aliasHintSource struct {
	name      string
	subscribe func(context.Context) (aliasHintSubscription, error)
}

// serviceLifecycle runs one goroutine function until Shutdown.
type serviceLifecycle struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan error
}

func (lifecycle *serviceLifecycle) start(runs ...func(context.Context)) error {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.done != nil {
		return errAliasHintsStarted
	}
	ctx, cancel := context.WithCancel(context.Background())
	lifecycle.cancel, lifecycle.done = cancel, make(chan error, 1)
	var running sync.WaitGroup
	for _, run := range runs {
		running.Go(func() { run(ctx) })
	}
	go func() {
		running.Wait()
		lifecycle.done <- nil
		close(lifecycle.done)
	}()
	return nil
}

func (lifecycle *serviceLifecycle) Done() <-chan error {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	return lifecycle.done
}

func (lifecycle *serviceLifecycle) Shutdown(ctx context.Context) error {
	lifecycle.mu.Lock()
	cancel, done := lifecycle.cancel, lifecycle.done
	lifecycle.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// aliasWorkHints merges hint sources into one coalescing wakeup for the
// Device alias worker (devicealias.Hints).
type aliasWorkHints struct {
	serviceLifecycle
	sources []aliasHintSource
	logger  *slog.Logger
	wakeups chan struct{}
	// open counts the sources whose subscription is open.
	open atomic.Int32
}

func newAliasWorkHints(logger *slog.Logger, sources ...aliasHintSource) *aliasWorkHints {
	return &aliasWorkHints{sources: sources, logger: logger, wakeups: make(chan struct{}, 1)}
}

// Wakeups delivers at most one pending wakeup; more fold into it.
func (hints *aliasWorkHints) Wakeups() <-chan struct{} { return hints.wakeups }

// Listening reports whether every source's subscription is open.
func (hints *aliasWorkHints) Listening() bool {
	return len(hints.sources) > 0 && int(hints.open.Load()) == len(hints.sources)
}

// Start listens to every source until Shutdown.
func (hints *aliasWorkHints) Start(context.Context) error {
	runs := make([]func(context.Context), 0, len(hints.sources))
	for _, source := range hints.sources {
		runs = append(runs, func(ctx context.Context) { hints.listen(ctx, source) })
	}
	return hints.start(runs...)
}

func (hints *aliasWorkHints) wake() {
	select {
	case hints.wakeups <- struct{}{}:
	default:
	}
}

// listen keeps one source subscribed, opening it again with backoff.
func (hints *aliasWorkHints) listen(ctx context.Context, source aliasHintSource) {
	backoff := aliasHintMinimumBackoff
	for ctx.Err() == nil {
		subscription, err := source.subscribe(ctx)
		if err == nil {
			backoff = aliasHintMinimumBackoff
			hints.open.Add(1)
			// Anything may have changed while the source was not listening.
			hints.wake()
			hints.receive(ctx, subscription)
			hints.open.Add(-1)
			_ = subscription.Close()
		}
		if ctx.Err() != nil {
			return
		}
		hints.logger.WarnContext(ctx, "device alias hints interrupted; the worker sweeps at its poll interval",
			"error_code", "device_alias_hints_unavailable", "hints", source.name)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, aliasHintMaximumBackoff)
	}
}

func (hints *aliasWorkHints) receive(ctx context.Context, subscription aliasHintSubscription) {
	for {
		err := subscription.Receive(ctx)
		switch {
		case err == nil:
			hints.wake()
		case ctx.Err() != nil || !errors.Is(err, errMalformedAliasHint):
			return
		}
	}
}

// aliasClaimAnnouncer publishes claim hints for control without ever
// blocking a map session: claims that arrive while one is being published
// fold into one more publication.
type aliasClaimAnnouncer struct {
	serviceLifecycle
	publish func(context.Context) error
	logger  *slog.Logger
	pending chan struct{}
}

func newAliasClaimAnnouncer(publish func(context.Context) error, logger *slog.Logger) *aliasClaimAnnouncer {
	return &aliasClaimAnnouncer{publish: publish, logger: logger, pending: make(chan struct{}, 1)}
}

// Claimed queues one announcement; it never blocks.
func (announcer *aliasClaimAnnouncer) Claimed() {
	select {
	case announcer.pending <- struct{}{}:
	default:
	}
}

// Start publishes queued announcements until Shutdown.
func (announcer *aliasClaimAnnouncer) Start(context.Context) error {
	return announcer.start(announcer.run)
}

func (announcer *aliasClaimAnnouncer) run(ctx context.Context) {
	var warned time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-announcer.pending:
		}
		publishCtx, cancel := context.WithTimeout(ctx, aliasHintPublishTimeout)
		err := announcer.publish(publishCtx)
		cancel()
		// A lost hint costs latency only: the workers still sweep.
		if err != nil && ctx.Err() == nil && time.Since(warned) >= aliasHintWarnInterval {
			warned = time.Now()
			announcer.logger.WarnContext(ctx, "device alias claim hint not published; the workers find the work later",
				"error_code", "device_alias_claim_hint_failed", "error", err)
		}
		// Claims during the pause fold into the next publication.
		select {
		case <-ctx.Done():
			return
		case <-time.After(aliasHintPublishSpacing):
		}
	}
}
