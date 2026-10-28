package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"meshtransit.net/core/internal/domain/publicid"
)

// kubeCertHintSubscription receives Kubernetes certificate hints (the
// Redis adapter's KubeCertSubscription).
type kubeCertHintSubscription interface {
	Receive(ctx context.Context) (publicid.ID, error)
	Close() error
}

const (
	kubeCertHintMinimumBackoff = time.Second
	kubeCertHintMaximumBackoff = 30 * time.Second
	// kubeCertHintQueue bounds the hints waiting to be published; more are
	// dropped (the receivers poll anyway).
	kubeCertHintQueue = 256
	// kubeCertHintTimeout bounds publishing one hint.
	kubeCertHintTimeout = time.Second
)

var errKubeCertHintsStarted = errors.New("kubernetes certificate hints: already started")

// kubeCertHints listens to one kind of Kubernetes certificate hint (a3 §14
// R-H3) and hands each to deliver, and publishes the other kind from a
// bounded queue on a goroutine of its own, so a Redis that stalls never
// slows signing or a session's wait (review a3b Go M1). Hints are best
// effort: a lost subscription is opened again with backoff and never stops
// the process; the worker and control fall back to polling meanwhile.
type kubeCertHints struct {
	name      string
	subscribe func(context.Context) (kubeCertHintSubscription, error)
	deliver   func(publicid.ID)
	logger    *slog.Logger
	publishes chan func(context.Context)

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan error
}

func newKubeCertHints(name string, subscribe func(context.Context) (kubeCertHintSubscription, error),
	deliver func(publicid.ID), logger *slog.Logger,
) *kubeCertHints {
	return &kubeCertHints{
		name: name, subscribe: subscribe, deliver: deliver, logger: logger,
		publishes: make(chan func(context.Context), kubeCertHintQueue),
	}
}

// Publish queues one publication; it never blocks, and drops it when the
// queue is full or the listener stopped.
func (hints *kubeCertHints) Publish(publish func(context.Context)) {
	select {
	case hints.publishes <- publish:
	default:
	}
}

// Start runs the listener and the publisher until Shutdown.
func (hints *kubeCertHints) Start(context.Context) error {
	hints.mu.Lock()
	defer hints.mu.Unlock()
	if hints.done != nil {
		return errKubeCertHintsStarted
	}
	ctx, cancel := context.WithCancel(context.Background())
	hints.cancel, hints.done = cancel, make(chan error, 1)
	var running sync.WaitGroup
	running.Add(2)
	go func() {
		defer running.Done()
		hints.run(ctx)
	}()
	go func() {
		defer running.Done()
		hints.publish(ctx)
	}()
	go func() {
		running.Wait()
		hints.done <- nil
		close(hints.done)
	}()
	return nil
}

// Done is closed once the listener stopped.
func (hints *kubeCertHints) Done() <-chan error {
	hints.mu.Lock()
	defer hints.mu.Unlock()
	return hints.done
}

// Shutdown stops the listener and waits for it.
func (hints *kubeCertHints) Shutdown(ctx context.Context) error {
	hints.mu.Lock()
	cancel, done := hints.cancel, hints.done
	hints.mu.Unlock()
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

// publish sends queued hints one at a time, each bounded.
func (hints *kubeCertHints) publish(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case publish := <-hints.publishes:
			publishCtx, cancel := context.WithTimeout(ctx, kubeCertHintTimeout)
			publish(publishCtx)
			cancel()
		}
	}
}

func (hints *kubeCertHints) run(ctx context.Context) {
	backoff := kubeCertHintMinimumBackoff
	for ctx.Err() == nil {
		subscription, err := hints.subscribe(ctx)
		if err == nil {
			// Received hints until the subscription failed.
			backoff = kubeCertHintMinimumBackoff
			_ = hints.receive(ctx, subscription)
			_ = subscription.Close()
		}
		if ctx.Err() != nil {
			return
		}
		hints.logger.WarnContext(ctx, "kubernetes certificate hints interrupted", "error_code",
			"kubernetes_certificate_hints_unavailable", "hints", hints.name)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, kubeCertHintMaximumBackoff)
	}
}

// receive hands hints over until the subscription fails; a malformed hint
// is skipped.
func (hints *kubeCertHints) receive(ctx context.Context, subscription kubeCertHintSubscription) error {
	for {
		request, err := subscription.Receive(ctx)
		if err != nil {
			if ctx.Err() != nil || !malformedHint(err) {
				return err
			}
			continue
		}
		hints.deliver(request)
	}
}
