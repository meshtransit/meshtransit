package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
)

type fakeAliasSubscription struct {
	messages chan error
	closed   atomic.Bool
}

func newFakeAliasSubscription() *fakeAliasSubscription {
	return &fakeAliasSubscription{messages: make(chan error)}
}

func (subscription *fakeAliasSubscription) Receive(ctx context.Context) error {
	select {
	case err := <-subscription.messages:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (subscription *fakeAliasSubscription) Close() error {
	subscription.closed.Store(true)
	return nil
}

func drainWake(hints *aliasWorkHints) bool {
	select {
	case <-hints.Wakeups():
		return true
	default:
		return false
	}
}

func TestAliasWorkHintsListenWakeAndReconnect(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
		claims := newFakeAliasSubscription()
		var mu sync.Mutex
		revisions := []*fakeAliasSubscription{newFakeAliasSubscription(), newFakeAliasSubscription()}
		revisionOpens := 0
		hints := newAliasWorkHints(logger,
			aliasHintSource{name: "claims", subscribe: func(context.Context) (aliasHintSubscription, error) {
				return claims, nil
			}},
			aliasHintSource{name: "revisions", subscribe: func(context.Context) (aliasHintSubscription, error) {
				mu.Lock()
				defer mu.Unlock()
				subscription := revisions[revisionOpens]
				revisionOpens++
				return subscription, nil
			}},
		)
		if hints.Listening() {
			t.Fatal("listening before Start")
		}
		if err := hints.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if !hints.Listening() || !drainWake(hints) || drainWake(hints) {
			t.Fatal("want listening and exactly one catch-up wakeup")
		}

		// A hint wakes; a malformed one does not and keeps the subscription.
		claims.messages <- nil
		synctest.Wait()
		if !drainWake(hints) {
			t.Fatal("a claim hint did not wake")
		}
		claims.messages <- errMalformedAliasHint
		synctest.Wait()
		if drainWake(hints) || !hints.Listening() {
			t.Fatal("a malformed hint woke or closed the subscription")
		}

		// The revision subscription fails: not listening until it reopens.
		revisions[0].messages <- errors.New("connection reset")
		synctest.Wait()
		if hints.Listening() || !revisions[0].closed.Load() {
			t.Fatal("still listening after a failed subscription")
		}
		time.Sleep(aliasHintMinimumBackoff)
		synctest.Wait()
		if !hints.Listening() || !drainWake(hints) {
			t.Fatal("not listening with a catch-up wakeup after reconnecting")
		}

		if err := hints.Shutdown(t.Context()); err != nil {
			t.Fatal(err)
		}
		<-hints.Done()
		if !claims.closed.Load() || !revisions[1].closed.Load() {
			t.Fatal("Shutdown left a subscription open")
		}
	})
}

func TestAliasClaimAnnouncerFoldsClaimsAndNeverBlocks(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var publishes atomic.Int32
		var failures atomic.Int32
		announcer := newAliasClaimAnnouncer(func(ctx context.Context) error {
			publishes.Add(1)
			select {
			case <-release:
			case <-ctx.Done():
			}
			if failures.Load() > 0 {
				return errors.New("NOPERM")
			}
			return nil
		}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
		if err := announcer.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		announcer.Claimed()
		synctest.Wait() // the first publish is in flight and blocked
		for range 100 {
			announcer.Claimed() // never blocks
		}
		close(release)
		time.Sleep(aliasHintPublishSpacing)
		synctest.Wait()
		if got := publishes.Load(); got != 2 {
			t.Fatalf("published %d times, want 2 (the claims during a publish fold into one)", got)
		}
		// Publishes are spaced: two claims 100 ms apart publish once more
		// only after the spacing.
		failures.Store(1)
		time.Sleep(aliasHintPublishSpacing)
		announcer.Claimed()
		synctest.Wait()
		announcer.Claimed()
		synctest.Wait()
		if got := publishes.Load(); got != 3 {
			t.Fatalf("published %d times, want 3", got)
		}
		time.Sleep(aliasHintPublishSpacing)
		synctest.Wait()
		if got := publishes.Load(); got != 4 {
			t.Fatalf("published %d times after the spacing, want 4", got)
		}
		if err := announcer.Shutdown(t.Context()); err != nil {
			t.Fatal(err)
		}
		<-announcer.Done()
	})
}

func TestAliasHintSubscriptionsMapErrors(t *testing.T) {
	t.Parallel()
	failure := errors.New("connection reset")
	if err := claimHintResult(redisadapter.ErrInvalidDeviceAliasWakeup); !errors.Is(err, errMalformedAliasHint) {
		t.Errorf("malformed claim hint = %v, want skipped", err)
	}
	if err := claimHintResult(failure); !errors.Is(err, failure) || errors.Is(err, errMalformedAliasHint) {
		t.Errorf("claim transport failure = %v, want the failure", err)
	}
	if err := revisionHintResult(redisadapter.ErrInvalidRevisionWakeup); err != nil {
		t.Errorf("undecodable revision wakeup = %v, want a hint", err)
	}
	if err := revisionHintResult(failure); !errors.Is(err, failure) {
		t.Errorf("revision transport failure = %v, want the failure", err)
	}
	if claimHintResult(nil) != nil || revisionHintResult(nil) != nil {
		t.Error("a hint became an error")
	}
}
