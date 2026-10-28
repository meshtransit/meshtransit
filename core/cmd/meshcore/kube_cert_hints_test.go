package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/domain/publicid"
)

// scriptedHints plays hints, then fails like a lost connection.
type scriptedHints struct {
	mu      sync.Mutex
	results []error
	closed  int
}

func (hints *scriptedHints) Receive(ctx context.Context) (publicid.ID, error) {
	hints.mu.Lock()
	if len(hints.results) == 0 {
		hints.mu.Unlock()
		<-ctx.Done()
		return publicid.ID{}, ctx.Err()
	}
	next := hints.results[0]
	hints.results = hints.results[1:]
	hints.mu.Unlock()
	return publicid.ID{}, next
}

func (hints *scriptedHints) Close() error {
	hints.mu.Lock()
	defer hints.mu.Unlock()
	hints.closed++
	return nil
}

// Hints are delivered, a malformed one is skipped, a lost subscription is
// opened again, and publishing never blocks (review a3b Go M1).
func TestKubeCertHints(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	delivered, subscribed := 0, 0
	first := &scriptedHints{results: []error{nil, redisadapter.ErrInvalidKubeCertWakeup, nil,
		errors.New("connection reset")}}
	second := &scriptedHints{results: []error{nil}}
	hints := newKubeCertHints("test", func(context.Context) (kubeCertHintSubscription, error) {
		mu.Lock()
		defer mu.Unlock()
		subscribed++
		if subscribed == 1 {
			return first, nil
		}
		return second, nil
	}, func(publicid.ID) {
		mu.Lock()
		defer mu.Unlock()
		delivered++
	}, discardCompositionLogger())
	// Before Start a publication is queued, and more than the queue holds
	// are dropped without blocking.
	published := make(chan struct{}, kubeCertHintQueue+10)
	for range kubeCertHintQueue + 10 {
		hints.Publish(func(context.Context) { published <- struct{}{} })
	}
	if err := hints.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		done := delivered == 3 && subscribed == 2
		mu.Unlock()
		if done && len(published) == kubeCertHintQueue {
			break
		}
		if time.Now().After(deadline) {
			mu.Lock()
			defer mu.Unlock()
			t.Fatalf("delivered %d, subscribed %d, published %d", delivered, subscribed, len(published))
		}
		time.Sleep(10 * time.Millisecond)
	}
	shutdown, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := hints.Shutdown(shutdown); err != nil {
		t.Fatal(err)
	}
	if first.closed != 1 || second.closed != 1 {
		t.Fatalf("closed %d, %d", first.closed, second.closed)
	}
	if err := hints.Start(t.Context()); !errors.Is(err, errKubeCertHintsStarted) {
		t.Fatalf("a second Start = %v", err)
	}
}
