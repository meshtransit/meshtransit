package devicealias

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
)

type fakeHints struct {
	wakeups   chan struct{}
	listening atomic.Bool
}

func newFakeHints(listening bool) *fakeHints {
	hints := &fakeHints{wakeups: make(chan struct{}, 1)}
	hints.listening.Store(listening)
	return hints
}

func (hints *fakeHints) Wakeups() <-chan struct{} { return hints.wakeups }
func (hints *fakeHints) Listening() bool          { return hints.listening.Load() }
func (hints *fakeHints) wake() {
	select {
	case hints.wakeups <- struct{}{}:
	default:
	}
}

func hintOptions(t *testing.T, hints Hints) Options {
	t.Helper()
	options, _, _ := workerFixture(t)
	options.IdleInterval = time.Second
	options.Hints = hints
	return options
}

func TestNewRejectsUnsafeHintOptions(t *testing.T) {
	t.Parallel()
	_, _, logger := workerFixture(t)
	work := workFunc(func(context.Context, deployment.ID, Cursor, int) (Page, error) { return Page{Done: true}, nil })
	changes := changeFunc(func(context.Context, ChangeIntent) (bool, error) { return false, nil })
	var typedNil *fakeHints
	for name, options := range map[string]Options{
		"idle without hints": func() Options { o := hintOptions(t, nil); return o }(),
		"hints without idle": func() Options { o := hintOptions(t, newFakeHints(true)); o.IdleInterval = 0; return o }(),
		"idle below poll": func() Options {
			o := hintOptions(t, newFakeHints(true))
			o.IdleInterval = 50 * time.Millisecond
			return o
		}(),
		"idle beyond a minute": func() Options {
			o := hintOptions(t, newFakeHints(true))
			o.IdleInterval = time.Minute + time.Second
			return o
		}(),
		"typed nil hints": hintOptions(t, typedNil),
	} {
		if _, err := New(options, work, changes, logger); !errors.Is(err, ErrInvalidWorker) {
			t.Errorf("%s: New() error = %v, want ErrInvalidWorker", name, err)
		}
	}
}

func TestWorkerWithoutHintsSweepsEveryPollInterval(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		options, _, _ := workerFixture(t)
		passes := runAliasWorker(t, options, idlePages(), time.Second, nil)
		assertPassTimes(t, passes, 0, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000)
	})
}

func TestWorkerBacksOffBetweenIdleSweepsWhileListening(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		passes := runAliasWorker(t, hintOptions(t, newFakeHints(true)), idlePages(), 3500*time.Millisecond, nil)
		// Waits double from the poll interval up to the idle interval:
		// 200, 400, 800, then 1000 ms.
		assertPassTimes(t, passes, 0, 200, 600, 1400, 2400, 3400)
	})
}

func TestWorkerPollsWhileHintsAreNotListening(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		passes := runAliasWorker(t, hintOptions(t, newFakeHints(false)), idlePages(), 500*time.Millisecond, nil)
		assertPassTimes(t, passes, 0, 100, 200, 300, 400, 500)
	})
}

func TestWorkerHintWakesAndResetsTheBackOff(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		hints := newFakeHints(true)
		passes := runAliasWorker(t, hintOptions(t, hints), idlePages(), 2500*time.Millisecond, func() {
			time.Sleep(1500 * time.Millisecond)
			hints.wake()
		})
		// Idle at 0, 200, 600, 1400; the hint at 1500 sweeps at once (more
		// than a poll interval after 1400) and the back-off starts over.
		assertPassTimes(t, passes, 0, 200, 600, 1400, 1500, 1700, 2100)
	})
}

func TestWorkerSpacesHintsByThePollInterval(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		hints := newFakeHints(true)
		passes := runAliasWorker(t, hintOptions(t, hints), idlePages(), 350*time.Millisecond, func() {
			time.Sleep(210 * time.Millisecond)
			hints.wake()
			hints.wake()
		})
		// The hint at 210 ms comes 10 ms after the sweep at 200: it waits
		// for the poll interval, and the second hint folds into it.
		assertPassTimes(t, passes, 0, 200, 300)
	})
}

func TestWorkerKeepsPagingAtThePollIntervalAndBacksOffOnlyBetweenSweeps(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		options := hintOptions(t, newFakeHints(true))
		_, intent, _ := workerFixture(t)
		next := Cursor{EndpointID: intent.EndpointID, ConsumerID: intent.ConsumerID}
		// Every sweep is two pages without work.
		work := func(_ context.Context, _ deployment.ID, after Cursor, _ int) (Page, error) {
			if after == (Cursor{}) {
				return Page{Next: next}, nil
			}
			return Page{Done: true, Next: next}, nil
		}
		passes := runAliasWorker(t, options, work, 1500*time.Millisecond, nil)
		// Sweep 1: 0, 100; wait 200. Sweep 2: 300, 400; wait 400. Sweep 3: 800, 900.
		assertPassTimes(t, passes, 0, 100, 300, 400, 800, 900)
	})
}

func TestWorkerHintDuringASweepKeepsTheNextSweepFast(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		hints := newFakeHints(true)
		options := hintOptions(t, hints)
		_, intent, _ := workerFixture(t)
		next := Cursor{EndpointID: intent.EndpointID, ConsumerID: intent.ConsumerID}
		work := func(_ context.Context, _ deployment.ID, after Cursor, _ int) (Page, error) {
			if after == (Cursor{}) {
				return Page{Next: next}, nil
			}
			return Page{Done: true, Next: next}, nil
		}
		passes := runAliasWorker(t, options, work, 1200*time.Millisecond, func() {
			time.Sleep(350 * time.Millisecond)
			hints.wake() // between the two pages of the second sweep
		})
		// Sweep 1: 0, 100; wait 200. Sweep 2: 300, then the hint at 350
		// (page two at 400 stays at the poll interval); the next sweep
		// follows at the poll interval: 500, 600; then 200 → 800, 900.
		assertPassTimes(t, passes, 0, 100, 300, 400, 500, 600, 800, 900)
	})
}

func TestWorkerReturnsToThePollIntervalAfterWorkOrAFailedRead(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		options := hintOptions(t, newFakeHints(true))
		_, intent, _ := workerFixture(t)
		var reads atomic.Int32
		work := func(context.Context, deployment.ID, Cursor, int) (Page, error) {
			switch reads.Add(1) {
			case 3: // a sweep that finds work
				return Page{Items: []ChangeIntent{intent}, Done: true}, nil
			case 5: // a failed read
				return Page{}, errors.New("database unavailable")
			}
			return Page{Done: true}, nil
		}
		passes := runAliasWorker(t, options, work, 2*time.Second, nil)
		// 0 idle (wait 200), 200 idle (wait 400), 600 work (wait 100),
		// 700 idle (wait 200), 900 failed (retry after 100), 1000 ends the
		// sweep the failure was part of (wait 100), 1100 idle (200), 1300
		// idle (400), 1700.
		assertPassTimes(t, passes, 0, 200, 600, 700, 900, 1000, 1100, 1300, 1700)
	})
}

func idlePages() func(context.Context, deployment.ID, Cursor, int) (Page, error) {
	return func(context.Context, deployment.ID, Cursor, int) (Page, error) { return Page{Done: true}, nil }
}

// runAliasWorker runs a started worker inside a synctest bubble and returns
// when each pass read work, in milliseconds.
func runAliasWorker(
	t *testing.T, options Options, list func(context.Context, deployment.ID, Cursor, int) (Page, error),
	duration time.Duration, script func(),
) []int64 {
	t.Helper()
	_, _, logger := workerFixture(t)
	started := time.Now()
	var mu sync.Mutex
	var passes []int64
	work := workFunc(func(ctx context.Context, id deployment.ID, after Cursor, limit int) (Page, error) {
		mu.Lock()
		passes = append(passes, time.Since(started).Milliseconds())
		mu.Unlock()
		return list(ctx, id, after, limit)
	})
	changes := changeFunc(func(context.Context, ChangeIntent) (bool, error) { return true, nil })
	worker, err := New(options, work, changes, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := worker.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if script != nil {
		go script()
	}
	time.Sleep(duration)
	synctest.Wait()
	if err := worker.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-worker.Done()
	mu.Lock()
	defer mu.Unlock()
	return append([]int64(nil), passes...)
}

func assertPassTimes(t *testing.T, got []int64, want ...int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("passes at %v ms, want %v ms", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("passes at %v ms, want %v ms", got, want)
		}
	}
}
