package certqueue

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/publicid"
)

// fakeStore queues one answer and plays reads from a list.
type fakeStore struct {
	mu        sync.Mutex
	state     SigningState
	stateErr  error
	states    int
	enqueued  []Request
	enqueue   Stored
	enqueueEr error
	reads     []Stored // each read takes the next; the last repeats
	readCalls int
	abandoned int
	abandonOK bool // abandon's context was alive
	abandonAs Stored
}

func (store *fakeStore) Enqueue(_ context.Context, request Request) (Stored, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.enqueued = append(store.enqueued, request)
	return store.enqueue, store.enqueueEr
}

func (store *fakeStore) Read(context.Context, publicid.ID, publicid.ID) (Stored, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.readCalls++
	if len(store.reads) == 0 {
		return store.enqueue, true, nil
	}
	next := store.reads[0]
	if len(store.reads) > 1 {
		store.reads = store.reads[1:]
	}
	return next, true, nil
}

func (store *fakeStore) Abandon(ctx context.Context, _, _ publicid.ID) (Stored, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.abandoned++
	store.abandonOK = ctx.Err() == nil
	if store.abandonAs.State == "" {
		return Stored{State: StateAbandoned}, true, nil
	}
	return store.abandonAs, true, nil
}

func (store *fakeStore) SigningState(context.Context) (SigningState, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.states++
	return store.state, store.stateErr
}

var ready = SigningState{SignerReady: true, Checked: true}

func mustID(t *testing.T) publicid.ID {
	t.Helper()
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func pending(t *testing.T) Stored {
	t.Helper()
	return Stored{State: StatePending, Request: mustID(t), Device: mustID(t)}
}

func testService(t *testing.T, store *fakeStore) *Service {
	t.Helper()
	service, err := New(store, Options{Wait: time.Second, Backstop: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func between(t *testing.T, got, low, high time.Duration) {
	t.Helper()
	if got < low || got > high {
		t.Fatalf("retry after %v, want between %v and %v", got, low, high)
	}
}

func TestRequestRefusedAtOnceWithoutASigner(t *testing.T) {
	t.Parallel()
	for name, state := range map[string]SigningState{
		"no signer":           {Checked: true},
		"a restore suspected": {SignerReady: true, Checked: true, RestoreSuspected: true},
		"tripwire unchecked":  {SignerReady: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := &fakeStore{state: state}
			service := testService(t, store)
			// Nothing reaches the queue; the gateway waits one to five
			// minutes (§14 R-H3), and the state is read once for both.
			for range 2 {
				result := service.Request(t.Context(), Request{})
				if result.Outcome != OutcomeRetry || result.Reason != ReasonUnavailable {
					t.Fatalf("Request() = %+v", result)
				}
				between(t, result.RetryAfter, time.Minute, 5*time.Minute)
			}
			if len(store.enqueued) != 0 || store.states != 1 || service.Snapshot().Ready {
				t.Fatalf("enqueued %d, states read %d", len(store.enqueued), store.states)
			}
		})
	}
}

func TestRequestRetriesWhenTheStateCannotBeRead(t *testing.T) {
	t.Parallel()
	store := &fakeStore{stateErr: errors.New("database")}
	result := testService(t, store).Request(t.Context(), Request{})
	if result.Outcome != OutcomeRetry || result.Reason != ReasonInternal || len(store.enqueued) != 0 {
		t.Fatalf("Request() = %+v", result)
	}
	between(t, result.RetryAfter, 2500*time.Millisecond, 7500*time.Millisecond)
}

func TestRequestAnswersWhatQueueingSaid(t *testing.T) {
	t.Parallel()
	issued := pending(t)
	issued.State, issued.Certificate = StateIssued, []byte("certificate")
	for name, test := range map[string]struct {
		stored      Stored
		err         error
		outcome     Outcome
		reason      string
		low, high   time.Duration
		certificate bool
	}{
		"issued before":   {stored: issued, outcome: OutcomeIssued, certificate: true},
		"revoked":         {stored: Stored{State: StateRefused, Reason: "revoked"}, outcome: OutcomeRefused, reason: "revoked"},
		"another key":     {stored: Stored{State: StateConflict}, outcome: OutcomeRefused, reason: ReasonConflict},
		"keys not proven": {err: ErrNotProven, outcome: OutcomeRefused, reason: ReasonNotProven},
		"a limit": {
			stored:  Stored{State: StateLimited, Reason: "limited", RetryAfter: 2 * time.Second},
			outcome: OutcomeRetry, reason: ReasonLimited, low: 2 * time.Second, high: 3 * time.Second,
		},
		"the installation's limit": {
			stored:  Stored{State: StateLimited, Reason: "overloaded", RetryAfter: 5 * time.Second},
			outcome: OutcomeRetry, reason: ReasonOverloaded, low: 5 * time.Second, high: 7500 * time.Millisecond,
		},
		"a database error": {
			err: errors.New("database"), outcome: OutcomeRetry, reason: ReasonInternal,
			low: 2500 * time.Millisecond, high: 7500 * time.Millisecond,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := &fakeStore{state: ready, enqueue: test.stored, enqueueEr: test.err}
			result := testService(t, store).Request(t.Context(), Request{})
			if result.Outcome != test.outcome || result.Reason != test.reason ||
				(len(result.Issued.Certificate) > 0) != test.certificate {
				t.Fatalf("Request() = %+v", result)
			}
			if test.outcome == OutcomeRetry {
				between(t, result.RetryAfter, test.low, test.high)
			}
			if store.readCalls != 0 || store.abandoned != 0 {
				t.Fatalf("read %d, abandoned %d", store.readCalls, store.abandoned)
			}
		})
	}
}

func TestRequestWaitsForTheWorker(t *testing.T) {
	t.Parallel()
	queued := pending(t)
	issued := queued
	issued.State, issued.Certificate, issued.NetworkRevision = StateIssued, []byte("certificate"), 7
	store := &fakeStore{state: ready, enqueue: queued, reads: []Stored{queued, issued}}
	hinted := 0
	service, err := New(store, Options{
		Wait: 5 * time.Second, Backstop: 5 * time.Second,
		Queued: func(context.Context) { hinted++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	// The worker's hint, not the backstop, answers the session.
	go func() {
		for range 2 {
			time.Sleep(50 * time.Millisecond)
			service.Settled(queued.Request)
		}
	}()
	started := time.Now()
	result := service.Request(t.Context(), Request{})
	if result.Outcome != OutcomeIssued || result.Issued.NetworkRevision != 7 || hinted != 1 ||
		time.Since(started) > 2*time.Second {
		t.Fatalf("Request() = %+v after %v, hinted %d", result, time.Since(started), hinted)
	}
	if snapshot := service.Snapshot(); snapshot.Issued != 1 || snapshot.Waits != 1 || !snapshot.Ready {
		t.Fatalf("snapshot %+v", snapshot)
	}
	// Nothing waits any more.
	service.waitersMu.Lock()
	defer service.waitersMu.Unlock()
	if len(service.waiters) != 0 {
		t.Fatalf("waiters left: %d", len(service.waiters))
	}
}

func TestRequestReadsBackWithoutHints(t *testing.T) {
	t.Parallel()
	queued := pending(t)
	refused := queued
	refused.State, refused.Reason = StateRefused, "token_used"
	store := &fakeStore{state: ready, enqueue: queued, reads: []Stored{queued, queued, refused}}
	result := testService(t, store).Request(t.Context(), Request{})
	if result.Outcome != OutcomeRefused || result.Reason != "token_used" || store.readCalls != 3 {
		t.Fatalf("Request() = %+v, reads %d", result, store.readCalls)
	}
}

func TestRequestTimesOut(t *testing.T) {
	t.Parallel()
	store := &fakeStore{state: ready, enqueue: pending(t)}
	result := testService(t, store).Request(t.Context(), Request{})
	// Still queued: it stays queued (a worker may sign it meanwhile, review
	// a3b Go M3), and the gateway sends it again in 1 to 3 s.
	if result.Outcome != OutcomeRetry || result.Reason != ReasonTimeout || store.abandoned != 0 {
		t.Fatalf("Request() = %+v, abandoned %d", result, store.abandoned)
	}
	between(t, result.RetryAfter, time.Second, 3*time.Second)
	// Abandoned meanwhile by an earlier session that ended: sent again
	// soon, it waits again.
	abandoned := pending(t)
	abandoned.State = StateAbandoned
	store = &fakeStore{state: ready, enqueue: pending(t), reads: []Stored{abandoned}}
	started := time.Now()
	if result := testService(t, store).Request(t.Context(), Request{}); result.Outcome != OutcomeRetry ||
		result.Reason != ReasonTimeout || time.Since(started) > 900*time.Millisecond {
		t.Fatalf("Request() = %+v after %v", result, time.Since(started))
	}
}

// The signers' state is read once per 10 s for every session; a session
// that ends during the read does not spoil it, and a failed read keeps the
// last good state for a minute (review a3b Go M2).
func TestSigningStateCache(t *testing.T) {
	t.Parallel()
	store := &fakeStore{state: ready}
	now := time.Now()
	service, err := New(store, Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ended, cancel := context.WithCancel(t.Context())
	cancel()
	if _, ok := service.Available(ended); !ok {
		t.Fatal("a session that ended spoiled the read")
	}
	now = now.Add(11 * time.Second)
	store.mu.Lock()
	store.stateErr = errors.New("database")
	store.mu.Unlock()
	if _, ok := service.Available(t.Context()); !ok || store.states != 2 {
		t.Fatalf("the last good state was not kept: reads %d", store.states)
	}
	now = now.Add(2 * time.Minute)
	if result, ok := service.Available(t.Context()); ok || result.Reason != ReasonInternal {
		t.Fatalf("Available() after a minute of failed reads = %+v", result)
	}
}

func TestRequestAbandonedWhenTheSessionEnds(t *testing.T) {
	t.Parallel()
	store := &fakeStore{state: ready, enqueue: pending(t)}
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(50*time.Millisecond, cancel)
	result := testService(t, store).Request(ctx, Request{})
	if result.Outcome != 0 || store.abandoned != 1 || !store.abandonOK {
		t.Fatalf("Request() = %+v, abandoned %d (alive %v)", result, store.abandoned, store.abandonOK)
	}
}

func TestRequestRedacts(t *testing.T) {
	t.Parallel()
	request := Request{Token: "secret-token"}
	for _, formatted := range []string{request.String(), request.GoString(), request.LogValue().String()} {
		if formatted == "" || strings.Contains(formatted, "secret") {
			t.Fatalf("formatted %q", formatted)
		}
	}
	if request.Renewal() {
		t.Fatal("a token request is a renewal")
	}
}

func TestNewRefusesUnsafeOptions(t *testing.T) {
	t.Parallel()
	for name, options := range map[string]Options{
		"a long wait":     {Wait: time.Minute},
		"a short wait":    {Wait: 100 * time.Millisecond},
		"a fast backstop": {Backstop: time.Millisecond},
		"a slow backstop": {Wait: time.Second, Backstop: 2 * time.Second},
	} {
		if _, err := New(&fakeStore{}, options); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := New(nil, Options{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("no store")
	}
}
