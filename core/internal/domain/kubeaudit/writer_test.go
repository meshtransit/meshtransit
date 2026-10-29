package kubeaudit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/publicid"
)

// fakeStore answers accepted for each row, unless a row's verb is "bad" (a
// DataError for the whole call) or a scripted error comes first. With
// block set, each call says it entered, then waits for block to close.
type fakeStore struct {
	mu      sync.Mutex
	calls   [][]Row
	script  []error // the next calls' errors, in turn; nil: answer as usual
	entered chan struct{}
	block   chan struct{}
}

func (store *fakeStore) Record(_ context.Context, rows []Row) ([]StoredAnswer, error) {
	if store.block != nil {
		store.entered <- struct{}{}
		<-store.block
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.calls = append(store.calls, rows)
	if len(store.script) > 0 {
		err := store.script[0]
		store.script = store.script[1:]
		if err != nil {
			return nil, err
		}
	}
	answers := make([]StoredAnswer, len(rows))
	for index, row := range rows {
		if row.Intent.Verb == "bad" {
			return nil, DataError{Err: errors.New("22001")}
		}
		id, err := publicid.New()
		if err != nil {
			return nil, err
		}
		answers[index] = StoredAnswer{Outcome: OutcomeAccepted, AuditID: id}
	}
	return answers, nil
}

func (store *fakeStore) recorded() [][]Row {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.calls
}

func blockingStore() *fakeStore {
	return &fakeStore{entered: make(chan struct{}, 16), block: make(chan struct{})}
}

// awaitCall returns once the writer is inside a store call.
func (store *fakeStore) awaitCall(t *testing.T) {
	t.Helper()
	select {
	case <-store.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the writer never called the store")
	}
}

func testRows(n int, workspace, verb string) []Row {
	rows := make([]Row, n)
	for index := range rows {
		rows[index] = Row{Gateway: Gateway{Workspace: workspace}, Intent: Intent{Verb: verb}}
	}
	return rows
}

func testWriter(t *testing.T, store Store, queue int, isolated func()) *Writer {
	t.Helper()
	writer, err := NewWriter(store, WriterOptions{Window: 5 * time.Millisecond, Rows: 8, Queue: queue,
		Timeout: time.Second, RetryAfter: time.Second, Isolated: isolated})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(writer.Close)
	return writer
}

func receive(t *testing.T, answers <-chan []Answer) []Answer {
	t.Helper()
	select {
	case got := <-answers:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
		return nil
	}
}

func outcomes(answers []Answer) []Outcome {
	got := make([]Outcome, len(answers))
	for index, answer := range answers {
		got[index] = answer.Outcome
	}
	return got
}

func allOutcome(t *testing.T, name string, answers []Answer, want Outcome) {
	t.Helper()
	for _, answer := range answers {
		if answer.Outcome != want {
			t.Fatalf("%s: %v, want %s", name, outcomes(answers), want)
		}
	}
}

// Submissions of several sessions share transactions; each gets its own
// answers, in its order, with audit_ids issued for them.
func TestWriterBatchesAndAnswers(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	writer := testWriter(t, store, 64, nil)
	firstAnswers, secondAnswers := writer.Submit(testRows(3, "a", "delete")), writer.Submit(testRows(2, "b", "create"))
	got, other := receive(t, firstAnswers), receive(t, secondAnswers)
	allOutcome(t, "first", got, OutcomeAccepted)
	allOutcome(t, "second", other, OutcomeAccepted)
	seen := map[publicid.ID]bool{}
	for _, answer := range append(got, other...) {
		if !answer.AuditID.IsValid() || seen[answer.AuditID] {
			t.Fatalf("audit_id %v missing or repeated", answer.AuditID)
		}
		seen[answer.AuditID] = true
	}
	if calls := store.recorded(); len(calls) != 1 || calls[0][4].Intent.Verb != "create" ||
		calls[0][2].Intent.Verb != "delete" {
		t.Fatalf("%d store calls, want one shared transaction in order", len(calls))
	}
}

// The writer keeps its own copy of the rows it was given.
func TestWriterCopiesRows(t *testing.T) {
	t.Parallel()
	store := blockingStore()
	writer := testWriter(t, store, 64, nil)
	rows := testRows(2, "a", "delete")
	answers := writer.Submit(rows)
	store.awaitCall(t)
	rows[1].Intent.Verb = "changed"
	close(store.block)
	receive(t, answers)
	if got := store.recorded()[0][1].Intent.Verb; got != "delete" {
		t.Fatalf("the writer wrote the caller's later change %q", got)
	}
}

// After a failure that is not a row's data, the writer answers unavailable
// without calling the store until it cooled off (review b0b2 M-a).
func TestWriterCoolsOffAfterAFailure(t *testing.T) {
	t.Parallel()
	store := &fakeStore{script: []error{errors.New("commit timeout")}}
	var cooled int
	var mu sync.Mutex
	writer, err := NewWriter(store, WriterOptions{Window: time.Millisecond, Rows: 8, Queue: 64, Timeout: time.Second,
		RetryAfter: time.Hour, CooledOff: func() { mu.Lock(); cooled++; mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(writer.Close)
	allOutcome(t, "failed", receive(t, writer.Submit(testRows(1, "a", "delete"))), OutcomeUnavailable)
	got := receive(t, writer.Submit(testRows(1, "a", "delete")))
	allOutcome(t, "cooling off", got, OutcomeUnavailable)
	if got[0].RetryAfter == 0 || len(store.recorded()) != 1 {
		t.Fatalf("%d store calls while cooling off", len(store.recorded()))
	}
	mu.Lock()
	defer mu.Unlock()
	if cooled != 1 {
		t.Fatalf("cooled off %d times", cooled)
	}
}

// Rows out of bounds, of no Workspace or of several are invalid at once.
func TestWriterRefusesSubmissionsOutOfForm(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	writer := testWriter(t, store, 64, nil)
	mixed := append(testRows(1, "a", "get"), testRows(1, "b", "get")...)
	for name, rows := range map[string][]Row{
		"none": nil, "over Rows": testRows(9, "a", "get"), "no Workspace": testRows(1, "", "get"), "mixed": mixed,
	} {
		got := receive(t, writer.Submit(rows))
		if len(got) != len(rows) {
			t.Fatalf("%s: %d answers for %d rows", name, len(got), len(rows))
		}
		allOutcome(t, name, got, OutcomeInvalid)
	}
	if calls := store.recorded(); len(calls) != 0 {
		t.Fatalf("%d store calls", len(calls))
	}
}

// One submission's bad data fails only it; another failure answers the
// whole batch unavailable without trying again (design §5).
func TestWriterIsolatesBadData(t *testing.T) {
	t.Parallel()
	store := blockingStore()
	var isolations int
	var mu sync.Mutex
	writer := testWriter(t, store, 64, func() { mu.Lock(); isolations++; mu.Unlock() })
	// The first call blocks, so the next two submissions share a batch.
	blocker := writer.Submit(testRows(1, "a", "get"))
	store.awaitCall(t)
	good, bad := writer.Submit(testRows(2, "b", "delete")), writer.Submit(testRows(1, "c", "bad"))
	close(store.block)
	receive(t, blocker)
	allOutcome(t, "good", receive(t, good), OutcomeAccepted)
	if got := receive(t, bad); got[0].Outcome != OutcomeUnavailable || got[0].RetryAfter == 0 {
		t.Fatalf("the bad submission: %+v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if isolations != 1 {
		t.Fatalf("%d isolations", isolations)
	}
	failing := &fakeStore{script: []error{errors.New("connection reset")}}
	broken := testWriter(t, failing, 64, nil)
	one, two := broken.Submit(testRows(1, "a", "delete")), broken.Submit(testRows(1, "b", "delete"))
	allOutcome(t, "one", receive(t, one), OutcomeUnavailable)
	allOutcome(t, "two", receive(t, two), OutcomeUnavailable)
	if calls := failing.recorded(); len(calls) > 2 {
		t.Fatalf("%d store calls after a failure, want no retry", len(calls))
	}
}

// Isolation stops at a failure that is not its data, and gives up when
// every submission fails alone (review b0b2 H2).
func TestWriterStopsIsolating(t *testing.T) {
	t.Parallel()
	data, timeout := DataError{Err: errors.New("23514")}, errors.New("timeout")
	for name, test := range map[string]struct {
		script []error // after the blocker's call and the batch's DataError
		calls  int
		want   []Outcome
	}{
		"not data": {[]error{timeout}, 3,
			[]Outcome{OutcomeUnavailable, OutcomeUnavailable, OutcomeUnavailable, OutcomeUnavailable}},
		"every row": {[]error{data, data}, 2 + isolationGiveUp,
			[]Outcome{OutcomeUnavailable, OutcomeUnavailable, OutcomeUnavailable, OutcomeUnavailable}},
		"one is bad": {[]error{data}, 6,
			[]Outcome{OutcomeUnavailable, OutcomeAccepted, OutcomeAccepted, OutcomeAccepted}},
	} {
		store := blockingStore()
		writer := testWriter(t, store, 64, nil)
		blocker := writer.Submit(testRows(1, "z", "get"))
		store.awaitCall(t)
		var queued []<-chan []Answer
		for _, workspace := range []string{"a", "b", "c", "d"} {
			queued = append(queued, writer.Submit(testRows(1, workspace, "delete")))
		}
		store.mu.Lock()
		store.script = append([]error{nil, data}, test.script...)
		store.mu.Unlock()
		close(store.block)
		receive(t, blocker)
		for index, answers := range queued {
			if got := receive(t, answers); got[0].Outcome != test.want[index] {
				t.Fatalf("%s: submission %d %s, want %s", name, index, got[0].Outcome, test.want[index])
			}
		}
		if calls := store.recorded(); len(calls) != test.calls {
			t.Fatalf("%s: %d store calls, want %d", name, len(calls), test.calls)
		}
	}
}

// A full queue refuses the newest submissions of its longest Workspace, so
// a noisy Workspace never shuts a quiet one out; while another waits, none
// holds more than half; Workspaces take turns; a batch never passes Rows.
func TestWriterIsFairBetweenWorkspaces(t *testing.T) {
	t.Parallel()
	store := blockingStore()
	writer := testWriter(t, store, 16, nil)
	blocker := writer.Submit(testRows(1, "noisy", "get"))
	store.awaitCall(t)
	var noisy []<-chan []Answer
	for range 4 {
		noisy = append(noisy, writer.Submit(testRows(4, "noisy", "delete")))
	}
	// noisy filled the queue alone; quiet takes its newest submission's room.
	quiet := writer.Submit(testRows(4, "quiet", "create"))
	if got := receive(t, noisy[3]); got[0].Outcome != OutcomeOverloaded || got[0].RetryAfter == 0 {
		t.Fatalf("the noisy newest: %+v", got)
	}
	// Now quiet waits; noisy may hold no more than half.
	allOutcome(t, "over half", receive(t, writer.Submit(testRows(1, "noisy", "delete"))), OutcomeOverloaded)
	close(store.block)
	receive(t, blocker)
	allOutcome(t, "quiet", receive(t, quiet), OutcomeAccepted)
	for _, answers := range noisy[:3] {
		allOutcome(t, "noisy", receive(t, answers), OutcomeAccepted)
	}
	calls := store.recorded()
	for _, call := range calls {
		if len(call) > 8 {
			t.Fatalf("a batch of %d rows", len(call))
		}
	}
	// After the blocker, noisy's oldest and quiet share the next batch.
	if len(calls) < 2 || calls[1][len(calls[1])-1].Intent.Verb != "create" {
		t.Fatal("quiet did not take its turn after noisy's first submission")
	}
}

// Close writes what was queued, then answers unavailable; twice is once.
func TestWriterClose(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	writer, err := NewWriter(store, WriterOptions{Window: time.Hour, Rows: 100, Queue: 256, Timeout: time.Second,
		RetryAfter: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	queued := writer.Submit(testRows(2, "a", "delete"))
	writer.Close()
	writer.Close()
	allOutcome(t, "queued before Close", receive(t, queued), OutcomeAccepted)
	allOutcome(t, "after Close", receive(t, writer.Submit(testRows(1, "a", "delete"))), OutcomeUnavailable)
}

// A writer's bounds hold the store's and fit its largest submission.
func TestNewWriterRefusesInconsistentBounds(t *testing.T) {
	t.Parallel()
	for name, options := range map[string]WriterOptions{
		"over the store's": {Window: time.Millisecond, Rows: MaximumRows + 1, Queue: 4000, Timeout: time.Second,
			RetryAfter: time.Second},
		"half too small": {Window: time.Millisecond, Rows: 1000, Queue: 255, Timeout: time.Second,
			RetryAfter: time.Second},
	} {
		if _, err := NewWriter(&fakeStore{}, options); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	writer, err := NewWriter(&fakeStore{}, WriterOptions{Window: 5 * time.Millisecond, Rows: 1000, Queue: 400,
		Timeout: time.Second, RetryAfter: time.Second})
	if err != nil {
		t.Fatalf("the design's starting bounds: %v", err)
	}
	writer.Close()
}
