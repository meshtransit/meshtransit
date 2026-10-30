package kubeaudit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
)

// fakeStream answers each call with answer(batch), after delay.
type fakeStream struct {
	calls   chan controlplane.KubeAuditCall
	reports chan controlplane.KubeAuditReport
	mu      sync.Mutex
	batches []controlplane.KubeAuditBatch
}

func (stream *fakeStream) serve(ctx context.Context, delay time.Duration,
	answer func(int, controlplane.KubeAuditBatch) controlplane.KubeAuditReply,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case call := <-stream.calls:
			stream.mu.Lock()
			stream.batches = append(stream.batches, call.Batch)
			n := len(stream.batches)
			stream.mu.Unlock()
			go func() {
				time.Sleep(delay)
				call.Reply <- answer(n, call.Batch)
			}()
		}
	}
}

func (stream *fakeStream) recorded() []controlplane.KubeAuditBatch {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return stream.batches
}

func recordAll(_ int, batch controlplane.KubeAuditBatch) controlplane.KubeAuditReply {
	results := make([]controlplane.KubeAuditResult, len(batch.Intents))
	for index, intent := range batch.Intents {
		results[index] = controlplane.KubeAuditResult{IntentID: intent.ID, AuditID: intent.ID}
	}
	return controlplane.KubeAuditReply{Results: results}
}

func testRecorder(t *testing.T, change func(*Options)) (*Recorder, *fakeStream, context.Context) {
	t.Helper()
	stream := &fakeStream{
		calls:   make(chan controlplane.KubeAuditCall),
		reports: make(chan controlplane.KubeAuditReport, 8),
	}
	options := DefaultOptions()
	options.Calls, options.Reports, options.CoreNow = stream.calls, stream.reports, time.Now
	options.Window, options.Wait = 20*time.Millisecond, 2*time.Second
	options.ReportWindow, options.DenialWindow = 20*time.Millisecond, 20*time.Millisecond
	if change != nil {
		change(&options)
	}
	recorder, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = recorder.Run(ctx)
	}()
	t.Cleanup(func() { cancel(); <-done })
	return recorder, stream, ctx
}

func testIntent() controlplane.KubeAuditIntent {
	return controlplane.KubeAuditIntent{
		Peer: "01890f00-0000-7000-8000-000000000702", Class: "write", Verb: "delete",
		Resource: "pods", Namespace: "default", Name: "web-0",
	}
}

// Intents of several Devices share a batch; each gets its own answer; the
// recorder gives each a UUIDv7 ID and Core's time.
func TestRecorderBatchesAndAnswers(t *testing.T) {
	t.Parallel()
	recorder, stream, ctx := testRecorder(t, nil)
	go stream.serve(ctx, 0, recordAll)
	answers := make(chan Answer, 2)
	for _, device := range []string{"a", "b"} {
		go func() { answers <- recorder.Record(t.Context(), device, testIntent()) }()
	}
	for range 2 {
		if answer := <-answers; !answer.Recorded || answer.Err != nil || answer.AuditID == ([16]byte{}) {
			t.Fatalf("answer = %+v", answer)
		}
	}
	batches := stream.recorded()
	if len(batches) != 1 || len(batches[0].Intents) != 2 {
		t.Fatalf("%d batches", len(batches))
	}
	intent := batches[0].Intents[0]
	if intent.ID[6]>>4 != 7 || intent.ID[8]>>6 != 2 || time.Since(intent.ObservedAt) > time.Minute {
		t.Fatalf("intent %x at %v", intent.ID, intent.ObservedAt)
	}
}

// A Device past its share is refused at once, without reaching Core.
func TestRecorderLimitsADevice(t *testing.T) {
	t.Parallel()
	recorder, stream, ctx := testRecorder(t, func(options *Options) {
		options.DevicePending, options.DeviceBurst, options.DeviceRate = 1, 1, 0.001
	})
	release := make(chan struct{})
	go stream.serve(ctx, 0, func(n int, batch controlplane.KubeAuditBatch) controlplane.KubeAuditReply {
		<-release
		return recordAll(n, batch)
	})
	first := make(chan Answer, 1)
	go func() { first <- recorder.Record(t.Context(), "a", testIntent()) }()
	for len(stream.recorded()) == 0 {
		time.Sleep(time.Millisecond)
	}
	if answer := recorder.Record(t.Context(), "a", testIntent()); answer.Refused != RefusedLimited {
		t.Fatalf("a second intent waiting: %+v", answer)
	}
	close(release)
	if answer := <-first; !answer.Recorded {
		t.Fatalf("first = %+v", answer)
	}
	// Its bucket is now empty; another Device still records.
	if answer := recorder.Record(t.Context(), "a", testIntent()); answer.Refused != RefusedLimited {
		t.Fatalf("past the burst: %+v", answer)
	}
	if answer := recorder.Record(t.Context(), "b", testIntent()); !answer.Recorded {
		t.Fatalf("another Device: %+v", answer)
	}
}

// Core's "limited" pauses the gateway and halves its rate; an intent that
// waited under a second goes back to the queue and is recorded later.
func TestRecorderRequeuesOnLimited(t *testing.T) {
	t.Parallel()
	recorder, stream, ctx := testRecorder(t, nil)
	go stream.serve(ctx, 0, func(n int, batch controlplane.KubeAuditBatch) controlplane.KubeAuditReply {
		if n == 1 {
			results := make([]controlplane.KubeAuditResult, len(batch.Intents))
			for index, intent := range batch.Intents {
				results[index] = controlplane.KubeAuditResult{
					IntentID: intent.ID, Refused: RefusedLimited,
					RetryAfter: 30 * time.Millisecond,
				}
			}
			return controlplane.KubeAuditReply{Results: results}
		}
		return recordAll(n, batch)
	})
	started := time.Now()
	if answer := recorder.Record(t.Context(), "a", testIntent()); !answer.Recorded {
		t.Fatalf("answer = %+v", answer)
	}
	if waited := time.Since(started); waited < 30*time.Millisecond {
		t.Fatalf("not paused: %v", waited)
	}
	if batches := stream.recorded(); len(batches) != 2 || batches[0].Intents[0].ID != batches[1].Intents[0].ID {
		t.Fatal("the intent was not sent again with its ID")
	}
	if measured := recorder.Snapshot(); measured.Rate >= DefaultOptions().Rate {
		t.Fatalf("rate %v not lowered", measured.Rate)
	}
}

// An answer that comes after the caller gave up never lets it forward, and
// a record made for it is reported with status 0 (not forwarded).
func TestRecorderLateAnswerNeverForwards(t *testing.T) {
	t.Parallel()
	recorder, stream, ctx := testRecorder(t, func(options *Options) { options.Wait = 50 * time.Millisecond })
	late := make(chan struct{})
	go stream.serve(ctx, 0, func(n int, batch controlplane.KubeAuditBatch) controlplane.KubeAuditReply {
		<-late
		return recordAll(n, batch)
	})
	if answer := recorder.Record(t.Context(), "a", testIntent()); !errors.Is(answer.Err, ErrTimeout) || answer.Recorded {
		t.Fatalf("answer = %+v", answer)
	}
	close(late)
	select {
	case report := <-stream.reports:
		if len(report.Outcomes) != 1 || report.Outcomes[0].Status != 0 {
			t.Fatalf("report = %+v", report)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no outcome for the record never forwarded")
	}
}

// Without a stream to take the batch, an intent is answered within Wait.
func TestRecorderWithoutAStream(t *testing.T) {
	t.Parallel()
	recorder, _, _ := testRecorder(t, func(options *Options) { options.Wait = 50 * time.Millisecond })
	if answer := recorder.Record(t.Context(), "a", testIntent()); answer.Err == nil || answer.Recorded {
		t.Fatalf("answer = %+v", answer)
	}
}

// Devices take turns in a batch.
func TestRecorderTakesDevicesInTurn(t *testing.T) {
	t.Parallel()
	recorder, err := New(Options{
		Calls: make(chan controlplane.KubeAuditCall), Reports: make(chan controlplane.KubeAuditReport),
		CoreNow: time.Now, Window: time.Millisecond, Wait: time.Second, Rate: 1, Burst: maximumBatch, DeviceRate: 1,
		DeviceBurst: 1, DevicePending: 1, ReportWindow: time.Second, DenialWindow: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range []string{"a", "a", "a", "b", "c", "c"} {
		recorder.enqueueLocked(&waiter{device: device, reply: make(chan Answer, 1)}, false)
	}
	var order []string
	for _, waiting := range recorder.takeLocked(5) {
		order = append(order, waiting.device)
	}
	if got := len(order); got != 5 || order[0] != "a" || order[1] != "b" || order[2] != "c" || order[3] != "a" ||
		order[4] != "c" {
		t.Fatalf("order = %v", order)
	}
}

// Denials are counted by peer and reason; past the bound, a new peer's go
// to its reason's unnamed count.
func TestReportsCountDenials(t *testing.T) {
	t.Parallel()
	held := newReports()
	now := time.Now()
	held.denied("a", "forbidden", nil, now)
	held.denied("a", "forbidden", nil, now.Add(time.Second))
	for index := range maximumDenials * 2 {
		held.denied(string(rune('A'+index%26))+string(rune('a'+index/26)), "stale", nil, now)
	}
	counts := held.takeDenials()
	if len(counts) > maximumDenials {
		t.Fatalf("%d counts", len(counts))
	}
	total, unnamed := 0, false
	for _, count := range counts {
		total += count.Count
		unnamed = unnamed || count.Peer == "" && count.Reason == "stale"
		if count.Peer == "a" && (count.Count != 2 || !count.Last.After(count.First)) {
			t.Fatalf("a's count = %+v", count)
		}
	}
	if total != 2+maximumDenials*2 || !unnamed {
		t.Fatalf("total %d, unnamed %t", total, unnamed)
	}
	if len(held.takeDenials()) != 0 {
		t.Fatal("counts taken twice")
	}
}

// Stopping answers every intent still queued.
func TestRecorderStopAnswersTheQueue(t *testing.T) {
	t.Parallel()
	recorder, _, _ := testRecorder(t, nil)
	recorder.mu.Lock()
	recorder.inFlight = maximumInFlight // nothing leaves
	recorder.mu.Unlock()
	answer := make(chan Answer, 1)
	go func() { answer <- recorder.Record(t.Context(), "a", testIntent()) }()
	for recorder.Snapshot().Queued == 0 {
		time.Sleep(time.Millisecond)
	}
	recorder.stop()
	if got := <-answer; !errors.Is(got.Err, ErrStopped) {
		t.Fatalf("answer = %+v", got)
	}
	if got := recorder.Record(t.Context(), "a", testIntent()); !errors.Is(got.Err, ErrStopped) {
		t.Fatalf("after stop = %+v", got)
	}
}

// An intent out of Core's bounds is refused here, never sent (review b2 H1).
func TestRecorderRefusesIntentsOutOfBounds(t *testing.T) {
	t.Parallel()
	recorder, stream, _ := testRecorder(t, nil)
	for name, change := range map[string]func(*controlplane.KubeAuditIntent){
		"long name":     func(intent *controlplane.KubeAuditIntent) { intent.Name = string(make([]byte, 254)) },
		"17 groups":     func(intent *controlplane.KubeAuditIntent) { intent.Groups = make([]string, 17) },
		"empty group":   func(intent *controlplane.KubeAuditIntent) { intent.Groups = []string{""} },
		"control":       func(intent *controlplane.KubeAuditIntent) { intent.Namespace = "a\nb" },
		"bidi":          func(intent *controlplane.KubeAuditIntent) { intent.Name = "a‮b" },
		"no verb":       func(intent *controlplane.KubeAuditIntent) { intent.Verb = "" },
		"long token ID": func(intent *controlplane.KubeAuditIntent) { intent.TokenID = make([]byte, 33) },
		"bad UTF-8":     func(intent *controlplane.KubeAuditIntent) { intent.Resource = "\xff" },
	} {
		intent := testIntent()
		change(&intent)
		if answer := recorder.Record(t.Context(), "a", intent); answer.Refused != RefusedInvalid || answer.Recorded {
			t.Errorf("%s: %+v", name, answer)
		}
	}
	if len(stream.recorded()) != 0 {
		t.Fatal("an intent out of bounds was sent")
	}
}

// A batch stays under the message's size: large intents split batches.
func TestRecorderSplitsBatchesBySize(t *testing.T) {
	t.Parallel()
	recorder, err := New(DefaultOptionsFor(t))
	if err != nil {
		t.Fatal(err)
	}
	recorder.messages.tokens = messageBurst
	for _, device := range []string{"a", "b", "c"} {
		recorder.enqueueLocked(&waiter{device: device, size: 50 << 10, reply: make(chan Answer, 1)}, false)
	}
	if first := recorder.takeLocked(maximumBatch); len(first) != 2 {
		t.Fatalf("first batch of %d", len(first))
	}
	if second := recorder.takeLocked(maximumBatch); len(second) != 1 {
		t.Fatalf("second batch of %d", len(second))
	}
}

// DefaultOptionsFor are valid options with channels nobody serves.
func DefaultOptionsFor(t *testing.T) Options {
	t.Helper()
	options := DefaultOptions()
	options.Calls, options.Reports = make(chan controlplane.KubeAuditCall), make(chan controlplane.KubeAuditReport)
	options.CoreNow = time.Now
	return options
}

// A session lost sends the intents again, with their IDs: Core answers the
// same audit_ids (review b2 M2).
func TestRecorderResendsAfterASessionLost(t *testing.T) {
	t.Parallel()
	recorder, stream, ctx := testRecorder(t, nil)
	go stream.serve(ctx, 0, func(n int, batch controlplane.KubeAuditBatch) controlplane.KubeAuditReply {
		if n == 1 {
			return controlplane.KubeAuditReply{Err: controlplane.ErrKubeAuditSessionLost}
		}
		return recordAll(n, batch)
	})
	if answer := recorder.Record(t.Context(), "a", testIntent()); !answer.Recorded {
		t.Fatalf("answer = %+v", answer)
	}
	if batches := stream.recorded(); len(batches) != 2 || batches[0].Intents[0].ID != batches[1].Intents[0].ID {
		t.Fatal("not sent again with its ID")
	}
}

// "limited" never shortens a pause, halves the rate and takes the burst
// down with it (review b2 M4, M5); a "limited" after stop answers the
// intent stopped (L1).
func TestRecorderLimitedPausesAndSlows(t *testing.T) {
	t.Parallel()
	recorder, err := New(DefaultOptionsFor(t))
	if err != nil {
		t.Fatal(err)
	}
	limited := func(retry time.Duration) {
		waiting := &waiter{device: "a", reply: make(chan Answer, 1), queuedAt: time.Now().Add(-time.Minute)}
		recorder.mu.Lock()
		recorder.pending["a"]++
		recorder.mu.Unlock()
		recorder.dispatch([]*waiter{waiting}, controlplane.KubeAuditReply{Results: []controlplane.KubeAuditResult{
			{Refused: RefusedLimited, RetryAfter: retry},
		}})
		if answer := <-waiting.reply; answer.Refused != RefusedLimited {
			t.Fatalf("answer = %+v", answer)
		}
	}
	limited(10 * time.Second)
	paused := recorder.paused
	limited(time.Second)
	if !recorder.paused.Equal(paused) {
		t.Fatal("a shorter pause replaced a longer one")
	}
	if quarter := DefaultOptions().Rate / 4; recorder.rate < quarter || recorder.rate > quarter*1.01 ||
		recorder.gateway.tokens > recorder.rate {
		t.Fatalf("rate %v, tokens %v", recorder.rate, recorder.gateway.tokens)
	}
	recorder.stop()
	waiting := &waiter{device: "a", reply: make(chan Answer, 1), queuedAt: time.Now()}
	recorder.dispatch([]*waiter{waiting}, controlplane.KubeAuditReply{Results: []controlplane.KubeAuditResult{
		{Refused: RefusedLimited},
	}})
	if answer := <-waiting.reply; !errors.Is(answer.Err, ErrStopped) {
		t.Fatalf("after stop = %+v", answer)
	}
}

// A reason Core does not take is counted as "other" (review b2 L3).
func TestReportsMapUnknownReasons(t *testing.T) {
	t.Parallel()
	held := newReports()
	held.denied("a", "bored", nil, time.Now())
	if counts := held.takeDenials(); len(counts) != 1 || counts[0].Reason != "other" {
		t.Fatalf("counts = %+v", counts)
	}
}

// A batch never spends more of Core's budget than the bucket holds.
func TestRecorderKeepsBatchesWithinTheBudget(t *testing.T) {
	t.Parallel()
	recorder, err := New(DefaultOptionsFor(t))
	if err != nil {
		t.Fatal(err)
	}
	recorder.messages.tokens = 10 << 10
	for _, device := range []string{"a", "b", "c"} {
		recorder.enqueueLocked(&waiter{device: device, size: 4 << 10, reply: make(chan Answer, 1)}, false)
	}
	if batch := recorder.takeLocked(maximumBatch); len(batch) != 2 {
		t.Fatalf("a batch of %d", len(batch))
	}
}

// A profile's count keeps the window's first sample, a copy.
func TestReportsKeepTheFirstProfileSample(t *testing.T) {
	t.Parallel()
	held := newReports()
	now := time.Now()
	first := controlplane.KubeAuditDenialSample{Verb: "delete", Resource: "pods", Namespace: "a", Scope: [32]byte{1}}
	held.denied("p", "profile_denied", &first, now)
	first.Verb = "changed"
	held.denied("p", "profile_denied", &controlplane.KubeAuditDenialSample{Verb: "get"}, now)
	held.denied("p", "profile_would_deny", nil, now)
	counts := held.takeDenials()
	if len(counts) != 2 {
		t.Fatalf("%d counts", len(counts))
	}
	for _, count := range counts {
		switch count.Reason {
		case "profile_denied":
			if count.Count != 2 || count.Sample == nil || count.Sample.Verb != "delete" {
				t.Fatalf("denied: %+v", count)
			}
		case "profile_would_deny":
			if count.Sample != nil {
				t.Fatalf("would deny: %+v", count)
			}
		default:
			t.Fatalf("reason %q", count.Reason)
		}
	}
}
