package mtcp

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/kubecluster"
)

type recordedKeyReport struct {
	machine    [32]byte
	reason     kubecluster.KeyEventReason
	suppressed int
}

// keyRecorderStub answers with outcome, or waits for release when block.
type keyRecorderStub struct {
	mu      sync.Mutex
	calls   []recordedKeyReport
	outcome kubecluster.KeyEventOutcome
	block   chan struct{}
	called  chan struct{}
}

func (stub *keyRecorderStub) Record(ctx context.Context, machine [32]byte, reason kubecluster.KeyEventReason,
	suppressed int) (kubecluster.KeyEventOutcome, error) {
	stub.mu.Lock()
	stub.calls = append(stub.calls, recordedKeyReport{machine, reason, suppressed})
	outcome, block, called := stub.outcome, stub.block, stub.called
	stub.mu.Unlock()
	if called != nil {
		called <- struct{}{}
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return outcome, nil
}

func (stub *keyRecorderStub) reports() []recordedKeyReport {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return append([]recordedKeyReport(nil), stub.calls...)
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *fakeClock) advance(by time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(by)
	clock.mu.Unlock()
}

func newTestKeyReporter(t *testing.T, recorder GatewayKeyRecorder, clock *fakeClock, queue int) *gatewayKeyReporter {
	t.Helper()
	reporter := newGatewayKeyReporter(recorder, NewMetrics(), slog.New(slog.NewTextHandler(io.Discard, nil)),
		clock.Now, queue)
	t.Cleanup(reporter.stop)
	return reporter
}

// waitReports waits until the recorder saw want reports.
func waitReports(t *testing.T, stub *keyRecorderStub, want int) []recordedKeyReport {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := stub.reports(); len(got) >= want {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("the recorder saw %d reports, want %d", len(stub.reports()), want)
	return nil
}

// A key and reason is recorded once per hold; the reports in between are
// counted into the next event.
func TestGatewayKeyReporterFoldsRepeats(t *testing.T) {
	t.Parallel()
	stub := &keyRecorderStub{outcome: kubecluster.KeyEventRecorded}
	clock := &fakeClock{now: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)}
	reporter := newTestKeyReporter(t, stub, clock, 8)
	machine := [32]byte{1}
	reporter.report(machine, kubecluster.KeyEventRetiredMachineKey)
	waitReports(t, stub, 1)
	reporter.report(machine, kubecluster.KeyEventRetiredMachineKey)
	reporter.report(machine, kubecluster.KeyEventRetiredMachineKey)
	// Another reason of the same key is its own event.
	reporter.report(machine, kubecluster.KeyEventReplayedHandshake)
	waitReports(t, stub, 2)
	clock.advance(gatewayKeyReportHold + time.Second)
	reporter.report(machine, kubecluster.KeyEventRetiredMachineKey)
	got := waitReports(t, stub, 3)
	if got[0].suppressed != 0 || got[1].reason != kubecluster.KeyEventReplayedHandshake ||
		got[2].reason != kubecluster.KeyEventRetiredMachineKey || got[2].suppressed != 2 {
		t.Fatalf("reports = %+v", got)
	}
}

// A report the database could not take is held only briefly.
func TestGatewayKeyReporterRetriesBusySoon(t *testing.T) {
	t.Parallel()
	stub := &keyRecorderStub{outcome: kubecluster.KeyEventBusy}
	clock := &fakeClock{now: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)}
	reporter := newTestKeyReporter(t, stub, clock, 8)
	machine := [32]byte{2}
	reporter.report(machine, kubecluster.KeyEventSessionFight)
	waitReports(t, stub, 1)
	// The worker settles the busy outcome after the call returns.
	deadline := time.Now().Add(5 * time.Second)
	for {
		clock.advance(gatewayKeyRetryHold + time.Second)
		reporter.report(machine, kubecluster.KeyEventSessionFight)
		if len(stub.reports()) >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := waitReports(t, stub, 2); got[1].reason != kubecluster.KeyEventSessionFight {
		t.Fatalf("reports = %+v", got)
	}
}

// A full queue drops reports instead of waiting; nothing blocks the caller.
func TestGatewayKeyReporterDropsWhenFull(t *testing.T) {
	t.Parallel()
	stub := &keyRecorderStub{outcome: kubecluster.KeyEventRecorded, block: make(chan struct{}),
		called: make(chan struct{}, 16)}
	clock := &fakeClock{now: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)}
	reporter := newTestKeyReporter(t, stub, clock, 1)
	reporter.report([32]byte{3}, kubecluster.KeyEventStaleNodeKey)
	<-stub.called                                                  // the worker holds the first report
	reporter.report([32]byte{4}, kubecluster.KeyEventStaleNodeKey) // queued
	done := make(chan struct{})
	go func() {
		reporter.report([32]byte{5}, kubecluster.KeyEventStaleNodeKey) // dropped
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("report blocked on a full queue")
	}
	close(stub.block)
	got := waitReports(t, stub, 2)
	time.Sleep(20 * time.Millisecond)
	if len(stub.reports()) != 2 || got[1].machine != ([32]byte{4}) {
		t.Fatalf("reports = %+v", stub.reports())
	}
}

// Stop ends a report the database holds, and later reports go nowhere.
func TestGatewayKeyReporterStops(t *testing.T) {
	t.Parallel()
	stub := &keyRecorderStub{outcome: kubecluster.KeyEventRecorded, block: make(chan struct{}),
		called: make(chan struct{}, 4)}
	clock := &fakeClock{now: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)}
	reporter := newTestKeyReporter(t, stub, clock, 4)
	reporter.report([32]byte{6}, kubecluster.KeyEventRetiredMachineKey)
	<-stub.called
	stopped := make(chan struct{})
	go func() {
		reporter.stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop waited for the database")
	}
	reporter.report([32]byte{7}, kubecluster.KeyEventRetiredMachineKey)
	reporter.stop()
	if got := stub.reports(); len(got) != 1 {
		t.Fatalf("reports after stop = %+v", got)
	}
}

// A nil reporter takes reports and does nothing.
func TestNilGatewayKeyReporter(t *testing.T) {
	t.Parallel()
	var reporter *gatewayKeyReporter
	reporter.report([32]byte{8}, kubecluster.KeyEventRetiredMachineKey)
	reporter.stop()
}

// Stop may come twice, before any report started the goroutine.
func TestGatewayKeyReporterStopsTwiceUnstarted(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)}
	reporter := newTestKeyReporter(t, &keyRecorderStub{outcome: kubecluster.KeyEventRecorded}, clock, 4)
	done := make(chan struct{})
	go func() {
		reporter.stop()
		reporter.stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a second stop hung")
	}
}
