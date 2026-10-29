package kubeaudit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeReportStore writes every row, or fails every call when fail is set.
type fakeReportStore struct {
	mu    sync.Mutex
	calls [][]Reports
	fail  error
}

func (store *fakeReportStore) RecordReports(_ context.Context, reports []Reports) (int, int, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.calls = append(store.calls, reports)
	if store.fail != nil {
		return 0, 0, store.fail
	}
	outcomes, denials := 0, 0
	for _, report := range reports {
		outcomes, denials = outcomes+len(report.Finished), denials+len(report.Denials)
	}
	return outcomes, denials, nil
}

func (store *fakeReportStore) state() ([][]Reports, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.calls, store.fail
}

func testReport(outcomes, denials int) Reports {
	return Reports{Finished: make([]Finished, outcomes), Denials: make([]Denials, denials)}
}

func newTestReportWriter(t *testing.T, store ReportStore, rows int, lost func(int)) *ReportWriter {
	t.Helper()
	writer, err := NewReportWriter(store, ReportOptions{Window: 5 * time.Millisecond, Rows: rows,
		Timeout: time.Second, Lost: lost})
	if err != nil {
		t.Fatal(err)
	}
	return writer
}

// Reports gather into calls within the store's bounds, and Close writes
// what was queued.
func TestReportWriterBatchesWithinTheStoresBounds(t *testing.T) {
	t.Parallel()
	store := &fakeReportStore{}
	writer := newTestReportWriter(t, store, 20000, nil)
	for range 12 {
		if !writer.Submit(testReport(MaximumReportOutcomes, 0)) {
			t.Fatal("a report within the queue was dropped")
		}
	}
	writer.Close()
	calls, _ := store.state()
	total := 0
	for _, call := range calls {
		outcomes := 0
		for _, report := range call {
			outcomes += len(report.Finished)
		}
		if outcomes > maximumCallOutcomes {
			t.Fatalf("one call carried %d outcomes", outcomes)
		}
		total += outcomes
	}
	if total != 12*MaximumReportOutcomes || len(calls) < 2 {
		t.Fatalf("wrote %d outcomes in %d calls", total, len(calls))
	}
	if writer.Submit(testReport(1, 0)) {
		t.Fatal("a closed writer took a report")
	}
}

// A full queue, or a message over its bounds, drops reports; a failed call
// counts its rows lost.
func TestReportWriterDropsAndCountsLosses(t *testing.T) {
	t.Parallel()
	store := &fakeReportStore{fail: errors.New("down")}
	var lost int
	var mu sync.Mutex
	writer := newTestReportWriter(t, store, MaximumReportOutcomes+MaximumReportDenials,
		func(rows int) { mu.Lock(); lost += rows; mu.Unlock() })
	if writer.Submit(testReport(MaximumReportOutcomes+1, 0)) || writer.Submit(testReport(0, MaximumReportDenials+1)) {
		t.Fatal("a report over a message's bounds was taken")
	}
	if !writer.Submit(testReport(0, 0)) {
		t.Fatal("an empty report is not a drop")
	}
	if !writer.Submit(testReport(MaximumReportOutcomes, 0)) {
		t.Fatal("a report within the queue was dropped")
	}
	if writer.Submit(testReport(1, MaximumReportDenials)) {
		t.Fatal("a full queue took a report")
	}
	writer.Close()
	mu.Lock()
	defer mu.Unlock()
	if lost != MaximumReportOutcomes {
		t.Fatalf("lost = %d", lost)
	}
}
