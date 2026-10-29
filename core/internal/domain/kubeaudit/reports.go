package kubeaudit

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ReportStore records gateways' finished operations and denials.
type ReportStore interface {
	RecordReports(ctx context.Context, reports []Reports) (outcomes, denials int, err error)
}

// Bounds of one report store call, the schema's (000245).
const (
	maximumCallOutcomes = 10000
	maximumCallDenials  = 2560
	// MaximumReportOutcomes and MaximumReportDenials bound one message's
	// (mtcp-v1 §6.10).
	MaximumReportOutcomes = 1024
	MaximumReportDenials  = 256
)

// ReportOptions bound a report writer (design §5): its own queue of Rows,
// never the intents'; a full queue drops what comes.
type ReportOptions struct {
	Window  time.Duration
	Rows    int
	Timeout time.Duration
	// Lost, when set, hears of rows the store failed to write.
	Lost func(rows int)
}

// ReportWriter records reports apart from intents, so they never hold an
// intent back; nothing waits for them (design §2 step 5).
type ReportWriter struct {
	store   ReportStore
	options ReportOptions

	mu      sync.Mutex
	queue   []Reports
	waiting int // rows queued
	closed  bool
	wake    chan struct{}
	done    chan struct{}
}

// NewReportWriter starts a report writer; Close stops it after writing
// what it holds.
func NewReportWriter(store ReportStore, options ReportOptions) (*ReportWriter, error) {
	if store == nil || options.Window <= 0 || options.Rows < MaximumReportOutcomes+MaximumReportDenials ||
		options.Timeout <= 0 {
		return nil, errors.New("kubeaudit: invalid report writer options")
	}
	writer := &ReportWriter{store: store, options: options, wake: make(chan struct{}, 1), done: make(chan struct{})}
	go writer.run()
	return writer, nil
}

// Submit queues one message's reports; false drops them: the writer is
// closed, the queue full, or they exceed one message's bounds.
func (writer *ReportWriter) Submit(report Reports) bool {
	rows := len(report.Finished) + len(report.Denials)
	if rows == 0 || len(report.Finished) > MaximumReportOutcomes || len(report.Denials) > MaximumReportDenials {
		return rows == 0
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed || writer.waiting+rows > writer.options.Rows {
		return false
	}
	writer.queue = append(writer.queue, report)
	writer.waiting += rows
	select {
	case writer.wake <- struct{}{}:
	default:
	}
	return true
}

// Queued returns the rows waiting.
func (writer *ReportWriter) Queued() int {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.waiting
}

// Close stops taking reports and returns once what was queued is written.
func (writer *ReportWriter) Close() {
	writer.mu.Lock()
	if !writer.closed {
		writer.closed = true
		close(writer.wake)
	}
	writer.mu.Unlock()
	<-writer.done
}

func (writer *ReportWriter) run() {
	defer close(writer.done)
	for {
		_, open := <-writer.wake
		if open {
			// Reports gather for the window: they are never urgent.
			timer := time.NewTimer(writer.options.Window)
			select {
			case <-timer.C:
			case _, open = <-writer.wake:
				// A second wake within the window: write what came so far.
				timer.Stop()
			}
		}
		for {
			batch, rows := writer.take()
			if len(batch) == 0 {
				break
			}
			writer.write(batch, rows)
		}
		if !open {
			return
		}
	}
}

// take removes reports up to one store call's bounds.
func (writer *ReportWriter) take() ([]Reports, int) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	outcomes, denials, taken := 0, 0, 0
	for _, report := range writer.queue {
		if taken > 0 && (outcomes+len(report.Finished) > maximumCallOutcomes ||
			denials+len(report.Denials) > maximumCallDenials) {
			break
		}
		outcomes, denials, taken = outcomes+len(report.Finished), denials+len(report.Denials), taken+1
	}
	batch := writer.queue[:taken:taken]
	writer.queue = writer.queue[taken:]
	writer.waiting -= outcomes + denials
	return batch, outcomes + denials
}

func (writer *ReportWriter) write(batch []Reports, rows int) {
	ctx, cancel := context.WithTimeout(context.Background(), writer.options.Timeout)
	defer cancel()
	outcomes, denials, err := writer.store.RecordReports(ctx, batch)
	// Rows of an unknown gateway or out of form are skipped by the store,
	// and counted lost with a failed call's.
	if lost := rows - outcomes - denials; (err != nil || lost > 0) && writer.options.Lost != nil {
		if err != nil {
			lost = rows
		}
		writer.options.Lost(lost)
	}
}
