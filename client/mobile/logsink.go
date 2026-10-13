package mobile

import (
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// logQueueLength bounds the records waiting for the platform's log sink.
const logQueueLength = 512

// asyncLog passes the runtime's log records to the platform on its own
// goroutine, so a slow or re-entrant sink never stalls the runtime (slog's
// handler holds a lock while it writes). A full queue drops records and
// counts them; the count is reported before the next record delivered, or
// when the queue closes.
type asyncLog struct {
	sink    LogSink
	records chan string
	dropped atomic.Uint64
	done    chan struct{}

	mu     sync.RWMutex // Write holds it shared; close exclusively
	closed bool
}

func newAsyncLog(sink LogSink) *asyncLog {
	queue := &asyncLog{sink: sink, records: make(chan string, logQueueLength), done: make(chan struct{})}
	go queue.run()
	return queue
}

// Write implements io.Writer for slog's JSON handler, one record per call.
func (queue *asyncLog) Write(record []byte) (int, error) {
	queue.mu.RLock()
	defer queue.mu.RUnlock()
	if queue.closed {
		return len(record), nil
	}
	select {
	case queue.records <- strings.TrimRight(string(record), "\n"):
	default:
		queue.dropped.Add(1)
	}
	return len(record), nil
}

func (queue *asyncLog) run() {
	defer close(queue.done)
	for record := range queue.records {
		queue.reportDropped()
		queue.deliver(record)
	}
	queue.reportDropped()
}

// reportDropped delivers the count of records dropped since the last report.
func (queue *asyncLog) reportDropped() {
	if dropped := queue.dropped.Swap(0); dropped != 0 {
		queue.deliver(`{"level":"WARN","msg":"log records dropped","count":` + strconv.FormatUint(dropped, 10) + `}`)
	}
}

// deliver calls the platform; a panic in the sink loses that record only.
func (queue *asyncLog) deliver(record string) {
	defer func() { _ = recover() }()
	queue.sink.Log(record)
}

// close stops accepting records and waits until the queued ones are
// delivered. Records written after close are dropped.
func (queue *asyncLog) close() {
	queue.mu.Lock()
	if queue.closed {
		queue.mu.Unlock()
		return
	}
	queue.closed = true
	close(queue.records)
	queue.mu.Unlock()
	<-queue.done
}

// newLogger returns the runtime's logger, writing JSON records to queue, or
// nowhere when queue is nil.
func newLogger(queue *asyncLog) *slog.Logger {
	if queue == nil {
		return slog.New(slog.DiscardHandler)
	}
	return slog.New(slog.NewJSONHandler(queue, &slog.HandlerOptions{Level: slog.LevelInfo}))
}
