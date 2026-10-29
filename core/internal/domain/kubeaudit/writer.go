package kubeaudit

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"meshtransit.net/core/internal/domain/publicid"
)

// Store records intents durably (schema 245).
type Store interface {
	// Record issues each row's audit_id right before writing them (the
	// schema refuses one issued seconds before, review b0b2 M-b), writes
	// them in one transaction, at READ COMMITTED with synchronous commit,
	// and answers each in order: accepted, duplicate (with the first
	// audit_id), conflict, invalid, gateway or device. A DataError means one
	// of the rows made the whole transaction fail.
	Record(ctx context.Context, rows []Row) ([]StoredAnswer, error)
}

// StoredAnswer is the store's answer for one row.
type StoredAnswer struct {
	Outcome Outcome
	AuditID publicid.ID
}

// DataError marks a store failure a row's data caused (SQLSTATE 22, 23):
// the writer then records each submission alone to find it.
type DataError struct{ Err error }

func (err DataError) Error() string { return "kubeaudit: a row was refused: " + err.Err.Error() }
func (err DataError) Unwrap() error { return err.Err }

// MaximumRows bounds one store call, the schema's (000245).
const MaximumRows = 1000

// maximumCoolOff bounds how long the writer stops calling the store after
// failures that are not a row's data (review b0b2 M-a).
const maximumCoolOff = 30 * time.Second

// isolationGiveUp is how many submissions written alone in a row may fail
// on their data, none succeeding, before the rest are answered unavailable:
// a failure every row meets (a missing partition) is no one submission's.
const isolationGiveUp = 2

// WriterOptions bound a writer (design §5).
type WriterOptions struct {
	// Window and Rows end a batch: whichever comes first. Rows is at most
	// MaximumRows.
	Window time.Duration
	Rows   int
	// Queue bounds the rows waiting, by the writer's measured drain in
	// 200 ms; a Workspace never holds more than half while others wait, so
	// half must fit the largest submission.
	Queue int
	// Timeout bounds one store call; its COMMIT is never cancelled by a
	// session ending (review v2 M2).
	Timeout time.Duration
	// RetryAfter is what an overloaded or unavailable answer asks to wait.
	RetryAfter time.Duration
	// Isolated, when set, hears of each batch written submission by
	// submission after a row's data failed it.
	Isolated func()
	// CooledOff, when set, hears of each batch answered unavailable without
	// a store call while the writer cools off.
	CooledOff func()
}

// Writer records submissions from many sessions in shared transactions,
// taking Workspaces in turn (design §5).
type Writer struct {
	store   Store
	options WriterOptions

	mu      sync.Mutex
	queues  map[string][]*submission // by Workspace
	held    map[string]int           // rows queued, by Workspace
	order   []string                 // Workspaces with a queue, in turn
	waiting int                      // rows queued
	closed  bool
	wake    chan struct{}
	done    chan struct{}

	// After a failure that is not a row's data the writer calls the store
	// again only after coolOff, doubling from RetryAfter to maximumCoolOff
	// while failures go on: a COMMIT stuck on a lost synchronous standby
	// holds its connection and locks, and each call would strand another
	// (review b0b2 M-a). Only the writer goroutine reads and writes them.
	coolOff      time.Duration
	coolingUntil time.Time
}

type submission struct {
	rows    []Row
	answers chan []Answer
}

// NewWriter starts a writer; Close stops it after writing what it holds.
func NewWriter(store Store, options WriterOptions) (*Writer, error) {
	if store == nil || options.Window <= 0 || options.Rows < 1 || options.Rows > MaximumRows ||
		options.Queue/2 < min(MaximumIntents, options.Rows) || options.Timeout <= 0 || options.RetryAfter <= 0 {
		return nil, errors.New("kubeaudit: invalid writer options")
	}
	writer := &Writer{store: store, options: options, queues: map[string][]*submission{}, held: map[string]int{},
		wake: make(chan struct{}, 1), done: make(chan struct{})}
	go writer.run()
	return writer, nil
}

// Submit queues a copy of one session's rows, all of one gateway's
// Workspace, and returns where their answers come; the store issues their
// audit_ids. Rows out of bounds are invalid; a submission that finds no
// room is overloaded at once (design §5).
func (writer *Writer) Submit(rows []Row) <-chan []Answer {
	answers := make(chan []Answer, 1)
	workspace, valid := writer.workspaceOf(rows)
	if !valid {
		answers <- writer.all(rows, OutcomeInvalid)
		return answers
	}
	rows = slices.Clone(rows)
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed {
		answers <- writer.all(rows, OutcomeUnavailable)
		return answers
	}
	if !writer.makeRoomLocked(workspace, len(rows)) {
		answers <- writer.all(rows, OutcomeOverloaded)
		return answers
	}
	if len(writer.queues[workspace]) == 0 {
		writer.order = append(writer.order, workspace)
	}
	writer.queues[workspace] = append(writer.queues[workspace], &submission{rows: rows, answers: answers})
	writer.held[workspace] += len(rows)
	writer.waiting += len(rows)
	select {
	case writer.wake <- struct{}{}:
	default:
	}
	return answers
}

// workspaceOf returns the Workspace of rows: 1 to the largest submission,
// all of the same one.
func (writer *Writer) workspaceOf(rows []Row) (string, bool) {
	if len(rows) == 0 || len(rows) > min(MaximumIntents, writer.options.Rows) || rows[0].Gateway.Workspace == "" {
		return "", false
	}
	workspace := rows[0].Gateway.Workspace
	for _, row := range rows[1:] {
		if row.Gateway.Workspace != workspace {
			return "", false
		}
	}
	return workspace, true
}

// makeRoomLocked reports whether workspace may queue n more rows. While
// another Workspace waits, none holds more than half the queue; a full
// queue refuses the newest submissions of its longest Workspace, so a
// noisy one never shuts a quiet one out (design §5).
func (writer *Writer) makeRoomLocked(workspace string, n int) bool {
	held := writer.held[workspace] + n
	others := len(writer.order)
	if writer.held[workspace] > 0 {
		others--
	}
	if others > 0 && held > writer.options.Queue/2 {
		return false
	}
	for writer.waiting+n > writer.options.Queue {
		longest := ""
		for queued, rows := range writer.held {
			if rows > writer.held[longest] || rows == writer.held[longest] && queued < longest {
				longest = queued
			}
		}
		if longest == "" || longest == workspace || writer.held[longest] <= held {
			return false
		}
		writer.evictNewestLocked(longest)
	}
	return true
}

// evictNewestLocked answers workspace's newest submission overloaded.
func (writer *Writer) evictNewestLocked(workspace string) {
	queue := writer.queues[workspace]
	newest := queue[len(queue)-1]
	newest.answers <- writer.all(newest.rows, OutcomeOverloaded)
	writer.queues[workspace] = queue[:len(queue)-1]
	writer.held[workspace] -= len(newest.rows)
	writer.waiting -= len(newest.rows)
	if len(writer.queues[workspace]) == 0 {
		writer.forgetLocked(workspace)
		writer.order = slices.DeleteFunc(writer.order, func(queued string) bool { return queued == workspace })
	}
}

func (writer *Writer) forgetLocked(workspace string) {
	delete(writer.queues, workspace)
	delete(writer.held, workspace)
}

func (writer *Writer) all(rows []Row, outcome Outcome) []Answer {
	answers := make([]Answer, len(rows))
	for index := range answers {
		answers[index] = Answer{Outcome: outcome}
		if outcome == OutcomeOverloaded || outcome == OutcomeUnavailable {
			answers[index].RetryAfter = writer.options.RetryAfter
		}
	}
	return answers
}

// Queued returns the rows waiting.
func (writer *Writer) Queued() int {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.waiting
}

// Close stops taking submissions and returns once what was queued is
// written or answered; each store call is bounded by Timeout and its
// COMMIT's own limit.
func (writer *Writer) Close() {
	writer.mu.Lock()
	if !writer.closed {
		writer.closed = true
		close(writer.wake)
	}
	writer.mu.Unlock()
	<-writer.done
}

func (writer *Writer) run() {
	defer close(writer.done)
	for {
		_, open := <-writer.wake
		// Gather for the window, unless the batch fills first.
		timer := time.NewTimer(writer.options.Window)
	gather:
		for open && writer.Queued() < writer.options.Rows {
			select {
			case _, open = <-writer.wake:
			case <-timer.C:
				break gather
			}
		}
		timer.Stop()
		for {
			batch := writer.take()
			if len(batch) == 0 {
				break
			}
			writer.write(batch)
		}
		if !open {
			return
		}
	}
}

// take removes up to Rows rows, a submission at a time, Workspaces in turn.
func (writer *Writer) take() []*submission {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	var batch []*submission
	rows := 0
	for len(writer.order) > 0 {
		workspace := writer.order[0]
		next := writer.queues[workspace][0]
		if rows+len(next.rows) > writer.options.Rows {
			break
		}
		batch = append(batch, next)
		rows += len(next.rows)
		writer.waiting -= len(next.rows)
		writer.held[workspace] -= len(next.rows)
		writer.queues[workspace] = writer.queues[workspace][1:]
		writer.order = writer.order[1:]
		if len(writer.queues[workspace]) > 0 {
			writer.order = append(writer.order, workspace)
		} else {
			writer.forgetLocked(workspace)
		}
	}
	return batch
}

// write records a batch in one transaction. A row's data failing it, each
// submission is written alone, so only the one with it fails; any other
// failure answers the rest unavailable without trying again, and the writer
// cools off (a slow database gets no more load, review v2 M2).
func (writer *Writer) write(batch []*submission) {
	if time.Now().Before(writer.coolingUntil) {
		if writer.options.CooledOff != nil {
			writer.options.CooledOff()
		}
		writer.unavailable(batch)
		return
	}
	var rows []Row
	for _, queued := range batch {
		rows = append(rows, queued.rows...)
	}
	stored, err := writer.record(rows)
	var data DataError
	switch {
	case err == nil:
		writer.answer(batch, stored)
	case errors.As(err, &data) && len(batch) > 1:
		if writer.options.Isolated != nil {
			writer.options.Isolated()
		}
		writer.isolate(batch)
	default:
		writer.unavailable(batch)
	}
}

// isolate writes each submission alone, until a failure that is not its
// data, or one every row seems to meet.
func (writer *Writer) isolate(batch []*submission) {
	failed, written := 0, 0
	for index, queued := range batch {
		alone, err := writer.record(queued.rows)
		var data DataError
		switch {
		case err == nil:
			written++
			writer.answer([]*submission{queued}, alone)
			continue
		case errors.As(err, &data):
			failed++
			queued.answers <- writer.all(queued.rows, OutcomeUnavailable)
			if written > 0 || failed < isolationGiveUp {
				continue
			}
		default:
			queued.answers <- writer.all(queued.rows, OutcomeUnavailable)
		}
		writer.unavailable(batch[index+1:])
		return
	}
}

func (writer *Writer) unavailable(batch []*submission) {
	for _, queued := range batch {
		queued.answers <- writer.all(queued.rows, OutcomeUnavailable)
	}
}

// record calls the store under the writer's own timeout: a session ending
// never cancels a COMMIT. A failure that is not a row's data starts or
// lengthens the cool-off; a success ends it.
func (writer *Writer) record(rows []Row) ([]StoredAnswer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), writer.options.Timeout)
	defer cancel()
	stored, err := writer.store.Record(ctx, rows)
	if err == nil && len(stored) != len(rows) {
		err = errors.New("kubeaudit: the store answered another number of rows")
	}
	var data DataError
	switch {
	case err == nil:
		writer.coolOff = 0
	case !errors.As(err, &data):
		writer.coolOff = min(max(2*writer.coolOff, writer.options.RetryAfter), maximumCoolOff)
		writer.coolingUntil = time.Now().Add(writer.coolOff)
	}
	return stored, err
}

func (writer *Writer) answer(batch []*submission, stored []StoredAnswer) {
	offset := 0
	for _, queued := range batch {
		answers := make([]Answer, len(queued.rows))
		for index := range queued.rows {
			got := stored[offset+index]
			answers[index] = Answer{Outcome: got.Outcome, AuditID: got.AuditID}
		}
		offset += len(queued.rows)
		queued.answers <- answers
	}
}
