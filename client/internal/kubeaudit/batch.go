package kubeaudit

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"meshtransit.net/client/internal/controlplane"
)

// Run sends batches and reports until ctx ends; then every intent still
// waiting is answered ErrStopped.
func (recorder *Recorder) Run(ctx context.Context) error {
	var running sync.WaitGroup
	running.Add(1)
	go func() {
		defer running.Done()
		recorder.reportLoop(ctx)
	}()
	defer running.Wait()
	defer recorder.stop()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		wait, ready := recorder.due(time.Now())
		if ready {
			recorder.sendBatch(ctx, &running)
			continue
		}
		timer.Reset(wait)
		select {
		case <-ctx.Done():
			return nil
		case <-recorder.wake:
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

// due reports whether a batch may leave now, else how long to wait: a
// batch leaves once full or Window after its oldest intent, while fewer
// than four wait, the gateway is not paused and its bucket holds a token.
func (recorder *Recorder) due(now time.Time) (time.Duration, bool) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	const idle = time.Hour
	if recorder.queued == 0 || recorder.inFlight >= maximumInFlight {
		return idle, false // woken by an intent or a batch's end
	}
	if now.Before(recorder.paused) {
		return recorder.paused.Sub(now), false
	}
	recorder.refillGatewayLocked(now)
	if recorder.gateway.tokens < 1 {
		return time.Duration(float64(time.Second) * (1 - recorder.gateway.tokens) / recorder.rate), false
	}
	recorder.messages.refill(messageRate, messageBurst, now)
	if recorder.messages.tokens < messageFloor {
		// Waiting lets more intents join the batch.
		return time.Duration(float64(time.Second) * (messageFloor - recorder.messages.tokens) / messageRate), false
	}
	if recorder.queued >= maximumBatch {
		return 0, true
	}
	oldest := now
	for _, device := range recorder.order {
		if queue := recorder.queues[device]; len(queue) > 0 && queue[0].queuedAt.Before(oldest) {
			oldest = queue[0].queuedAt
		}
	}
	if leave := oldest.Add(recorder.options.Window); now.Before(leave) {
		return leave.Sub(now), false
	}
	return 0, true
}

// refillGatewayLocked refills the gateway's bucket, and grows its rate back
// by 5% a second towards Rate after a "limited" (AIMD, Q67).
func (recorder *Recorder) refillGatewayLocked(now time.Time) {
	elapsed := now.Sub(recorder.gateway.at).Seconds()
	if elapsed <= 0 {
		return
	}
	recorder.rate = min(recorder.options.Rate, recorder.rate*(1+0.05*elapsed))
	recorder.gateway.refill(recorder.rate, recorder.options.Burst, now)
}

// takeLocked removes up to n intents, one Device at a time in turn, within
// the batch's encoded size and what Core's budget holds now, dropping those
// whose callers stopped waiting.
func (recorder *Recorder) takeLocked(n int) []*waiter {
	var batch []*waiter
	size := 0
	budget := min(batchBudget, max(messageFloor, int(recorder.messages.tokens)))
	for len(batch) < n && len(recorder.order) > 0 {
		device := recorder.order[0]
		queue := recorder.queues[device]
		next := queue[0]
		if !next.abandoned && len(batch) > 0 && size+next.size > budget {
			break // the next batch takes it
		}
		recorder.order = recorder.order[1:]
		queue = queue[1:]
		recorder.queued--
		if len(queue) > 0 {
			recorder.queues[device] = queue
			recorder.order = append(recorder.order, device)
		} else {
			delete(recorder.queues, device)
		}
		if !next.abandoned {
			batch = append(batch, next)
			size += next.size
		}
	}
	return batch
}

// sendBatch takes a batch and has its own goroutine send it and wait for
// the answer.
func (recorder *Recorder) sendBatch(ctx context.Context, running *sync.WaitGroup) {
	recorder.mu.Lock()
	batch := recorder.takeLocked(min(maximumBatch, int(recorder.gateway.tokens)))
	if len(batch) == 0 {
		recorder.mu.Unlock()
		return
	}
	recorder.gateway.tokens -= float64(len(batch))
	size := 0
	for _, waiting := range batch {
		size += waiting.size
	}
	recorder.messages.tokens -= float64(max(size, messageFloor))
	recorder.inFlight++
	recorder.mu.Unlock()
	running.Add(1)
	go func() {
		defer running.Done()
		reply := recorder.call(ctx, batch)
		recorder.dispatch(batch, reply)
		recorder.mu.Lock()
		recorder.inFlight--
		recorder.mu.Unlock()
		select {
		case recorder.wake <- struct{}{}:
		default:
		}
	}()
}

// call hands a batch to the map stream and waits for its answer, both
// within Wait: a stream that takes no call (no session, no map) answers
// unavailable.
func (recorder *Recorder) call(ctx context.Context, batch []*waiter) controlplane.KubeAuditReply {
	deadline := time.Now().Add(recorder.options.Wait)
	message := controlplane.KubeAuditBatch{Intents: make([]controlplane.KubeAuditIntent, len(batch))}
	if _, err := rand.Read(message.ID[:]); err != nil {
		return controlplane.KubeAuditReply{Err: err}
	}
	for index, waiting := range batch {
		message.Intents[index] = waiting.intent
	}
	reply := make(chan controlplane.KubeAuditReply, 1)
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case recorder.options.Calls <- controlplane.KubeAuditCall{Batch: message, Reply: reply, Deadline: deadline}:
	case <-timer.C:
		return controlplane.KubeAuditReply{Err: controlplane.ErrKubeAuditSessionLost}
	case <-ctx.Done():
		return controlplane.KubeAuditReply{Err: ErrStopped}
	}
	select {
	case answer := <-reply:
		return answer
	case <-timer.C:
	case <-ctx.Done():
	}
	// An answer that came with the timer is still the answer.
	select {
	case answer := <-reply:
		return answer
	default:
	}
	if ctx.Err() != nil {
		return controlplane.KubeAuditReply{Err: ErrStopped}
	}
	return controlplane.KubeAuditReply{Err: controlplane.ErrKubeAuditTimeout}
}

// dispatch answers each intent of a batch. A "limited" pauses the gateway
// for Core's wait and halves its rate; intents that waited under a second
// then go back to the queue instead of being refused (re-review M-2). A
// session lost goes back too, for intents still within their wait: Core
// dedupes them by ID (review b2 M2).
func (recorder *Recorder) dispatch(batch []*waiter, reply controlplane.KubeAuditReply) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	now := time.Now()
	if recorder.stopped {
		for _, waiting := range batch {
			recorder.deliverLocked(waiting, Answer{Err: ErrStopped})
		}
		return
	}
	if errors.Is(reply.Err, controlplane.ErrKubeAuditSessionLost) {
		// Backwards, so the Device's intents keep their order (review b2 L4).
		for index := len(batch) - 1; index >= 0; index-- {
			if waiting := batch[index]; !waiting.abandoned &&
				now.Sub(waiting.queuedAt) < recorder.options.Wait {
				recorder.enqueueLocked(waiting, true)
			} else {
				recorder.deliverLocked(waiting, Answer{Err: reply.Err})
			}
		}
		return
	}
	if reply.Err != nil || len(reply.Results) != len(batch) {
		err := reply.Err
		if err == nil {
			err = controlplane.ErrKubeAuditAck
		}
		for _, waiting := range batch {
			recorder.deliverLocked(waiting, Answer{Err: err})
		}
		return
	}
	limited := time.Duration(-1)
	for index := len(reply.Results) - 1; index >= 0; index-- {
		result, waiting := reply.Results[index], batch[index]
		switch {
		case result.Recorded():
			recorder.deliverLocked(waiting, Answer{AuditID: result.AuditID, Recorded: true})
		case result.Refused == RefusedLimited:
			limited = max(limited, result.RetryAfter)
			if now.Sub(waiting.queuedAt) < requeueWithin && !waiting.abandoned {
				recorder.enqueueLocked(waiting, true)
				continue
			}
			recorder.deliverLocked(waiting, Answer{Refused: result.Refused, RetryAfter: result.RetryAfter})
		default:
			recorder.deliverLocked(waiting, Answer{Refused: result.Refused, RetryAfter: result.RetryAfter})
		}
	}
	if limited >= 0 {
		if limited == 0 {
			limited = pauseOnUnknown
		}
		// A pause never shortens another (review b2 M5); the burst goes with
		// the rate, or it would be spent at once after it (M4).
		if until := now.Add(limited); until.After(recorder.paused) {
			recorder.paused = until
		}
		recorder.refillGatewayLocked(now) // credit the time before, at the old rate
		recorder.rate = max(recorder.rate/2, min(1, recorder.options.Rate))
		recorder.gateway.tokens = min(recorder.gateway.tokens, recorder.rate)
	}
}

// deliverLocked hands a waiter its answer; one whose caller stopped
// waiting gets none, and a record made for it is reported as not
// forwarded.
func (recorder *Recorder) deliverLocked(waiting *waiter, answer Answer) {
	if waiting.answered {
		return // answered once only (review b2 L2)
	}
	if waiting.abandoned {
		if answer.Recorded {
			recorder.reports.finished(answer.AuditID, 0, 0)
		}
		return
	}
	waiting.answered = true
	recorder.releaseLocked(waiting.device)
	waiting.reply <- answer
}

// stop refuses new intents and answers those still queued.
func (recorder *Recorder) stop() {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.stopped = true
	for _, device := range recorder.order {
		for _, waiting := range recorder.queues[device] {
			recorder.deliverLocked(waiting, Answer{Err: ErrStopped})
		}
		delete(recorder.queues, device)
	}
	recorder.order, recorder.queued = nil, 0
}
