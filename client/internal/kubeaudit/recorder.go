// Package kubeaudit has Core record a Kubernetes gateway's type A
// operations before the gateway forwards them, and reports their outcomes
// and the requests the gateway refused itself (gateway.audit1, mtcp-v1
// §6.10; K1b design §7).
package kubeaudit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"slices"
	"sync"
	"time"

	"meshtransit.net/client/internal/controlplane"
)

// RefusedLimited is Core's, or the recorder's own, refusal of an intent
// over the limits.
const RefusedLimited = "limited"

var (
	// ErrStopped reports a recorder that no longer takes intents.
	ErrStopped = errors.New("kubeaudit: recorder stopped")
	// ErrTimeout reports an intent Core did not answer within the wait: the
	// gateway must not forward it, whatever comes later.
	ErrTimeout = errors.New("kubeaudit: no answer in time")
)

// Options bound a recorder (K1b design §7, Q57, Q67).
type Options struct {
	// Calls and Reports go to the map stream (controlplane.NetmapOptions
	// KubeAudits, KubeAuditReports).
	Calls   chan<- controlplane.KubeAuditCall
	Reports chan<- controlplane.KubeAuditReport
	// CoreNow is the time by Core's clock: intent IDs carry it.
	CoreNow func() time.Time
	// Window: a batch leaves this long after its first intent, or full.
	Window time.Duration
	// Wait bounds how long an intent waits for its answer.
	Wait time.Duration
	// Rate and Burst are the gateway's own bucket, at or under Core's
	// cluster limit; Core's "limited" halves the rate, which then grows
	// back by 5% a second.
	Rate, Burst float64
	// DeviceRate, DeviceBurst and DevicePending bound one Device: its share
	// of the bucket, and how many of its intents may wait at once.
	DeviceRate, DeviceBurst float64
	DevicePending           int
	// ReportWindow and DenialWindow pace outcomes and denials.
	ReportWindow, DenialWindow time.Duration
}

// DefaultOptions are the design's (§7): 5 ms batches, 5 s wait, 180/s burst
// 1,800 for the gateway, 20/s burst 200 and 8 waiting for a Device.
func DefaultOptions() Options {
	return Options{Window: 5 * time.Millisecond, Wait: 5 * time.Second, Rate: 180, Burst: 1800,
		DeviceRate: 20, DeviceBurst: 200, DevicePending: 8, ReportWindow: time.Second, DenialWindow: 10 * time.Second}
}

func (options Options) valid() bool {
	return options.Calls != nil && options.Reports != nil && options.CoreNow != nil && options.Window >= minimumWindow &&
		options.Wait > 0 && options.Rate > 0 && options.Burst >= maximumBatch && options.DeviceRate > 0 &&
		options.DeviceBurst >= 1 && options.DevicePending >= 1 && options.ReportWindow > 0 && options.DenialWindow > 0
}

const (
	// maximumBatch is the most intents one batch carries; maximumInFlight
	// how many batches Core lets wait.
	maximumBatch    = 128
	maximumInFlight = 4
	// requeueWithin: an intent Core refused "limited" that has waited less
	// goes back to the queue instead of being refused.
	requeueWithin = time.Second
	// pauseOnUnknown is the pause after a "limited" without a wait.
	pauseOnUnknown = time.Second
	// pruneEvery paces forgetting full Device buckets.
	pruneEvery = time.Minute
	// Core charges each audit message at least messageFloor bytes of a
	// budget of 512 KiB at once and 256 KiB/s (mtcp-v1 §14): the recorder
	// keeps to 80% of it, so batches grow under load instead of each being
	// refused (review b2 re-review M-L7).
	messageFloor = 4 << 10
	messageRate  = 0.8 * (256 << 10)
	messageBurst = 0.8 * (512 << 10)
	// minimumWindow bounds how often batches may leave.
	minimumWindow = time.Millisecond
)

// Answer is Core's, or the recorder's, answer to one intent.
type Answer struct {
	// AuditID is set when Core recorded the intent: the gateway forwards
	// with it as Audit-ID.
	AuditID  [16]byte
	Recorded bool
	// Refused and RetryAfter say why not, when not recorded and Err is nil.
	Refused    string
	RetryAfter time.Duration
	// Err: no answer (the session, a timeout, the recorder stopped).
	Err error
}

// Recorder batches intents for Core, fairly among Devices.
type Recorder struct {
	options Options
	reports *reports

	mu       sync.Mutex
	queues   map[string][]*waiter // by Device
	order    []string             // Devices with a queue, in turn
	queued   int
	pending  map[string]int // by Device: intents not yet answered
	devices  map[string]*bucket
	gateway  bucket
	messages bucket    // bytes of Core's audit budget
	rate     float64   // the gateway's rate now (AIMD)
	paused   time.Time // no batch leaves before
	inFlight int
	stopped  bool
	pruned   time.Time
	wake     chan struct{}
}

type waiter struct {
	device   string
	intent   controlplane.KubeAuditIntent
	size     int // encodedSize of intent
	queuedAt time.Time
	reply    chan Answer // room for one
	// abandoned is set, under the recorder's lock, once the caller stopped
	// waiting: an answer then never reaches it. answered is set once an
	// answer was handed over.
	abandoned, answered bool
}

type bucket struct {
	tokens float64
	at     time.Time
}

// New makes a recorder; Run serves it.
func New(options Options) (*Recorder, error) {
	if !options.valid() {
		return nil, errors.New("kubeaudit: invalid options")
	}
	now := time.Now()
	return &Recorder{options: options, reports: newReports(), queues: map[string][]*waiter{},
		pending: map[string]int{}, devices: map[string]*bucket{}, gateway: bucket{tokens: options.Burst, at: now},
		messages: bucket{tokens: messageBurst, at: now}, rate: options.Rate, wake: make(chan struct{}, 1)}, nil
}

// Record has Core record intent for device before the gateway forwards it.
// The intent's ID and ObservedAt are set here. It returns once Core
// answered, the recorder refused it itself, ctx ended, or Wait passed: only
// an Answer with Recorded lets the gateway forward.
func (recorder *Recorder) Record(ctx context.Context, device string, intent controlplane.KubeAuditIntent) Answer {
	if !validIntent(intent) {
		return Answer{Refused: RefusedInvalid}
	}
	// The recorder keeps its own copy: the caller may reuse its slices once
	// it stopped waiting (review b2 M7).
	intent.Groups, intent.TokenID = slices.Clone(intent.Groups), bytes.Clone(intent.TokenID)
	coreNow := recorder.options.CoreNow()
	id, err := intentID(coreNow)
	if err != nil {
		return Answer{Err: err}
	}
	intent.ID, intent.ObservedAt = id, coreNow
	now := time.Now()
	recorder.mu.Lock()
	if recorder.stopped {
		recorder.mu.Unlock()
		return Answer{Err: ErrStopped}
	}
	if recorder.pending[device] >= recorder.options.DevicePending || !recorder.takeDevice(device, now) {
		recorder.mu.Unlock()
		return Answer{Refused: RefusedLimited, RetryAfter: time.Second}
	}
	waiting := &waiter{device: device, intent: intent, size: encodedSize(intent), queuedAt: now,
		reply: make(chan Answer, 1)}
	recorder.pending[device]++
	recorder.enqueueLocked(waiting, false)
	recorder.mu.Unlock()

	timer := time.NewTimer(recorder.options.Wait)
	defer timer.Stop()
	select {
	case answer := <-waiting.reply:
		return answer
	case <-ctx.Done():
		recorder.abandon(waiting)
		return Answer{Err: ctx.Err()}
	case <-timer.C:
		recorder.abandon(waiting)
		return Answer{Err: ErrTimeout}
	}
}

// abandon stops waiting: an answer still to come never reaches the caller,
// and one that records the intent is reported as not forwarded.
func (recorder *Recorder) abandon(waiting *waiter) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if !waiting.abandoned && !waiting.answered {
		recorder.releaseLocked(waiting.device)
	}
	waiting.abandoned = true
	select {
	case answer := <-waiting.reply:
		// It came as the caller gave up: never forwarded.
		if answer.Recorded {
			recorder.reports.finished(answer.AuditID, 0, 0)
		}
	default:
	}
}

// releaseLocked ends one of device's pending intents.
func (recorder *Recorder) releaseLocked(device string) {
	recorder.pending[device]--
	if recorder.pending[device] <= 0 {
		delete(recorder.pending, device)
	}
}

// Finished reports a forwarded operation's outcome.
func (recorder *Recorder) Finished(auditID [16]byte, status int, duration time.Duration) {
	recorder.reports.finished(auditID, status, duration)
}

// Denied counts a request of peer the gateway refused itself (type B).
func (recorder *Recorder) Denied(peer, reason string) {
	recorder.reports.denied(peer, reason, nil, time.Now())
}

// ProfileDenied counts a request of peer an access profile refused, or
// would refuse once its rule enforces, with the request as a sample.
func (recorder *Recorder) ProfileDenied(peer string, wouldDeny bool, sample controlplane.KubeAuditDenialSample) {
	reason := "profile_denied"
	if wouldDeny {
		reason = "profile_would_deny"
	}
	recorder.reports.denied(peer, reason, &sample, time.Now())
}

// takeDevice takes one token of device's bucket. Now and then the buckets
// refilled full of Devices with nothing pending are forgotten: a full
// bucket is the same as none (review b2 M6).
func (recorder *Recorder) takeDevice(device string, now time.Time) bool {
	if now.Sub(recorder.pruned) >= pruneEvery {
		recorder.pruned = now
		for other, held := range recorder.devices {
			if held.refill(recorder.options.DeviceRate, recorder.options.DeviceBurst, now); held.tokens >= recorder.options.DeviceBurst &&
				recorder.pending[other] == 0 {
				delete(recorder.devices, other)
			}
		}
	}
	held, found := recorder.devices[device]
	if !found {
		held = &bucket{tokens: recorder.options.DeviceBurst, at: now}
		recorder.devices[device] = held
	}
	held.refill(recorder.options.DeviceRate, recorder.options.DeviceBurst, now)
	if held.tokens < 1 {
		return false
	}
	held.tokens--
	return true
}

func (held *bucket) refill(rate, burst float64, now time.Time) {
	if elapsed := now.Sub(held.at); elapsed > 0 {
		held.tokens = min(burst, held.tokens+elapsed.Seconds()*rate)
		held.at = now
	}
}

// enqueueLocked queues a waiter for its Device, at the front when it goes
// back after a "limited".
func (recorder *Recorder) enqueueLocked(waiting *waiter, front bool) {
	queue := recorder.queues[waiting.device]
	if len(queue) == 0 {
		recorder.order = append(recorder.order, waiting.device)
	}
	if front {
		recorder.queues[waiting.device] = append([]*waiter{waiting}, queue...)
	} else {
		recorder.queues[waiting.device] = append(queue, waiting)
	}
	recorder.queued++
	select {
	case recorder.wake <- struct{}{}:
	default:
	}
}

// intentID is a UUIDv7 at now: 48 bits of milliseconds, version 7, the
// variant, random bits.
func intentID(now time.Time) ([16]byte, error) {
	var id [16]byte
	if _, err := rand.Read(id[6:]); err != nil {
		return id, err
	}
	var millis [8]byte
	binary.BigEndian.PutUint64(millis[:], uint64(now.UnixMilli())) //nolint:gosec // after 1970
	copy(id[:6], millis[2:])
	id[6] = 0x70 | id[6]&0x0f
	id[8] = 0x80 | id[8]&0x3f
	return id, nil
}
