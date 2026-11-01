package flowreport

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"path/filepath"
	"slices"
	"sync"
	"time"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/flowcount"
	"meshtransit.net/client/internal/privatefile"
	"meshtransit.net/shared/flowlog"
)

const (
	// postTimeout bounds one request: a batch of a few MiB on a slow uplink.
	postTimeout     = 2 * time.Minute
	minBackoff      = 5 * time.Second
	maxBackoff      = 5 * time.Minute
	maxSendsPerTurn = 64
)

// Config wires a Reporter to the packet filter and the disk.
type Config struct {
	// Dir holds one spool per Network; its parent must exist.
	Dir string
	// SetCounter starts (non-nil) or stops counting at the packet filter.
	SetCounter func(*flowcount.Counter)
	// Policy is what the filter enforces now.
	Policy func() Policy
	Logger *slog.Logger
	Limits Limits
	Now    func() time.Time
}

// Status is what the local API shows of connection logging. On means this
// node's connections are being counted for the Network.
type Status struct {
	On        bool
	NetworkID string
	Pending   uint64
	LastSent  time.Time
	LastError string
}

// Reporter counts, keeps and sends one Network's connection logs while Core
// grants a FlowTicket (flowlog-v1 §4–5).
type Reporter struct {
	config  Config
	tickets chan controlplane.FlowTicket

	mu     sync.Mutex
	status Status
}

// New returns a Reporter; Run makes it work.
func New(config Config) *Reporter {
	if config.Logger == nil {
		config.Logger = slog.New(slog.DiscardHandler)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Limits == (Limits{}) {
		config.Limits = DiskLimits()
	}
	return &Reporter{config: config, tickets: make(chan controlplane.FlowTicket, 1)}
}

// SetTicket hands over Core's latest FlowTicket; only the latest counts. An
// empty ticket stops logging.
func (r *Reporter) SetTicket(ticket controlplane.FlowTicket) {
	for {
		select {
		case r.tickets <- ticket:
			return
		default:
		}
		select {
		case <-r.tickets:
		default:
		}
	}
}

// Status is a snapshot for the local API.
func (r *Reporter) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

// active is the Network logging is on for.
type active struct {
	ticket controlplane.FlowTicket
	claims *flowlogv1.FlowTokenClaims
	// spoolKey is "<network>-<device>": one spool per Network and Device.
	spoolKey  string
	spool     *Spool
	counter   *flowcount.Counter
	forwarder bool
	cluster   flowcount.ID
	// boot is the spool's boot the cursor belongs to: sent is the highest
	// sequence the receiver holds or answered INVALID. The highest ever
	// sent is in the spool, which keeps it across restarts.
	boot         []byte
	sent         uint64
	lastSend     time.Time
	retryAt      time.Time
	backoff      time.Duration
	tokenRefused bool
}

// Run works until ctx ends, then puts the last window on disk.
func (r *Reporter) Run(ctx context.Context) error {
	var current *active
	defer func() {
		if current != nil {
			r.stop(current)
		}
	}()
	window := time.NewTimer(time.Hour)
	window.Stop()
	send := time.NewTimer(time.Hour)
	send.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ticket := <-r.tickets:
			before := windowOf(current)
			current = r.apply(current, ticket)
			if current == nil {
				window.Stop()
				send.Stop()
				continue
			}
			// A renewal keeps the window: tickets may come faster than it.
			if windowOf(current) != before {
				window.Reset(r.windowDelay(current))
			}
			send.Reset(r.untilRetry(current))
		case <-window.C:
			if current == nil {
				continue
			}
			r.tick(current)
			window.Reset(r.windowDelay(current))
			send.Reset(r.untilRetry(current))
		case <-send.C:
			if current != nil {
				send.Reset(r.sendTurn(ctx, current))
			}
		}
	}
}

func windowOf(current *active) time.Duration {
	if current == nil {
		return 0
	}
	return time.Duration(current.claims.GetWindowS()) * time.Second
}

func (r *Reporter) windowDelay(current *active) time.Duration {
	period := windowOf(current)
	return period + rand.N(period/10+1) //nolint:gosec // jitter, not secrets
}

func (r *Reporter) untilRetry(current *active) time.Duration {
	return max(current.retryAt.Sub(r.config.Now()), 0)
}

// expired reports a token past its expiry and the clock skew a receiver
// allows: no receiver takes it any more.
func (r *Reporter) expired(current *active) bool {
	return !r.config.Now().Before(time.UnixMilli(current.claims.GetExpiresAtMs()).Add(flowlog.ClockSkew))
}

// apply takes a ticket: off, the same Network renewed, or another Network.
func (r *Reporter) apply(current *active, ticket controlplane.FlowTicket) *active {
	if len(ticket.Token) == 0 {
		if current != nil {
			r.stop(current)
		}
		r.setStatus(func(status *Status) { *status = Status{} })
		return nil
	}
	claims, err := flowlog.ReadClaims(ticket.Token)
	if err != nil || ticket.Post == nil || ticket.Machine.IsZero() {
		r.config.Logger.Warn("connection logging: ignoring an unusable ticket", "error", err)
		return current
	}
	// One spool per Network and Device: a Device's batches never go out
	// under another Device's token (a new registration, another profile).
	spoolKey := hex.EncodeToString(claims.GetNetworkId()) + "-" + hex.EncodeToString(claims.GetDeviceId())
	if current != nil && current.spoolKey != spoolKey {
		r.stop(current)
		current = nil
	}
	if current == nil {
		next, err := r.start(spoolKey)
		if err != nil {
			r.config.Logger.Warn("connection logging: cannot open the spool", "error", err)
			r.setStatus(func(status *Status) { *status = Status{LastError: err.Error()} })
			return nil
		}
		current = next
	}
	current.ticket, current.claims, current.tokenRefused = ticket, claims, false
	forwarder := slices.ContainsFunc(claims.GetRoles(), func(role flowlogv1.FlowTokenClaims_Role) bool {
		return role != flowlogv1.FlowTokenClaims_DEVICE
	})
	current.cluster = flowcount.ID{}
	if ids := claims.GetClusterIds(); len(ids) > 0 {
		copy(current.cluster[:], ids[0])
	}
	if current.counter == nil || forwarder != current.forwarder {
		// A new role changes the caps: the old counter's window is kept.
		r.stopCounting(current)
		flows, denials := flowcount.DeviceKeys, flowcount.DeviceDenyKeys
		if forwarder {
			flows, denials = flowcount.ForwarderKeys, flowcount.ForwarderDenyKeys
		}
		current.counter = flowcount.NewCounter(flows, denials, r.config.Now())
		// Forwarded traffic only while the token grants a forwarding role
		// (design §7, s2c gate).
		current.counter.CountForwarded(forwarder)
		current.forwarder = forwarder
		r.config.SetCounter(current.counter)
	}
	r.setStatus(func(status *Status) {
		status.On, status.NetworkID = true, hex.EncodeToString(claims.GetNetworkId())
	})
	r.setPending(current)
	return current
}

func (r *Reporter) start(spoolKey string) (*active, error) {
	if err := privatefile.PrepareDir(r.config.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("flowreport: spool directory: %w", err)
	}
	spool, err := OpenSpool(filepath.Join(r.config.Dir, spoolKey), r.config.Limits, r.config.Now())
	if err != nil {
		return nil, err
	}
	return &active{spoolKey: spoolKey, spool: spool}, nil
}

// stop ends logging for current: counting stops, its last window and the
// spool stay on disk.
func (r *Reporter) stop(current *active) {
	r.stopCounting(current)
	_ = current.spool.Close()
}

// stopCounting takes the counter off the filter first, then keeps its last
// window, so no packet is counted into a window already ended.
func (r *Reporter) stopCounting(current *active) {
	if current.counter == nil {
		return
	}
	r.config.SetCounter(nil)
	r.keepWindow(current, current.counter)
	current.counter = nil
	r.setStatus(func(status *Status) { status.On = false })
}

// tick ends a window: kept while the counter runs; once the token expired
// with no new ticket, counting stops until one comes (logging may have
// been turned off while Core could not say so).
func (r *Reporter) tick(current *active) {
	if current.counter == nil {
		return
	}
	if r.expired(current) {
		r.stopCounting(current)
		r.setStatus(func(status *Status) { status.LastError = "waiting for a new ticket from control" })
		return
	}
	r.keepWindow(current, current.counter)
}

// keepWindow ends counter's window and keeps it, unless it is empty.
func (r *Reporter) keepWindow(current *active, counter *flowcount.Counter) {
	now := r.config.Now()
	window := counter.Drain(now, current.cluster)
	if len(window.Records) == 0 && window.Overflow == (flowcount.Overflow{}) {
		return
	}
	policy := Policy{}
	if r.config.Policy != nil {
		policy = r.config.Policy()
	}
	if err := current.spool.Add(window, policy, current.claims.GetWindowS(), now); err != nil {
		r.config.Logger.Warn("connection logging: a window was not kept", "error", err,
			"records", len(window.Records))
		r.setStatus(func(status *Status) { status.LastError = err.Error() })
	}
	r.setPending(current)
}

// sendTurn sends what the receiver does not hold yet, oldest first, and
// returns when to try again.
func (r *Reporter) sendTurn(ctx context.Context, current *active) time.Duration {
	now := r.config.Now()
	period := windowOf(current)
	if now.Before(current.retryAt) {
		return current.retryAt.Sub(now)
	}
	if current.tokenRefused || !now.Before(time.UnixMilli(current.claims.GetExpiresAtMs())) {
		return period // a new ticket wakes the reporter
	}
	for range maxSendsPerTurn {
		pending, ok, err := r.nextToSend(current, now, period)
		if err != nil {
			return r.fail(current, err, 0)
		}
		if !ok {
			return period
		}
		if !r.sendOne(ctx, current, pending) {
			return max(r.untilRetry(current), minBackoff)
		}
	}
	return 0
}

// nextToSend is the batch after the last the receiver holds, or, when
// nothing is new, the oldest uncommitted one again once a window passed,
// so the node learns how far the receiver committed.
func (r *Reporter) nextToSend(current *active, now time.Time, period time.Duration) (Pending, bool, error) {
	oldest, ok, err := current.spool.Oldest()
	if err != nil || !ok {
		return Pending{}, false, err
	}
	if string(oldest.Request.GetBootId()) != string(current.boot) {
		current.boot, current.sent = oldest.Request.GetBootId(), 0
	}
	if current.sent < oldest.Request.GetSequence() {
		return oldest, true, nil
	}
	if next, ok, err := current.spool.Get(current.sent + 1); err != nil || ok {
		return next, ok, err
	}
	if now.Sub(current.lastSend) >= period {
		return oldest, true, nil
	}
	return Pending{}, false, nil
}

// sendOne sends one batch and applies the answer; false stops the turn,
// with retryAt set.
func (r *Reporter) sendOne(ctx context.Context, current *active, pending Pending) bool {
	request, err := flowlog.NewRequest(current.ticket.Token, current.ticket.Machine, current.ticket.ReceiverKey,
		pending.Request, pending.Compressed, nil)
	if err != nil {
		r.fail(current, fmt.Errorf("building a request: %w", err), 0)
		return false
	}
	if err := current.spool.MarkSent(pending.Request.GetBootId(), pending.Request.GetSequence()); err != nil {
		r.fail(current, err, 0)
		return false
	}
	postCtx, cancel := context.WithTimeout(ctx, postTimeout)
	result, err := current.ticket.Post(postCtx, request.TokenHeader(), request.Body)
	cancel()
	current.lastSend = r.config.Now()
	if err != nil {
		r.fail(current, err, 0)
		return false
	}
	if result.Status != http.StatusOK {
		// A plain HTTP answer never drops a batch (flowlog-v1 §4).
		if result.Status == http.StatusUnauthorized || result.Status == http.StatusForbidden {
			current.tokenRefused = true
		}
		r.fail(current, fmt.Errorf("the receiver answered HTTP %d", result.Status), result.RetryAfter)
		return false
	}
	answer, err := request.OpenAnswer(result.Body)
	if err != nil {
		r.fail(current, err, 0)
		return false
	}
	return r.applyAnswer(current, pending.Request, answer)
}

func (r *Reporter) applyAnswer(current *active, request *flowlogv1.FlowRequest,
	answer *flowlogv1.FlowBatchResponse,
) bool {
	committed, sequence := answer.GetCommittedSequence(), request.GetSequence()
	if committed > current.spool.HighestSent(request.GetBootId()) {
		// No answer may drop what was never sent (flowlog-v1 §5).
		r.fail(current, errors.New("the receiver committed past the last batch sent"), 0)
		return false
	}
	if committed > 0 {
		if err := current.spool.Commit(request.GetBootId(), committed); err != nil {
			r.fail(current, err, 0)
			return false
		}
	}
	retry := time.Duration(answer.GetRetryAfterMs()) * time.Millisecond
	switch answer.GetStatus() {
	case flowlogv1.FlowBatchResponse_ACCEPTED, flowlogv1.FlowBatchResponse_INVALID:
		if answer.GetStatus() == flowlogv1.FlowBatchResponse_INVALID {
			r.config.Logger.Warn("connection logging: the receiver refused a batch as invalid", "sequence", sequence)
		}
		current.sent, current.backoff = max(current.sent, sequence), 0
		r.setStatus(func(status *Status) { status.LastSent, status.LastError = r.config.Now(), "" })
		r.setPending(current)
		if retry > 0 {
			current.retryAt = r.config.Now().Add(retry)
			return false
		}
		return true
	case flowlogv1.FlowBatchResponse_OUT_OF_ORDER:
		next := answer.GetNextSequence()
		if next == 0 || next >= sequence {
			// It must ask for an earlier batch, or the node would send
			// the same one for ever.
			r.fail(current, errors.New("the receiver asked for a batch out of order wrongly"), 0)
			return false
		}
		// A next below held_from makes Get offer held_from (rule 1 then
		// applies at the receiver).
		current.sent = next - 1
		return true
	case flowlogv1.FlowBatchResponse_THROTTLED:
		current.retryAt = r.config.Now().Add(max(retry, minBackoff))
		return false
	case flowlogv1.FlowBatchResponse_TOKEN_REJECTED:
		current.tokenRefused = true
		current.retryAt = r.config.Now().Add(windowOf(current))
		return false
	case flowlogv1.FlowBatchResponse_DISABLED:
		// Logging is off for the Network: nothing is counted or kept
		// until a new ticket.
		r.stopCounting(current)
		if err := current.spool.Reset(); err != nil {
			r.fail(current, err, 0)
			return false
		}
		current.boot, current.sent = nil, 0
		current.tokenRefused = true
		r.setPending(current)
		return false
	default:
		r.fail(current, errors.New("unknown answer"), 0)
		return false
	}
}

// fail records err and sets retryAt: a backoff doubling up to maxBackoff,
// or the receiver's own Retry-After when longer.
func (r *Reporter) fail(current *active, err error, retryAfter time.Duration) time.Duration {
	current.backoff = min(max(current.backoff*2, minBackoff), maxBackoff)
	wait := max(current.backoff, retryAfter)
	current.retryAt = r.config.Now().Add(wait)
	r.config.Logger.Debug("connection logging: sending failed", "error", err, "retry_in", wait)
	r.setStatus(func(status *Status) { status.LastError = err.Error() })
	r.setPending(current)
	return wait
}

func (r *Reporter) setPending(current *active) {
	pending := uint64(current.spool.Len()) //nolint:gosec // a count
	r.setStatus(func(status *Status) { status.Pending = pending })
}

func (r *Reporter) setStatus(change func(*Status)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	change(&r.status)
}
