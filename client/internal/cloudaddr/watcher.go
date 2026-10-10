package cloudaddr

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// Watcher states reported in Status.
const (
	StateNone    = "none"    // not a recognised cloud instance
	StatePending = "pending" // first lookup not finished
	StateReady   = "ready"
	StateFailed  = "failed"
)

// Status is the latest lookup. Addresses are shown locally on explicit
// request only; they are never logged.
type Status struct {
	State      string
	Platform   Platform
	Addresses  []netip.Addr
	ObservedAt time.Time
	Error      string
}

// watchSchedule holds the watcher's intervals; tests shorten them.
type watchSchedule struct {
	refresh     time.Duration // regular lookups
	minInterval time.Duration // spacing of lookups after network changes
	retry       time.Duration // first retry after a failure, doubling
	maxRetry    time.Duration
}

var defaultWatchSchedule = watchSchedule{
	refresh:     time.Hour,
	minInterval: time.Minute,
	retry:       time.Minute,
	maxRetry:    10 * time.Minute,
}

// lookupTimeout bounds one lookup across all its requests.
const lookupTimeout = 6 * time.Second

// WatcherOptions configures a Watcher. Zero values select the defaults.
type WatcherOptions struct {
	Logger *slog.Logger
	// ReadDMI reads a DMI field; nil reads the host's.
	ReadDMI func(string) string
	Client  *Client
	Clock   func() time.Time
}

// Watcher keeps the instance's public addresses current.
type Watcher struct {
	logger   *slog.Logger
	platform Platform
	client   *Client
	clock    func() time.Time
	schedule watchSchedule

	network chan struct{}
	changes chan struct{}

	mu     sync.Mutex
	status Status
}

// NewWatcher recognises the platform once and returns a watcher for it.
func NewWatcher(options WatcherOptions) *Watcher {
	if options.ReadDMI == nil {
		options.ReadDMI = ReadDMI
	}
	if options.Client == nil {
		options.Client = NewClient()
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	platform := DetectPlatform(options.ReadDMI)
	state := StatePending
	if platform == PlatformNone {
		state = StateNone
	}

	return &Watcher{
		logger:   options.Logger,
		platform: platform,
		client:   options.Client,
		clock:    options.Clock,
		schedule: defaultWatchSchedule,
		network:  make(chan struct{}, 1),
		changes:  make(chan struct{}, 1),
		status:   Status{State: state, Platform: platform},
	}
}

// Platform returns the recognised platform.
func (w *Watcher) Platform() Platform { return w.platform }

// Status returns the latest lookup.
func (w *Watcher) Status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	status := w.status
	status.Addresses = slices.Clone(status.Addresses)

	return status
}

// Addresses returns the public addresses from the latest successful lookup.
func (w *Watcher) Addresses() []netip.Addr {
	w.mu.Lock()
	defer w.mu.Unlock()

	return slices.Clone(w.status.Addresses)
}

// Changes receives a value whenever Addresses changes.
func (w *Watcher) Changes() <-chan struct{} { return w.changes }

// NetworkChanged asks for a lookup soon (at most every minute).
func (w *Watcher) NetworkChanged() {
	select {
	case w.network <- struct{}{}:
	default:
	}
}

// Run looks up the addresses now, hourly, after network changes and after
// failures, until ctx ends. On an unrecognised platform it only waits.
func (w *Watcher) Run(ctx context.Context) {
	if w.platform == PlatformNone {
		<-ctx.Done()

		return
	}
	var (
		failures int
		lastRun  time.Time
		timer    = time.NewTimer(0)
	)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-w.network:
			if since := time.Since(lastRun); since < w.schedule.minInterval {
				timer.Reset(w.schedule.minInterval - since)

				continue
			}
		}
		lastRun = time.Now()
		if err := w.lookup(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			failures++
			timer.Reset(backoff(w.schedule.retry, w.schedule.maxRetry, failures))

			continue
		}
		failures = 0
		timer.Reset(w.schedule.refresh)
	}
}

func (w *Watcher) lookup(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	addresses, err := w.client.PublicAddresses(ctx, w.platform)
	if err != nil {
		code := "network"
		if errors.Is(err, ErrInvalidResponse) {
			code = "invalid_response"
		}
		if w.logger != nil {
			// Only the code: errors can carry addresses.
			w.logger.Debug("cloud metadata lookup failed", "platform", string(w.platform), "error_code", code)
		}
		w.mu.Lock()
		if w.status.State != StateReady {
			w.status = Status{State: StateFailed, Platform: w.platform, Error: code}
		}
		w.mu.Unlock()

		return err
	}
	w.mu.Lock()
	changed := w.status.State != StateReady || !slices.Equal(w.status.Addresses, addresses)
	w.status = Status{State: StateReady, Platform: w.platform, Addresses: addresses, ObservedAt: w.clock()}
	w.mu.Unlock()
	if changed {
		if w.logger != nil {
			w.logger.Info("cloud public addresses updated", "platform", string(w.platform), "count", len(addresses))
		}
		select {
		case w.changes <- struct{}{}:
		default:
		}
	}

	return nil
}

func backoff(first, maximum time.Duration, failures int) time.Duration {
	delay := first
	for i := 1; i < failures && delay < maximum; i++ {
		delay *= 2
	}

	return min(delay, maximum)
}
