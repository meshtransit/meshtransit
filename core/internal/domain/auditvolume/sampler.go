// Package auditvolume samples how many audit events the Deployment stream
// holds, so its rate can be watched (TD-CORE-134): that stream is one row
// every Workspace's sign-ins and sessions lock until commit, with a measured
// ceiling of roughly 500–1 000 events/s.
package auditvolume

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrInvalidSampler rejects unsafe dependencies or bounds.
	ErrInvalidSampler = errors.New("audit volume sampler: invalid configuration")
	// ErrSamplerStarted rejects duplicate lifecycle ownership.
	ErrSamplerStarted = errors.New("audit volume sampler: already started")
	// ErrSamplerNotStarted rejects shutdown before startup.
	ErrSamplerNotStarted = errors.New("audit volume sampler: not started")
)

// Reader returns the events every Deployment stream holds.
type Reader interface {
	DeploymentEvents(ctx context.Context) (int64, error)
}

// Options bound the cadence and each read.
type Options struct {
	Interval time.Duration
	Timeout  time.Duration
}

// DefaultOptions sample every 30 seconds, enough for rate() over minutes.
func DefaultOptions() Options { return Options{Interval: 30 * time.Second, Timeout: 5 * time.Second} }

func (options Options) valid() bool {
	return options.Interval >= 10*time.Second && options.Interval <= time.Hour &&
		options.Timeout >= time.Second && options.Timeout < options.Interval
}

// Measurements are the last good sample and the failures since start.
type Measurements struct {
	Sampled bool
	Events  int64
	At      time.Time
	Failed  uint64
}

// Sampler owns one goroutine reading at start and every Interval.
type Sampler struct {
	options Options
	reader  Reader
	logger  *slog.Logger

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan error

	events  atomic.Int64
	at      atomic.Int64
	sampled atomic.Bool
	failed  atomic.Uint64
}

// New constructs a stopped sampler without I/O.
func New(options Options, reader Reader, logger *slog.Logger) (*Sampler, error) {
	if !options.valid() || reader == nil || logger == nil {
		return nil, ErrInvalidSampler
	}
	if value := reflect.ValueOf(reader); value.Kind() == reflect.Pointer && value.IsNil() {
		return nil, ErrInvalidSampler
	}
	return &Sampler{options: options, reader: reader, logger: logger}, nil
}

// Start owns cancellation separately from the caller's startup context.
func (sampler *Sampler) Start(ctx context.Context) error {
	if sampler == nil || ctx == nil {
		return ErrInvalidSampler
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	sampler.mu.Lock()
	defer sampler.mu.Unlock()
	if sampler.started {
		return ErrSamplerStarted
	}
	owned, cancel := context.WithCancel(context.WithoutCancel(ctx))
	sampler.cancel, sampler.done, sampler.started = cancel, make(chan error, 1), true
	go func() {
		sampler.run(owned)
		sampler.done <- nil
		close(sampler.done)
	}()
	return nil
}

// Done is the process-owned lifecycle join, available after Start.
func (sampler *Sampler) Done() <-chan error {
	if sampler == nil {
		return nil
	}
	sampler.mu.Lock()
	defer sampler.mu.Unlock()
	return sampler.done
}

// Shutdown cancels the loop. Done is the join path used by the process owner.
func (sampler *Sampler) Shutdown(ctx context.Context) error {
	if sampler == nil || ctx == nil {
		return ErrInvalidSampler
	}
	sampler.mu.Lock()
	defer sampler.mu.Unlock()
	if !sampler.started {
		return ErrSamplerNotStarted
	}
	sampler.cancel()
	return nil
}

// Snapshot returns race-safe measurements.
func (sampler *Sampler) Snapshot() Measurements {
	if sampler == nil || !sampler.sampled.Load() {
		return Measurements{Failed: sampler.failures()}
	}
	return Measurements{Sampled: true, Events: sampler.events.Load(),
		At: time.Unix(0, sampler.at.Load()), Failed: sampler.failed.Load()}
}

func (sampler *Sampler) failures() uint64 {
	if sampler == nil {
		return 0
	}
	return sampler.failed.Load()
}

func (sampler *Sampler) run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			sampler.Sample(ctx)
			timer.Reset(sampler.options.Interval)
		}
	}
}

// Sample reads once; a failure keeps the last good value. Exported for tests.
func (sampler *Sampler) Sample(ctx context.Context) {
	readCtx, cancel := context.WithTimeout(ctx, sampler.options.Timeout)
	defer cancel()
	events, err := sampler.reader.DeploymentEvents(readCtx)
	if err == nil && events < 0 {
		err = ErrInvalidSampler
	}
	if err != nil {
		if ctx.Err() == nil {
			sampler.failed.Add(1)
			sampler.logger.WarnContext(ctx, "Audit volume sample failed",
				"error_code", "audit_volume_sample_failed", "error", err)
		}
		return
	}
	sampler.events.Store(events)
	sampler.at.Store(time.Now().UnixNano())
	sampler.sampled.Store(true)
}
