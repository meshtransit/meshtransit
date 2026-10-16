package postgres

import (
	"context"
	"sync"
	"time"
)

// operatorStepMonitor reads the operator steps in its own goroutine, so the
// catalog query never runs inside a readiness check. A check only wakes it;
// it reads at most once per interval and publishes through the pool metrics.
type operatorStepMonitor struct {
	read     func(context.Context) (operatorStepSnapshot, error)
	metrics  *postgresPoolMetrics
	interval time.Duration
	wakeup   chan struct{}

	mu        sync.Mutex
	lastRead  time.Time
	cancel    context.CancelFunc
	done      chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
}

func newOperatorStepMonitor(
	read func(context.Context) (operatorStepSnapshot, error),
	metrics *postgresPoolMetrics,
	interval time.Duration,
) *operatorStepMonitor {
	return &operatorStepMonitor{read: read, metrics: metrics, interval: interval, wakeup: make(chan struct{}, 1)}
}

// start launches the single monitor goroutine; stop joins it.
func (monitor *operatorStepMonitor) start() {
	monitor.startOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		monitor.mu.Lock()
		monitor.cancel, monitor.done = cancel, done
		monitor.mu.Unlock()
		go func() {
			defer close(done)
			defer cancel()
			for {
				select {
				case <-ctx.Done():
					return
				case <-monitor.wakeup:
					if monitor.due(time.Now()) {
						monitor.probe(ctx)
					}
				}
			}
		}()
	})
}

// wake asks for a read without waiting; a pending wake is enough.
func (monitor *operatorStepMonitor) wake() {
	if monitor == nil {
		return
	}
	select {
	case monitor.wakeup <- struct{}{}:
	default:
	}
}

func (monitor *operatorStepMonitor) due(now time.Time) bool {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	if monitor.interval > 0 && !monitor.lastRead.IsZero() && now.Sub(monitor.lastRead) < monitor.interval {
		return false
	}
	monitor.lastRead = now
	return true
}

// probe runs one bounded read and publishes it.
func (monitor *operatorStepMonitor) probe(ctx context.Context) {
	readContext, cancel := context.WithTimeout(ctx, operatorStepCheckTimeout)
	defer cancel()
	startedAt := time.Now()
	snapshot, err := monitor.read(readContext)
	if ctx.Err() != nil {
		return
	}
	monitor.metrics.observeOperation(postgresOperationOperatorStepCheck, time.Since(startedAt), err)
	monitor.metrics.observeOperatorSteps(ctx, snapshot, err)
}

// stop cancels a read in flight and waits for the goroutine within ctx, so
// the pool drains with no connection held by the monitor.
func (monitor *operatorStepMonitor) stop(ctx context.Context) error {
	if monitor == nil {
		return nil
	}
	monitor.mu.Lock()
	cancel, done := monitor.cancel, monitor.done
	monitor.mu.Unlock()
	if cancel == nil {
		return nil
	}
	monitor.stopOnce.Do(cancel)
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
