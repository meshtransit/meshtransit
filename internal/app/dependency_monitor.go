package app

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrInvalidDependencyMonitor indicates inconsistent monitor inputs.
	ErrInvalidDependencyMonitor = errors.New("invalid dependency monitor")
	// ErrDependencyMonitorStarted indicates that a monitor starts at most once.
	ErrDependencyMonitorStarted = errors.New("dependency monitor already started")
	// ErrDependencyMonitorNotStarted indicates shutdown before a successful start.
	ErrDependencyMonitorNotStarted = errors.New("dependency monitor not started")
	// ErrDependencyUnavailable indicates that at least one bounded check failed.
	ErrDependencyUnavailable = errors.New("dependency unavailable")
)

// DependencyChecker is the application-owned health contract implemented by
// concrete infrastructure adapters.
type DependencyChecker interface {
	Component() Component
	// Check must return when ctx is canceled. Implementations must not retain
	// ctx or start work that outlives the call.
	Check(context.Context) error
}

// MonitorOptions contains validated dependency polling bounds.
type MonitorOptions struct {
	CheckTimeout  time.Duration
	CheckInterval time.Duration
}

// DependencyMonitor owns periodic dependency checks and their single
// goroutine. Start performs the first check synchronously before any listener
// may be opened.
type DependencyMonitor struct {
	options  MonitorOptions
	state    *RuntimeState
	checkers []DependencyChecker

	mu        sync.Mutex
	starting  bool
	started   bool
	stopping  bool
	cancel    context.CancelFunc
	startDone chan struct{}
	done      chan error
}

// NewDependencyMonitor constructs a stopped monitor with an exact checker set.
func NewDependencyMonitor(
	options MonitorOptions,
	state *RuntimeState,
	checkers ...DependencyChecker,
) (*DependencyMonitor, error) {
	if state == nil || options.CheckTimeout <= 0 || options.CheckInterval <= options.CheckTimeout {
		return nil, ErrInvalidDependencyMonitor
	}

	required := state.RequiredComponents()
	if len(checkers) != len(required) {
		return nil, ErrInvalidDependencyMonitor
	}
	requiredSet := make(map[Component]struct{}, len(required))
	for _, component := range required {
		requiredSet[component] = struct{}{}
	}
	seen := make(map[Component]struct{}, len(checkers))
	for _, checker := range checkers {
		if isNilLifecycleDependency(checker) {
			return nil, ErrInvalidDependencyMonitor
		}
		component := checker.Component()
		if _, ok := requiredSet[component]; !ok {
			return nil, ErrInvalidDependencyMonitor
		}
		if _, duplicate := seen[component]; duplicate {
			return nil, ErrInvalidDependencyMonitor
		}
		seen[component] = struct{}{}
	}

	return &DependencyMonitor{
		options:  options,
		state:    state,
		checkers: append([]DependencyChecker(nil), checkers...),
	}, nil
}

// Start performs the fail-closed initial check and then starts periodic checks.
func (monitor *DependencyMonitor) Start(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidDependencyMonitor
	}

	monitor.mu.Lock()
	if monitor.started || monitor.starting || monitor.stopping {
		monitor.mu.Unlock()
		return ErrDependencyMonitorStarted
	}
	startCtx, startCancel := context.WithCancel(ctx)
	startDone := make(chan struct{})
	monitor.starting = true
	monitor.cancel = startCancel
	monitor.startDone = startDone
	monitor.mu.Unlock()

	if err := monitor.checkAll(startCtx); err != nil {
		startCancel()
		monitor.mu.Lock()
		monitor.starting = false
		monitor.cancel = nil
		monitor.startDone = nil
		close(startDone)
		monitor.mu.Unlock()
		return err
	}

	monitorCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan error, 1)
	monitor.mu.Lock()
	if monitor.stopping || startCtx.Err() != nil {
		monitor.starting = false
		monitor.cancel = nil
		monitor.startDone = nil
		close(startDone)
		monitor.mu.Unlock()
		startCancel()
		cancel()
		return context.Canceled
	}
	monitor.cancel = cancel
	monitor.done = done
	monitor.starting = false
	monitor.started = true
	monitor.startDone = nil
	go func() {
		done <- monitor.run(monitorCtx)
		close(done)
	}()
	close(startDone)
	monitor.mu.Unlock()
	startCancel()
	return nil
}

// Done returns the join channel after a successful Start call.
func (monitor *DependencyMonitor) Done() <-chan error {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	return monitor.done
}

// Shutdown requests monitor cancellation. Done is the corresponding join path.
func (monitor *DependencyMonitor) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidDependencyMonitor
	}

	monitor.mu.Lock()
	if monitor.starting {
		monitor.stopping = true
		cancel := monitor.cancel
		startDone := monitor.startDone
		monitor.mu.Unlock()
		cancel()
		select {
		case <-startDone:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	started := monitor.started
	cancel := monitor.cancel
	if started {
		monitor.stopping = true
	}
	monitor.mu.Unlock()
	if !started {
		return ErrDependencyMonitorNotStarted
	}
	cancel()
	return nil
}

func (monitor *DependencyMonitor) run(ctx context.Context) error {
	ticker := time.NewTicker(monitor.options.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_ = monitor.checkAll(ctx)
		}
	}
}

func (monitor *DependencyMonitor) checkAll(parent context.Context) error {
	if len(monitor.checkers) == 0 {
		return nil
	}

	statuses := make([]ComponentStatus, len(monitor.checkers))
	errorsByIndex := make([]error, len(monitor.checkers))
	var checks sync.WaitGroup
	for index, checker := range monitor.checkers {
		checks.Go(func() {
			checkCtx, cancel := context.WithTimeout(parent, monitor.options.CheckTimeout)
			defer cancel()
			if err := checker.Check(checkCtx); err != nil {
				statuses[index] = ComponentStatusUnavailable
				errorsByIndex[index] = fmt.Errorf("%s check: %w", checker.Component(), err)
				return
			}
			statuses[index] = ComponentStatusReady
		})
	}
	checks.Wait()

	updates := make(map[Component]ComponentStatus, len(monitor.checkers))
	var checkErrors []error
	for index, checker := range monitor.checkers {
		updates[checker.Component()] = statuses[index]
		if errorsByIndex[index] != nil {
			checkErrors = append(checkErrors, errorsByIndex[index])
		}
	}
	if err := monitor.state.SetComponentStatuses(updates); err != nil {
		return errors.Join(ErrInvalidDependencyMonitor, err)
	}
	if len(checkErrors) != 0 {
		return errors.Join(append([]error{ErrDependencyUnavailable}, checkErrors...)...)
	}
	return nil
}
