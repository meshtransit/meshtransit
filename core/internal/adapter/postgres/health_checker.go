package postgres

import (
	"context"
	"errors"
	"fmt"

	"meshtransit.net/core/internal/platform/app"
)

// HealthChecker presents one PostgreSQL readiness component while verifying
// the independently authenticated runtime and worker pools that are configured.
type HealthChecker struct {
	runtime *Pool
	worker  *Pool
}

// NewHealthChecker constructs a checker for at least one role pool.
func NewHealthChecker(runtime, worker *Pool) (*HealthChecker, error) {
	if (runtime == nil && worker == nil) ||
		(runtime != nil && runtime.role != PoolRoleRuntime) ||
		(worker != nil && worker.role != PoolRoleWorker) {
		return nil, ErrInvalidOptions
	}
	return &HealthChecker{runtime: runtime, worker: worker}, nil
}

// Component identifies the combined PostgreSQL dependency to readiness.
func (*HealthChecker) Component() app.Component { return app.ComponentPostgreSQL }

// Check verifies every configured role pool within the caller's shared bound.
func (checker *HealthChecker) Check(ctx context.Context) error {
	if ctx == nil || checker == nil || (checker.runtime == nil && checker.worker == nil) {
		return ErrInvalidOptions
	}
	var results []error
	if checker.runtime != nil {
		if err := checker.runtime.Check(ctx); err != nil {
			results = append(results, fmt.Errorf("runtime role pool: %w", err))
		}
	}
	if checker.worker != nil {
		if err := checker.worker.Check(ctx); err != nil {
			results = append(results, fmt.Errorf("worker role pool: %w", err))
		}
	}
	return errors.Join(results...)
}
