package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/internal/app"
)

func TestHealthCheckerChecksConfiguredRolePools(t *testing.T) {
	t.Parallel()

	runtimeChecks := 0
	workerChecks := 0
	runtimePool := testHealthyPool(PoolRoleRuntime, func() { runtimeChecks++ })
	workerPool := testHealthyPool(PoolRoleWorker, func() { workerChecks++ })
	checker, err := NewHealthChecker(runtimePool, workerPool)
	if err != nil {
		t.Fatalf("NewHealthChecker() error = %v", err)
	}
	if err := checker.Check(t.Context()); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if runtimeChecks != 1 || workerChecks != 1 {
		t.Fatalf("role pool checks = (%d, %d), want (1, 1)", runtimeChecks, workerChecks)
	}
	if checker.Component() != app.ComponentPostgreSQL {
		t.Fatalf("Component() = %s, want postgresql", checker.Component())
	}
}

func TestHealthCheckerAggregatesRolePoolFailures(t *testing.T) {
	t.Parallel()

	runtimeErr := errors.New("runtime unavailable")
	workerErr := errors.New("worker unavailable")
	checker, err := NewHealthChecker(
		testFailingPool(PoolRoleRuntime, runtimeErr),
		testFailingPool(PoolRoleWorker, workerErr),
	)
	if err != nil {
		t.Fatalf("NewHealthChecker() error = %v", err)
	}
	checkErr := checker.Check(t.Context())
	if !errors.Is(checkErr, runtimeErr) || !errors.Is(checkErr, workerErr) {
		t.Fatalf("Check() error = %v, want both role-pool failures", checkErr)
	}
}

func TestHealthCheckerRejectsMissingPoolsAndContext(t *testing.T) {
	t.Parallel()

	if _, err := NewHealthChecker(nil, nil); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("NewHealthChecker(nil, nil) error = %v, want ErrInvalidOptions", err)
	}
	checker, err := NewHealthChecker(testHealthyPool(PoolRoleRuntime, func() {}), nil)
	if err != nil {
		t.Fatalf("NewHealthChecker() error = %v", err)
	}
	var nilContext context.Context
	if err := checker.Check(nilContext); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("Check(nil) error = %v, want ErrInvalidOptions", err)
	}
}

func TestHealthCheckerRejectsSwappedPoolRoles(t *testing.T) {
	t.Parallel()

	if _, err := NewHealthChecker(
		testHealthyPool(PoolRoleWorker, func() {}),
		testHealthyPool(PoolRoleRuntime, func() {}),
	); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("NewHealthChecker() error = %v, want ErrInvalidOptions", err)
	}
}

func testHealthyPool(role PoolRole, checked func()) *Pool {
	return &Pool{
		role: role,
		ping: func(context.Context) error {
			checked()
			return nil
		},
		checkSchema: func(context.Context) error { return nil },
		close:       func() {},
	}
}

func testFailingPool(role PoolRole, checkErr error) *Pool {
	return &Pool{
		role:        role,
		ping:        func(context.Context) error { return checkErr },
		checkSchema: func(context.Context) error { return nil },
		close:       func() {},
	}
}
