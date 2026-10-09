package postgres

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/adapter/postgres/registrationintake"
)

func TestNewRegistrationIntakeTransactionsRequiresRuntimePool(t *testing.T) {
	t.Parallel()

	options := registrationintake.Options{}
	for name, pool := range map[string]*Pool{
		"nil":           nil,
		"uninitialized": {},
		"worker": {
			role: PoolRoleWorker,
			registrationIntake: func(
				registrationintake.Options,
			) (*registrationintake.Transactions, error) {
				return nil, errors.New("must not be called")
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewRegistrationIntakeTransactions(pool, options); !errors.Is(
				err,
				ErrInvalidRegistrationIntake,
			) {
				t.Fatalf("NewRegistrationIntakeTransactions() error = %v", err)
			}
		})
	}

	called := false
	wantErr := errors.New("controlled registration-intake construction failure")
	pool := &Pool{
		role: PoolRoleRuntime,
		registrationIntake: func(
			registrationintake.Options,
		) (*registrationintake.Transactions, error) {
			called = true
			return nil, wantErr
		},
	}
	if _, err := NewRegistrationIntakeTransactions(pool, options); !errors.Is(err, wantErr) {
		t.Fatalf("NewRegistrationIntakeTransactions() error = %v, want delegated error", err)
	}
	if !called {
		t.Fatal("runtime pool did not delegate registration-intake construction")
	}
}

func TestRegistrationIntakeObserverUsesFixedOperationLabels(t *testing.T) {
	t.Parallel()

	metrics := newPostgresPoolMetrics(PoolRoleRuntime, func() postgresPoolStats {
		return postgresPoolStats{}
	})
	metrics.Observe(registrationintake.OperationApply, 25*time.Millisecond, nil)

	body := gatherPostgresMetrics(t, &postgresMetricsCollector{pools: []*postgresPoolMetrics{metrics}})
	want := `meshtransit_postgres_operations_total{operation="registration_intake_apply",pool_role="runtime",result="success"} 1`
	if !strings.Contains(body, want) {
		t.Fatalf("metrics missing registration intake outcome %q", want)
	}
}
