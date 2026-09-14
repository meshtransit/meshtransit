package postgres

import (
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/internal/adapter/postgres/registrationintake"
)

// ErrInvalidRegistrationIntake reports a pool without runtime write authority.
var ErrInvalidRegistrationIntake = errors.New("invalid postgres registration intake")

var _ registrationintake.Observer = (*postgresPoolMetrics)(nil)

// NewRegistrationIntakeTransactions constructs the credential-authenticated
// intent adapter from a runtime-scoped pool.
func NewRegistrationIntakeTransactions(
	pool *Pool,
	options registrationintake.Options,
) (*registrationintake.Transactions, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.registrationIntake == nil {
		return nil, ErrInvalidRegistrationIntake
	}
	return pool.registrationIntake(options)
}

func (metrics *postgresPoolMetrics) Observe(
	operation registrationintake.Operation,
	duration time.Duration,
	err error,
) {
	var mapped postgresOperation
	switch operation {
	case registrationintake.OperationBegin:
		mapped = postgresOperationIntakeBegin
	case registrationintake.OperationResolve:
		mapped = postgresOperationIntakeResolve
	case registrationintake.OperationApply:
		mapped = postgresOperationIntakeApply
	case registrationintake.OperationCommit:
		mapped = postgresOperationIntakeCommit
	case registrationintake.OperationRollback:
		mapped = postgresOperationIntakeRollback
	case registrationintake.OperationReplay:
		mapped = postgresOperationIntakeReplay
	default:
		return
	}
	metrics.observeOperation(mapped, duration, err)
}
