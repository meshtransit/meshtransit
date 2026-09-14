package registrationintake

import "time"

// Operation is a fixed low-cardinality registration-intake database operation.
type Operation uint8

const (
	// OperationUnknown is the invalid zero value.
	OperationUnknown Operation = iota
	// OperationBegin resolves and installs exact transaction scope.
	OperationBegin
	// OperationResolve locks and rehydrates credential authority.
	OperationResolve
	// OperationApply writes pending intent, audit, and outbox evidence.
	OperationApply
	// OperationCommit commits one prepared intent.
	OperationCommit
	// OperationRollback closes an uncommitted transaction.
	OperationRollback
	// OperationReplay resolves durable evidence after an uncertain commit.
	OperationReplay
)

// Observer records bounded operation latency and outcome without request labels.
type Observer interface {
	Observe(Operation, time.Duration, error)
}

func observe(observer Observer, operation Operation, startedAt time.Time, err error) {
	if observer == nil {
		return
	}
	observer.Observe(operation, time.Since(startedAt), err)
}
